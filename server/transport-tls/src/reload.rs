//! # Hot-reload of the mutual-TLS server config — atomic + FAIL-SAFE
//!
//! [`crate::server_config_from_files`] / [`crate::server_config_from_files_with_crl`] build a
//! [`ServerConfig`] from ops-provisioned files ONCE. In production those files change on a
//! RUNNING agent: a CA is rotated, a compromised client cert is revoked by publishing a new
//! CRL. [`ReloadableServerConfig`] lets the agent pick up those changes **without a restart**
//! and **without changing** [`crate::accept`] / [`crate::connect`] / the `TlsTransport` — each
//! [`accept`](crate::accept) simply takes a fresh [`current`](ReloadableServerConfig::current)
//! snapshot of the live config.
//!
//! ## The two guarantees
//!
//! - **Atomic.** A reload rebuilds a brand-new [`ServerConfig`] from the spec's files FIRST and,
//!   only after that whole build succeeds, swaps it into place under a write lock in a single
//!   `Arc` pointer store. No accept ever observes a half-built config: it holds either the whole
//!   old `Arc` or the whole new one.
//! - **FAIL-SAFE.** If ANY step of the rebuild fails (a file is missing, truncated, mid-write,
//!   a key no longer matches its chain, a CRL is malformed), [`reload`](ReloadableServerConfig::reload)
//!   returns `Err` and leaves the live config **exactly as it was**. A bad reload therefore can
//!   never (a) disarm mutual auth into an accept-any state, nor (b) break the currently-serving
//!   config. The running agent keeps enforcing the last-known-good mutual-TLS policy.
//!
//! ## What a reload does and does NOT affect
//!
//! A reload governs FUTURE handshakes: the next [`accept`](crate::accept) that calls
//! [`current`](ReloadableServerConfig::current) uses the new config, so a freshly-revoked client
//! is rejected on its NEXT connection. Sessions already established keep their existing
//! `ServerConnection` and are unaffected — a reload rejects future handshakes, it does not tear
//! down in-flight ones.
//!
//! ## Mutual auth is never weakened here
//!
//! This wrapper adds NO `dangerous()` / accept-any path of its own. It builds exclusively through
//! the same file loaders, which install the REQUIRED [`rustls::server::WebPkiClientVerifier`]
//! (`.build()`), so mutual client authentication stays mandatory across every reload.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use rustls::ServerConfig;

use crate::{server_config_from_files, server_config_from_files_with_crl};

/// The files a [`ReloadableServerConfig`] (re)builds its mutual-TLS [`ServerConfig`] from.
///
/// These are the SAME inputs the one-shot loaders take, kept as owned paths so a reload can
/// re-read them on a running agent. Rotating a CA or publishing a new CRL is done by rewriting
/// the file at one of these paths and calling [`ReloadableServerConfig::reload`]; the set of
/// paths itself does not change.
///
/// - `ca_paths`: one or more CA files — the multi-CA client-auth trust root (rotation overlap).
/// - `cert_chain`: the server leaf chain file presented to peers.
/// - `key`: the server private-key file matching `cert_chain`'s leaf.
/// - `crl_paths`: zero or more CRL files. **Empty means no CRL enforcement** (built via
///   [`server_config_from_files`]); non-empty means revocation is enforced at the handshake
///   (built via [`server_config_from_files_with_crl`], which fail-closes on an empty CRL set).
#[derive(Clone, Debug)]
pub struct CertFileSpec {
    /// CA file(s) forming the multi-CA client-auth trust root.
    pub ca_paths: Vec<PathBuf>,
    /// The server leaf certificate chain file.
    pub cert_chain: PathBuf,
    /// The server private-key file.
    pub key: PathBuf,
    /// CRL file(s); empty = no CRL enforcement, non-empty = revocation enforced at the handshake.
    pub crl_paths: Vec<PathBuf>,
}

impl CertFileSpec {
    /// Build a fresh [`ServerConfig`] from the CURRENT contents of the spec's files.
    ///
    /// Dispatches to [`server_config_from_files_with_crl`] when `crl_paths` is non-empty (so
    /// revocation is enforced) and to [`server_config_from_files`] otherwise. Both install the
    /// REQUIRED client-cert verifier, so mutual auth is mandatory regardless of the CRL branch.
    /// Any I/O, parse, trust-anchor, CRL, verifier, or cert/key-mismatch error propagates as
    /// [`io::Error`] — nothing here can silently produce an accept-any config.
    fn build(&self) -> io::Result<Arc<ServerConfig>> {
        // The loaders want `&[&Path]`; borrow each owned `PathBuf` for the call.
        let ca_refs: Vec<&Path> = self.ca_paths.iter().map(PathBuf::as_path).collect();
        if self.crl_paths.is_empty() {
            server_config_from_files(&ca_refs, &self.cert_chain, &self.key)
        } else {
            let crl_refs: Vec<&Path> = self.crl_paths.iter().map(PathBuf::as_path).collect();
            server_config_from_files_with_crl(&ca_refs, &self.cert_chain, &self.key, &crl_refs)
        }
    }
}

/// A live, hot-reloadable mutual-TLS [`ServerConfig`] rebuilt from the SAME files on a running
/// agent, swapped **atomically** and **fail-safe**.
///
/// Hold ONE of these for the lifetime of the agent's listener. Each accepted connection takes a
/// [`current`](Self::current) snapshot and hands it to [`crate::accept`]; a
/// [`reload`](Self::reload) (triggered by a SIGHUP, a control command, a file-watch, ...) rebuilds
/// from the spec's files and swaps in the new config for FUTURE accepts only. See the module docs
/// for the atomic + fail-safe + no-restart semantics.
pub struct ReloadableServerConfig {
    /// The live config. `RwLock` so many concurrent accepts read cheaply while a reload takes the
    /// write lock only for the instantaneous `Arc` pointer swap.
    inner: RwLock<Arc<ServerConfig>>,
    /// The files every (re)build reads from.
    spec: CertFileSpec,
}

impl ReloadableServerConfig {
    /// Build the initial live config from the spec's files.
    ///
    /// Errors (returns `Err`, constructs nothing) if the files do not load into a valid
    /// mutual-TLS config — an agent must not come up with a broken or accept-any trust config, so
    /// initialization fails closed exactly as the one-shot loaders do.
    pub fn from_files(spec: CertFileSpec) -> io::Result<Self> {
        let initial = spec.build()?;
        Ok(ReloadableServerConfig {
            inner: RwLock::new(initial),
            spec,
        })
    }

    /// A snapshot of the live config for ONE [`crate::accept`].
    ///
    /// Takes the read lock and clones the `Arc` (a cheap refcount bump), so the returned config
    /// stays valid for this whole handshake even if a concurrent [`reload`](Self::reload) swaps in
    /// a new one meanwhile. A poisoned lock is recovered (`into_inner`) rather than panicked on:
    /// the last config an accept saw is still a valid, mutual-auth config, so serving it is the
    /// fail-safe choice.
    pub fn current(&self) -> Arc<ServerConfig> {
        match self.inner.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Rebuild the config from the spec's files and, ONLY on full success, atomically swap it in.
    ///
    /// The new config is built FIRST (`spec.build()?`). If that fails — a missing/half-written
    /// file, a bad key/chain pair, a malformed CRL — the `?` returns `Err` **before** the write
    /// lock is ever taken, so the live config is untouched: no accept-any, nothing broken, the
    /// agent keeps enforcing the last-good policy. On success the fresh `Arc` replaces the old one
    /// under the write lock in a single store; because [`current`](Self::current) hands out whole
    /// `Arc`s, every accept sees either the entire old config or the entire new one, never a
    /// mixture. A poisoned lock is recovered (`into_inner`) so a panic elsewhere cannot wedge
    /// reloads.
    ///
    /// Only FUTURE handshakes see the new config; in-flight sessions are unaffected.
    pub fn reload(&self) -> io::Result<()> {
        // Build first. A failure here propagates WITHOUT mutating `self` (fail-safe).
        let fresh = self.spec.build()?;
        // Atomic swap: replace the whole Arc under the write lock.
        let mut guard = match self.inner.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard = fresh;
        Ok(())
    }

    /// The spec this config reloads from (its files). Useful for callers that need to know WHICH
    /// paths a reload will re-read (e.g. to set up a file watch).
    pub fn spec(&self) -> &CertFileSpec {
        &self.spec
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{generate_test_pki, write_pki_to_pem};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// A unique temp dir for a unit test, cleaned on drop.
    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            static C: AtomicU64 = AtomicU64::new(0);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let n = C.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "torda-reload-unit-{}-{}-{}",
                std::process::id(),
                nanos,
                n
            ));
            std::fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn from_files_then_current_and_reload_keep_a_valid_config() {
        let dir = TempDir::new();
        let pki = generate_test_pki();
        let p = write_pki_to_pem(&pki, &dir.0).unwrap();
        let spec = CertFileSpec {
            ca_paths: vec![p.ca.clone()],
            cert_chain: p.server_chain.clone(),
            key: p.server_key.clone(),
            crl_paths: vec![],
        };
        let reloadable = ReloadableServerConfig::from_files(spec).unwrap();
        let before = reloadable.current();
        // A successful reload swaps in a NEW Arc (rebuilt from the same files).
        reloadable
            .reload()
            .expect("reload from the same good files succeeds");
        let after = reloadable.current();
        assert!(
            !Arc::ptr_eq(&before, &after),
            "a successful reload installs a fresh Arc"
        );
    }

    #[test]
    fn a_failed_build_leaves_the_live_config_unchanged() {
        let dir = TempDir::new();
        let pki = generate_test_pki();
        let p = write_pki_to_pem(&pki, &dir.0).unwrap();
        let spec = CertFileSpec {
            ca_paths: vec![p.ca.clone()],
            cert_chain: p.server_chain.clone(),
            key: p.server_key.clone(),
            crl_paths: vec![],
        };
        let reloadable = ReloadableServerConfig::from_files(spec).unwrap();
        let before = reloadable.current();
        // Corrupt the key file so the next build fails.
        std::fs::write(&p.server_key, b"not a key").unwrap();
        assert!(reloadable.reload().is_err(), "a bad rebuild returns Err");
        let after = reloadable.current();
        assert!(
            Arc::ptr_eq(&before, &after),
            "fail-safe: the live config is the SAME Arc after a failed reload"
        );
    }
}
