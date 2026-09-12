//! The local feed store: a directory holding the active verified content plus a
//! `state.json` commit marker recording which bundle is installed.
//!
//! Layout under the store root:
//! - `content/`     — the verified content files of the active bundle
//! - `state.json`   — [`FeedState`] (written last, as the commit marker)
//!
//! Reads are local-only (no network, satisfying the "no network in a hot path"
//! rule); sync/install is the only writer.

use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::bundle::verify_bundle;
use crate::manifest::{FeedManifest, FeedTier};
use crate::sign::FeedVerifier;

/// The commit marker recording the active installed feed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedState {
    pub feed_version: String,
    pub source: String,
    pub tier: FeedTier,
    /// When the feed data was built (from the manifest) — drives staleness.
    pub created_at: i64,
    /// When this store installed it (epoch millis).
    pub applied_at: i64,
}

/// A feed store rooted at a directory.
pub struct FeedStore {
    root: PathBuf,
}

impl FeedStore {
    /// A store rooted at `root`. The directory need not exist yet; `install`
    /// creates it.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The store root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The directory holding the active bundle's verified content files. A
    /// consumer points its parser here (e.g. `BundledEnrichment::load_from_dir`).
    pub fn content_dir(&self) -> PathBuf {
        self.root.join("content")
    }

    fn state_path(&self) -> PathBuf {
        self.root.join("state.json")
    }

    /// The active install state, or `None` if nothing is installed yet. A
    /// present-but-unparseable `state.json` is an error (corruption, not "empty").
    pub fn state(&self) -> anyhow::Result<Option<FeedState>> {
        let path = self.state_path();
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(anyhow::Error::from(e)
                    .context(format!("reading feed state {}", path.display())))
            }
        };
        let state: FeedState = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing feed state {}", path.display()))?;
        Ok(Some(state))
    }

    /// The active feed version, or `None` if nothing is installed / state is
    /// unreadable. (Convenience over [`state`](Self::state) for the common
    /// "which version?" question; swallows the error into `None`.)
    pub fn active_version(&self) -> Option<String> {
        self.state().ok().flatten().map(|s| s.feed_version)
    }

    /// Age of the installed feed *data* in milliseconds at `now_ms`
    /// (`now_ms - created_at`), or `None` if nothing is installed. Negative
    /// clamps to 0 (a created_at in the future). Callers pass their own clock so
    /// the result is testable/deterministic.
    pub fn staleness_ms(&self, now_ms: i64) -> Option<i64> {
        self.state()
            .ok()
            .flatten()
            .map(|s| (now_ms - s.created_at).max(0))
    }

    /// Verify `bundle_dir` and install it as the active feed. On success the
    /// store's `content/` holds the verified files and `state.json` names the
    /// new version. Verification runs BEFORE anything is swapped, so a bad
    /// bundle leaves the current install untouched.
    ///
    /// Ordering (crash-safety): content is swapped into place first, then
    /// `state.json` is written last as the commit marker. A crash between leaves
    /// the previous `state.json` (or none) and is fixed by re-installing —
    /// install is idempotent and always re-verifies.
    pub fn install(
        &self,
        bundle_dir: &Path,
        verifier: &FeedVerifier,
    ) -> anyhow::Result<FeedManifest> {
        let manifest = verify_bundle(bundle_dir, verifier)
            .with_context(|| format!("verifying feed bundle {}", bundle_dir.display()))?;

        std::fs::create_dir_all(&self.root)
            .with_context(|| format!("creating feed store {}", self.root.display()))?;

        // Stage the verified content in a fresh temp dir in the same root, then
        // swap it over `content/`.
        let staging = self.root.join(format!(
            ".content-new-{}-{}",
            std::process::id(),
            next_counter()
        ));
        // Clean any stray prior staging dir with this (unlikely) name.
        let _ = std::fs::remove_dir_all(&staging);
        std::fs::create_dir_all(&staging)
            .with_context(|| format!("creating feed staging dir {}", staging.display()))?;

        let stage_result = (|| -> anyhow::Result<()> {
            for entry in &manifest.entries {
                let from = bundle_dir.join(&entry.name);
                let to = staging.join(&entry.name);
                std::fs::copy(&from, &to).with_context(|| {
                    format!(
                        "staging feed content {} -> {}",
                        from.display(),
                        to.display()
                    )
                })?;
            }
            Ok(())
        })();
        if let Err(e) = stage_result {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(e);
        }

        // Swap: remove the old content dir (if any), then move staging into place.
        let content = self.content_dir();
        if content.exists() {
            std::fs::remove_dir_all(&content)
                .with_context(|| format!("removing old feed content {}", content.display()))?;
        }
        if let Err(e) = std::fs::rename(&staging, &content) {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(anyhow::Error::from(e).context(format!(
                "installing feed content into {}",
                content.display()
            )));
        }

        // Commit marker, written last and atomically.
        let state = FeedState {
            feed_version: manifest.feed_version.clone(),
            source: manifest.source.clone(),
            tier: manifest.tier,
            created_at: manifest.created_at,
            applied_at: crate::now_millis(),
        };
        let bytes = serde_json::to_vec_pretty(&state).context("serializing feed state")?;
        write_atomic(&self.state_path(), &bytes)?;

        Ok(manifest)
    }
}

/// A per-process monotonic counter for unique temp names (no RNG dependency).
fn next_counter() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Atomic file write: temp file in the same directory, flushed + fsynced, then
/// renamed over the target. Same pattern as the ingest findings store.
fn write_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;

    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| anyhow::anyhow!("state path has no parent dir: {}", path.display()))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("state path has no file name: {}", path.display()))?
        .to_string_lossy();
    let tmp_path = dir.join(format!(
        "{}.{}.{}.tmp",
        file_name,
        std::process::id(),
        next_counter()
    ));

    let write_result = (|| -> anyhow::Result<()> {
        let mut f = std::fs::File::create(&tmp_path)?;
        f.write_all(bytes)?;
        f.flush()?;
        f.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e.context(format!("writing temp feed state {}", tmp_path.display())));
    }
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(anyhow::Error::from(e).context(format!(
            "atomically replacing feed state {}",
            path.display()
        )));
    }
    Ok(())
}
