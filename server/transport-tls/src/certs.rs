//! # File-loaded mutual-TLS configs — the ops-provisioned certificate path
//!
//! Where [`crate::generate_test_pki`] / [`crate::server_config`] / [`crate::client_config`]
//! build configs from an **in-memory** test PKI, this module builds the SAME kind of
//! mutual-TLS configs from **files provisioned by ops**: the CA(s), the leaf certificate
//! chain, and the private key are read off disk. This is the production loading path.
//!
//! ## Guarantees (all fail-closed, all panic-free)
//!
//! - **PEM and DER both load, auto-detected by content.** A file whose bytes (after
//!   leading whitespace) begin with `-----BEGIN` is parsed as PEM; anything else is
//!   treated as a single DER object. No caller has to declare the format.
//! - **PEM cert files may hold MANY certs** (a leaf chain, or several CA certs in one
//!   file); every cert in the file is loaded. A DER cert file holds exactly one cert.
//! - **Zero certs parsed is an error, never a silent empty chain.** An empty file, an
//!   empty/garbage PEM, or a truncated cert fails closed with an [`io::Error`].
//! - **Size-capped before read.** Each file's on-disk length is checked against
//!   [`MAX_CERT_FILE_BYTES`] via `metadata` *before* a single byte is read, so an
//!   oversized or accidental file is rejected without being loaded into RAM.
//! - **Never panics.** Malformed PEM/DER, a missing path, a rejected trust anchor, or a
//!   mismatched cert/key pair all map to `Err(io::Error)`; there is no `unwrap`/`expect`
//!   on file or peer-controlled input.
//!
//! ## Mutual auth is REQUIRED and UNCHANGED
//!
//! [`server_config_from_files`] installs the **mandatory** client-cert verifier
//! ([`WebPkiClientVerifier::builder(roots).build()`](WebPkiClientVerifier) — the same
//! `.build()` required variant [`crate::server_config`] uses, never
//! `allow_unauthenticated`, never a `dangerous()`/accept-any verifier). The ISSUER-side
//! file-loaded `ClientConfig` builder (`client_config_from_files`) lives in the FSL
//! `torda-control-server` crate and reuses [`load_root_store`] from here; it verifies the
//! server against the loaded CA roots and presents the client cert with no `dangerous()`
//! no-op verifier. Loading from files does not weaken authentication in any way.
//!
//! ## Multi-CA root store = rotation overlap
//!
//! Both constructors take a **list** of CA files and add EVERY CA cert from EVERY file to
//! one [`RootCertStore`]. Trusting two CAs at once is exactly what a CA rotation needs:
//! during the overlap window a peer whose cert still chains to the OLD CA and a peer whose
//! cert chains to the NEW CA are both accepted, so the fleet can migrate without a flag day.
//!
//! The ring crypto provider is supplied explicitly per-config, exactly as the in-memory
//! constructors do — no global `install_default`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};

use crate::TestPki;

/// Upper bound on the on-disk size of a certificate/chain/key file that the loaders will
/// read. A PEM leaf chain plus a couple of intermediates, or a multi-CA rotation-overlap
/// file, is a few KiB; a private key is smaller still. This 1 MiB cap is generous headroom
/// while still refusing to allocate against a pathologically large or accidental file,
/// which is rejected from its on-disk size **before** any byte is read.
pub const MAX_CERT_FILE_BYTES: u64 = 1024 * 1024;

/// Read a certificate/key file into memory, but ONLY after checking its on-disk size, so an
/// oversized file is rejected WITHOUT ever being read into RAM.
///
/// Mirrors `read_capped_key_file` in `torda-control-plane`: `fs::read` would allocate the
/// whole file first, so `fs::metadata(path)?.len()` is consulted and a file exceeding
/// [`MAX_CERT_FILE_BYTES`] is rejected with `Err(InvalidData)` up front. A missing/unreadable
/// path surfaces as the underlying `io::Error`. Fail-closed + panic-free.
pub fn read_capped_cert_file(path: &Path) -> io::Result<Vec<u8>> {
    let len = fs::metadata(path)?.len();
    if len > MAX_CERT_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "certificate file {} too large: {len} bytes exceeds the {MAX_CERT_FILE_BYTES}-byte cap",
                path.display()
            ),
        ));
    }
    fs::read(path)
}

/// PEM if the bytes, after any leading ASCII whitespace, begin with `-----BEGIN`; otherwise
/// the content is treated as DER. Auto-detection means callers never declare the format.
fn looks_like_pem(bytes: &[u8]) -> bool {
    let first = bytes.iter().position(|b| !b.is_ascii_whitespace());
    match first {
        Some(i) => bytes[i..].starts_with(b"-----BEGIN"),
        None => false, // empty / all-whitespace is not PEM
    }
}

/// Parse certificate bytes (auto-detecting PEM vs DER) into one or more DER certificates.
///
/// - **PEM** → every `CERTIFICATE` section in the file is parsed (a leaf chain, or several
///   CA certs bundled in one file). A malformed/garbage PEM body is an `Err`.
/// - **DER** → the bytes are one certificate.
///
/// **Fail-closed:** zero certificates parsed (empty file, empty PEM, PEM with no
/// `CERTIFICATE` section) is an [`io::Error`], never an empty chain. Never panics.
pub fn load_certs(bytes: &[u8]) -> io::Result<Vec<CertificateDer<'static>>> {
    let certs: Vec<CertificateDer<'static>> = if looks_like_pem(bytes) {
        CertificateDer::pem_slice_iter(bytes)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid PEM certificate data: {e}"),
                )
            })?
    } else if bytes.is_empty() {
        Vec::new()
    } else {
        // A single DER certificate. Structural validity (that it parses as an X.509 cert)
        // is enforced when it is used — the root store / verifier / `with_single_cert`
        // reject unparseable DER — so a bad DER cert still fails closed, never panics.
        vec![CertificateDer::from(bytes.to_vec())]
    };
    // Fail closed on both "no certs at all" and a parsed-but-empty cert (an empty PEM body
    // decodes to a zero-length DER, which is never a real certificate).
    if certs.is_empty() || certs.iter().any(|c| c.as_ref().is_empty()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no valid certificates parsed (fail-closed: refusing an empty certificate chain)",
        ));
    }
    Ok(certs)
}

/// Parse a private key (auto-detecting PEM vs DER) into a single [`PrivateKeyDer`].
///
/// - **PEM** → the first PKCS#8 / SEC1 / PKCS#1 key section (`from_pem_slice`). No key
///   section (empty/garbage PEM) is an `Err`.
/// - **DER** → PKCS#8 / SEC1 / PKCS#1 auto-detected by structure (`try_from`); unknown or
///   truncated DER is an `Err`.
///
/// Never panics on malformed input.
pub fn load_private_key(bytes: &[u8]) -> io::Result<PrivateKeyDer<'static>> {
    if looks_like_pem(bytes) {
        PrivateKeyDer::from_pem_slice(bytes).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid PEM private key: {e}"),
            )
        })
    } else {
        PrivateKeyDer::try_from(bytes.to_vec()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid DER private key: {e}"),
            )
        })
    }
}

/// Parse certificate-revocation-list bytes (auto-detecting PEM vs DER) into one or more
/// [`CertificateRevocationListDer`]s — the CRL analogue of [`load_certs`].
///
/// - **PEM** → every `X509 CRL` section in the file is parsed. A malformed/garbage PEM body
///   is an `Err`.
/// - **DER** → the bytes are one CRL. (Structural validity of a DER CRL is enforced when it
///   is handed to the verifier builder — [`server_config_from_files_with_crl`] maps that
///   parse failure to an `Err`, so a bad DER CRL still fails closed, never panics.)
///
/// **Fail-closed:** zero CRLs parsed (empty file, empty PEM, PEM with no `X509 CRL` section)
/// is an [`io::Error`], never a silently-empty CRL set — enforcing "no CRLs" would silently
/// disable revocation checking. Never panics on hostile input.
pub fn load_crls(bytes: &[u8]) -> io::Result<Vec<CertificateRevocationListDer<'static>>> {
    let crls: Vec<CertificateRevocationListDer<'static>> = if looks_like_pem(bytes) {
        CertificateRevocationListDer::pem_slice_iter(bytes)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid PEM CRL data: {e}"),
                )
            })?
    } else if bytes.is_empty() {
        Vec::new()
    } else {
        vec![CertificateRevocationListDer::from(bytes.to_vec())]
    };
    // Fail closed: an empty CRL set (or an empty-body PEM decoding to a zero-length DER) would
    // silently disable revocation enforcement — refuse it.
    if crls.is_empty() || crls.iter().any(|c| c.as_ref().is_empty()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no valid CRLs parsed (fail-closed: refusing to build a revocation-enforcing config with an empty CRL set)",
        ));
    }
    Ok(crls)
}

/// Load ALL CRLs from EVERY file in `crl_paths` (each file may hold one or more CRLs),
/// size-capped before read via [`read_capped_cert_file`]. Fail-closed: an unreadable/oversized
/// file, a malformed CRL, or a zero-CRL result all propagate `Err`.
pub fn load_crls_from_files(
    crl_paths: &[&Path],
) -> io::Result<Vec<CertificateRevocationListDer<'static>>> {
    let mut all = Vec::new();
    for path in crl_paths {
        let bytes = read_capped_cert_file(path)?;
        all.extend(load_crls(&bytes)?);
    }
    if all.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no CRLs loaded (fail-closed: a revocation-enforcing config needs at least one CRL)",
        ));
    }
    Ok(all)
}

/// Build a multi-CA [`RootCertStore`] by loading EVERY file in `ca_paths` (each file may
/// hold one or more CA certs) and adding ALL of them. This is the rotation-overlap store:
/// a peer chaining to ANY listed CA is trusted.
///
/// Fail-closed: an unreadable/oversized CA file, a garbage CA cert, or a cert the root
/// store rejects as an invalid trust anchor all propagate `Err`.
///
/// `pub` so the issuer-side client-config builder in `torda-control-server` can reuse this
/// exact multi-CA trust-store construction when it loads a [`ClientConfig`] from files.
pub fn load_root_store(ca_paths: &[&Path]) -> io::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for path in ca_paths {
        let bytes = read_capped_cert_file(path)?;
        for cert in load_certs(&bytes)? {
            roots.add(cert).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "CA cert from {} rejected as a trust anchor: {e}",
                        path.display()
                    ),
                )
            })?;
        }
    }
    Ok(roots)
}

/// Build a mutual-TLS [`ServerConfig`] from ops-provisioned FILES.
///
/// - `ca_paths`: one or more CA files (PEM or DER); ALL their CA certs form the multi-CA
///   trust root (rotation overlap). The **required** client-cert verifier is built from
///   them with `WebPkiClientVerifier::builder(roots).build()` — identical mandatory client
///   auth to [`crate::server_config`], no `allow_unauthenticated`, no `dangerous()`.
/// - `cert_chain`: the server leaf chain file (PEM chain or single DER).
/// - `key`: the server private-key file (PEM or DER).
///
/// The ring provider is supplied explicitly. Any I/O, parse, trust-anchor, verifier, or
/// cert/key-mismatch error maps to [`io::Error`]; nothing panics.
pub fn server_config_from_files(
    ca_paths: &[&Path],
    cert_chain: &Path,
    key: &Path,
) -> io::Result<Arc<ServerConfig>> {
    let roots = Arc::new(load_root_store(ca_paths)?);
    let client_verifier = WebPkiClientVerifier::builder(roots).build().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to build required client-cert verifier: {e}"),
        )
    })?;

    let chain = load_certs(&read_capped_cert_file(cert_chain)?)?;
    let leaf_key = load_private_key(&read_capped_cert_file(key)?)?;

    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(chain, leaf_key)
            .map_err(io::Error::other)?;

    Ok(Arc::new(config))
}

/// Build a mutual-TLS [`ServerConfig`] from ops-provisioned FILES that ALSO enforces
/// certificate REVOCATION via one or more CRLs.
///
/// Identical to [`server_config_from_files`] — same multi-CA `RootCertStore`, same
/// **required** client-cert verifier (`.build()`, never `allow_unauthenticated`, never a
/// `dangerous()`/accept-any verifier) — with ONE addition: the verifier is built with
/// [`WebPkiClientVerifier::builder(roots).with_crls(crls)`](WebPkiClientVerifier::builder),
/// so a client whose leaf serial appears in a loaded CRL fails path validation **at the TLS
/// handshake**, before any application frame is exchanged. By default rustls checks the
/// revocation status of the whole verified chain and treats an undeterminable status as an
/// error (fail-closed); we keep those defaults.
///
/// `crl_paths` are loaded (PEM or DER, size-capped) via [`load_crls_from_files`]; an empty
/// CRL set is rejected up front so revocation can never be silently disabled. Any I/O, parse,
/// trust-anchor, CRL-parse, verifier, or cert/key-mismatch error maps to [`io::Error`];
/// nothing panics (a structurally-malformed CRL surfaces as the builder's parse error here).
pub fn server_config_from_files_with_crl(
    ca_paths: &[&Path],
    cert_chain: &Path,
    key: &Path,
    crl_paths: &[&Path],
) -> io::Result<Arc<ServerConfig>> {
    let roots = Arc::new(load_root_store(ca_paths)?);
    let crls = load_crls_from_files(crl_paths)?;
    // Same REQUIRED client-cert verifier as `server_config_from_files` (`.build()`), now also
    // enforcing the CRLs. `.build()` returns Err on an unparseable CRL DER — mapped to io::Error.
    let client_verifier = WebPkiClientVerifier::builder(roots)
        .with_crls(crls)
        .build()
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to build required CRL-enforcing client-cert verifier: {e}"),
            )
        })?;

    let chain = load_certs(&read_capped_cert_file(cert_chain)?)?;
    let leaf_key = load_private_key(&read_capped_cert_file(key)?)?;

    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(chain, leaf_key)
            .map_err(io::Error::other)?;

    Ok(Arc::new(config))
}

/// The five files a full mTLS peer set is written to by [`write_pki_to_pem`] /
/// [`write_pki_to_der`]: the shared CA plus each side's leaf chain and private key.
#[derive(Debug, Clone)]
pub struct CertFilePaths {
    /// The CA certificate file (the shared trust anchor).
    pub ca: PathBuf,
    /// The server leaf certificate chain file.
    pub server_chain: PathBuf,
    /// The server private-key file.
    pub server_key: PathBuf,
    /// The client leaf certificate chain file.
    pub client_chain: PathBuf,
    /// The client private-key file.
    pub client_key: PathBuf,
}

impl CertFilePaths {
    /// The conventional file names inside `dir` for the given extension (`"pem"`/`"der"`).
    fn in_dir(dir: &Path, ext: &str) -> Self {
        CertFilePaths {
            ca: dir.join(format!("ca.{ext}")),
            server_chain: dir.join(format!("server-chain.{ext}")),
            server_key: dir.join(format!("server-key.{ext}")),
            client_chain: dir.join(format!("client-chain.{ext}")),
            client_key: dir.join(format!("client-key.{ext}")),
        }
    }
}

/// Encode one DER blob as a single PEM block (`kind` is e.g. `CERTIFICATE` /
/// `PRIVATE KEY`), 64 base64 chars per line. Uses the audited `base64` crate — the armor
/// is not hand-rolled.
fn der_to_pem_block(kind: &str, der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::with_capacity(b64.len() + kind.len() * 2 + 64);
    out.push_str("-----BEGIN ");
    out.push_str(kind);
    out.push_str("-----\n");
    let bytes = b64.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let end = (i + 64).min(bytes.len());
        // base64 output is pure ASCII, so these byte indices are valid char boundaries.
        out.push_str(&b64[i..end]);
        out.push('\n');
        i = end;
    }
    out.push_str("-----END ");
    out.push_str(kind);
    out.push_str("-----\n");
    out
}

/// Encode a whole certificate chain as concatenated `CERTIFICATE` PEM blocks (leaf first).
fn chain_to_pem(chain: &[CertificateDer<'static>]) -> String {
    let mut out = String::new();
    for cert in chain {
        out.push_str(&der_to_pem_block("CERTIFICATE", cert.as_ref()));
    }
    out
}

/// Write `pki` out as five **PEM** files under `dir` (created if missing), returning their
/// paths. This is a test/demo helper: it materializes an in-memory [`TestPki`] to disk so
/// the file loaders above can be exercised end to end (the CA and both leaf chains as
/// `CERTIFICATE` PEM, both keys as `PRIVATE KEY` PKCS#8 PEM).
pub fn write_pki_to_pem(pki: &TestPki, dir: &Path) -> io::Result<CertFilePaths> {
    fs::create_dir_all(dir)?;
    let paths = CertFilePaths::in_dir(dir, "pem");
    fs::write(
        &paths.ca,
        der_to_pem_block("CERTIFICATE", pki.ca_cert.as_ref()),
    )?;
    fs::write(&paths.server_chain, chain_to_pem(&pki.server_cert_chain))?;
    fs::write(
        &paths.server_key,
        der_to_pem_block("PRIVATE KEY", pki.server_key.secret_der()),
    )?;
    fs::write(&paths.client_chain, chain_to_pem(&pki.client_cert_chain))?;
    fs::write(
        &paths.client_key,
        der_to_pem_block("PRIVATE KEY", pki.client_key.secret_der()),
    )?;
    Ok(paths)
}

/// Write `pki` out as five raw **DER** files under `dir` (created if missing), returning
/// their paths. Each leaf chain here is a single cert, so one DER cert per file is exact.
/// Companion to [`write_pki_to_pem`] used to exercise the DER auto-detect path.
pub fn write_pki_to_der(pki: &TestPki, dir: &Path) -> io::Result<CertFilePaths> {
    fs::create_dir_all(dir)?;
    let paths = CertFilePaths::in_dir(dir, "der");
    fs::write(&paths.ca, pki.ca_cert.as_ref())?;
    fs::write(
        &paths.server_chain,
        single_cert_der(&pki.server_cert_chain)?,
    )?;
    fs::write(&paths.server_key, pki.server_key.secret_der())?;
    fs::write(
        &paths.client_chain,
        single_cert_der(&pki.client_cert_chain)?,
    )?;
    fs::write(&paths.client_key, pki.client_key.secret_der())?;
    Ok(paths)
}

/// The DER bytes of a single-cert chain; a raw DER file cannot frame more than one cert, so
/// a multi-cert chain is rejected rather than silently truncated.
fn single_cert_der<'a>(chain: &'a [CertificateDer<'static>]) -> io::Result<&'a [u8]> {
    match chain {
        [only] => Ok(only.as_ref()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a raw DER file holds exactly one certificate; use PEM for a multi-cert chain",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_test_pki;

    #[test]
    fn pem_is_detected_and_der_is_the_fallback() {
        assert!(looks_like_pem(b"-----BEGIN CERTIFICATE-----\n"));
        assert!(looks_like_pem(b"\n  \t-----BEGIN PRIVATE KEY-----\n"));
        assert!(!looks_like_pem(b"\x30\x82\x01")); // DER SEQUENCE prefix
        assert!(!looks_like_pem(b"")); // empty is not PEM
    }

    #[test]
    fn load_certs_roundtrips_pem_and_der_and_rejects_empty() {
        let pki = generate_test_pki();
        let pem = chain_to_pem(&pki.server_cert_chain);
        let loaded = load_certs(pem.as_bytes()).expect("PEM chain loads");
        assert_eq!(
            loaded, pki.server_cert_chain,
            "PEM round-trips to the same DER"
        );

        let der = pki.server_cert_chain[0].as_ref();
        let loaded_der = load_certs(der).expect("DER cert loads");
        assert_eq!(loaded_der.len(), 1);

        assert!(load_certs(b"").is_err(), "empty file is fail-closed");
        assert!(
            load_certs(b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n").is_err(),
            "empty PEM body is fail-closed"
        );
    }

    #[test]
    fn load_private_key_roundtrips_pem_and_der() {
        let pki = generate_test_pki();
        let pem = der_to_pem_block("PRIVATE KEY", pki.server_key.secret_der());
        assert!(
            load_private_key(pem.as_bytes()).is_ok(),
            "PKCS#8 PEM key loads"
        );
        assert!(
            load_private_key(pki.server_key.secret_der()).is_ok(),
            "PKCS#8 DER key loads"
        );
        assert!(
            load_private_key(b"not a key").is_err(),
            "garbage key is fail-closed"
        );
    }
}
