//! Bundle layout + fail-closed verification.
//!
//! A bundle is a directory containing:
//! - `manifest.json`      — a serialized [`FeedManifest`]
//! - `manifest.json.sig`  — the detached Ed25519 signature (lowercase hex)
//! - one file per manifest entry, named exactly `entry.name`

use std::path::Path;

use anyhow::{bail, Context};

use crate::manifest::FeedManifest;
use crate::sign::{sha256_hex, FeedVerifier};

/// Manifest file name inside a bundle directory.
pub const MANIFEST_NAME: &str = "manifest.json";
/// Detached-signature file name inside a bundle directory.
pub const SIGNATURE_NAME: &str = "manifest.json.sig";

/// Reject a manifest that lists more entries than this — feed data is untrusted
/// input and a manifest must not be able to fan out unboundedly.
pub const MAX_MANIFEST_ENTRIES: usize = 1024;
/// Reject a content file larger than this (256 MiB) — a bound on how much a
/// bundle can make a consumer read into memory to digest.
pub const MAX_CONTENT_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// Verify a bundle directory and return its manifest. Fails **closed** on any
/// of: missing/unparseable manifest or signature; a signature not made by a
/// trusted key; too many entries; an entry `name` that is not a plain file name
/// (path separators or `..`); a missing, oversized, or digest-mismatched content
/// file; or a duplicate entry name.
pub fn verify_bundle(dir: &Path, verifier: &FeedVerifier) -> anyhow::Result<FeedManifest> {
    if verifier.is_empty() {
        bail!("refusing to verify a feed bundle with no trusted keys configured");
    }

    let manifest_path = dir.join(MANIFEST_NAME);
    let sig_path = dir.join(SIGNATURE_NAME);

    let manifest_text = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("reading feed manifest {}", manifest_path.display()))?;
    let sig_hex = std::fs::read_to_string(&sig_path)
        .with_context(|| format!("reading feed manifest signature {}", sig_path.display()))?;

    let manifest: FeedManifest = serde_json::from_str(&manifest_text)
        .with_context(|| format!("parsing feed manifest {}", manifest_path.display()))?;

    // 1. Authenticity: the manifest must be signed by a trusted key.
    if !verifier.verify_manifest(&manifest, &sig_hex) {
        bail!(
            "feed manifest signature is not valid for any trusted key (version {:?}, source {:?})",
            manifest.feed_version,
            manifest.source
        );
    }

    // 2. Sanity bound on fan-out.
    if manifest.entries.len() > MAX_MANIFEST_ENTRIES {
        bail!(
            "feed manifest lists {} entries, over the {} cap",
            manifest.entries.len(),
            MAX_MANIFEST_ENTRIES
        );
    }

    // 3. Integrity: every content file's digest must match the manifest.
    let mut seen = std::collections::HashSet::new();
    for entry in &manifest.entries {
        if !is_plain_file_name(&entry.name) {
            bail!("feed entry name {:?} is not a plain file name", entry.name);
        }
        if !seen.insert(entry.name.as_str()) {
            bail!("feed manifest lists {:?} more than once", entry.name);
        }

        let file_path = dir.join(&entry.name);
        let meta = std::fs::metadata(&file_path)
            .with_context(|| format!("stat feed content file {}", file_path.display()))?;
        if meta.len() > MAX_CONTENT_FILE_BYTES {
            bail!(
                "feed content file {} is {} bytes, over the {} cap",
                file_path.display(),
                meta.len(),
                MAX_CONTENT_FILE_BYTES
            );
        }

        let bytes = std::fs::read(&file_path)
            .with_context(|| format!("reading feed content file {}", file_path.display()))?;
        let actual = sha256_hex(&bytes);
        if !actual.eq_ignore_ascii_case(entry.sha256.trim()) {
            bail!(
                "feed content file {} digest mismatch: manifest says {}, file is {}",
                file_path.display(),
                entry.sha256,
                actual
            );
        }
    }

    Ok(manifest)
}

/// A plain file name: non-empty, no path separators, not a `.`/`..` traversal
/// component. Keeps a manifest from pointing outside the bundle directory.
fn is_plain_file_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
}
