//! Build and write signed bundles from a directory of content files. Used by
//! the `torda-feed gen-sample` operator command and by the FSL `torda-feed-live`
//! crate to materialize its bundles; a production publisher pipeline would use
//! the same functions with a real signing key.

use std::path::Path;

use anyhow::{bail, Context};

use crate::bundle::{MANIFEST_NAME, SIGNATURE_NAME};
use crate::manifest::{FeedContentKind, FeedEntry, FeedManifest, FeedTier};
use crate::sign::{sha256_hex, FeedSigner};

/// The content files a bundle may carry, by their canonical name, in the fixed
/// order the enrichment consumer expects. A production feed keeps these names so
/// `BundledEnrichment::load_from_dir` reads the installed content unchanged.
const KNOWN_CONTENT: &[(&str, FeedContentKind)] = &[
    ("osv-bundle.json", FeedContentKind::Osv),
    ("nvd-bundle.json", FeedContentKind::Nvd),
    ("epss-sample.csv", FeedContentKind::Epss),
    ("kev-sample.json", FeedContentKind::Kev),
];

/// Build a manifest describing whichever known content files are present in
/// `content_dir`, computing each file's SHA-256. Errors if none are present (an
/// empty feed is never a valid bundle).
pub fn manifest_from_content_dir(
    content_dir: &Path,
    feed_version: impl Into<String>,
    created_at: i64,
    source: impl Into<String>,
    tier: FeedTier,
) -> anyhow::Result<FeedManifest> {
    let mut entries = Vec::new();
    for (name, kind) in KNOWN_CONTENT {
        let path = content_dir.join(name);
        if !path.is_file() {
            continue;
        }
        let bytes = std::fs::read(&path)
            .with_context(|| format!("reading feed content {}", path.display()))?;
        entries.push(FeedEntry {
            name: (*name).to_string(),
            sha256: sha256_hex(&bytes),
            kind: *kind,
        });
    }
    if entries.is_empty() {
        bail!(
            "no known feed content files in {} (expected one of {:?})",
            content_dir.display(),
            KNOWN_CONTENT.iter().map(|(n, _)| *n).collect::<Vec<_>>()
        );
    }
    Ok(FeedManifest {
        feed_version: feed_version.into(),
        created_at,
        source: source.into(),
        tier,
        entries,
    })
}

/// Write a complete signed bundle into `out_dir`: copy each content file from
/// `content_dir`, write `manifest.json` (pretty) and `manifest.json.sig`
/// (detached hex signature over the manifest's canonical bytes). Returns the
/// manifest. Creates `out_dir` if needed.
pub fn write_signed_bundle(
    content_dir: &Path,
    out_dir: &Path,
    manifest: &FeedManifest,
    signer: &FeedSigner,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("creating bundle out dir {}", out_dir.display()))?;

    for entry in &manifest.entries {
        let from = content_dir.join(&entry.name);
        let to = out_dir.join(&entry.name);
        std::fs::copy(&from, &to)
            .with_context(|| format!("copying content {} -> {}", from.display(), to.display()))?;
    }

    let manifest_json = serde_json::to_vec_pretty(manifest).context("serializing manifest.json")?;
    std::fs::write(out_dir.join(MANIFEST_NAME), &manifest_json)
        .with_context(|| format!("writing {}", out_dir.join(MANIFEST_NAME).display()))?;

    let sig = signer.sign_manifest(manifest);
    std::fs::write(out_dir.join(SIGNATURE_NAME), sig.as_bytes())
        .with_context(|| format!("writing {}", out_dir.join(SIGNATURE_NAME).display()))?;

    Ok(())
}
