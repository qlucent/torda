//! The tiering seam: a [`FeedSource`] produces a bundle directory ready to
//! verify + install. The community source is static and offline; the enterprise
//! source (FSL `torda-feed-live`) implements the same trait behind an
//! entitlement gate. Both hand their bundle to the same [`FeedStore::install`],
//! which re-verifies regardless of source.
//!
//! [`FeedStore::install`]: crate::FeedStore::install

use std::path::{Path, PathBuf};

use anyhow::Context;

use crate::manifest::FeedTier;

/// A source of feed bundles. Implementors materialize a bundle into (or under)
/// `workdir` and return the directory that [`crate::verify_bundle`] /
/// [`crate::FeedStore::install`] should read. The returned bundle is NOT trusted
/// on the source's say-so — install verifies its signature and digests.
pub trait FeedSource {
    /// Which tier this source serves.
    fn tier(&self) -> FeedTier;

    /// Produce a bundle directory ready to install. `workdir` is a caller-owned
    /// scratch directory a networked source may download into; a source backed
    /// by an on-disk bundle may return that path directly and ignore `workdir`.
    fn fetch_bundle(&self, workdir: &Path) -> anyhow::Result<PathBuf>;
}

/// The community tier: a static, signed bundle already on disk (the
/// periodically-published release asset, or a side-loaded copy for air-gap). No
/// network, no auth.
pub struct StaticBundleSource {
    dir: PathBuf,
}

impl StaticBundleSource {
    /// A community source backed by the signed bundle directory at `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }
}

impl FeedSource for StaticBundleSource {
    fn tier(&self) -> FeedTier {
        FeedTier::Community
    }

    fn fetch_bundle(&self, _workdir: &Path) -> anyhow::Result<PathBuf> {
        // The bundle is already local and read-only; install copies from it.
        if !self.dir.join(crate::bundle::MANIFEST_NAME).is_file() {
            return Err(anyhow::anyhow!(
                "no feed bundle at {} (missing {})",
                self.dir.display(),
                crate::bundle::MANIFEST_NAME
            ))
            .context("community static feed source");
        }
        Ok(self.dir.clone())
    }
}
