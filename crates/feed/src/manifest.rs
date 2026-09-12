//! The feed bundle manifest: the signed description of a bundle's contents.

use serde::{Deserialize, Serialize};

/// Which tier a bundle belongs to. Governs nothing about verification (both
/// tiers verify identically); it is provenance the store records and `status`
/// reports, and it lets a consumer tell a community snapshot from an enterprise
/// one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedTier {
    Community,
    Enterprise,
}

impl std::fmt::Display for FeedTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FeedTier::Community => f.write_str("community"),
            FeedTier::Enterprise => f.write_str("enterprise"),
        }
    }
}

/// The kind of a content file, so a consumer knows how to parse it. The names
/// match the existing enrichment snapshot files (see `server/ingest`'s
/// `BundledEnrichment`): `osv-bundle.json`, `nvd-bundle.json`, `epss-sample.csv`,
/// `kev-sample.json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedContentKind {
    /// OSV advisory bundle (CVSS severity + maturity), a JSON array.
    Osv,
    /// NVD community bundle (CVSS + Windows/registry ranges), a wrapped JSON object.
    Nvd,
    /// FIRST.org EPSS CSV.
    Epss,
    /// CISA KEV catalog subset, JSON.
    Kev,
}

/// One content file described in the manifest. `sha256` is the lowercase-hex
/// SHA-256 of the file's exact bytes; verification recomputes it and rejects any
/// mismatch. `name` is a plain file name within the bundle directory — no path
/// separators or `..` (enforced by [`crate::verify_bundle`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedEntry {
    pub name: String,
    pub sha256: String,
    pub kind: FeedContentKind,
}

/// The signed description of a feed bundle. The detached signature
/// (`manifest.json.sig`) covers exactly [`to_canonical_json_bytes`]; the on-disk
/// `manifest.json` may be pretty-printed without affecting verification, because
/// verification re-serializes the parsed manifest to the same canonical bytes.
///
/// [`to_canonical_json_bytes`]: FeedManifest::to_canonical_json_bytes
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedManifest {
    /// Monotonic snapshot version, e.g. an RFC3339 timestamp
    /// `"2026-09-12T00:00:00Z"`. Opaque to this crate; consumers compare by
    /// install order, not by parsing it.
    pub feed_version: String,
    /// When the feed data was built (epoch millis). Drives staleness.
    pub created_at: i64,
    /// Human-readable origin, e.g. `"qlucent-community"`.
    pub source: String,
    pub tier: FeedTier,
    pub entries: Vec<FeedEntry>,
}

impl FeedManifest {
    /// The exact bytes that are signed and verified. Deterministic: serde_json
    /// serializes struct fields in declaration order and this manifest contains
    /// no maps, so the same manifest always yields the same bytes regardless of
    /// how `manifest.json` was formatted on disk.
    pub fn to_canonical_json_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("FeedManifest is always serializable")
    }
}
