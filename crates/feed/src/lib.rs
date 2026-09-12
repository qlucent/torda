//! `torda-feed` — the open, signed **enrichment feed** format shared by both
//! tiers of Torda's vulnerability/threat-intel enrichment.
//!
//! A *feed* is the corpus of CVSS / EPSS / KEV / advisory evidence the Findings
//! Engine recomputes a canonical, explainable score from. This crate is
//! deliberately **Apache-2.0** and free of the moat: it defines the on-disk
//! bundle format, verifies a bundle's authenticity + integrity, keeps a verified
//! copy in a local store, and exposes the [`FeedSource`] seam that the two tiers
//! plug into:
//!
//! - **Community** — a static, periodically-published, signed bundle
//!   ([`StaticBundleSource`]). No network, no auth; anyone can produce, publish,
//!   verify, and consume it. This is the open format, like the OCSF envelope.
//! - **Enterprise** — a live, curated, entitlement-gated source that lives in
//!   the FSL crate `torda-feed-live`. It implements the same [`FeedSource`]
//!   trait and installs into the same store using the same verification here.
//!
//! ## Trust model
//! A bundle carries a [`FeedManifest`] (version, source, tier, and a
//! `sha256` per content file) plus a detached Ed25519 signature over the
//! manifest's canonical bytes. [`verify_bundle`] fails **closed**: it rejects a
//! bundle whose manifest signature is not made by a trusted key, or whose any
//! content file's digest does not match the manifest. Feed data is untrusted
//! external input, so verification also caps entry counts and file sizes and
//! forbids path traversal in entry names.
//!
//! The bundle **signature** attests content authenticity/integrity; it is a
//! separate concern from tier **entitlement** (who may fetch the enterprise
//! source), which the FSL crate enforces with its own issuer key. Both bundles
//! may be signed by the same feed key.
//!
//! ## Air-gap
//! The same signed bundle can be side-loaded offline: `torda-feed install
//! --from <bundle-dir>` verifies and installs it exactly as an online sync
//! would, so connected and disconnected environments share one artifact path.
//!
//! ## Explainability
//! The store's active `feed_version` is stamped by the consumer (the ingest
//! `EnrichmentSource`) into every finding it scores, so "why is this critical?"
//! always cites which feed snapshot supplied the inputs.

pub mod builder;
mod bundle;
mod manifest;
pub mod sample;
mod sign;
mod source;
mod store;

pub use builder::{manifest_from_content_dir, write_signed_bundle};
pub use bundle::{verify_bundle, MAX_CONTENT_FILE_BYTES, MAX_MANIFEST_ENTRIES};
pub use manifest::{FeedContentKind, FeedEntry, FeedManifest, FeedTier};
pub use sign::{sha256_hex, FeedSigner, FeedVerifier};
pub use source::{FeedSource, StaticBundleSource};
pub use store::{FeedState, FeedStore};

/// Current epoch time in milliseconds (wall clock). Used to stamp
/// `applied_at` and to compute feed staleness; callers that need determinism
/// pass their own `now_ms` to [`FeedStore::staleness`].
pub fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
