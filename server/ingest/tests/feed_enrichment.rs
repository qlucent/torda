//! Part C wiring: enrichment loaded from a verified feed store stamps the
//! active `feed_version` onto every returned `Enrichment`, so a finding scored
//! from it cites which feed snapshot supplied its inputs (explainability).

use std::path::{Path, PathBuf};

use torda_feed::{sample, FeedStore};
use torda_findings_engine::input::EnrichmentSource;
use torda_ingest::enrichment::BundledEnrichment;

/// The committed community sample bundle, over in the `torda-feed` crate.
fn community_sample_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/feed/sample-bundle")
}

struct TmpDir(PathBuf);
impl TmpDir {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        TmpDir(std::env::temp_dir().join(format!(
            "torda-ingest-feed-test-{}-{}-{}",
            tag,
            std::process::id(),
            n
        )))
    }
}
impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn enrichment_from_feed_store_stamps_feed_version() {
    let tmp = TmpDir::new("stamp");
    let store = FeedStore::new(tmp.0.join("store"));
    store
        .install(&community_sample_dir(), &sample::verifier())
        .expect("community sample installs");

    let src = BundledEnrichment::load_from_feed_store(&store).expect("load from feed store");
    assert_eq!(src.feed_version(), Some("2026-09-12T00:00:00Z"));

    // CVE-2021-3156 (sudo Baron Samedit) is in the sample OSV + KEV snapshots.
    let e = src
        .lookup("CVE-2021-3156")
        .expect("a known CVE has evidence");
    assert!(e.kev, "still joins the KEV evidence");
    assert_eq!(
        e.feed_version.as_deref(),
        Some("2026-09-12T00:00:00Z"),
        "the enrichment cites which feed snapshot scored it"
    );
}

#[test]
fn plain_snapshot_load_leaves_feed_version_unset() {
    // The unversioned loader path keeps feed_version = None (backward compatible).
    let src = BundledEnrichment::from_snapshots(
        r#"[{"id":"CVE-2021-3156","database_specific":{"cvss_base_score":7.8}}]"#,
        "cve,epss,percentile\n",
        r#"{"vulnerabilities":[{"cveID":"CVE-2021-3156"}]}"#,
    )
    .unwrap();
    assert_eq!(src.feed_version(), None);
    let e = src.lookup("CVE-2021-3156").unwrap();
    assert_eq!(e.feed_version, None);
}

#[test]
fn load_from_feed_store_errors_when_empty() {
    let tmp = TmpDir::new("empty");
    let store = FeedStore::new(tmp.0.join("store"));
    assert!(
        BundledEnrichment::load_from_feed_store(&store).is_err(),
        "no installed feed must be an explicit error, not a silent empty feed"
    );
}
