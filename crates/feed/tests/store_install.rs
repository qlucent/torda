//! Installing a verified bundle into a local store, and reading its state.

use std::path::{Path, PathBuf};

use torda_feed::{sample, FeedStore, FeedTier, FeedVerifier};

fn sample_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("sample-bundle")
}

struct TmpDir(PathBuf);
impl TmpDir {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!(
            "torda-feed-store-test-{}-{}-{}",
            tag,
            std::process::id(),
            n
        ));
        TmpDir(d)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn install_populates_content_and_state() {
    let tmp = TmpDir::new("install");
    let store = FeedStore::new(tmp.path().join("store"));
    assert!(store.active_version().is_none(), "fresh store has no feed");

    let manifest = store.install(&sample_dir(), &sample::verifier()).unwrap();
    assert_eq!(manifest.feed_version, "2026-09-12T00:00:00Z");

    // Active state reflects the install.
    let state = store.state().unwrap().expect("state present after install");
    assert_eq!(state.feed_version, "2026-09-12T00:00:00Z");
    assert_eq!(state.tier, FeedTier::Community);
    assert_eq!(
        store.active_version().as_deref(),
        Some("2026-09-12T00:00:00Z")
    );

    // Content dir holds the verified files, ready for the enrichment parser.
    for name in [
        "osv-bundle.json",
        "nvd-bundle.json",
        "epss-sample.csv",
        "kev-sample.json",
    ] {
        assert!(
            store.content_dir().join(name).is_file(),
            "installed content missing {name}"
        );
    }
}

#[test]
fn staleness_is_measured_from_created_at() {
    let tmp = TmpDir::new("stale");
    let store = FeedStore::new(tmp.path().join("store"));
    let manifest = store.install(&sample_dir(), &sample::verifier()).unwrap();

    // A "now" one day after the feed's created_at ⇒ ~1 day of staleness.
    let now = manifest.created_at + 86_400_000;
    let age = store.staleness_ms(now).unwrap();
    assert_eq!(age, 86_400_000);

    // A now before created_at clamps to 0, never negative.
    assert_eq!(store.staleness_ms(manifest.created_at - 5).unwrap(), 0);
}

#[test]
fn reinstall_is_idempotent() {
    let tmp = TmpDir::new("reinstall");
    let store = FeedStore::new(tmp.path().join("store"));
    store.install(&sample_dir(), &sample::verifier()).unwrap();
    // Installing the same bundle again succeeds and leaves the same active version.
    store.install(&sample_dir(), &sample::verifier()).unwrap();
    assert_eq!(
        store.active_version().as_deref(),
        Some("2026-09-12T00:00:00Z")
    );
    // Exactly the four content files, no leftover staging dirs.
    let content_files: Vec<_> = std::fs::read_dir(store.content_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(content_files.len(), 4, "content dir holds only the 4 files");
}

#[test]
fn install_with_untrusted_verifier_is_refused() {
    let tmp = TmpDir::new("untrusted");
    let store = FeedStore::new(tmp.path().join("store"));
    // Empty verifier trusts nothing ⇒ verification (and thus install) fails, and
    // no state is written.
    assert!(store.install(&sample_dir(), &FeedVerifier::new()).is_err());
    assert!(
        store.active_version().is_none(),
        "nothing installed on failure"
    );
}
