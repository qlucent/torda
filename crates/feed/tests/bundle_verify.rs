//! Fail-closed verification of feed bundles, against the committed community
//! sample bundle.

use std::path::{Path, PathBuf};

use torda_feed::{
    sample, sha256_hex, verify_bundle, write_signed_bundle, FeedContentKind, FeedEntry,
    FeedManifest, FeedTier, FeedVerifier,
};

fn sample_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("sample-bundle")
}

/// A unique temp dir, cleaned on drop.
struct TmpDir(PathBuf);
impl TmpDir {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!(
            "torda-feed-test-{}-{}-{}",
            tag,
            std::process::id(),
            n
        ));
        std::fs::create_dir_all(&d).unwrap();
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

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        if e.file_type().unwrap().is_file() {
            std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
        }
    }
}

#[test]
fn committed_sample_bundle_verifies() {
    let manifest = verify_bundle(&sample_dir(), &sample::verifier())
        .expect("committed community sample bundle must verify against the sample key");
    assert_eq!(manifest.feed_version, "2026-09-12T00:00:00Z");
    assert_eq!(manifest.tier, FeedTier::Community);
    assert_eq!(manifest.entries.len(), 4);
}

#[test]
fn committed_manifest_digests_match_content_no_drift() {
    // The manifest's digests must equal freshly-computed digests of the content
    // files, so an edited content file that wasn't re-signed can never pass.
    let dir = sample_dir();
    let text = std::fs::read_to_string(dir.join("manifest.json")).unwrap();
    let manifest: FeedManifest = serde_json::from_str(&text).unwrap();
    for entry in &manifest.entries {
        let bytes = std::fs::read(dir.join(&entry.name)).unwrap();
        assert_eq!(
            sha256_hex(&bytes),
            entry.sha256,
            "digest drift for {}",
            entry.name
        );
    }
}

#[test]
fn tampered_content_is_rejected() {
    let tmp = TmpDir::new("tamper");
    copy_dir(&sample_dir(), tmp.path());
    // Flip a byte in a content file without re-signing.
    let victim = tmp.path().join("osv-bundle.json");
    let mut bytes = std::fs::read(&victim).unwrap();
    bytes.push(b'!');
    std::fs::write(&victim, &bytes).unwrap();

    let err = verify_bundle(tmp.path(), &sample::verifier()).unwrap_err();
    assert!(
        format!("{err:#}").contains("digest mismatch"),
        "expected a digest mismatch, got: {err:#}"
    );
}

#[test]
fn bad_signature_is_rejected() {
    let tmp = TmpDir::new("badsig");
    copy_dir(&sample_dir(), tmp.path());
    std::fs::write(tmp.path().join("manifest.json.sig"), b"deadbeef").unwrap();

    let err = verify_bundle(tmp.path(), &sample::verifier()).unwrap_err();
    assert!(
        format!("{err:#}").contains("signature is not valid"),
        "expected a signature failure, got: {err:#}"
    );
}

#[test]
fn missing_content_file_is_rejected() {
    let tmp = TmpDir::new("missing");
    copy_dir(&sample_dir(), tmp.path());
    std::fs::remove_file(tmp.path().join("kev-sample.json")).unwrap();

    assert!(verify_bundle(tmp.path(), &sample::verifier()).is_err());
}

#[test]
fn no_trusted_keys_is_rejected() {
    // An empty verifier must never admit a bundle, even a genuine one.
    let err = verify_bundle(&sample_dir(), &FeedVerifier::new()).unwrap_err();
    assert!(
        format!("{err:#}").contains("no trusted keys"),
        "expected a no-trusted-keys refusal, got: {err:#}"
    );
}

#[test]
fn path_traversal_entry_name_is_rejected() {
    // A manifest legitimately signed by a trusted key but whose entry name tries
    // to escape the bundle directory must still be rejected.
    let tmp = TmpDir::new("traversal");
    std::fs::create_dir_all(tmp.path()).unwrap();
    std::fs::write(tmp.path().join("payload"), b"x").unwrap();
    let bytes = std::fs::read(tmp.path().join("payload")).unwrap();

    let manifest = FeedManifest {
        feed_version: "evil".into(),
        created_at: 0,
        source: "attacker".into(),
        tier: FeedTier::Community,
        entries: vec![FeedEntry {
            name: "../escape".into(),
            sha256: sha256_hex(&bytes),
            kind: FeedContentKind::Osv,
        }],
    };
    // Write the manifest + a real signature by the sample key, then a content
    // file at the traversal target would-be name isn't even needed.
    write_signed_bundle(tmp.path(), tmp.path(), &manifest, &sample::signer()).ok();
    // write_signed_bundle tries to copy "../escape" and may fail; regardless, a
    // direct verify must reject the name. Re-write manifest+sig explicitly:
    std::fs::write(
        tmp.path().join("manifest.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(
        tmp.path().join("manifest.json.sig"),
        sample::signer().sign_manifest(&manifest),
    )
    .unwrap();

    let err = verify_bundle(tmp.path(), &sample::verifier()).unwrap_err();
    assert!(
        format!("{err:#}").contains("not a plain file name"),
        "expected a path-traversal refusal, got: {err:#}"
    );
}
