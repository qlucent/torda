//! The paid boundary: only a valid, unexpired, enterprise-tier entitlement lets
//! the live source produce a bundle; everything else is refused with a clear
//! error (never a silent downgrade).

use std::path::PathBuf;

use torda_feed::{FeedSource, FeedStore, FeedTier};
use torda_feed_live::{sample, verify_entitlement, Entitlement, LiveFeedSource};

const NOW: i64 = 1_800_000_000_000; // a fixed "now" for determinism

fn token(tier: FeedTier, expires_at: i64) -> String {
    sample::issuer().issue(&Entitlement {
        subject: "acme-corp".into(),
        tier,
        issued_at: NOW - 1000,
        expires_at,
        feeds: vec!["vuln".into()],
    })
}

struct TmpDir(PathBuf);
impl TmpDir {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        TmpDir(std::env::temp_dir().join(format!(
            "torda-feed-live-test-{}-{}-{}",
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
fn valid_enterprise_entitlement_fetches_and_installs() {
    let tok = token(FeedTier::Enterprise, NOW + 86_400_000);
    let source = LiveFeedSource::connect(
        &tok,
        &sample::issuer_key(),
        NOW,
        sample::enterprise_bundle_dir(),
    )
    .expect("valid enterprise entitlement should connect");
    assert_eq!(source.tier(), FeedTier::Enterprise);
    assert_eq!(source.entitlement().subject, "acme-corp");

    // Fetch a bundle and install it — proving the enterprise source flows
    // through the same verified store as community.
    let tmp = TmpDir::new("install");
    let workdir = tmp.0.join("work");
    std::fs::create_dir_all(&workdir).unwrap();
    let bundle = source.fetch_bundle(&workdir).unwrap();

    let store = FeedStore::new(tmp.0.join("store"));
    let manifest = store
        .install(&bundle, &torda_feed::sample::verifier())
        .expect("enterprise bundle installs via the feed verifier");
    assert_eq!(manifest.tier, FeedTier::Enterprise);
    assert_eq!(
        store.active_version().as_deref(),
        Some("2026-09-12T06:00:00Z"),
        "enterprise feed is a newer snapshot than community"
    );
}

#[test]
fn missing_or_malformed_token_is_refused() {
    let tmp = LiveFeedSource::connect(
        "",
        &sample::issuer_key(),
        NOW,
        sample::enterprise_bundle_dir(),
    );
    assert!(tmp.is_err(), "empty token must be refused");
    let bad = LiveFeedSource::connect(
        "not-a-token",
        &sample::issuer_key(),
        NOW,
        sample::enterprise_bundle_dir(),
    );
    assert!(bad.is_err(), "malformed token must be refused");
}

#[test]
fn expired_entitlement_is_refused() {
    let tok = token(FeedTier::Enterprise, NOW - 1); // already expired
    let err = LiveFeedSource::connect(
        &tok,
        &sample::issuer_key(),
        NOW,
        sample::enterprise_bundle_dir(),
    )
    .unwrap_err();
    assert!(
        format!("{err:#}").contains("expired"),
        "expected an expiry refusal, got: {err:#}"
    );
}

#[test]
fn community_tier_token_is_refused_for_the_live_source() {
    let tok = token(FeedTier::Community, NOW + 86_400_000);
    let err = LiveFeedSource::connect(
        &tok,
        &sample::issuer_key(),
        NOW,
        sample::enterprise_bundle_dir(),
    )
    .unwrap_err();
    assert!(
        format!("{err:#}").contains("enterprise tier required"),
        "expected an enterprise-required refusal, got: {err:#}"
    );
}

#[test]
fn tampered_signature_is_refused() {
    let mut tok = token(FeedTier::Enterprise, NOW + 86_400_000);
    // Flip the last hex nibble of the signature.
    let last = tok.pop().unwrap();
    tok.push(if last == 'a' { 'b' } else { 'a' });
    assert!(verify_entitlement(&tok, &sample::issuer_key(), NOW).is_err());
    assert!(LiveFeedSource::connect(
        &tok,
        &sample::issuer_key(),
        NOW,
        sample::enterprise_bundle_dir()
    )
    .is_err());
}

#[test]
fn wrong_issuer_key_is_refused() {
    // A token minted by the real sample issuer, verified against a DIFFERENT key.
    let tok = token(FeedTier::Enterprise, NOW + 86_400_000);
    let other = torda_feed_live::EntitlementIssuer::from_seed([7u8; 32]).verifying_key();
    let err = verify_entitlement(&tok, &other, NOW).unwrap_err();
    assert!(
        format!("{err:#}").contains("not valid for the issuer"),
        "expected an issuer-mismatch refusal, got: {err:#}"
    );
}
