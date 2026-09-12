//! A **non-production sample signing key**, committed so the shipped sample
//! bundle verifies out of the box — exactly as `torda-transport-tls` ships a
//! test PKI. The private seed here is public by design; it is NOT a production
//! feed trust root. A real deployment trusts a real published key via
//! `torda-feed install --trust <hex-or-file>` (or a `FeedVerifier` built from
//! the real key), and the real private half is never committed.

use crate::sign::{FeedSigner, FeedVerifier};

/// The demo feed signing seed. **Non-production**: anyone can forge a bundle the
/// [`sample::verifier`](verifier) trusts, which is fine for a demo trust root
/// and never used to gate anything real.
pub const SAMPLE_FEED_SEED: [u8; 32] = [
    0x54, 0x6f, 0x72, 0x64, 0x61, 0x2d, 0x66, 0x65, 0x65, 0x64, 0x2d, 0x73, 0x61, 0x6d, 0x70, 0x6c,
    0x65, 0x2d, 0x6b, 0x65, 0x79, 0x2d, 0x76, 0x30, 0x2d, 0x64, 0x6f, 0x2d, 0x6e, 0x6f, 0x74, 0x21,
];

/// A signer over the sample key (for regenerating the sample bundle).
pub fn signer() -> FeedSigner {
    FeedSigner::from_seed(SAMPLE_FEED_SEED)
}

/// A verifier trusting the sample key — the default trust root for the shipped
/// community sample bundle.
pub fn verifier() -> FeedVerifier {
    let mut v = FeedVerifier::new();
    v.trust(signer().verifying_key());
    v
}
