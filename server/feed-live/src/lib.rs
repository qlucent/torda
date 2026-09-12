//! `torda-feed-live` — the **enterprise (paid) feed source** and its entitlement
//! layer. FSL-1.1-ALv2: this is the moat half of the feed tiering.
//!
//! The community tier ([`torda_feed::StaticBundleSource`]) is a static, signed,
//! openly-consumable bundle. This crate adds the *live* tier: a [`LiveFeedSource`]
//! that implements the same [`torda_feed::FeedSource`] trait but only after an
//! **entitlement** is verified. The entitlement is a compact Ed25519-signed
//! token asserting a subject, a tier, and an expiry; it is verified **offline**
//! against the issuer's public key, so the tier gate itself needs no network.
//!
//! Separation of concerns (deliberate): the feed **bundle** is signed for
//! content integrity by the *feed* key ([`torda_feed::FeedVerifier`] admits it,
//! same as any community bundle). The **entitlement** is signed by a distinct
//! *issuer* key and decides *access*. A valid bundle you're not entitled to is
//! still refused, and an entitlement without a valid bundle installs nothing.
//!
//! In this slice the hosted fetch is **stubbed**: with a valid enterprise
//! entitlement, [`LiveFeedSource::fetch_bundle`] serves a local enterprise
//! bundle (a stand-in for the hosted endpoint). A production impl would download
//! over TLS into the caller's workdir; either way the store re-verifies the
//! bundle on install.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use torda_feed::{FeedSource, FeedTier};

/// A signed grant: which subject may use which tier, until when.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entitlement {
    /// Who the entitlement is for (org/customer id).
    pub subject: String,
    /// The tier granted. The live source requires [`FeedTier::Enterprise`].
    pub tier: FeedTier,
    /// Epoch millis the token was issued.
    pub issued_at: i64,
    /// Epoch millis after which the token is invalid.
    pub expires_at: i64,
    /// Named feeds the subject may pull (informational in this slice).
    pub feeds: Vec<String>,
}

impl Entitlement {
    /// The exact bytes signed and verified. Deterministic (no maps).
    fn canonical(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("Entitlement is always serializable")
    }
}

/// Mints entitlement tokens. Held by the control plane / license service (the
/// FSL side); a customer never holds one.
pub struct EntitlementIssuer {
    key: SigningKey,
}

impl EntitlementIssuer {
    /// Build an issuer from a 32-byte Ed25519 seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(&seed),
        }
    }

    /// The issuer's public key — what a client verifies tokens against, offline.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Issue a token: `hex(claims).hex(sig)`, where `claims` are the
    /// entitlement's canonical JSON bytes and `sig` is an Ed25519 signature over
    /// them.
    pub fn issue(&self, entitlement: &Entitlement) -> String {
        let claims = entitlement.canonical();
        let sig = self.key.sign(&claims);
        format!("{}.{}", hex::encode(&claims), hex::encode(sig.to_bytes()))
    }
}

/// Verify an entitlement token **offline** against `issuer` at time `now_ms`.
/// Fails closed on: malformed token, undecodable parts, a signature not made by
/// `issuer`, or an expired token.
pub fn verify_entitlement(
    token: &str,
    issuer: &VerifyingKey,
    now_ms: i64,
) -> anyhow::Result<Entitlement> {
    let (claims_hex, sig_hex) = token
        .split_once('.')
        .ok_or_else(|| anyhow!("malformed entitlement token (want claims.sig)"))?;
    let claims = hex::decode(claims_hex.trim()).context("decoding entitlement claims")?;
    let sig_bytes = hex::decode(sig_hex.trim()).context("decoding entitlement signature")?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("entitlement signature must be 64 bytes"))?;
    let sig = Signature::from_bytes(&sig_arr);

    issuer
        .verify_strict(&claims, &sig)
        .map_err(|_| anyhow!("entitlement signature is not valid for the issuer key"))?;

    let entitlement: Entitlement =
        serde_json::from_slice(&claims).context("parsing entitlement claims")?;
    if now_ms > entitlement.expires_at {
        bail!(
            "entitlement expired at {} (now {})",
            entitlement.expires_at,
            now_ms
        );
    }
    Ok(entitlement)
}

/// The enterprise live feed source. Constructed only via [`connect`], which
/// enforces the entitlement gate up front.
///
/// [`connect`]: LiveFeedSource::connect
#[derive(Debug)]
pub struct LiveFeedSource {
    entitlement: Entitlement,
    bundle_dir: PathBuf,
}

impl LiveFeedSource {
    /// Connect to the enterprise feed: verify `token` against `issuer` at
    /// `now_ms` and require it grants [`FeedTier::Enterprise`]. `bundle_dir` is
    /// the local enterprise bundle standing in for the hosted endpoint in this
    /// slice.
    ///
    /// Returns a clear error (not a silent downgrade) when the token is missing,
    /// malformed, expired, or grants a lesser tier — this IS the paid boundary.
    pub fn connect(
        token: &str,
        issuer: &VerifyingKey,
        now_ms: i64,
        bundle_dir: impl Into<PathBuf>,
    ) -> anyhow::Result<Self> {
        let entitlement =
            verify_entitlement(token, issuer, now_ms).context("enterprise tier required")?;
        if entitlement.tier != FeedTier::Enterprise {
            bail!(
                "enterprise tier required: this entitlement grants the {} tier",
                entitlement.tier
            );
        }
        Ok(Self {
            entitlement,
            bundle_dir: bundle_dir.into(),
        })
    }

    /// The verified entitlement backing this source.
    pub fn entitlement(&self) -> &Entitlement {
        &self.entitlement
    }
}

impl FeedSource for LiveFeedSource {
    fn tier(&self) -> FeedTier {
        FeedTier::Enterprise
    }

    fn fetch_bundle(&self, _workdir: &Path) -> anyhow::Result<PathBuf> {
        // STUB: a production source downloads the current enterprise snapshot
        // over TLS into `_workdir`. Here we serve the committed enterprise
        // bundle; the store re-verifies its signature + digests on install
        // regardless of how it arrived.
        if !self.bundle_dir.join("manifest.json").is_file() {
            bail!(
                "enterprise feed bundle not found at {}",
                self.bundle_dir.display()
            );
        }
        Ok(self.bundle_dir.clone())
    }
}

/// A **non-production** sample issuer key + the committed enterprise sample
/// bundle, so tests and demos exercise the full gate out of the box. The seed is
/// public by design and never a production license root.
pub mod sample {
    use super::*;

    /// Demo entitlement-issuer seed. Non-production.
    pub const SAMPLE_ISSUER_SEED: [u8; 32] = [
        0x54, 0x6f, 0x72, 0x64, 0x61, 0x2d, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x6c, 0x65, 0x2d, 0x69,
        0x73, 0x73, 0x75, 0x65, 0x72, 0x2d, 0x76, 0x30, 0x2d, 0x64, 0x6f, 0x2d, 0x6e, 0x6f, 0x74,
        0x21, 0x21,
    ];

    /// The sample issuer (mints demo tokens).
    pub fn issuer() -> EntitlementIssuer {
        EntitlementIssuer::from_seed(SAMPLE_ISSUER_SEED)
    }

    /// The sample issuer's public key (verifies demo tokens).
    pub fn issuer_key() -> VerifyingKey {
        issuer().verifying_key()
    }

    /// Path to the committed enterprise sample bundle (signed by the
    /// `torda_feed` sample feed key, so `torda_feed::sample::verifier()` admits
    /// it on install).
    pub fn enterprise_bundle_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("enterprise-bundle")
    }
}
