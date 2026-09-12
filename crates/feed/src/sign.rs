//! Ed25519 signing/verification of a feed manifest, and the SHA-256 helper for
//! content-file digests. Mirrors `torda-control-plane`'s `CommandSigner` /
//! `Ed25519Verifier`: ed25519-dalek v2, `verify_strict`, fail-closed, no
//! hand-rolled crypto.

use anyhow::{anyhow, Context};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::manifest::FeedManifest;

/// Lowercase-hex SHA-256 of `bytes`, via ring (the audited primitive rustls
/// already links here).
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    hex::encode(digest.as_ref())
}

/// Signs feed manifests. The private key never leaves this type; the seed is a
/// raw 32-byte Ed25519 secret. A publisher holds one of these; a consumer never
/// does.
pub struct FeedSigner {
    key: SigningKey,
}

impl FeedSigner {
    /// Build a signer from a 32-byte Ed25519 seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(&seed),
        }
    }

    /// The paired public key, for embedding in a [`FeedVerifier`].
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// The paired public key as lowercase hex (what a consumer trusts).
    pub fn verifying_key_hex(&self) -> String {
        hex::encode(self.key.verifying_key().to_bytes())
    }

    /// Detached signature over the manifest's canonical bytes, lowercase hex.
    pub fn sign_manifest(&self, manifest: &FeedManifest) -> String {
        let sig = self.key.sign(&manifest.to_canonical_json_bytes());
        hex::encode(sig.to_bytes())
    }
}

/// Verifies feed-manifest signatures against a set of trusted public keys.
/// Fail-closed: an unparseable signature, a wrong-length key, or a signature not
/// made by any trusted key all return `false`.
#[derive(Default, Clone)]
pub struct FeedVerifier {
    trusted: Vec<VerifyingKey>,
}

impl FeedVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Trust a public key (idempotent).
    pub fn trust(&mut self, key: VerifyingKey) {
        if !self.trusted.contains(&key) {
            self.trusted.push(key);
        }
    }

    /// Trust a public key given as 64-char lowercase hex (32 bytes).
    pub fn trust_from_hex(&mut self, hex_key: &str) -> anyhow::Result<()> {
        let bytes = hex::decode(hex_key.trim()).context("decoding trusted feed key hex")?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("ed25519 public key must be 32 bytes, got {}", bytes.len()))?;
        let key = VerifyingKey::from_bytes(&arr).context("invalid ed25519 public key")?;
        self.trust(key);
        Ok(())
    }

    /// No keys trusted — verification would reject everything.
    pub fn is_empty(&self) -> bool {
        self.trusted.is_empty()
    }

    /// `true` iff `sig_hex` is a valid signature over `manifest`'s canonical
    /// bytes by at least one trusted key.
    pub fn verify_manifest(&self, manifest: &FeedManifest, sig_hex: &str) -> bool {
        let Ok(sig_bytes) = hex::decode(sig_hex.trim()) else {
            return false;
        };
        let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.as_slice().try_into() else {
            return false;
        };
        let sig = Signature::from_bytes(&sig_arr);
        let payload = manifest.to_canonical_json_bytes();
        self.trusted
            .iter()
            .any(|k| k.verify_strict(&payload, &sig).is_ok())
    }
}
