//! Golden vectors for ops-provisioned key LOADING + key rotation/revocation, end to
//! end with REAL ed25519. Production signing keys and trust sets live in files, not in
//! code; these vectors prove the file/byte load path is fail-closed, panic-free, and
//! all-or-nothing, and that the multi-key trust store supports a rotation OVERLAP that
//! can then RETIRE the old key, and immediate revocation of a compromised key.
//!
//! Key material is built deterministically from seeds via `CommandSigner::from_seed`
//! and `hex::encode(signer.verifying_key().to_bytes())`, so the "expected" public keys
//! are known. Disk-touching vectors write into a UNIQUE temp dir under
//! `std::env::temp_dir()` and best-effort clean it up (ignored on drop / error).
use std::path::{Path, PathBuf};

use torda_control_plane::{CommandSigner, Ed25519Verifier};
use torda_remediation::action::*;
use torda_remediation::control::{CommandKind, ControlCommand, SignatureVerifier};

/// A signed Draft command from `actor`, ready to hand to `verify`.
fn signed_cmd(signer: &CommandSigner, actor: &str) -> ControlCommand {
    let action = RemediationAction {
        id: "a".into(),
        name: "n".into(),
        method: Method::Shell,
        payload: "echo hi".into(),
        targets: AssetSelector {
            asset_ids: vec!["h1".into()],
        },
        requires_approval: true,
        dry_run_supported: true,
        rollback: None,
        verify: VerifySpec {
            finding_ids: vec![],
        },
        canary: CanarySpec {
            cohort_size: 1,
            failure_threshold: 0.0,
        },
    };
    let mut cmd = ControlCommand {
        action_id: "a".into(),
        kind: CommandKind::Draft(Box::new(action)),
        actor: actor.into(),
        session: "s1".into(),
        seq: 1,
        schedule: None,
        signature: String::new(),
    };
    signer.sign(&mut cmd);
    cmd
}

/// The hex public-key line for a seed-derived signer (what a public-key file holds).
fn pub_hex(signer: &CommandSigner) -> String {
    hex::encode(signer.verifying_key().to_bytes())
}

/// The hex private-key (seed) line for a seed (what a private-key file holds).
fn seed_hex(seed: [u8; 32]) -> String {
    hex::encode(seed)
}

/// Does `verifier` accept `cmd`'s signature under its claimed actor?
fn verifies(verifier: &Ed25519Verifier, cmd: &ControlCommand) -> bool {
    verifier.verify(&cmd.payload(), &cmd.signature, &cmd.actor)
}

/// A unique temp directory that removes itself on drop (best-effort, ignored on error).
struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        // Uniqueness without a rng dep: pid + a nanosecond timestamp + the caller tag.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "torda-keymgmt-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create unique temp dir");
        Self(dir)
    }
    fn path(&self) -> &Path {
        &self.0
    }
    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let p = self.0.join(name);
        std::fs::write(&p, contents).expect("write temp key file");
        p
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0); // best-effort cleanup
    }
}

/// 1. Load a signer from a private-key file + a trust set from a directory, then sign
///    and verify a real command round-trips.
#[test]
fn load_signer_and_trust_round_trips() {
    let seed = [1u8; 32];
    let alice = CommandSigner::from_seed("alice", seed);

    let dir = TempDir::new("roundtrip");
    let priv_path = dir.write(
        "alice.key",
        &format!("# alice private seed\n{}\n", seed_hex(seed)),
    );
    // A trust directory whose file STEM = actor id ("alice").
    let trust_dir = TempDir::new("roundtrip-trust");
    trust_dir.write(
        "alice.pub",
        &format!("# alice public key(s)\n{}\n", pub_hex(&alice)),
    );

    // Load the signer from its private-key file; load trust from the directory.
    let signer = CommandSigner::from_key_file("alice", &priv_path).expect("load signer from file");
    let verifier = Ed25519Verifier::load_trust_dir(trust_dir.path()).expect("load trust dir");

    // The file-loaded signer must be the SAME key as the seed-built one.
    assert_eq!(
        pub_hex(&signer),
        pub_hex(&alice),
        "file-loaded signer matches seed-built key"
    );

    let cmd = signed_cmd(&signer, "alice");
    assert!(
        verifies(&verifier, &cmd),
        "file-loaded signer + dir-loaded trust verify a real command"
    );
}

/// 2. THE CORE ROTATION FLOW: overlap then retire. Trust k1; a k1-signed command
///    verifies. Add k2 from bytes (now k1+k2 both trusted = overlap); BOTH a k1- and a
///    k2-signed command verify. Revoke k1; the k1-signed command is now REJECTED while
///    the k2-signed one still verifies.
#[test]
fn rotation_overlap_then_retire() {
    let k1 = CommandSigner::from_seed("alice", [1u8; 32]);
    let k2 = CommandSigner::from_seed("alice", [2u8; 32]);

    let mut verifier = Ed25519Verifier::new();
    // Trust k1 from a public-key file (bytes).
    verifier
        .trust_from_bytes("alice", pub_hex(&k1).as_bytes())
        .expect("trust k1");

    let c1 = signed_cmd(&k1, "alice");
    assert!(
        verifies(&verifier, &c1),
        "k1-signed command verifies before rotation"
    );

    // Rotation OVERLAP: add k2; k1 stays trusted (additive).
    verifier
        .trust_from_bytes("alice", pub_hex(&k2).as_bytes())
        .expect("trust k2 (overlap)");
    let c2 = signed_cmd(&k2, "alice");
    assert!(verifies(&verifier, &c1), "k1 still verifies DURING overlap");
    assert!(verifies(&verifier, &c2), "k2 verifies DURING overlap");

    // RETIRE k1 (rotation complete). k1 is immediately rejected; k2 survives.
    verifier.revoke("alice", &k1.verifying_key());
    assert!(
        !verifies(&verifier, &c1),
        "retired k1 is REJECTED after overlap"
    );
    assert!(
        verifies(&verifier, &c2),
        "k2 still verifies after k1 retired"
    );
}

/// 3. A single public-key file with k1 AND k2 on TWO lines trusts BOTH (a rotation
///    overlap expressed as one file).
#[test]
fn two_line_public_key_file_trusts_both() {
    let k1 = CommandSigner::from_seed("alice", [1u8; 32]);
    let k2 = CommandSigner::from_seed("alice", [2u8; 32]);

    let file = format!(
        "# two trusted keys (overlap)\n{}\n{}\n",
        pub_hex(&k1),
        pub_hex(&k2)
    );
    let mut verifier = Ed25519Verifier::new();
    verifier
        .trust_from_bytes("alice", file.as_bytes())
        .expect("trust both lines");

    assert!(
        verifies(&verifier, &signed_cmd(&k1, "alice")),
        "first-line key verifies"
    );
    assert!(
        verifies(&verifier, &signed_cmd(&k2, "alice")),
        "second-line key verifies"
    );
}

/// 4. Revoking a compromised key rejects it IMMEDIATELY: the SAME command that verified
///    true now verifies false after revoke.
#[test]
fn revoking_a_compromised_key_rejects_it_immediately() {
    let k = CommandSigner::from_seed("alice", [3u8; 32]);
    let mut verifier = Ed25519Verifier::new();
    verifier
        .trust_from_bytes("alice", pub_hex(&k).as_bytes())
        .expect("trust key");

    let cmd = signed_cmd(&k, "alice");
    assert!(
        verifies(&verifier, &cmd),
        "command verifies while key is trusted"
    );

    verifier.revoke("alice", &k.verifying_key());
    assert!(
        !verifies(&verifier, &cmd),
        "the SAME command is rejected the instant the key is revoked"
    );
}

/// 5. Malformed key material ALWAYS errors, never panics, and trust is ALL-OR-NOTHING:
///    a file with one good + one bad line trusts NEITHER key.
#[test]
fn malformed_key_material_errors_without_panic() {
    let good = CommandSigner::from_seed("alice", [1u8; 32]);
    let good_pub = pub_hex(&good);

    // -- CommandSigner::from_key_bytes rejects every malformed private-key input --
    assert!(
        CommandSigner::from_key_bytes("alice", b"zz").is_err(),
        "bad hex -> Err"
    );
    let thirty_one = hex::encode([9u8; 31]); // 62 hex chars = 31 bytes, not 32
    assert!(
        CommandSigner::from_key_bytes("alice", thirty_one.as_bytes()).is_err(),
        "31-byte key -> Err"
    );
    assert!(
        CommandSigner::from_key_bytes("alice", b"").is_err(),
        "empty (no key line) -> Err"
    );
    assert!(
        CommandSigner::from_key_bytes("alice", b"   \n# only comments\n").is_err(),
        "no key lines -> Err"
    );
    // Two seeds where a signer file must hold exactly one.
    let two_seeds = format!("{}\n{}\n", seed_hex([1u8; 32]), seed_hex([2u8; 32]));
    assert!(
        CommandSigner::from_key_bytes("alice", two_seeds.as_bytes()).is_err(),
        "two seeds for one signer -> Err"
    );
    // Raw non-UTF-8 garbage bytes.
    assert!(
        CommandSigner::from_key_bytes("alice", &[0xff, 0xfe, 0x00, 0x99]).is_err(),
        "garbage bytes -> Err"
    );

    // -- Ed25519Verifier::trust_from_bytes: malformed -> Err AND nothing added --
    let mut v = Ed25519Verifier::new();
    assert!(
        v.trust_from_bytes("alice", b"zz").is_err(),
        "bad hex -> Err"
    );
    assert!(
        v.trust_from_bytes("alice", thirty_one.as_bytes()).is_err(),
        "31-byte key -> Err"
    );
    assert!(
        v.trust_from_bytes("alice", &[0xff, 0xfe]).is_err(),
        "garbage bytes -> Err"
    );

    // ALL-OR-NOTHING: one good + one bad line trusts NEITHER key.
    let mixed = format!("{good_pub}\nzz-not-hex\n");
    assert!(
        v.trust_from_bytes("alice", mixed.as_bytes()).is_err(),
        "mixed good+bad -> Err"
    );
    assert!(
        !verifies(&v, &signed_cmd(&good, "alice")),
        "all-or-nothing: the good line was NOT trusted when a sibling line was bad"
    );

    // A subsequently-loaded clean file DOES trust (proving the store was untouched, not poisoned).
    v.trust_from_bytes("alice", good_pub.as_bytes())
        .expect("clean load after a failed one");
    assert!(
        verifies(&v, &signed_cmd(&good, "alice")),
        "a later clean load trusts normally"
    );
}

/// 5b. A line that is VALID 64-hex decoding to exactly 32 bytes but is NOT a canonical
///     ed25519 public key is rejected (hits the `VerifyingKey::from_bytes` Err branch,
///     distinct from the earlier hex/length/UTF-8 failures) and trusts NOTHING. Note the
///     same 32 bytes would be a valid PRIVATE seed — this branch is public-key-only.
#[test]
fn non_canonical_public_key_is_rejected() {
    // 32 bytes of 0x02: valid hex + exactly 32 bytes, but its compressed y-coordinate does
    // NOT decompress to a curve point, so VerifyingKey::from_bytes rejects it as invalid.
    // (0xff*32 happens to decompress on this ed25519-dalek version; 0x02*32 does not.)
    let non_canonical = "02".repeat(32);
    assert_eq!(
        non_canonical.len(),
        64,
        "the input IS valid 64-hex (fails at from_bytes, not hex/length)"
    );

    let mut v = Ed25519Verifier::new();
    let err = v
        .trust_from_bytes("alice", non_canonical.as_bytes())
        .expect_err("a non-canonical public key must be rejected, not trusted");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::InvalidData,
        "mapped to InvalidData, not a panic"
    );

    // Nothing was trusted: an actor with only this rejected key still fails closed.
    let alice = CommandSigner::from_seed("alice", [7u8; 32]);
    assert!(
        !verifies(&v, &signed_cmd(&alice, "alice")),
        "nothing trusted after the rejected non-canonical key"
    );

    // Sanity: the SAME 32 bytes ARE a valid private seed (the seed path must not change).
    assert!(
        CommandSigner::from_key_bytes("alice", non_canonical.as_bytes()).is_ok(),
        "any 32 bytes is a valid ed25519 SEED — only the public-key path rejects non-canonical points"
    );
}

/// 5c. A pathologically oversized key file is rejected up front (Err InvalidData), never
///     a panic or an unbounded allocation/hang. Every real vector above is tiny and green.
#[test]
fn oversized_key_file_is_rejected() {
    // Well over the 64 KiB cap: a valid public-key hex line repeated many times.
    let alice = CommandSigner::from_seed("alice", [1u8; 32]);
    let one_line = format!("{}\n", pub_hex(&alice)); // 65 bytes/line
    let huge = one_line.repeat(2000); // ~130 KiB, > 64 KiB cap
    assert!(huge.len() > 64 * 1024, "input is genuinely over the cap");

    let mut v = Ed25519Verifier::new();
    let err = v
        .trust_from_bytes("alice", huge.as_bytes())
        .expect_err("an over-cap key file must be rejected");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::InvalidData,
        "over-cap file -> InvalidData, not a panic/hang"
    );
    assert!(
        !verifies(&v, &signed_cmd(&alice, "alice")),
        "nothing trusted from a rejected oversized file"
    );

    // The same over-cap bound applies to the private-signer loader.
    assert!(
        CommandSigner::from_key_bytes("alice", huge.as_bytes()).is_err(),
        "oversized private-key file also rejected"
    );
}

/// 5d. The size cap also protects the DISK loaders: a file just over MAX_KEY_FILE_BYTES
///     is rejected from its on-disk size (metadata) WITHOUT being read into memory, by
///     BOTH `from_key_file` (private-key path) and `load_trust_dir` (trust-store path).
#[test]
fn oversized_key_file_on_disk_is_rejected() {
    // A file slightly over the 64 KiB cap proves the metadata pre-check fires (no need for
    // a multi-GB file). Content is valid hex lines; only its SIZE is the disqualifier.
    let alice = CommandSigner::from_seed("alice", [1u8; 32]);
    let one_line = format!("{}\n", pub_hex(&alice)); // 65 bytes/line
    let over_cap = one_line.repeat(1100); // ~71.5 KiB, > 64 KiB
    assert!(
        over_cap.len() > 64 * 1024,
        "the on-disk file is genuinely over the cap"
    );

    let dir = TempDir::new("oversized-disk");

    // Private-key loader: reject the oversized file from disk.
    let priv_path = dir.write("alice.key", &over_cap);
    assert!(
        CommandSigner::from_key_file("alice", &priv_path).is_err(),
        "from_key_file rejects an oversized file via its on-disk size"
    );

    // Trust-store loader: an oversized trust file makes the whole directory load fail.
    let trust_dir = TempDir::new("oversized-disk-trust");
    trust_dir.write("alice.pub", &over_cap);
    assert!(
        Ed25519Verifier::load_trust_dir(trust_dir.path()).is_err(),
        "load_trust_dir rejects an oversized trust file via its on-disk size"
    );
}

/// 6. Unknown actor + missing key fail closed; an empty trust dir loads to an empty
///    (trust-nothing) verifier.
#[test]
fn unknown_actor_and_missing_key_fail_closed() {
    // A verifier that trusts alice does not trust bob.
    let alice = CommandSigner::from_seed("alice", [1u8; 32]);
    let mut v = Ed25519Verifier::new();
    v.trust_from_bytes("alice", pub_hex(&alice).as_bytes())
        .expect("trust alice");
    let bob = CommandSigner::from_seed("bob", [5u8; 32]);
    assert!(
        !verifies(&v, &signed_cmd(&bob, "bob")),
        "unknown actor with no loaded key fails closed"
    );

    // An empty directory -> Ok(empty verifier); every actor fails closed.
    let empty = TempDir::new("empty-trust");
    let ev = Ed25519Verifier::load_trust_dir(empty.path()).expect("empty dir loads Ok");
    assert!(
        !verifies(&ev, &signed_cmd(&alice, "alice")),
        "empty trust store verifies nothing"
    );
    assert!(
        !verifies(&ev, &signed_cmd(&bob, "bob")),
        "empty trust store verifies nothing for any actor"
    );
}
