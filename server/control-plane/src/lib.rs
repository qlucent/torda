//! Control-plane cryptography: real ed25519 signing + verification for remediation
//! commands. `CommandSigner` (server side) signs a command's canonical bytes;
//! `Ed25519Verifier` (the real `SignatureVerifier`) accepts a command ONLY if its
//! signature verifies against the trusted public key of the claimed actor. Uses the
//! audited `ed25519-dalek` library — no hand-rolled crypto. Key distribution /
//! rotation is the mTLS control-channel work (P3b-3); here trusted keys are held
//! in memory and seeded deterministically for reproducible tests.
use std::collections::{HashMap, HashSet};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use torda_remediation::audit::AuditSink;
use torda_remediation::bridge::{Bridge, Executor, StageOutcome, Verifier};
use torda_remediation::control::{
    dispatch, dispatch_execution_fresh, dispatch_fresh, Authorizer, Clock, CommandKind,
    ControlCommand, ReplayGuard, SignatureVerifier,
};
use torda_remediation::scheduler::Scheduler;
use torda_transport::Transport;

/// Upper bound on the size of a key file [`parse_hex_key_lines`] will decode. A real
/// public-key file is at most a rotation overlap of a few 65-byte hex lines (well under
/// a KiB); this 64 KiB cap is generous headroom while still refusing to allocate against
/// a pathologically large or accidental file (which is rejected before any decoding). At
/// 65 bytes per key line this also transitively bounds the key count to ~1000.
const MAX_KEY_FILE_BYTES: usize = 64 * 1024;

/// Read a key file into memory, but ONLY after checking its on-disk size so an oversized
/// file is rejected WITHOUT ever being read into RAM.
///
/// This is the disk counterpart to the in-[`parse_hex_key_lines`] byte cap: `std::fs::read`
/// would allocate the WHOLE file first, so a multi-GB file would be fully read before the
/// byte cap could reject it. Here `std::fs::metadata(path)?.len()` is consulted first, and a
/// file whose length exceeds [`MAX_KEY_FILE_BYTES`] is rejected with `Err(InvalidData)`
/// before a single byte is read. On success the bytes are returned for parsing (where the
/// same cap still runs, catching any post-metadata growth). Fail-closed + panic-free.
fn read_capped_key_file(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    let len = std::fs::metadata(path)?.len();
    if len > MAX_KEY_FILE_BYTES as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "key file {} too large: {len} bytes exceeds the {MAX_KEY_FILE_BYTES}-byte cap",
                path.display()
            ),
        ));
    }
    std::fs::read(path)
}

/// Parse ops-provisioned key-file bytes into a list of raw 32-byte ed25519 keys.
///
/// # File format (this slice)
/// Hex-encoded 32-byte keys, ONE PER LINE. Blank lines and lines whose first
/// non-whitespace character is `#` are ignored (comments). Every other line MUST be
/// exactly 64 hex characters decoding to 32 bytes. A private-key file holds exactly
/// ONE line (the seed); a public-key file may hold MULTIPLE lines — a key-rotation
/// OVERLAP, i.e. several public keys trusted simultaneously.
///
/// # Guarantees
/// Fail-closed + all-or-nothing + panic-free: ANY non-ignored line that is not valid
/// 32-byte hex (bad hex, wrong length) makes the WHOLE parse fail with an
/// [`std::io::Error`] of kind [`std::io::ErrorKind::InvalidData`] and yields NOTHING —
/// trust is never applied partially or silently. Non-UTF-8 bytes are an `Err`, not a
/// panic. This function only decodes bytes; canonical-key validation (for public keys)
/// is the caller's [`VerifyingKey::from_bytes`] step.
///
/// NOTE: PKCS#8 / SPKI PEM is a future format refinement; this slice is raw hex only.
///
/// # Resource bound
/// A key file is trusted input authored by ops, but this loader still refuses to
/// allocate against a pathologically large one: an in-memory buffer exceeding
/// [`MAX_KEY_FILE_BYTES`] is rejected with `Err(InvalidData)` BEFORE any decoding, so a
/// giant or accidental buffer can never cause unbounded allocation or a hang. The DISK
/// loaders ([`CommandSigner::from_key_file`] / [`Ed25519Verifier::load_trust_dir`]) apply
/// the SAME cap even earlier, via [`read_capped_key_file`], so an oversized file is
/// rejected from its on-disk size WITHOUT being read into memory at all. A real
/// public-key file (a rotation overlap of a few keys) is well under a KiB, so the cap is
/// generous.
fn parse_hex_key_lines(bytes: &[u8]) -> std::io::Result<Vec<[u8; 32]>> {
    // Bound the input up front: refuse to even decode an implausibly large file.
    if bytes.len() > MAX_KEY_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "key file too large: {} bytes exceeds the {MAX_KEY_FILE_BYTES}-byte cap",
                bytes.len()
            ),
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut keys = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue; // blank line or comment
        }
        let decoded = hex::decode(line).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid hex key line: {e}"),
            )
        })?;
        let key: [u8; 32] = decoded.as_slice().try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("ed25519 key must be 32 bytes, got {}", decoded.len()),
            )
        })?;
        keys.push(key);
    }
    Ok(keys)
}

/// The real `SignatureVerifier`: verifies an ed25519 signature over a command's
/// canonical payload against a trusted public key of the claimed actor.
///
/// # Rotation & revocation semantics
/// An actor is trusted under a SET of keys, not a single key, so a key rotation
/// can trust the OLD and NEW key SIMULTANEOUSLY (an overlap window during which
/// commands signed by either verify). [`trust`](Self::trust) is ADDITIVE and
/// idempotent — it adds a key to the actor's set without displacing existing keys,
/// and trusting the same key twice is a no-op. [`revoke`](Self::revoke) removes ONE
/// key IMMEDIATELY (for a compromised key), and [`revoke_actor`](Self::revoke_actor)
/// removes ALL of an actor's keys (offboarding). A revoked key can NEVER verify again
/// unless explicitly re-trusted, because [`verify`](Self::verify) only ever consults
/// the current set. All paths are fail-closed.
///
/// `VerifyingKey` is neither `Hash` nor `Ord`, so the per-actor set is keyed by the
/// canonical 32-byte encoding (`key.to_bytes()`) — this makes insertion dedup-correct
/// (the same key maps to the same slot) while still holding the parsed `VerifyingKey`.
#[derive(Default)]
pub struct Ed25519Verifier {
    trusted: HashMap<String, HashMap<[u8; 32], VerifyingKey>>,
}

impl Ed25519Verifier {
    pub fn new() -> Self {
        Self::default()
    }
    /// Trust one of `actor`'s public keys. ADDITIVE + idempotent: the key is added to
    /// the actor's trusted SET (so old+new keys can be trusted together during a
    /// rotation overlap), and trusting the same key twice does NOT create a duplicate.
    /// In production these are distributed over the mTLS control channel (P3b-3); here
    /// they are added explicitly.
    pub fn trust(&mut self, actor: &str, key: VerifyingKey) {
        self.trusted
            .entry(actor.to_string())
            .or_default()
            .insert(key.to_bytes(), key);
    }
    /// Revoke exactly `key` from `actor`'s trusted set, effective IMMEDIATELY (for a
    /// compromised key). If it was the actor's last key, the actor is left with no
    /// trusted keys and every subsequent `verify` for that actor fails-closed. A no-op
    /// if the key was not trusted for the actor.
    pub fn revoke(&mut self, actor: &str, key: &VerifyingKey) {
        if let Some(keys) = self.trusted.get_mut(actor) {
            keys.remove(&key.to_bytes());
        }
    }
    /// Revoke ALL of `actor`'s trusted keys (offboarding). After this, no signature
    /// claiming `actor` can verify until a key is re-trusted. A no-op for an unknown actor.
    pub fn revoke_actor(&mut self, actor: &str) {
        self.trusted.remove(actor);
    }

    /// Trust one actor's public key(s) from raw key-file bytes: one or more hex-encoded
    /// 32-byte ed25519 public keys, ONE PER LINE (blank/`#` lines ignored). MULTIPLE
    /// lines = a rotation OVERLAP (every listed key trusted simultaneously). Production
    /// keys live in ops-provisioned files, not in code; this is the load path.
    ///
    /// ALL-OR-NOTHING + fail-closed + panic-free: every line is decoded AND validated as
    /// a canonical [`VerifyingKey`] FIRST, and only if EVERY key parses are they ALL
    /// added via [`trust`](Self::trust) (additive + idempotent). If ANY line is
    /// malformed — bad hex, not 32 bytes, or a non-canonical public key that
    /// [`VerifyingKey::from_bytes`] rejects (its `Err` is mapped to
    /// [`std::io::ErrorKind::InvalidData`], never unwrapped) — this returns `Err` and
    /// adds NOTHING for this call (a file with one good + one bad line trusts NEITHER).
    pub fn trust_from_bytes(&mut self, actor: &str, bytes: &[u8]) -> std::io::Result<()> {
        let raw = parse_hex_key_lines(bytes)?;
        // Parse+validate EVERY key BEFORE mutating self: a non-canonical public key is an
        // Err (mapped from VerifyingKey::from_bytes), never a panic. All-or-nothing.
        let mut parsed = Vec::with_capacity(raw.len());
        for key in &raw {
            let vk = VerifyingKey::from_bytes(key).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("non-canonical ed25519 public key: {e}"),
                )
            })?;
            parsed.push(vk);
        }
        for vk in parsed {
            self.trust(actor, vk);
        }
        Ok(())
    }

    /// Load a full trust store from an ops-provisioned DIRECTORY. Each regular file
    /// `<actor>.<ext>` contributes actor id = the file STEM, and its lines are that
    /// actor's trusted public keys (see [`trust_from_bytes`](Self::trust_from_bytes) for
    /// the per-file format + all-or-nothing guarantee — one bad line fails that file, and
    /// thus the whole load). Sub-directories and non-file entries are skipped.
    ///
    /// Fail-closed + panic-free: a malformed line in ANY file, an unreadable entry, or a
    /// file whose stem is not valid UTF-8 propagates `Err` and the load fails as a whole
    /// (never a partially-populated store). Each file's on-disk size is checked FIRST (via
    /// [`read_capped_key_file`]) so a file exceeding [`MAX_KEY_FILE_BYTES`] is rejected
    /// WITHOUT being read into memory. An EMPTY directory yields `Ok` of an empty,
    /// trust-nothing verifier (every `verify` fails-closed).
    pub fn load_trust_dir(path: &std::path::Path) -> std::io::Result<Self> {
        let mut verifier = Self::new();
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let file_path = entry.path();
            if !file_path.is_file() {
                continue; // skip sub-directories and other non-file entries
            }
            let stem = file_path
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "trust file has no valid actor stem: {}",
                            file_path.display()
                        ),
                    )
                })?;
            let bytes = read_capped_key_file(&file_path)?;
            verifier.trust_from_bytes(stem, &bytes)?;
        }
        Ok(verifier)
    }
}

impl SignatureVerifier for Ed25519Verifier {
    fn verify(&self, payload: &str, signature: &str, actor: &str) -> bool {
        // Fail-closed at every step; never panic on attacker-controlled input.
        let Some(keys) = self.trusted.get(actor) else {
            return false;
        };
        // Decode + parse the signature ONCE, before trying any key.
        let Ok(bytes) = hex::decode(signature) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(&bytes) else {
            return false;
        };
        // Accept iff SOME currently-trusted key for the actor verifies. verify_strict
        // rejects malleable / non-canonical signatures (security best practice). An
        // empty set (all keys revoked) yields `any` over nothing -> false (fail-closed).
        keys.values()
            .any(|key| key.verify_strict(payload.as_bytes(), &sig).is_ok())
    }
}

/// A `SignatureVerifier` whose ed25519 trust store can be ATOMICALLY hot-reloaded from
/// ops-provisioned files on a RUNNING agent — no process restart, no reconstruction of
/// the handler, no gap during which trust is absent.
///
/// # Why
/// The command-verification seam ([`AgentControlHandler::verifier`]) is a
/// `&dyn SignatureVerifier`, so this drops in wherever an [`Ed25519Verifier`] did. Ops
/// can revoke a compromised key or roll in a new one by rewriting the trust directory and
/// calling [`reload_from_dir`](Self::reload_from_dir); the change takes effect on the very
/// next `verify` with no downtime.
///
/// # Concurrency + atomicity
/// The live store sits behind a [`std::sync::RwLock`]. `verify` takes a READ lock (many
/// concurrent verifications proceed in parallel); `reload_from_dir` swaps the WHOLE store
/// under a single WRITE lock, so a verification either sees entirely the OLD store or
/// entirely the NEW one — never a half-applied trust set.
///
/// # Fail-safe (SECURITY-critical)
/// A reload is BUILD-NEW-THEN-SWAP: the fresh store is fully built and validated by
/// [`Ed25519Verifier::load_trust_dir`] BEFORE the live store is touched. If the load
/// fails for ANY reason (missing dir, malformed/oversized/non-canonical key file, unreadable
/// entry), `reload_from_dir` returns `Err` and the CURRENT store is left completely
/// UNCHANGED. A bad reload can therefore never disarm the agent (never drop to zero-trust)
/// nor widen trust — the worst case of a bad reload is a no-op with an error.
///
/// # Panic-free
/// `verify` NEVER panics: on a poisoned lock (a writer panicked mid-swap — which this code
/// never does, but a defense-in-depth guard) it FAILS CLOSED, returning `false`, rather
/// than unwrapping. `reload_from_dir` likewise recovers a poisoned write lock via
/// `PoisonError::into_inner` instead of panicking, then performs the (already-validated)
/// swap. Neither path can panic on lock state.
pub struct ReloadableVerifier {
    inner: std::sync::RwLock<Ed25519Verifier>,
}

impl ReloadableVerifier {
    /// Wrap an initial trust store. The store is live immediately; call
    /// [`reload_from_dir`](Self::reload_from_dir) later to atomically replace it.
    pub fn new(initial: Ed25519Verifier) -> Self {
        Self {
            inner: std::sync::RwLock::new(initial),
        }
    }

    /// Atomically rebuild the trust store from `path` and, ONLY on full success, replace
    /// the live store in place.
    ///
    /// BUILD-NEW-THEN-SWAP + FAIL-SAFE: the new store is constructed by
    /// [`Ed25519Verifier::load_trust_dir`] FIRST — this either yields a COMPLETE new store
    /// or returns `Err` WITHOUT touching `self`. Only after a successful build is the write
    /// lock taken and the store swapped, so a failed load never mutates the live store
    /// (never zero-trust, never widened). The swap holds the write lock for the duration of
    /// a single move, so `verify` observers see the old-or-new store atomically.
    ///
    /// Panic-free: if the write lock is poisoned it is recovered via
    /// [`std::sync::PoisonError::into_inner`] and the swap proceeds — never an `unwrap()`
    /// panic. Returns `Ok(())` on success or the load's `io::Error` on failure.
    pub fn reload_from_dir(&self, path: &std::path::Path) -> std::io::Result<()> {
        // Build + validate a COMPLETE new store BEFORE touching the live one. On ANY error
        // this returns early and `self.inner` is never mutated (fail-safe).
        let fresh = Ed25519Verifier::load_trust_dir(path)?;
        // Atomic swap under the write lock. Recover a poisoned lock rather than panic: the
        // store we are about to install is already fully validated.
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        *guard = fresh;
        Ok(())
    }
}

impl SignatureVerifier for ReloadableVerifier {
    /// Delegate to the live [`Ed25519Verifier`] under a READ lock. FAILS CLOSED on a
    /// poisoned lock (returns `false`) rather than unwrapping a panic, so a verifier whose
    /// lock was somehow poisoned rejects everything instead of crashing the agent.
    fn verify(&self, payload: &str, signature: &str, actor: &str) -> bool {
        match self.inner.read() {
            Ok(guard) => guard.verify(payload, signature, actor),
            Err(_) => false, // poisoned lock -> fail closed, never panic
        }
    }
}

/// Signs remediation commands with an ed25519 private key. Deterministic from a
/// 32-byte seed (test/dev); real key generation + custody is P3b-3/ops.
pub struct CommandSigner {
    key: SigningKey,
    pub actor: String,
}

impl CommandSigner {
    pub fn from_seed(actor: &str, seed: [u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(&seed),
            actor: actor.to_string(),
        }
    }

    /// Load a signer from a private-key FILE: ONE line of hex-encoded 32-byte ed25519
    /// seed (blank/`#` comment lines ignored). Production signing keys live in
    /// ops-provisioned files, not in code. Checks the on-disk size FIRST (via
    /// [`read_capped_key_file`]) so a file exceeding [`MAX_KEY_FILE_BYTES`] is rejected
    /// WITHOUT being read into memory, then delegates the bytes to
    /// [`from_key_bytes`](Self::from_key_bytes); see it for the fail-closed, panic-free
    /// guarantees. PKCS#8 PEM is a future format refinement.
    pub fn from_key_file(actor: &str, path: &std::path::Path) -> std::io::Result<Self> {
        let bytes = read_capped_key_file(path)?;
        Self::from_key_bytes(actor, &bytes)
    }

    /// Load a signer from raw private-key file bytes (testable without disk). The bytes
    /// MUST contain EXACTLY ONE hex-encoded 32-byte seed line (blank/`#` lines ignored).
    ///
    /// Fail-closed + panic-free: malformed input — bad hex, not 32 bytes, empty (no key
    /// line), or MORE than one key line — is [`std::io::ErrorKind::InvalidData`], NEVER a
    /// panic. On success the seed is fed to `SigningKey::from_bytes` (any 32 bytes is a
    /// valid ed25519 seed, so no further validation is needed for a PRIVATE key).
    pub fn from_key_bytes(actor: &str, bytes: &[u8]) -> std::io::Result<Self> {
        let keys = parse_hex_key_lines(bytes)?;
        let [seed] = keys.as_slice() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "a private-key file must hold exactly one seed line, found {}",
                    keys.len()
                ),
            ));
        };
        Ok(Self {
            key: SigningKey::from_bytes(seed),
            actor: actor.to_string(),
        })
    }
    /// The public key a verifier must trust to accept this signer's commands.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
    /// Signs an arbitrary payload string, returning the hex-encoded signature.
    pub fn sign_payload(&self, payload: &str) -> String {
        hex::encode(self.key.sign(payload.as_bytes()).to_bytes())
    }
    /// Signs a command over its canonical `payload()` (which binds the full
    /// command), writing the hex signature into `cmd.signature`.
    pub fn sign(&self, cmd: &mut ControlCommand) {
        cmd.signature = self.sign_payload(&cmd.payload());
    }
}

/// The return leg of the control channel: whether a `ControlCommand` was applied
/// to the bridge or rejected by one of its gates. This is the outcome the agent
/// signs and hands back to the issuing control plane so an operator learns the
/// fate of a command they authored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommandOutcome {
    /// The command passed authentication + authorization and its gated bridge
    /// operation succeeded (the state transition was applied).
    Applied,
    /// The command was refused — a bad signature, an unauthorized actor, or an
    /// illegal lifecycle transition. The bridge state is unchanged.
    Rejected,
}

/// A signed acknowledgment of a single `ControlCommand`, produced by the agent and
/// returned to the issuing control plane. It carries the outcome and a human-readable
/// detail, and is authenticated by the AGENT's own ed25519 signature over its
/// canonical (unsigned) payload. This closes the trust loop in both directions: the
/// server proves WHO issued a command (via `ControlCommand`), and the agent proves
/// WHO reported the result and that the report was not tampered with in transit
/// (via `CommandResult::signature`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandResult {
    /// The `action_id` of the command this result acknowledges.
    pub action_id: String,
    /// Whether the command was applied or rejected.
    pub outcome: CommandOutcome,
    /// Human-readable detail: `"applied"` on success, or the dispatch error text
    /// (e.g. the signature/authorization/lifecycle rejection reason) on failure.
    pub detail: String,
    /// The agent actor that produced and signed this result — the key the issuer
    /// must trust under this name to authenticate the acknowledgment.
    pub agent: String,
    /// Per-session freshness token (part 1), ECHOED from the command this result
    /// answers: the control session the answered command belonged to. Bound by
    /// `signature` (folded into `payload()`) so a later replay guard can trust that
    /// the result is tied to the exact command it acknowledges. No guard consumes it yet.
    pub session: String,
    /// Per-session freshness token (part 2), ECHOED from the command this result
    /// answers: the answered command's sequence number within `session`. Bound by
    /// `signature` (folded into `payload()`) for the same reason as `session`. No
    /// guard consumes it yet.
    pub seq: u64,
    /// Hex-encoded ed25519 signature over `payload()` (the unsigned result). Excluded
    /// from `payload()` itself so signing does not alter what is signed.
    pub signature: String,
}

impl CommandResult {
    /// The canonical string the result's signature is computed over: a deterministic
    /// serialization of the UNSIGNED acknowledgment (`action_id`, `outcome`, `detail`,
    /// `agent`, and the echoed `(session, seq)` freshness token), EXCLUDING `signature`.
    /// Uses the same borrowed-`Unsigned` pattern as `ControlCommand::payload()`, so
    /// re-signing an already-signed result reproduces the identical payload and any
    /// tampering with a bound field — including `session` or `seq` — invalidates the
    /// signature.
    pub fn payload(&self) -> String {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            action_id: &'a str,
            outcome: &'a CommandOutcome,
            detail: &'a str,
            agent: &'a str,
            session: &'a str,
            seq: u64,
        }
        serde_json::to_string(&Unsigned {
            action_id: &self.action_id,
            outcome: &self.outcome,
            detail: &self.detail,
            agent: &self.agent,
            session: &self.session,
            seq: self.seq,
        })
        .expect("CommandResult is always serializable")
    }
}

/// The agent-side handler for the remediation control channel. It runs one incoming
/// `ControlCommand` through the existing `dispatch` gate (signature verification +
/// authorization + the bridge's lifecycle guards) and returns a `CommandResult`
/// signed with the agent's OWN key. It adds NO gate of its own and changes none of
/// dispatch's logic: it only observes dispatch's `Result` and signs the outcome, so
/// the issuing control plane can verify the acknowledgment's authenticity and detect
/// tampering.
pub struct AgentControlHandler<'a> {
    /// The command-verification seam, held as a trait object so ANY `SignatureVerifier`
    /// drops in: a plain [`Ed25519Verifier`] OR a [`ReloadableVerifier`] whose trust store
    /// can be hot-reloaded on a running agent. The handler only ever calls
    /// `SignatureVerifier::verify` through this (never a concrete `Ed25519Verifier`
    /// method), and forwards it UNCHANGED to `dispatch`/`dispatch_fresh`/
    /// `dispatch_execution_fresh` (all of which take `&dyn SignatureVerifier`), so the
    /// widening is fully behavior-preserving.
    verifier: &'a dyn SignatureVerifier,
    authz: &'a dyn Authorizer,
    signer: &'a CommandSigner,
}

impl<'a> AgentControlHandler<'a> {
    /// Construct a handler from the command verifier (authenticates issuers), the
    /// authorizer (decides who may issue what), and the agent's signer (signs the
    /// returned acknowledgment). The verifier is a `&dyn SignatureVerifier`, so both a
    /// plain `&Ed25519Verifier` (which coerces automatically) and a `&ReloadableVerifier`
    /// are accepted without any call-site change.
    pub fn new(
        verifier: &'a dyn SignatureVerifier,
        authz: &'a dyn Authorizer,
        signer: &'a CommandSigner,
    ) -> Self {
        Self {
            verifier,
            authz,
            signer,
        }
    }

    /// Run one command through `dispatch` and return a signed acknowledgment.
    ///
    /// The command is forwarded UNCHANGED to `dispatch`, which owns every gate
    /// (authentication, authorization, and the bridge's lifecycle guards). This
    /// method neither adds nor bypasses any gate — it maps `dispatch`'s `Result`
    /// to a `CommandOutcome`, records the detail, and signs the result with the
    /// agent's key. It never panics on any input: `dispatch` returns a `Result`
    /// (its own gates are fail-closed and non-panicking) and signing is pure hex
    /// encoding of an ed25519 signature over an always-serializable payload.
    pub fn handle<A: AuditSink>(
        &self,
        bridge: &mut Bridge<A>,
        cmd: ControlCommand,
    ) -> CommandResult {
        // Capture the action id AND the freshness token (session, seq) BEFORE `cmd`
        // is moved into `dispatch`. The result ECHOES the command's (session, seq) so
        // the acknowledgment is cryptographically bound to the exact command it answers.
        let action_id = cmd.action_id.clone();
        let session = cmd.session.clone();
        let seq = cmd.seq;
        let (outcome, detail) = Self::classify(dispatch(bridge, cmd, self.verifier, self.authz));
        self.sign_outcome(action_id, session, seq, outcome, detail)
    }

    /// The REPLAY-GUARDED sibling of [`handle`](Self::handle). It is byte-for-byte the
    /// same acknowledgment logic, except it forwards the command to
    /// [`dispatch_fresh`] — running the freshness (replay) gate BETWEEN authentication
    /// and authorization — instead of the un-guarded [`dispatch`]. This is the entry
    /// point the wire loop ([`AgentControlLoop::serve_one`]) uses: every command that
    /// arrives over the transport is admitted through the `guard`, so a replayed
    /// (session, seq) is rejected and can never re-apply a bridge mutation. Closes the
    /// P3b-5 advisory that the plain `handle`/`dispatch` path was reachable from the wire.
    ///
    /// Like `handle`, it never panics: `dispatch_fresh` is fail-closed and returns a
    /// `Result`, and signing is pure hex encoding over an always-serializable payload.
    pub fn handle_fresh<A: AuditSink>(
        &self,
        bridge: &mut Bridge<A>,
        guard: &mut ReplayGuard,
        cmd: ControlCommand,
    ) -> CommandResult {
        let action_id = cmd.action_id.clone();
        let session = cmd.session.clone();
        let seq = cmd.seq;
        let (outcome, detail) = Self::classify(dispatch_fresh(
            bridge,
            guard,
            cmd,
            self.verifier,
            self.authz,
        ));
        self.sign_outcome(action_id, session, seq, outcome, detail)
    }

    /// The REPLAY-GUARDED EXECUTION sibling of [`handle_fresh`](Self::handle_fresh): the
    /// wire entry point for the two EXECUTION commands (`Canary`/`Rollout`), which apply a
    /// user's fix to real targets. It mirrors `handle_fresh` exactly — capture the
    /// `(action_id, session, seq)` BEFORE the move, run the command through the ONE gated
    /// execution path, then map + sign the outcome with the SAME [`sign_outcome`](Self::sign_outcome)
    /// tail — but forwards to [`dispatch_execution_fresh`] with a held `Executor`/`Verifier`.
    ///
    /// Gate order (authn -> freshness -> authz -> run) is owned entirely by
    /// `dispatch_execution_fresh`: a forged, replayed, stale, or unauthorized execution
    /// command NEVER reaches the executor, so nothing is applied to any target. On success
    /// the returned [`StageOutcome`](torda_remediation::bridge::StageOutcome) (Promoted / Closed /
    /// RolledBack / AppliedUnverified) is reported in the result `detail`, so the issuer sees
    /// the stage's fate; on refusal the detail carries the gate's rejection reason.
    ///
    /// Like the lifecycle siblings it never panics: `dispatch_execution_fresh` is fail-closed
    /// and returns a `Result`, and signing is pure hex encoding over an always-serializable payload.
    pub fn execute_fresh<A: AuditSink>(
        &self,
        bridge: &mut Bridge<A>,
        guard: &mut ReplayGuard,
        cmd: ControlCommand,
        executor: &mut dyn Executor,
        verifier: &dyn Verifier,
    ) -> CommandResult {
        let action_id = cmd.action_id.clone();
        let session = cmd.session.clone();
        let seq = cmd.seq;
        // The ONLY execution path: authn -> freshness (guard) -> authz -> run the stage.
        let (outcome, detail) = match dispatch_execution_fresh(
            bridge,
            guard,
            cmd,
            self.verifier,
            self.authz,
            executor,
            verifier,
        ) {
            // The stage's fate (Promoted/Closed/RolledBack/AppliedUnverified) becomes the
            // result detail so the issuer learns exactly what the execution did.
            Ok(stage) => (CommandOutcome::Applied, format!("{stage:?}")),
            Err(e) => (CommandOutcome::Rejected, e.to_string()),
        };
        self.sign_outcome(action_id, session, seq, outcome, detail)
    }

    /// Map a lifecycle-dispatch `Result` to `(CommandOutcome, detail)`: Applied + `"applied"`
    /// on `Ok`, Rejected + the error text on `Err`. Shared by [`handle`](Self::handle) and
    /// [`handle_fresh`](Self::handle_fresh) so the lifecycle entry points cannot drift in how
    /// they report an outcome. (Execution reports the `StageOutcome` in its own detail.)
    fn classify(outcome: anyhow::Result<()>) -> (CommandOutcome, String) {
        match outcome {
            Ok(()) => (CommandOutcome::Applied, "applied".to_string()),
            Err(e) => (CommandOutcome::Rejected, e.to_string()),
        }
    }

    /// Shared result-building tail for [`handle`](Self::handle),
    /// [`handle_fresh`](Self::handle_fresh), and [`execute_fresh`](Self::execute_fresh): take
    /// the already-mapped `(outcome, detail)`, echo the command's `(session, seq)` freshness
    /// token, and sign the acknowledgment with the agent's own key. Factored out so every
    /// entry point signs an outcome identically — they differ ONLY in which dispatch they call
    /// and how they derive `detail`.
    fn sign_outcome(
        &self,
        action_id: String,
        session: String,
        seq: u64,
        outcome: CommandOutcome,
        detail: String,
    ) -> CommandResult {
        let mut result = CommandResult {
            action_id,
            outcome,
            detail,
            agent: self.signer.actor.clone(),
            session,
            seq,
            signature: String::new(),
        };
        result.signature = self.signer.sign_payload(&result.payload());
        result
    }
}

/// Issuer-side correlation + replay rejection for agent results. The issuer records
/// each (session, seq) it issued as outstanding; a result is accepted only if its
/// (session, seq) is outstanding-and-unconsumed AND its signature verifies under the
/// agent key; acceptance consumes it (a second identical result is rejected). This
/// defeats result-replay and the drop-and-substitute attack: a captured older result
/// whose (session, seq) was already consumed can never be re-accepted, and a still-
/// outstanding request stays unanswered until its OWN genuine result arrives.
#[derive(Default)]
pub struct ResultCorrelator {
    outstanding: HashSet<(String, u64)>,
}

impl ResultCorrelator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a command the issuer just sent as awaiting a result.
    pub fn issue(&mut self, session: &str, seq: u64) {
        self.outstanding.insert((session.into(), seq));
    }

    /// Accept `result` iff BOTH hold: (1) its (session, seq) is outstanding — i.e.
    /// issued and not yet consumed — AND (2) its signature verifies under the agent
    /// key. Acceptance CONSUMES the outstanding entry (a second identical result is
    /// then rejected). A forged result for an otherwise-outstanding (session, seq) is
    /// rejected WITHOUT consuming the entry, so the genuine result can still arrive.
    /// Order: outstanding is checked FIRST (cheap set lookup) then the signature, but
    /// both conditions must hold for acceptance and the entry is removed ONLY when both
    /// pass — a signature failure leaves the request outstanding.
    pub fn accept(&mut self, result: &CommandResult, verifier: &Ed25519Verifier) -> bool {
        let key = (result.session.clone(), result.seq);
        if !self.outstanding.contains(&key) {
            return false; // not outstanding / already consumed / stale
        }
        if !verifier.verify(&result.payload(), &result.signature, &result.agent) {
            return false; // forged/tampered — do NOT consume; genuine result may still come
        }
        self.outstanding.remove(&key); // consume
        true
    }
}

/// The single wire representation of everything that crosses the control channel.
///
/// The [`Transport`] seam moves opaque frames; this enum is the domain payload those
/// frames carry, serialized with `serde_json`. A `Command` travels operator -> agent
/// (a signed request to mutate the bridge) and a `Result` travels agent -> operator
/// (the agent's signed acknowledgment of a command's fate). Encoding a frame is
/// `serde_json::to_vec(&ControlFrame)` and decoding one is
/// `serde_json::from_slice(&bytes)`; the transport handles the length-framing, so a
/// caller passes/receives ONE whole serialized `ControlFrame` per `send`/`recv`.
///
/// The direction of a frame is meaningful and enforced: the agent loop treats a
/// `Result` arriving at the agent as wrong-direction and ignores it; the client treats
/// a `Command` arriving at the operator likewise. Neither ever panics on a frame it did
/// not expect.
#[derive(Serialize, Deserialize)]
pub enum ControlFrame {
    /// Operator -> agent: a signed command to run through the (replay-guarded) gate.
    Command(ControlCommand),
    /// Agent -> operator: the agent's signed acknowledgment of a command's outcome.
    Result(CommandResult),
}

/// The agent-side control channel driver: the SINGLE enforced entry point for wire
/// commands. It owns an [`AgentControlHandler`] and a [`ReplayGuard`], and drives them
/// over any [`Transport`]. Its command path is [`handle_fresh`](AgentControlHandler::handle_fresh)
/// -> [`dispatch_fresh`] ONLY — the plain, un-guarded `handle`/`dispatch` is NEVER
/// reached from the wire, so every command that crosses the transport is authenticated,
/// admitted through the replay guard, then authorized + lifecycle-gated. This is what
/// closes the P3b-5 advisory (a replay-guarded path existed but was not the wire path).
///
/// Sessions must be opened before commands on them are admitted (the guard is
/// fail-closed): construct with [`new`](Self::new) and call
/// [`open_session`](Self::open_session), or use [`with_session`](Self::with_session).
pub struct AgentControlLoop<'a> {
    handler: AgentControlHandler<'a>,
    guard: ReplayGuard,
    /// The orchestrator's target executor: consulted ONLY by
    /// [`execute_fresh`](AgentControlHandler::execute_fresh), and ONLY on a fully-gated
    /// execution command. Owned (boxed) so the loop can hand a `&mut` to the gate without
    /// entangling the borrow of `self.guard`.
    executor: Box<dyn Executor>,
    /// The orchestrator's re-score verifier (the Findings-Engine seam), consulted by the
    /// execution gate to decide promote/close vs roll-back. Owned (boxed) for the same
    /// borrow reason as `executor`.
    verifier: Box<dyn Verifier>,
    /// Holds SCHEDULED execution commands (a `Canary`/`Rollout` with a signed window)
    /// gate-validated at [`serve_one`](Self::serve_one) and released in-window by
    /// [`tick`](Self::tick). A separate field so `serve_one` can borrow it disjointly from
    /// `handler`/`guard`. The scheduler is the ONLY component that reads the injected
    /// `Clock`; the dispatch gates stay clock-free.
    scheduler: Scheduler,
}

impl<'a> AgentControlLoop<'a> {
    /// Build a loop around `handler` with an empty replay guard and a held orchestrator
    /// (`executor` + engine `verifier`). No session is open yet, so call
    /// [`open_session`](Self::open_session) for each session to be served before driving
    /// commands (the guard refuses an unopened session, fail-closed).
    pub fn new(
        handler: AgentControlHandler<'a>,
        executor: Box<dyn Executor>,
        verifier: Box<dyn Verifier>,
    ) -> Self {
        Self {
            handler,
            guard: ReplayGuard::new(),
            executor,
            verifier,
            scheduler: Scheduler::new(),
        }
    }

    /// Build a loop and open a single `session` in one step (admitting seq strictly
    /// greater than `from`; use `0` to accept seq >= 1). Convenience over
    /// `new(..).open_session(..)` for the common single-session case.
    pub fn with_session(
        handler: AgentControlHandler<'a>,
        session: &str,
        from: u64,
        executor: Box<dyn Executor>,
        verifier: Box<dyn Verifier>,
    ) -> Self {
        let mut me = Self::new(handler, executor, verifier);
        me.open_session(session, from);
        me
    }

    /// Open `session` for service, admitting commands whose seq is strictly greater than
    /// `from`. Re-opening a session resets its high-water mark (see [`ReplayGuard`]).
    pub fn open_session(&mut self, session: &str, from: u64) {
        self.guard.open_session(session, from);
    }

    /// Handle AT MOST ONE inbound frame from `transport`.
    ///
    /// Returns `Ok(false)` when there is nothing to do — `recv` yielded `None` (no
    /// buffered frame, or the peer has closed). Otherwise a frame was consumed and the
    /// method returns `Ok(true)`:
    /// - a `ControlFrame::Command` is run through
    ///   [`handle_fresh`](AgentControlHandler::handle_fresh) — the ONLY command path,
    ///   which is replay-guarded via [`dispatch_fresh`] — and the resulting signed
    ///   `ControlFrame::Result` is sent back on the same transport;
    /// - a `ControlFrame::Result` (wrong direction: a result should never arrive at the
    ///   agent) is IGNORED — the frame is consumed but the bridge is not mutated and no
    ///   panic occurs;
    /// - bytes that fail to decode as a `ControlFrame` (truncated/hostile input) are
    ///   likewise consumed and IGNORED — no panic, no bridge mutation.
    ///
    /// This is the enforced replay-guarded entry point: the plain `dispatch`/`handle`
    /// is unreachable from here, so no wire command can bypass the freshness gate.
    pub fn serve_one<A: AuditSink, T: Transport>(
        &mut self,
        transport: &mut T,
        bridge: &mut Bridge<A>,
        clock: &dyn Clock,
    ) -> std::io::Result<bool> {
        let Some(bytes) = transport.recv()? else {
            return Ok(false); // nothing buffered / peer closed
        };
        // Decode defensively: malformed or hostile bytes are consumed and ignored,
        // never panicked on and never allowed to touch the bridge.
        let frame: ControlFrame = match serde_json::from_slice(&bytes) {
            Ok(f) => f,
            Err(_) => return Ok(true), // frame consumed, ignored (no mutation)
        };
        match frame {
            ControlFrame::Command(cmd) => {
                // Route on kind, but ALL paths are replay-guarded through the SAME
                // `self.guard`, so replay/forgery/authz are gated identically:
                //  - SCHEDULED EXECUTION (Canary/Rollout WITH a signed window): ENQUEUE via
                //    the scheduler (gates run ONCE here — authn/freshness/authz — the seq is
                //    consumed now); the command fires later, in-window, from `tick`.
                //  - IMMEDIATE EXECUTION (Canary/Rollout, no window): execute_fresh ->
                //    dispatch_execution_fresh, exactly as P3b-8. The executor runs ONLY on a
                //    fully-gated command.
                //  - LIFECYCLE: handle_fresh -> dispatch_fresh, exactly as before. An Abort
                //    additionally drops any scheduled command for the action (kill switch).
                // The plain, un-guarded `dispatch`/`handle` is UNREACHABLE from the wire.
                let result = if cmd.kind.is_execution() {
                    if cmd.schedule.is_some() {
                        // Capture identity BEFORE the move; the result echoes (session, seq).
                        let action_id = cmd.action_id.clone();
                        let session = cmd.session.clone();
                        let seq = cmd.seq;
                        // Disjoint field borrows: scheduler (mut) + guard (mut) + the
                        // handler's verifier/authz (shared) are separate fields of `self`.
                        let (outcome, detail) = match self.scheduler.enqueue(
                            bridge,
                            &mut self.guard,
                            cmd,
                            self.handler.verifier,
                            self.handler.authz,
                            clock,
                        ) {
                            Ok(schedule) => (
                                CommandOutcome::Applied,
                                format!(
                                    "scheduled [{},{}]",
                                    schedule.not_before, schedule.not_after
                                ),
                            ),
                            Err(e) => (CommandOutcome::Rejected, e.to_string()),
                        };
                        self.handler
                            .sign_outcome(action_id, session, seq, outcome, detail)
                    } else {
                        self.handler.execute_fresh(
                            bridge,
                            &mut self.guard,
                            cmd,
                            self.executor.as_mut(),
                            self.verifier.as_ref(),
                        )
                    }
                } else {
                    // Capture whether this is an Abort (+ its action_id) BEFORE the move so
                    // the kill switch also drops any scheduled command for the action.
                    let abort_id = matches!(cmd.kind, CommandKind::Abort { .. })
                        .then(|| cmd.action_id.clone());
                    let result = self.handler.handle_fresh(bridge, &mut self.guard, cmd);
                    // Only an Abort that actually APPLIED (authenticated + authorized +
                    // lifecycle-valid) may cancel pending scheduled commands. A forged,
                    // unauthorized, or stale Abort is rejected by handle_fresh (bridge
                    // untouched) and MUST NOT touch the scheduler — otherwise one garbage-
                    // signed Abort frame could silently suppress a victim's scheduled
                    // remediation (a denial-of-remediation / unauthenticated mutation).
                    if let Some(id) = abort_id {
                        if result.outcome == CommandOutcome::Applied {
                            self.scheduler.cancel(bridge, &id);
                        }
                    }
                    result
                };
                let out = serde_json::to_vec(&ControlFrame::Result(result))
                    .map_err(std::io::Error::other)?;
                transport.send(&out)?;
                Ok(true)
            }
            // A result at the agent is wrong-direction: consume and ignore, never mutate.
            ControlFrame::Result(_) => Ok(true),
        }
    }

    /// Release every scheduled execution command whose window is now OPEN, on a still-valid
    /// action, using the loop's held executor + engine verifier. Drops (audited) any command
    /// whose window has passed WITHOUT firing (expired), and leaves not-yet-due commands
    /// pending. Returns `(action_id, StageOutcome)` for each command that fired. The agent
    /// calls this periodically with an advancing `Clock`; it is the ONLY reader of the clock.
    pub fn tick<A: AuditSink>(
        &mut self,
        bridge: &mut Bridge<A>,
        clock: &dyn Clock,
    ) -> Vec<(String, StageOutcome)> {
        self.scheduler.tick(
            bridge,
            clock,
            self.executor.as_mut(),
            self.verifier.as_ref(),
        )
    }
}

/// The operator-side control channel driver. It issues signed commands over a
/// [`Transport`] and accepts agent results ONLY through a [`ResultCorrelator`], so a
/// forged, stale, or replayed result can never be treated as a genuine acknowledgment.
/// It owns the issuer's [`CommandSigner`], the correlator, and a server-side
/// [`Ed25519Verifier`] that trusts the agent's key (used to authenticate results).
pub struct ControlPlaneClient {
    signer: CommandSigner,
    corr: ResultCorrelator,
    verifier: Ed25519Verifier,
}

impl ControlPlaneClient {
    /// Build a client from the issuer's `signer` and a `verifier` trusting the agent's
    /// key (under the agent's actor name), with a fresh correlator.
    pub fn new(signer: CommandSigner, verifier: Ed25519Verifier) -> Self {
        Self {
            signer,
            corr: ResultCorrelator::new(),
            verifier,
        }
    }

    /// Sign `cmd` in place with the issuer's key. Convenience for callers building a
    /// command to send; the wire path itself never signs — a command is authenticated
    /// by whatever signature it already carries when it reaches [`send_command`](Self::send_command).
    pub fn sign(&self, cmd: &mut ControlCommand) {
        self.signer.sign(cmd);
    }

    /// Record `cmd`'s `(session, seq)` as outstanding in the correlator, then send it as
    /// a `ControlFrame::Command`. Registering BEFORE sending is what lets
    /// [`await_result`](Self::await_result) later recognize the genuine reply; a result
    /// whose `(session, seq)` was never issued (or was already consumed) is refused.
    pub fn send_command<T: Transport>(
        &mut self,
        transport: &mut T,
        cmd: ControlCommand,
    ) -> std::io::Result<()> {
        self.corr.issue(&cmd.session, cmd.seq);
        let out = serde_json::to_vec(&ControlFrame::Command(cmd)).map_err(std::io::Error::other)?;
        transport.send(&out)
    }

    /// Receive AT MOST ONE frame and return a genuine agent result, or `None`.
    ///
    /// Returns `Ok(Some(result))` ONLY when the frame is a `ControlFrame::Result` that
    /// the [`ResultCorrelator`] accepts — i.e. its `(session, seq)` is outstanding AND
    /// its signature verifies under the trusted agent key; acceptance consumes the
    /// outstanding entry, so a replayed copy of that same result is refused on a later
    /// call. Returns `Ok(None)` for every other case — `recv` yielded nothing, a
    /// wrong-direction `Command` frame arrived at the operator, the correlator rejected
    /// the result (forged / stale / already-consumed), or the bytes were malformed.
    /// Never panics on hostile bytes.
    pub fn await_result<T: Transport>(
        &mut self,
        transport: &mut T,
    ) -> std::io::Result<Option<CommandResult>> {
        let Some(bytes) = transport.recv()? else {
            return Ok(None);
        };
        let frame: ControlFrame = match serde_json::from_slice(&bytes) {
            Ok(f) => f,
            Err(_) => return Ok(None), // malformed / hostile: ignored, no panic
        };
        match frame {
            ControlFrame::Result(r) if self.corr.accept(&r, &self.verifier) => Ok(Some(r)),
            // Wrong-direction Command, or a result the correlator refuses (forged /
            // stale / replayed): not a genuine acknowledgment.
            _ => Ok(None),
        }
    }
}

/// Derive a deterministic control-session id for `(peer, nonce)`.
///
/// STUB — deliberately deterministic and network-free. The real handshake binds the
/// session id to the mTLS peer certificate and a per-connection nonce so a session
/// cannot be spoofed or reused across connections; that is P3b-7. Until then this gives
/// tests and the in-memory transport a stable, reproducible session id with no clock,
/// randomness, or network involved.
pub fn establish_session(peer: &str, nonce: u64) -> String {
    format!("sess-{peer}-{nonce}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use torda_remediation::action::*;
    use torda_remediation::control::CommandKind;

    fn draft_cmd(actor: &str) -> ControlCommand {
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
        ControlCommand {
            action_id: "a".into(),
            kind: CommandKind::Draft(Box::new(action)),
            actor: actor.into(),
            session: "s1".into(),
            seq: 1,
            schedule: None,
            signature: String::new(),
        }
    }

    #[test]
    fn a_genuinely_signed_command_verifies() {
        let signer = CommandSigner::from_seed("secops", [7u8; 32]);
        let mut v = Ed25519Verifier::new();
        v.trust("secops", signer.verifying_key());
        let mut cmd = draft_cmd("secops");
        signer.sign(&mut cmd);
        assert!(
            v.verify(&cmd.payload(), &cmd.signature, &cmd.actor),
            "authentic ed25519 signature accepted"
        );
    }

    #[test]
    fn tampering_the_payload_breaks_verification() {
        let signer = CommandSigner::from_seed("secops", [7u8; 32]);
        let mut v = Ed25519Verifier::new();
        v.trust("secops", signer.verifying_key());
        let mut cmd = draft_cmd("secops");
        signer.sign(&mut cmd);
        // Verify over a DIFFERENT payload than what was signed -> cryptographic mismatch.
        assert!(!v.verify("tampered payload", &cmd.signature, "secops"));
    }

    #[test]
    fn a_signature_from_an_untrusted_key_is_rejected() {
        let real = CommandSigner::from_seed("secops", [7u8; 32]);
        let attacker = CommandSigner::from_seed("secops", [9u8; 32]); // different key, same claimed actor
        let mut v = Ed25519Verifier::new();
        v.trust("secops", real.verifying_key()); // trust ONLY the real key
        let mut cmd = draft_cmd("secops");
        attacker.sign(&mut cmd); // signed by the attacker's key
        assert!(
            !v.verify(&cmd.payload(), &cmd.signature, &cmd.actor),
            "wrong key rejected"
        );
    }

    #[test]
    fn unknown_actor_and_malformed_signature_return_false_not_panic() {
        let signer = CommandSigner::from_seed("secops", [7u8; 32]);
        let mut v = Ed25519Verifier::new();
        v.trust("secops", signer.verifying_key());
        // Unknown actor.
        assert!(!v.verify("p", "deadbeef", "nobody"));
        // Malformed hex.
        assert!(!v.verify("p", "not-hex-zz", "secops"));
        // Valid hex, wrong length for an ed25519 signature.
        assert!(!v.verify("p", "abcd", "secops"));
    }

    // --- Multi-key trust store: rotation overlap + revocation (P3b-10) ---

    #[test]
    fn single_trusted_key_behaves_as_before() {
        // Parity with the old one-key behavior: trust one key, a command it signed
        // verifies; a different (untrusted) key's signature verifies false.
        let signer = CommandSigner::from_seed("alice", [1u8; 32]);
        let other = CommandSigner::from_seed("alice", [2u8; 32]); // untrusted key
        let mut v = Ed25519Verifier::new();
        v.trust("alice", signer.verifying_key());

        let mut cmd = draft_cmd("alice");
        signer.sign(&mut cmd);
        assert!(
            v.verify(&cmd.payload(), &cmd.signature, "alice"),
            "trusted single key verifies"
        );

        let mut forged = draft_cmd("alice");
        other.sign(&mut forged);
        assert!(
            !v.verify(&forged.payload(), &forged.signature, "alice"),
            "untrusted key rejected"
        );
    }

    #[test]
    fn two_trusted_keys_either_verifies() {
        // A rotation overlap: alice is trusted under k1 AND k2 at once, so a command
        // signed by EITHER verifies.
        let k1 = CommandSigner::from_seed("alice", [1u8; 32]);
        let k2 = CommandSigner::from_seed("alice", [2u8; 32]);
        let mut v = Ed25519Verifier::new();
        v.trust("alice", k1.verifying_key());
        v.trust("alice", k2.verifying_key());

        let mut c1 = draft_cmd("alice");
        k1.sign(&mut c1);
        assert!(
            v.verify(&c1.payload(), &c1.signature, "alice"),
            "k1-signed command verifies"
        );

        let mut c2 = draft_cmd("alice");
        k2.sign(&mut c2);
        assert!(
            v.verify(&c2.payload(), &c2.signature, "alice"),
            "k2-signed command verifies"
        );
    }

    #[test]
    fn revoking_a_key_rejects_only_that_key() {
        // Trust k1+k2, revoke k1: a k1-signed command now fails, a k2-signed one still passes.
        let k1 = CommandSigner::from_seed("alice", [1u8; 32]);
        let k2 = CommandSigner::from_seed("alice", [2u8; 32]);
        let mut v = Ed25519Verifier::new();
        v.trust("alice", k1.verifying_key());
        v.trust("alice", k2.verifying_key());

        v.revoke("alice", &k1.verifying_key());

        let mut c1 = draft_cmd("alice");
        k1.sign(&mut c1);
        assert!(
            !v.verify(&c1.payload(), &c1.signature, "alice"),
            "revoked k1 can no longer verify"
        );

        let mut c2 = draft_cmd("alice");
        k2.sign(&mut c2);
        assert!(
            v.verify(&c2.payload(), &c2.signature, "alice"),
            "surviving k2 still verifies"
        );
    }

    #[test]
    fn revoke_actor_rejects_everything() {
        // Offboarding: revoke ALL of alice's keys; both k1 and k2 now fail-closed.
        let k1 = CommandSigner::from_seed("alice", [1u8; 32]);
        let k2 = CommandSigner::from_seed("alice", [2u8; 32]);
        let mut v = Ed25519Verifier::new();
        v.trust("alice", k1.verifying_key());
        v.trust("alice", k2.verifying_key());

        v.revoke_actor("alice");

        let mut c1 = draft_cmd("alice");
        k1.sign(&mut c1);
        let mut c2 = draft_cmd("alice");
        k2.sign(&mut c2);
        assert!(
            !v.verify(&c1.payload(), &c1.signature, "alice"),
            "no key verifies after revoke_actor"
        );
        assert!(
            !v.verify(&c2.payload(), &c2.signature, "alice"),
            "no key verifies after revoke_actor"
        );
    }

    #[test]
    fn trusting_the_same_key_twice_is_idempotent() {
        // Dedup proof: trusting k1 twice then revoking it once fully removes it — there
        // is no lingering duplicate that would keep verifying.
        let k1 = CommandSigner::from_seed("alice", [1u8; 32]);
        let mut v = Ed25519Verifier::new();
        v.trust("alice", k1.verifying_key());
        v.trust("alice", k1.verifying_key()); // idempotent: no second entry

        v.revoke("alice", &k1.verifying_key()); // single revoke removes it entirely

        let mut c1 = draft_cmd("alice");
        k1.sign(&mut c1);
        assert!(
            !v.verify(&c1.payload(), &c1.signature, "alice"),
            "one revoke suffices — no duplicate lingered"
        );
    }

    #[test]
    fn unknown_actor_and_malformed_signature_still_fail_closed() {
        // Multi-key store keeps the old fail-closed guarantees: unknown actor, bad hex,
        // and wrong-length signatures all return false without panicking.
        let signer = CommandSigner::from_seed("alice", [1u8; 32]);
        let mut v = Ed25519Verifier::new();
        v.trust("alice", signer.verifying_key());
        assert!(
            !v.verify("p", "deadbeef", "nobody"),
            "unknown actor rejected"
        );
        assert!(
            !v.verify("p", "not-hex-zz", "alice"),
            "malformed hex rejected"
        );
        assert!(
            !v.verify("p", "abcd", "alice"),
            "wrong-length signature rejected"
        );
    }

    // --- ReloadableVerifier: atomic + fail-safe hot-reload of the trust store (P3b-12) ---

    /// A unique temp directory that removes itself on drop (best-effort). Mirrors the
    /// P3b-10 key_management_vectors helper: pid + nanosecond timestamp + a caller tag
    /// makes the path unique without adding an rng dependency.
    struct ReloadTempDir(std::path::PathBuf);
    impl ReloadTempDir {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let dir = std::env::temp_dir()
                .join(format!("torda-reload-{tag}-{}-{nanos}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("create unique temp dir");
            Self(dir)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
        /// Write `<stem>.pub` holding one hex public-key line for `signer` (actor = stem).
        fn write_pub(&self, stem: &str, signer: &CommandSigner) {
            let hexline = format!("{}\n", hex::encode(signer.verifying_key().to_bytes()));
            std::fs::write(self.0.join(format!("{stem}.pub")), hexline)
                .expect("write pub key file");
        }
        /// Remove `<stem>.pub` from the directory.
        fn remove_pub(&self, stem: &str) {
            let _ = std::fs::remove_file(self.0.join(format!("{stem}.pub")));
        }
    }
    impl Drop for ReloadTempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn reload_picks_up_a_revocation_with_no_restart() {
        // Trust alice; a command she signs verifies TRUE on the running verifier.
        let alice = CommandSigner::from_seed("alice", [1u8; 32]);
        let dir = ReloadTempDir::new("revocation");
        dir.write_pub("alice", &alice);

        let v = ReloadableVerifier::new(
            Ed25519Verifier::load_trust_dir(dir.path()).expect("initial trust load"),
        );
        let mut cmd = draft_cmd("alice");
        alice.sign(&mut cmd);
        assert!(
            v.verify(&cmd.payload(), &cmd.signature, "alice"),
            "alice trusted before reload"
        );

        // Rewrite the trust dir to REMOVE alice's key, then hot-reload on the SAME verifier
        // (no reconstruction). The very same alice-signed command must now be REJECTED —
        // proving the revocation took effect on a running verifier with no restart.
        dir.remove_pub("alice");
        v.reload_from_dir(dir.path())
            .expect("reload of an empty-but-valid dir succeeds");
        assert!(
            !v.verify(&cmd.payload(), &cmd.signature, "alice"),
            "revocation applied live: alice no longer verifies after reload, no restart"
        );
    }

    #[test]
    fn reload_picks_up_a_new_key_rotation() {
        // Start trusting only k1; a k2-signed command is FALSE.
        let k1 = CommandSigner::from_seed("alice", [1u8; 32]);
        let k2 = CommandSigner::from_seed("alice", [2u8; 32]);
        let dir = ReloadTempDir::new("rotation");
        dir.write_pub("alice", &k1);

        let v = ReloadableVerifier::new(
            Ed25519Verifier::load_trust_dir(dir.path()).expect("initial trust load"),
        );
        let mut c2 = draft_cmd("alice");
        k2.sign(&mut c2);
        assert!(
            !v.verify(&c2.payload(), &c2.signature, "alice"),
            "k2 untrusted before rotation"
        );

        // Rewrite the dir so alice's file lists BOTH k1 and k2 (a rotation overlap), reload.
        let both = format!(
            "{}\n{}\n",
            hex::encode(k1.verifying_key().to_bytes()),
            hex::encode(k2.verifying_key().to_bytes())
        );
        std::fs::write(dir.path().join("alice.pub"), both)
            .expect("rewrite alice.pub with both keys");
        v.reload_from_dir(dir.path())
            .expect("reload with the new key succeeds");
        assert!(
            v.verify(&c2.payload(), &c2.signature, "alice"),
            "k2 verifies after the rotation reload"
        );
        // And k1 still verifies (overlap), proving an additive rotation, not a swap-out.
        let mut c1 = draft_cmd("alice");
        k1.sign(&mut c1);
        assert!(
            v.verify(&c1.payload(), &c1.signature, "alice"),
            "k1 still verifies during the overlap"
        );
    }

    #[test]
    fn a_failed_reload_is_fail_safe_current_trust_intact() {
        // Trust alice; she verifies TRUE.
        let alice = CommandSigner::from_seed("alice", [1u8; 32]);
        let dir = ReloadTempDir::new("failsafe");
        dir.write_pub("alice", &alice);
        let v = ReloadableVerifier::new(
            Ed25519Verifier::load_trust_dir(dir.path()).expect("initial trust load"),
        );
        let mut cmd = draft_cmd("alice");
        alice.sign(&mut cmd);
        assert!(
            v.verify(&cmd.payload(), &cmd.signature, "alice"),
            "alice trusted before the bad reload"
        );

        // A reload from a MISSING directory must fail...
        let missing = dir.path().join("does-not-exist");
        let err = v.reload_from_dir(&missing);
        assert!(err.is_err(), "reload from a missing dir returns Err");

        // ...and a reload from a dir holding a MALFORMED key file must also fail.
        let bad = ReloadTempDir::new("failsafe-bad");
        std::fs::write(bad.path().join("alice.pub"), "zz-not-hex\n")
            .expect("write garbage key file");
        assert!(
            v.reload_from_dir(bad.path()).is_err(),
            "reload from a garbage key file returns Err"
        );

        // FAIL-SAFE: after BOTH failed reloads the live store is UNCHANGED — alice STILL
        // verifies. A bad reload never disarmed the agent (never dropped to zero-trust).
        assert!(
            v.verify(&cmd.payload(), &cmd.signature, "alice"),
            "current trust intact after failed reloads: alice still verifies"
        );
    }

    #[test]
    fn empty_trust_dir_reload_semantics() {
        // Ed25519Verifier::load_trust_dir returns Ok(empty) for a dir with no key files
        // (see key_management_vectors::unknown_actor_and_missing_key_fail_closed). So a
        // reload from an empty dir SUCCEEDS and installs a trust-NOTHING store — an
        // intentional, fail-closed "revoke everyone". We assert that documented behavior:
        // the reload is Ok and afterwards nothing verifies.
        let alice = CommandSigner::from_seed("alice", [1u8; 32]);
        let dir = ReloadTempDir::new("empty-start");
        dir.write_pub("alice", &alice);
        let v = ReloadableVerifier::new(
            Ed25519Verifier::load_trust_dir(dir.path()).expect("initial trust load"),
        );
        let mut cmd = draft_cmd("alice");
        alice.sign(&mut cmd);
        assert!(
            v.verify(&cmd.payload(), &cmd.signature, "alice"),
            "alice trusted initially"
        );

        // Reload from a dir that contains NO key files -> Ok(empty), revoke-everyone.
        let empty = ReloadTempDir::new("empty-dir");
        v.reload_from_dir(empty.path())
            .expect("empty dir loads Ok (revoke everyone)");
        assert!(
            !v.verify(&cmd.payload(), &cmd.signature, "alice"),
            "empty-dir reload succeeds and now nothing verifies (intentional fail-closed revoke-all)"
        );
    }

    #[test]
    fn poisoned_lock_verify_fails_closed() {
        // Poison the RwLock by panicking while holding the WRITE lock, then assert `verify`
        // returns false (fail-closed) instead of panicking on the poisoned lock.
        let alice = CommandSigner::from_seed("alice", [1u8; 32]);
        let mut inner = Ed25519Verifier::new();
        inner.trust("alice", alice.verifying_key());
        let v = std::sync::Arc::new(ReloadableVerifier::new(inner));
        let mut cmd = draft_cmd("alice");
        alice.sign(&mut cmd);
        assert!(
            v.verify(&cmd.payload(), &cmd.signature, "alice"),
            "alice trusted before poison"
        );

        // Poison the lock: take the write lock in another thread and panic while holding it.
        let v2 = std::sync::Arc::clone(&v);
        let _ = std::thread::spawn(move || {
            let _guard = v2.inner.write().expect("acquire write lock to poison");
            panic!("intentionally poison the lock");
        })
        .join(); // join swallows the panic; the lock is now poisoned

        // verify must FAIL CLOSED on the poisoned lock, not panic.
        assert!(
            !v.verify(&cmd.payload(), &cmd.signature, "alice"),
            "verify fails closed (false) on a poisoned lock instead of panicking"
        );
    }

    // --- Return-leg (AgentControlHandler / CommandResult) tests ---
    use torda_remediation::audit::VecAuditSink;
    use torda_remediation::control::{AllowAll, Role, RolePolicy};

    /// The agent's own signer (distinct key from any command issuer).
    fn agent_signer() -> CommandSigner {
        CommandSigner::from_seed("agent-1", [42u8; 32])
    }

    /// A `Ed25519Verifier` a "server" uses to authenticate the agent's returned
    /// acknowledgment: it trusts the agent's key under the agent's actor name.
    fn server_trusting(agent: &CommandSigner) -> Ed25519Verifier {
        let mut v = Ed25519Verifier::new();
        v.trust(&agent.actor, agent.verifying_key());
        v
    }

    /// Build an unsigned control command for `kind` from `actor`.
    fn command(action_id: &str, kind: CommandKind, actor: &str) -> ControlCommand {
        ControlCommand {
            action_id: action_id.into(),
            kind,
            actor: actor.into(),
            session: "s1".into(),
            seq: 1,
            schedule: None,
            signature: String::new(),
        }
    }

    #[test]
    fn authorized_command_yields_applied_signed_result() {
        // Operator signs a valid Draft; verifier trusts the operator's key.
        let operator = CommandSigner::from_seed("operator", [7u8; 32]);
        let mut verifier = Ed25519Verifier::new();
        verifier.trust(&operator.actor, operator.verifying_key());
        let mut cmd = draft_cmd("operator");
        operator.sign(&mut cmd);

        let agent = agent_signer();
        let handler = AgentControlHandler::new(&verifier, &AllowAll, &agent);
        let mut bridge = Bridge::new(VecAuditSink::default());

        let result = handler.handle(&mut bridge, cmd);

        assert_eq!(result.outcome, CommandOutcome::Applied);
        assert_eq!(result.detail, "applied");
        assert_eq!(result.action_id, "a");
        assert_eq!(result.agent, "agent-1");
        assert_eq!(
            bridge.state("a"),
            Some(ActionState::Drafted),
            "the gated draft was applied"
        );

        // The result is authentically signed by the AGENT's key: a server that
        // trusts that key under `result.agent` verifies the acknowledgment.
        let server = server_trusting(&agent);
        assert!(
            server.verify(&result.payload(), &result.signature, &result.agent),
            "agent-signed result verifies"
        );
    }

    #[test]
    fn forged_command_yields_rejected_result() {
        // Command signed by an UNTRUSTED key (verifier trusts a different key).
        let real = CommandSigner::from_seed("operator", [7u8; 32]);
        let attacker = CommandSigner::from_seed("operator", [9u8; 32]);
        let mut verifier = Ed25519Verifier::new();
        verifier.trust(&real.actor, real.verifying_key()); // trust ONLY the real key
        let mut cmd = draft_cmd("operator");
        attacker.sign(&mut cmd); // forged

        let agent = agent_signer();
        let handler = AgentControlHandler::new(&verifier, &AllowAll, &agent);
        let mut bridge = Bridge::new(VecAuditSink::default());

        let result = handler.handle(&mut bridge, cmd);

        assert_eq!(result.outcome, CommandOutcome::Rejected);
        assert!(
            result.detail.contains("signature"),
            "rejection detail names the signature failure"
        );
        assert_eq!(
            bridge.state("a"),
            None,
            "the forged command never reached the bridge"
        );

        // Even a rejection is an AUTHENTIC acknowledgment: the agent signs it, so the
        // issuer can trust the reported outcome and detect tampering.
        let server = server_trusting(&agent);
        assert!(
            server.verify(&result.payload(), &result.signature, &result.agent),
            "rejected result is still agent-signed"
        );
    }

    #[test]
    fn unauthorized_actor_yields_rejected_result() {
        // Valid signature, but the role policy denies the actor for this kind: an
        // Operator may not Approve (separation of duties).
        let operator = CommandSigner::from_seed("operator", [7u8; 32]);
        let mut verifier = Ed25519Verifier::new();
        verifier.trust(&operator.actor, operator.verifying_key());
        let mut policy = RolePolicy::new();
        policy.assign("operator", Role::Operator);
        let mut cmd = command("a", CommandKind::Approve, "operator");
        operator.sign(&mut cmd); // authentic signature

        let agent = agent_signer();
        let handler = AgentControlHandler::new(&verifier, &policy, &agent);
        let mut bridge = Bridge::new(VecAuditSink::default());

        let result = handler.handle(&mut bridge, cmd);

        assert_eq!(
            result.outcome,
            CommandOutcome::Rejected,
            "authenticated but unauthorized"
        );
        assert!(
            result.detail.contains("not authorized"),
            "rejection detail names the authorization failure"
        );
        let server = server_trusting(&agent);
        assert!(server.verify(&result.payload(), &result.signature, &result.agent));
    }

    #[test]
    fn lifecycle_violation_yields_rejected_result() {
        // Authorized + authentic Submit, but on an action that was never drafted:
        // the bridge's lifecycle gate refuses it.
        let operator = CommandSigner::from_seed("operator", [7u8; 32]);
        let mut verifier = Ed25519Verifier::new();
        verifier.trust(&operator.actor, operator.verifying_key());
        let mut policy = RolePolicy::new();
        policy.assign("operator", Role::Operator); // Operator MAY Submit
        let mut cmd = command("ghost", CommandKind::Submit, "operator");
        operator.sign(&mut cmd);

        let agent = agent_signer();
        let handler = AgentControlHandler::new(&verifier, &policy, &agent);
        let mut bridge = Bridge::new(VecAuditSink::default());

        let result = handler.handle(&mut bridge, cmd);

        assert_eq!(
            result.outcome,
            CommandOutcome::Rejected,
            "lifecycle gate refuses a submit on an undrafted action"
        );
        assert_eq!(bridge.state("ghost"), None);
        let server = server_trusting(&agent);
        assert!(server.verify(&result.payload(), &result.signature, &result.agent));
    }

    #[test]
    fn rejected_result_leaves_bridge_state_untouched() {
        // First legitimately draft "a" so there is real state to protect.
        let operator = CommandSigner::from_seed("operator", [7u8; 32]);
        let mut verifier = Ed25519Verifier::new();
        verifier.trust(&operator.actor, operator.verifying_key());
        let agent = agent_signer();
        let handler = AgentControlHandler::new(&verifier, &AllowAll, &agent);
        let mut bridge = Bridge::new(VecAuditSink::default());
        let mut draft = draft_cmd("operator");
        operator.sign(&mut draft);
        handler.handle(&mut bridge, draft);
        let before = bridge.state("a");
        assert_eq!(before, Some(ActionState::Drafted));

        // Now a forged command targeting "a" is rejected and must not mutate state.
        let attacker = CommandSigner::from_seed("operator", [9u8; 32]);
        let mut forged = command("a", CommandKind::Approve, "operator");
        attacker.sign(&mut forged);
        let result = handler.handle(&mut bridge, forged);

        assert_eq!(result.outcome, CommandOutcome::Rejected);
        // The bridge-untouched-on-reject property is inherited from `dispatch`
        // (a rejected command never invokes a state-changing bridge method); we
        // observe it via the state accessor being identical before and after.
        assert_eq!(
            bridge.state("a"),
            before,
            "rejected command left the action state unchanged"
        );
    }

    #[test]
    fn lifecycle_refused_command_leaves_real_prior_state_untouched() {
        use torda_remediation::bridge::Executor;

        /// Preview-only executor, used only to advance an action into DryRun during
        /// setup (dry-run is side-effect-free; apply/rollback are never called here).
        struct PreviewOnly;
        impl Executor for PreviewOnly {
            fn preview(&self, _a: &RemediationAction) -> String {
                "preview".into()
            }
            fn apply(&mut self, _a: &RemediationAction, _t: &str) -> anyhow::Result<()> {
                Ok(())
            }
            fn rollback(&mut self, _a: &RemediationAction, _t: &str) -> anyhow::Result<()> {
                Ok(())
            }
        }

        // Draft "a" and advance it to a real, DEFINITE state: DryRun.
        let scoped = RemediationAction {
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
        let mut bridge = Bridge::new(VecAuditSink::default());
        bridge.draft(scoped, "operator").unwrap();
        bridge.dry_run("a", &PreviewOnly, "operator").unwrap();
        let before = bridge.state("a");
        assert_eq!(
            before,
            Some(ActionState::DryRun),
            "action sits in a real, non-None prior state"
        );

        // An authentic + AUTHORIZED Approve (an Approver MAY approve), but the bridge
        // lifecycle guard refuses Approve from DryRun: `approve` is guarded to only
        // [PendingApproval] -> Approved, so DryRun -> Approved is an illegal transition.
        // Thus the ONLY thing that refuses this command is the lifecycle gate.
        let approver = CommandSigner::from_seed("approver", [11u8; 32]);
        let mut verifier = Ed25519Verifier::new();
        verifier.trust(&approver.actor, approver.verifying_key());
        let mut policy = RolePolicy::new();
        policy.assign("approver", Role::Approver); // authorized for Approve
        let mut cmd = command("a", CommandKind::Approve, "approver");
        approver.sign(&mut cmd); // authentic signature

        let agent = agent_signer();
        let handler = AgentControlHandler::new(&verifier, &policy, &agent);
        let result = handler.handle(&mut bridge, cmd);

        assert_eq!(
            result.outcome,
            CommandOutcome::Rejected,
            "the lifecycle guard refuses Approve from DryRun"
        );
        // The command PASSED authn + authz and REACHED the bridge, yet the genuine
        // prior state is intact — a lifecycle-refused command mutates nothing.
        assert_eq!(
            bridge.state("a"),
            before,
            "real prior DryRun state left untouched by the refused command"
        );
        let server = server_trusting(&agent);
        assert!(
            server.verify(&result.payload(), &result.signature, &result.agent),
            "the rejection is still agent-signed"
        );
    }

    #[test]
    fn result_payload_excludes_signature() {
        let base = CommandResult {
            action_id: "a".into(),
            outcome: CommandOutcome::Applied,
            detail: "applied".into(),
            agent: "agent-1".into(),
            session: "s1".into(),
            seq: 1,
            signature: "aaaa".into(),
        };
        let other = CommandResult {
            signature: "bbbb".into(),
            ..base.clone()
        };
        // Identical except `signature` -> identical canonical payload.
        assert_eq!(
            base.payload(),
            other.payload(),
            "the signature field is NOT part of the signed payload"
        );
        assert!(!base.payload().contains("aaaa"));
        // The freshness token IS part of the signed payload now.
        assert!(
            base.payload().contains("\"session\":\"s1\""),
            "session is bound by the result signature"
        );
        assert!(
            base.payload().contains("\"seq\":1"),
            "seq is bound by the result signature"
        );
    }

    #[test]
    fn mutating_session_or_seq_breaks_result_verification() {
        // Real ed25519: sign a result, then bump seq / rewrite session WITHOUT
        // re-signing, and assert the real verifier rejects the mutated payload.
        let agent = agent_signer();
        let server = server_trusting(&agent);
        let mut result = CommandResult {
            action_id: "a".into(),
            outcome: CommandOutcome::Applied,
            detail: "applied".into(),
            agent: agent.actor.clone(),
            session: "sess-1".into(),
            seq: 5,
            signature: String::new(),
        };
        result.signature = agent.sign_payload(&result.payload());
        // Sanity: the untouched, genuine result verifies.
        assert!(
            server.verify(&result.payload(), &result.signature, &result.agent),
            "genuine result verifies"
        );

        // Bump `seq` keeping the original signature -> real ed25519 check fails.
        let mut bumped_seq = result.clone();
        bumped_seq.seq = 6;
        assert!(
            !server.verify(
                &bumped_seq.payload(),
                &bumped_seq.signature,
                &bumped_seq.agent
            ),
            "bumping seq without re-signing fails real ed25519 verification"
        );

        // Rewrite `session` keeping the original signature -> real ed25519 check fails.
        let mut new_session = result.clone();
        new_session.session = "sess-2".into();
        assert!(
            !server.verify(
                &new_session.payload(),
                &new_session.signature,
                &new_session.agent
            ),
            "rewriting session without re-signing fails real ed25519 verification"
        );
    }

    #[test]
    fn result_echoes_command_session_and_seq() {
        // The result must carry the SAME (session, seq) as the command it answers.
        let operator = CommandSigner::from_seed("operator", [7u8; 32]);
        let mut verifier = Ed25519Verifier::new();
        verifier.trust(&operator.actor, operator.verifying_key());
        let mut cmd = draft_cmd("operator");
        cmd.session = "sess-echo".into();
        cmd.seq = 99;
        operator.sign(&mut cmd);
        let expected_session = cmd.session.clone();
        let expected_seq = cmd.seq;

        let agent = agent_signer();
        let handler = AgentControlHandler::new(&verifier, &AllowAll, &agent);
        let mut bridge = Bridge::new(VecAuditSink::default());
        let result = handler.handle(&mut bridge, cmd);

        assert_eq!(
            result.session, expected_session,
            "result echoes the command's session"
        );
        assert_eq!(result.seq, expected_seq, "result echoes the command's seq");
    }
}
