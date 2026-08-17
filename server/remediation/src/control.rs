//! The signed control-command gate. Every remediation command arrives as a
//! `ControlCommand` carrying a signature; the gate verifies the signature FIRST
//! and only then invokes the corresponding (already-gated) `Bridge` method. A
//! forged or unsigned command never reaches the bridge and is audited as rejected.
//! Signature verification is a seam — real ed25519 over the mTLS control channel
//! is the P3b control plane; here it is injected.
use crate::action::RemediationAction;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Verifies that `signature` authentically signs `payload` for `actor`. Stubbed
/// here (tests inject valid/forged); P3b supplies real ed25519 over mTLS.
pub trait SignatureVerifier {
    fn verify(&self, payload: &str, signature: &str, actor: &str) -> bool;
}

/// Decides whether an (authenticated) actor may issue a given command. A valid
/// signature proves WHO the actor is (authentication); this decides WHETHER they
/// are permitted (authorization). Checked AFTER the signature, BEFORE the bridge op.
pub trait Authorizer {
    fn authorized(&self, actor: &str, kind: &CommandKind) -> bool;
}

/// Authorizes everything — for contexts that gate on signature alone (tests that
/// exercise authentication, not authorization).
pub struct AllowAll;
impl Authorizer for AllowAll {
    fn authorized(&self, _actor: &str, _kind: &CommandKind) -> bool {
        true
    }
}

/// A control-plane role. Capabilities enforce separation of duties: the actor who
/// authors/submits an action cannot be the one who approves it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Authors and submits actions for approval.
    Operator,
    /// Approves or rejects pending actions (cannot author).
    Approver,
    /// Incident response: the kill switch.
    Responder,
    /// All commands.
    Admin,
}

impl Role {
    /// Whether this role may issue the given command.
    fn permits(&self, kind: &CommandKind) -> bool {
        match self {
            Role::Admin => true,
            // The change owner authors/submits AND drives their own approved change
            // through execution (Canary/Rollout). Four-eyes is preserved on the
            // APPROVAL gate (author != approver), not on execution by the owner.
            Role::Operator => matches!(
                kind,
                CommandKind::Draft(_)
                    | CommandKind::Submit
                    | CommandKind::Canary
                    | CommandKind::Rollout
            ),
            Role::Approver => matches!(kind, CommandKind::Approve | CommandKind::Reject { .. }),
            Role::Responder => matches!(kind, CommandKind::Abort { .. }),
        }
    }
}

/// Maps actors to roles and authorizes commands accordingly. An actor with no
/// assigned role is denied everything (fail-closed).
#[derive(Default)]
pub struct RolePolicy {
    roles: HashMap<String, Role>,
}

impl RolePolicy {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn assign(&mut self, actor: &str, role: Role) {
        self.roles.insert(actor.to_string(), role);
    }
}

impl Authorizer for RolePolicy {
    fn authorized(&self, actor: &str, kind: &CommandKind) -> bool {
        self.roles.get(actor).is_some_and(|r| r.permits(kind))
    }
}

use crate::audit::AuditSink;
use crate::bridge::{Bridge, Executor, StageOutcome, Verifier};

/// The bridge operations that arrive as signed control commands. The five lifecycle
/// commands (Draft/Submit/Approve/Reject/Abort) need no executor and route through
/// `dispatch`. The two EXECUTION commands (`Canary`/`Rollout`) apply the user's fix
/// to real targets and require an `Executor`/`Verifier`; they route only through
/// `dispatch_execution_fresh`. `dispatch` refuses them (defense in depth).
#[derive(Serialize, Deserialize)]
pub enum CommandKind {
    Draft(Box<RemediationAction>),
    Submit,
    Approve,
    Reject {
        reason: String,
    },
    Abort {
        reason: String,
    },
    /// Run the canary cohort of an approved action (execution — needs an executor).
    Canary,
    /// Run the staged rollout of a promoted action (execution — needs an executor).
    Rollout,
}

impl CommandKind {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            CommandKind::Draft(_) => "Draft",
            CommandKind::Submit => "Submit",
            CommandKind::Approve => "Approve",
            CommandKind::Reject { .. } => "Reject",
            CommandKind::Abort { .. } => "Abort",
            CommandKind::Canary => "Canary",
            CommandKind::Rollout => "Rollout",
        }
    }

    /// True for the two EXECUTION commands (`Canary`/`Rollout`) that apply a user's fix
    /// to real targets and therefore MUST route through [`dispatch_execution_fresh`]
    /// (with an `Executor`/`Verifier`), never plain `dispatch`. The wire loop uses this
    /// to send execution frames down the guarded orchestrator path and every lifecycle
    /// command down `dispatch_fresh`.
    pub fn is_execution(&self) -> bool {
        matches!(self, CommandKind::Canary | CommandKind::Rollout)
    }
}

/// An execution window in logical clock units (see `Clock`). Bound by the command
/// signature (folded into `payload()`), so the window cannot be tampered after signing.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Schedule {
    pub not_before: u64,
    pub not_after: u64,
}

/// A remediation command over the control channel: an intended bridge operation
/// bound to an `action_id` and `actor`, plus the `signature` that authenticates it.
#[derive(Serialize, Deserialize)]
pub struct ControlCommand {
    pub action_id: String,
    pub kind: CommandKind,
    pub actor: String,
    /// Per-session freshness token (part 1): identifies the control session this
    /// command belongs to. Bound by `signature` (folded into `payload()`), so a
    /// replay guard in a later slice can trust it — an attacker cannot strip or
    /// rewrite it without breaking the signature. No guard consumes it yet.
    pub session: String,
    /// Per-session freshness token (part 2): a monotonically-increasing sequence
    /// number within `session`. Bound by `signature` (folded into `payload()`) for
    /// the same reason as `session`. No guard consumes it yet.
    pub seq: u64,
    /// Optional signed execution window. `None` = execute immediately (today's
    /// behavior); `Some(Schedule)` = the command is only valid within the window.
    /// Bound by `signature` (folded into `payload()`), so an attacker cannot add,
    /// remove, or move the window without breaking the signature. The `Scheduler`
    /// (a later slice) is the only consumer; `dispatch`/gates stay clock-free.
    pub schedule: Option<Schedule>,
    pub signature: String,
}

impl ControlCommand {
    /// The canonical string a signature is computed over: a deterministic
    /// serialization of the UNSIGNED command (action_id, kind — including the full
    /// Draft action body and any reason — actor, and the `(session, seq)` freshness
    /// token) and the optional execution window. The `signature` field is excluded.
    /// Tampering with any bound field — including `session`, `seq`, or `schedule` —
    /// changes this payload and thus invalidates the signature. (A stricter canonical
    /// encoding lands with real crypto in P3b-2.)
    pub fn payload(&self) -> String {
        #[derive(serde::Serialize)]
        struct Unsigned<'a> {
            action_id: &'a str,
            kind: &'a CommandKind,
            actor: &'a str,
            session: &'a str,
            seq: u64,
            schedule: &'a Option<Schedule>,
        }
        serde_json::to_string(&Unsigned {
            action_id: &self.action_id,
            kind: &self.kind,
            actor: &self.actor,
            session: &self.session,
            seq: self.seq,
            schedule: &self.schedule,
        })
        .expect("ControlCommand is always serializable")
    }
}

/// The ONLY time source in the system. Gates / the hot path stay clock-free
/// (determinism preserved); only the Scheduler (a later slice) reads this. Units are
/// logical (seconds). Tests inject a `FakeClock`.
pub trait Clock {
    fn now(&self) -> u64;
}

/// Production wall clock (unix seconds). NOTE: this is the ONLY place the slice
/// touches real time; keep it out of dispatch/gates.
pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Deterministic test/demo clock: settable + advanceable.
pub struct FakeClock(std::cell::Cell<u64>);
impl FakeClock {
    pub fn new(t: u64) -> Self {
        FakeClock(std::cell::Cell::new(t))
    }
    pub fn set(&self, t: u64) {
        self.0.set(t);
    }
    pub fn advance(&self, d: u64) {
        self.0.set(self.0.get().saturating_add(d));
    }
}
impl Clock for FakeClock {
    fn now(&self) -> u64 {
        self.0.get()
    }
}

/// The shared authentication + authorization gates. Gate 1 (signature/authn) then
/// Gate 2 (role/authz); on failure it audits the rejection and bails, EXACTLY as
/// `dispatch` did inline. Factored out so `dispatch` and (indirectly) the execution
/// entry point share one byte-identical authn/authz path.
fn authenticate_and_authorize<A: AuditSink>(
    bridge: &mut Bridge<A>,
    cmd: &ControlCommand,
    sig: &dyn SignatureVerifier,
    authz: &dyn Authorizer,
) -> anyhow::Result<()> {
    // Gate 1 — authentication: the command must be validly signed.
    if !sig.verify(&cmd.payload(), &cmd.signature, &cmd.actor) {
        bridge.audit_rejected_command(
            &cmd.action_id,
            &cmd.actor,
            &format!("invalid signature for {}", cmd.kind.label()),
        );
        anyhow::bail!(
            "rejected: invalid signature for {} on {}",
            cmd.kind.label(),
            cmd.action_id
        );
    }
    // Gate 2 — authorization: the actor must be permitted to issue this command.
    if !authz.authorized(&cmd.actor, &cmd.kind) {
        bridge.audit_rejected_command(
            &cmd.action_id,
            &cmd.actor,
            &format!(
                "actor {} not authorized for {}",
                cmd.actor,
                cmd.kind.label()
            ),
        );
        anyhow::bail!(
            "rejected: {} not authorized for {} on {}",
            cmd.actor,
            cmd.kind.label(),
            cmd.action_id
        );
    }
    Ok(())
}

/// Verifies the command's signature FIRST (authentication); only then checks
/// whether the actor is authorized to issue this command (authorization); only
/// an authentic AND authorized command invokes the corresponding gated `Bridge`
/// method. A forged/unsigned command, or a validly-signed but unauthorized one,
/// never reaches the bridge — the rejection is audited and returned as an error.
///
/// Routes only the five LIFECYCLE commands. Execution commands (`Canary`/`Rollout`)
/// have no executor here and are REFUSED (defense in depth): an execution command
/// mis-routed to `dispatch` is bailed on, never silently applied. Real execution
/// goes through [`dispatch_execution_fresh`].
pub fn dispatch<A: AuditSink>(
    bridge: &mut Bridge<A>,
    cmd: ControlCommand,
    sig: &dyn SignatureVerifier,
    authz: &dyn Authorizer,
) -> anyhow::Result<()> {
    authenticate_and_authorize(bridge, &cmd, sig, authz)?;
    match cmd.kind {
        CommandKind::Draft(action) => bridge.draft(*action, &cmd.actor),
        CommandKind::Submit => bridge.submit_for_approval(&cmd.action_id, &cmd.actor),
        CommandKind::Approve => bridge.approve(&cmd.action_id, &cmd.actor),
        CommandKind::Reject { reason } => bridge.reject(&cmd.action_id, &cmd.actor, &reason),
        CommandKind::Abort { reason } => bridge.abort(&cmd.action_id, &cmd.actor, &reason),
        CommandKind::Canary | CommandKind::Rollout => {
            anyhow::bail!(
                "execution command {} requires the orchestrator",
                cmd.kind.label()
            )
        }
    }
}

/// Per-session monotonic replay guard: admits a command only if its (session, seq)
/// is strictly newer than the last admitted seq for that session. Fail-closed: an
/// unknown/unopened session is refused. Clock-free (a monotonic counter, no wall
/// clock, no rand, no network) — freshness is decided purely by the high-water mark.
#[derive(Default)]
pub struct ReplayGuard {
    seen: HashMap<String, u64>,
}

impl ReplayGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a session, admitting seq strictly greater than `from` (use 0 to accept
    /// seq >= 1). Re-opening a session resets its high-water mark to `from`.
    pub fn open_session(&mut self, session: &str, from: u64) {
        self.seen.insert(session.into(), from);
    }

    /// True iff (session, seq) is fresh: the session is open AND `seq` is strictly
    /// greater than the last admitted seq for that session. On success, advances the
    /// high-water mark to `seq`. On failure (unknown session, or `seq` not strictly
    /// newer), leaves state unchanged. Fail-closed: an unopened session is refused
    /// even for an otherwise-valid seq.
    pub fn admit(&mut self, session: &str, seq: u64) -> bool {
        match self.seen.get_mut(session) {
            Some(hwm) if seq > *hwm => {
                *hwm = seq;
                true
            }
            _ => false,
        }
    }
}

/// Freshness-gated dispatch. Gate order is **authn -> freshness -> authz -> lifecycle**:
///  1. verify the signature (authentication) FIRST;
///  2. only then admit the command through the `ReplayGuard` (freshness);
///  3. then hand off to `dispatch` for authorization + the bridge's lifecycle guards.
///
/// AUTHENTICATE-BEFORE-MUTATING-FRESHNESS: the signature is checked BEFORE `admit`
/// because `admit` mutates per-session state (it advances the high-water mark), and
/// unauthenticated input must never mutate freshness state. Session ids travel in the
/// clear, so if an UNAUTHENTICATED command could advance the mark, an attacker could
/// inject a garbage-signed command with `seq = u64::MAX` on a known session and brick
/// it — every later legitimate seq would be refused as stale forever (a seq-exhaustion
/// DoS / desync). This slice's replay defense must hold INDEPENDENT of the transport
/// (mTLS), so a signature-FAILING command is rejected + audited and never touches the
/// guard. `dispatch` then re-verifies the signature; that single redundant ed25519
/// verify on an already-authentic command is acceptable and keeps `dispatch` byte-
/// unchanged (this wrapper is purely additive).
///
/// SEQ-BURN (authenticated-but-refused commands only): if a command AUTHENTICATES and
/// so advances the high-water mark, but is then rejected by `dispatch` at the authz or
/// lifecycle gate, its seq stays consumed — the guard is NOT rolled back. Rolling it
/// back would re-admit that exact (session, seq), reopening the replay window. A burned
/// seq can't be replayed; the genuine issuer advances to the next seq. Note a signature-
/// FAILING command never reaches `admit`, so it never advances (nor burns) the mark.
pub fn dispatch_fresh<A: AuditSink>(
    bridge: &mut Bridge<A>,
    guard: &mut ReplayGuard,
    cmd: ControlCommand,
    sig: &dyn SignatureVerifier,
    authz: &dyn Authorizer,
) -> anyhow::Result<()> {
    // Gate 1 — authentication FIRST: an unauthenticated command must never mutate the
    // replay guard (prevents an injected garbage-signed seq from bricking the session).
    if !sig.verify(&cmd.payload(), &cmd.signature, &cmd.actor) {
        bridge.audit_rejected_command(
            &cmd.action_id,
            &cmd.actor,
            &format!("invalid signature for {}", cmd.kind.label()),
        );
        anyhow::bail!(
            "rejected: invalid signature for {} on {}",
            cmd.kind.label(),
            cmd.action_id
        );
    }
    // Gate 2 — freshness: only an AUTHENTIC command may advance the high-water mark.
    if !guard.admit(&cmd.session, cmd.seq) {
        bridge.audit_rejected_command(
            &cmd.action_id,
            &cmd.actor,
            &format!(
                "stale or replayed command (session {}, seq {})",
                cmd.session, cmd.seq
            ),
        );
        anyhow::bail!(
            "rejected: stale or replayed command (session {}, seq {}) on {}",
            cmd.session,
            cmd.seq,
            cmd.action_id
        );
    }
    // Gates 3 & 4 — authorization + lifecycle (dispatch re-verifies the signature; that
    // single redundant verify keeps dispatch's gate branches byte-unchanged).
    dispatch(bridge, cmd, sig, authz)
}

/// Runs the execution GATE STACK — authentication (signature) → freshness (replay
/// guard) → authorization — and validates that the command is an execution kind. It
/// audits + bails on any gate failure EXACTLY as [`dispatch_execution_fresh`] did
/// inline, preserving the P3b-5 order (authn is checked BEFORE `guard.admit` mutates
/// freshness state, so an UNAUTHENTICATED command can never advance/brick the session's
/// high-water mark). It does NOT run the stage.
///
/// Shared by [`dispatch_execution_fresh`] (which runs the stage immediately) AND the
/// [`Scheduler`](crate::scheduler::Scheduler) (which holds the gate-validated command
/// and releases it inside its window). Factoring the gate here guarantees the deferred
/// path is gated byte-identically to the immediate one — the freshness `seq` is consumed
/// exactly once, at the single point the command passes through this stack.
pub(crate) fn gate_execution<A: AuditSink>(
    bridge: &mut Bridge<A>,
    guard: &mut ReplayGuard,
    cmd: &ControlCommand,
    sig: &dyn SignatureVerifier,
    authz: &dyn Authorizer,
) -> anyhow::Result<()> {
    // Gate 1 — authentication FIRST: an unauthenticated command must NOT touch the
    // guard (an injected garbage-signed seq must not advance/brick the session).
    if !sig.verify(&cmd.payload(), &cmd.signature, &cmd.actor) {
        bridge.audit_rejected_command(
            &cmd.action_id,
            &cmd.actor,
            &format!("invalid signature for {}", cmd.kind.label()),
        );
        anyhow::bail!(
            "rejected: invalid signature for {} on {}",
            cmd.kind.label(),
            cmd.action_id
        );
    }
    // Gate 2 — freshness: only an AUTHENTIC command may advance the high-water mark.
    if !guard.admit(&cmd.session, cmd.seq) {
        bridge.audit_rejected_command(
            &cmd.action_id,
            &cmd.actor,
            &format!(
                "stale or replayed command (session {}, seq {})",
                cmd.session, cmd.seq
            ),
        );
        anyhow::bail!(
            "rejected: stale or replayed command (session {}, seq {}) on {}",
            cmd.session,
            cmd.seq,
            cmd.action_id
        );
    }
    // Gate 3 — authorization: the actor must be permitted to issue this command.
    if !authz.authorized(&cmd.actor, &cmd.kind) {
        bridge.audit_rejected_command(
            &cmd.action_id,
            &cmd.actor,
            &format!(
                "actor {} not authorized for {}",
                cmd.actor,
                cmd.kind.label()
            ),
        );
        anyhow::bail!(
            "rejected: {} not authorized for {} on {}",
            cmd.actor,
            cmd.kind.label(),
            cmd.action_id
        );
    }
    // Defense in depth: this path applies a fix, so the command MUST be an execution
    // kind. A non-execution kind that reached here (mis-route) is bailed on, unrun.
    if !cmd.kind.is_execution() {
        anyhow::bail!("dispatch_execution_fresh only handles execution commands");
    }
    Ok(())
}

/// Gated EXECUTION entry point — the only path that applies a user's fix to real
/// targets. Gate order is **authn -> freshness -> authz -> run the stage**, mirroring
/// [`dispatch_fresh`]: the signature is checked BEFORE `guard.admit` mutates freshness
/// state, so an UNAUTHENTICATED command can never advance (and thus never brick) the
/// session's high-water mark (the P3b-5 fix — do not regress it).
///
/// Handles ONLY `Canary`/`Rollout`; any other kind bails. "The bridge is never a
/// decider": execution runs solely on a fully-gated, user-signed command — a forged,
/// unauthorized, replayed, or stale command NEVER calls the `Executor`, so nothing is
/// applied to any target. The `Executor`/`Verifier` are supplied by the caller (the
/// control-plane orchestrator).
///
/// The gate portion is [`gate_execution`]; the same stack backs the deferred-release
/// [`Scheduler`](crate::scheduler::Scheduler). This function = gate, then run.
pub fn dispatch_execution_fresh<A: AuditSink>(
    bridge: &mut Bridge<A>,
    guard: &mut ReplayGuard,
    cmd: ControlCommand,
    sig: &dyn SignatureVerifier,
    authz: &dyn Authorizer,
    executor: &mut dyn Executor,
    verifier: &dyn Verifier,
) -> anyhow::Result<StageOutcome> {
    // Gates 1–3 + is-execution (audits + bails on failure, consuming the seq once).
    gate_execution(bridge, guard, &cmd, sig, authz)?;
    // Structural window guard: a command carrying a signed window MUST be released by the
    // Scheduler inside `[not_before, not_after]`, never fired at once here — otherwise the
    // window this slice enforces would be bypassed. The wire loop routes on `schedule`, but
    // this makes the invariant structural (not routing-convention-dependent): the immediate
    // path is `schedule: None` ONLY. (Byte-identical for the None case — this only adds a bail.)
    if cmd.schedule.is_some() {
        bridge.audit_rejected_command(
            &cmd.action_id,
            &cmd.actor,
            &format!(
                "scheduled {} must be released by the scheduler within its window",
                cmd.kind.label()
            ),
        );
        anyhow::bail!("scheduled command must be released by the scheduler within its window, not executed immediately");
    }
    // Run the stage. Only now — fully gated — is the executor consulted.
    match cmd.kind {
        CommandKind::Canary => bridge.run_canary(&cmd.action_id, executor, verifier, &cmd.actor),
        CommandKind::Rollout => bridge.run_rollout(&cmd.action_id, executor, verifier, &cmd.actor),
        _ => anyhow::bail!("dispatch_execution_fresh only handles execution commands"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::*;
    use crate::audit::{Outcome, VecAuditSink};
    use crate::bridge::Bridge;

    /// Accepts a signature iff it equals `sign(payload, actor)` for a shared secret.
    /// A deterministic stand-in for real asymmetric verification.
    struct FakeSig(&'static str);
    impl FakeSig {
        fn sign(&self, payload: &str, actor: &str) -> String {
            format!("{}:{}:{}", self.0, actor, payload)
        }
    }
    impl SignatureVerifier for FakeSig {
        fn verify(&self, payload: &str, signature: &str, actor: &str) -> bool {
            signature == self.sign(payload, actor)
        }
    }

    fn action(id: &str) -> RemediationAction {
        RemediationAction {
            id: id.into(),
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
        }
    }

    #[test]
    fn payload_is_deterministic_and_binds_the_full_command() {
        let cmd = ControlCommand {
            action_id: "a".into(),
            kind: CommandKind::Reject {
                reason: "too risky".into(),
            },
            actor: "secops".into(),
            session: "s1".into(),
            seq: 1,
            schedule: None,
            signature: "ignored".into(),
        };
        let p = cmd.payload();
        // Deterministic (same content -> same payload) and excludes the signature.
        assert_eq!(p, cmd.payload());
        assert!(
            !p.contains("ignored"),
            "the signature field is NOT part of the signed payload"
        );
        // Binds the fields that matter: id, kind, actor, and the reason text.
        assert!(p.contains("\"action_id\":\"a\""));
        assert!(p.contains("secops"));
        assert!(
            p.contains("too risky"),
            "the reason text is bound by the signature"
        );
    }

    #[test]
    fn mutating_session_or_seq_breaks_command_verification() {
        let sig = FakeSig("k");
        // Sign a command carrying a specific (session, seq) freshness token.
        let mut cmd = ControlCommand {
            action_id: "a".into(),
            kind: CommandKind::Submit,
            actor: "secops".into(),
            session: "sess-1".into(),
            seq: 5,
            schedule: None,
            signature: String::new(),
        };
        cmd.signature = sig.sign(&cmd.payload(), &cmd.actor);
        // Sanity: the untouched command verifies over its own payload.
        assert!(
            sig.verify(&cmd.payload(), &cmd.signature, &cmd.actor),
            "genuine command verifies"
        );

        // Mutate `session` AFTER signing: the recomputed payload no longer matches
        // the signature -> verification fails (the token is bound by the signature).
        let mut tampered_session = ControlCommand {
            action_id: cmd.action_id.clone(),
            kind: CommandKind::Submit,
            actor: cmd.actor.clone(),
            session: "sess-2".into(),
            seq: cmd.seq,
            schedule: None,
            signature: cmd.signature.clone(),
        };
        assert!(
            !sig.verify(
                &tampered_session.payload(),
                &tampered_session.signature,
                &tampered_session.actor
            ),
            "mutating session invalidates the signature"
        );

        // Separately, mutate `seq` AFTER signing: same result.
        tampered_session.session = cmd.session.clone();
        let tampered_seq = ControlCommand {
            action_id: cmd.action_id.clone(),
            kind: CommandKind::Submit,
            actor: cmd.actor.clone(),
            session: cmd.session.clone(),
            seq: 6,
            schedule: None,
            signature: cmd.signature.clone(),
        };
        assert!(
            !sig.verify(
                &tampered_seq.payload(),
                &tampered_seq.signature,
                &tampered_seq.actor
            ),
            "mutating seq invalidates the signature"
        );
    }

    #[test]
    fn tampering_the_draft_action_body_invalidates_the_signature() {
        let sig = FakeSig("k");
        let mut b = Bridge::new(VecAuditSink::default());
        // Sign a Draft whose action runs a benign script.
        let mut benign = action("a");
        benign.payload = "echo hello".into();
        let mut cmd = ControlCommand {
            action_id: "a".into(),
            kind: CommandKind::Draft(Box::new(benign)),
            actor: "secops".into(),
            session: "s1".into(),
            seq: 1,
            schedule: None,
            signature: String::new(),
        };
        cmd.signature = sig.sign(&cmd.payload(), &cmd.actor);
        // Attacker swaps the script AFTER signing (id/kind-label/actor unchanged —
        // the OLD partial payload would still have matched!).
        if let CommandKind::Draft(a) = &mut cmd.kind {
            a.payload = "rm -rf /".into();
        }
        // With full canonicalization the recomputed payload differs -> rejected.
        assert!(
            dispatch(&mut b, cmd, &sig, &AllowAll).is_err(),
            "tampered action body must be rejected"
        );
        assert_eq!(
            b.state("a"),
            None,
            "nothing drafted — the tampered command never reached the bridge"
        );
    }

    #[test]
    fn forged_command_is_rejected_before_touching_the_bridge() {
        let sig = FakeSig("k");
        let mut b = Bridge::new(VecAuditSink::default());
        // A DRAFT command with a bad signature must not create the action.
        let cmd = ControlCommand {
            action_id: "a".into(),
            kind: CommandKind::Draft(Box::new(action("a"))),
            actor: "attacker".into(),
            session: "s1".into(),
            seq: 1,
            schedule: None,
            signature: "forged".into(),
        };
        let out = dispatch(&mut b, cmd, &sig, &AllowAll);
        assert!(out.is_err(), "forged signature rejected at the gate");
        assert_eq!(
            b.state("a"),
            None,
            "nothing was drafted — the bridge was never touched"
        );
        let last = b.audit().events.last().unwrap();
        assert_eq!(last.outcome, Outcome::Rejected);
        assert!(
            last.detail.contains("signature"),
            "rejection audited as a signature failure"
        );
    }

    #[test]
    fn validly_signed_draft_reaches_the_bridge() {
        let sig = FakeSig("k");
        let mut b = Bridge::new(VecAuditSink::default());
        let mut cmd = ControlCommand {
            action_id: "a".into(),
            kind: CommandKind::Draft(Box::new(action("a"))),
            actor: "secops".into(),
            session: "s1".into(),
            seq: 1,
            schedule: None,
            signature: String::new(),
        };
        cmd.signature = sig.sign(&cmd.payload(), &cmd.actor);
        dispatch(&mut b, cmd, &sig, &AllowAll).unwrap();
        assert_eq!(
            b.state("a"),
            Some(ActionState::Drafted),
            "authentic command runs the gated draft"
        );
    }

    struct DenyAll;
    impl Authorizer for DenyAll {
        fn authorized(&self, _a: &str, _k: &CommandKind) -> bool {
            false
        }
    }

    #[test]
    fn a_validly_signed_but_unauthorized_command_is_rejected() {
        let sig = FakeSig("k");
        let mut b = Bridge::new(VecAuditSink::default());
        let mut cmd = ControlCommand {
            action_id: "a".into(),
            kind: CommandKind::Draft(Box::new(action("a"))),
            actor: "secops".into(),
            session: "s1".into(),
            seq: 1,
            schedule: None,
            signature: String::new(),
        };
        cmd.signature = sig.sign(&cmd.payload(), &cmd.actor); // signature is VALID
                                                              // ...but authorization denies it.
        assert!(
            dispatch(&mut b, cmd, &sig, &DenyAll).is_err(),
            "authenticated but unauthorized -> rejected"
        );
        assert_eq!(
            b.state("a"),
            None,
            "unauthorized command never reached the bridge"
        );
        assert_eq!(b.audit().events.last().unwrap().outcome, Outcome::Rejected);
    }

    #[test]
    fn role_capabilities_enforce_separation_of_duties() {
        // Operator: author/submit only.
        assert!(Role::Operator.permits(&CommandKind::Submit));
        assert!(Role::Operator.permits(&CommandKind::Draft(Box::new(action("a")))));
        assert!(
            !Role::Operator.permits(&CommandKind::Approve),
            "operator cannot approve (four-eyes)"
        );
        // Approver: approve/reject only.
        assert!(Role::Approver.permits(&CommandKind::Approve));
        assert!(Role::Approver.permits(&CommandKind::Reject { reason: "x".into() }));
        assert!(
            !Role::Approver.permits(&CommandKind::Draft(Box::new(action("a")))),
            "approver cannot author"
        );
        // Responder: kill switch.
        assert!(Role::Responder.permits(&CommandKind::Abort { reason: "x".into() }));
        assert!(!Role::Responder.permits(&CommandKind::Approve));
        // Admin: everything.
        assert!(Role::Admin.permits(&CommandKind::Approve));
    }

    #[test]
    fn role_policy_denies_unknown_actor() {
        let p = RolePolicy::new();
        assert!(
            !p.authorized("nobody", &CommandKind::Submit),
            "no role -> denied (fail-closed)"
        );
    }

    #[test]
    fn mutating_the_schedule_window_breaks_verification() {
        let sig = FakeSig("k");
        // Sign a command bound to a specific execution window.
        let mut cmd = ControlCommand {
            action_id: "a".into(),
            kind: CommandKind::Submit,
            actor: "secops".into(),
            session: "s1".into(),
            seq: 1,
            schedule: Some(Schedule {
                not_before: 10,
                not_after: 20,
            }),
            signature: String::new(),
        };
        cmd.signature = sig.sign(&cmd.payload(), &cmd.actor);
        assert!(
            sig.verify(&cmd.payload(), &cmd.signature, &cmd.actor),
            "genuine scheduled command verifies"
        );

        // Move `not_after` AFTER signing, keeping the original signature -> the
        // recomputed payload no longer matches -> verification fails.
        let moved_after = ControlCommand {
            action_id: cmd.action_id.clone(),
            kind: CommandKind::Submit,
            actor: cmd.actor.clone(),
            session: cmd.session.clone(),
            seq: cmd.seq,
            schedule: Some(Schedule {
                not_before: 10,
                not_after: 999,
            }),
            signature: cmd.signature.clone(),
        };
        assert!(
            !sig.verify(
                &moved_after.payload(),
                &moved_after.signature,
                &moved_after.actor
            ),
            "moving not_after invalidates the signature"
        );

        // Separately, move `not_before` AFTER signing -> same result.
        let moved_before = ControlCommand {
            action_id: cmd.action_id.clone(),
            kind: CommandKind::Submit,
            actor: cmd.actor.clone(),
            session: cmd.session.clone(),
            seq: cmd.seq,
            schedule: Some(Schedule {
                not_before: 0,
                not_after: 20,
            }),
            signature: cmd.signature.clone(),
        };
        assert!(
            !sig.verify(
                &moved_before.payload(),
                &moved_before.signature,
                &moved_before.actor
            ),
            "moving not_before invalidates the signature"
        );
    }

    #[test]
    fn adding_or_removing_a_schedule_breaks_verification() {
        let sig = FakeSig("k");
        // (1) Sign with NO window, then ADD one keeping the signature -> fails.
        let mut immediate = ControlCommand {
            action_id: "a".into(),
            kind: CommandKind::Submit,
            actor: "secops".into(),
            session: "s1".into(),
            seq: 1,
            schedule: None,
            signature: String::new(),
        };
        immediate.signature = sig.sign(&immediate.payload(), &immediate.actor);
        let smuggled_window = ControlCommand {
            action_id: immediate.action_id.clone(),
            kind: CommandKind::Submit,
            actor: immediate.actor.clone(),
            session: immediate.session.clone(),
            seq: immediate.seq,
            schedule: Some(Schedule {
                not_before: 10,
                not_after: 20,
            }),
            signature: immediate.signature.clone(),
        };
        assert!(
            !sig.verify(
                &smuggled_window.payload(),
                &smuggled_window.signature,
                &smuggled_window.actor
            ),
            "adding a window to a signed-immediate command invalidates the signature"
        );

        // (2) Sign WITH a window, then STRIP it keeping the signature -> fails.
        let mut scheduled = ControlCommand {
            action_id: "a".into(),
            kind: CommandKind::Submit,
            actor: "secops".into(),
            session: "s1".into(),
            seq: 1,
            schedule: Some(Schedule {
                not_before: 10,
                not_after: 20,
            }),
            signature: String::new(),
        };
        scheduled.signature = sig.sign(&scheduled.payload(), &scheduled.actor);
        let stripped = ControlCommand {
            action_id: scheduled.action_id.clone(),
            kind: CommandKind::Submit,
            actor: scheduled.actor.clone(),
            session: scheduled.session.clone(),
            seq: scheduled.seq,
            schedule: None,
            signature: scheduled.signature.clone(),
        };
        assert!(
            !sig.verify(&stripped.payload(), &stripped.signature, &stripped.actor),
            "stripping the window from a signed-scheduled command invalidates the signature"
        );
    }

    #[test]
    fn an_unscheduled_command_still_verifies() {
        let sig = FakeSig("k");
        // The immediate path (schedule: None) signs and verifies unchanged.
        let mut cmd = ControlCommand {
            action_id: "a".into(),
            kind: CommandKind::Submit,
            actor: "secops".into(),
            session: "s1".into(),
            seq: 1,
            schedule: None,
            signature: String::new(),
        };
        cmd.signature = sig.sign(&cmd.payload(), &cmd.actor);
        assert!(
            sig.verify(&cmd.payload(), &cmd.signature, &cmd.actor),
            "immediate command signs + verifies"
        );
    }

    #[test]
    fn payload_still_excludes_signature() {
        // Two commands identical but for `signature` produce the same payload.
        let base = ControlCommand {
            action_id: "a".into(),
            kind: CommandKind::Submit,
            actor: "secops".into(),
            session: "s1".into(),
            seq: 1,
            schedule: Some(Schedule {
                not_before: 10,
                not_after: 20,
            }),
            signature: "sig-one".into(),
        };
        let other = ControlCommand {
            action_id: "a".into(),
            kind: CommandKind::Submit,
            actor: "secops".into(),
            session: "s1".into(),
            seq: 1,
            schedule: Some(Schedule {
                not_before: 10,
                not_after: 20,
            }),
            signature: "sig-two".into(),
        };
        assert_eq!(
            base.payload(),
            other.payload(),
            "signature is excluded from the payload"
        );
        assert!(
            !base.payload().contains("sig-one"),
            "the signature field is NOT part of the payload"
        );
        // And the schedule fields ARE bound when Some.
        assert!(
            base.payload().contains("not_before"),
            "schedule is folded into the payload"
        );
        assert!(base.payload().contains("not_after"));
    }

    #[test]
    fn fake_clock_advances() {
        let clk = FakeClock::new(5);
        assert_eq!(clk.now(), 5);
        clk.advance(3);
        assert_eq!(clk.now(), 8);
        clk.set(1);
        assert_eq!(clk.now(), 1);
    }
}
