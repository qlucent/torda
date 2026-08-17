//! Golden vectors for the P3b-5 **command-side replay guard** (`ReplayGuard` +
//! `dispatch_fresh`). Deterministic, no clock / rand / network.
//!
//! These vectors exercise the guard, whose admission decision is over `seq` (not
//! signatures), and the guard's composition with the signature gate. The signature is
//! modelled by the same in-crate `FakeSig` verifier the sibling `signature_vectors.rs`
//! uses (a deterministic shared-secret stand-in) — the command side needs no real
//! ed25519, so `torda-remediation`'s test graph stays crypto-free and acyclic. (The
//! result-side vectors in `torda-control-plane` keep real ed25519; that crate owns crypto.)
//!
//! Gate order under test is **authn -> freshness -> authz -> lifecycle**: a signature-
//! FAILING command is rejected before it can touch the guard, so an unauthenticated
//! attacker can never advance (and thus never brick) a session's high-water mark.

use torda_remediation::action::{
    ActionState, AssetSelector, CanarySpec, Method, RemediationAction, VerifySpec,
};
use torda_remediation::audit::{Outcome, VecAuditSink};
use torda_remediation::bridge::Bridge;
use torda_remediation::control::{
    dispatch_fresh, AllowAll, CommandKind, ControlCommand, ReplayGuard, SignatureVerifier,
};

/// Deterministic shared-secret signature stand-in (same shape as signature_vectors.rs).
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

/// Build a genuinely `FakeSig`-signed Draft command on `(session, seq)`. Signing is
/// deterministic, so rebuilding with identical inputs reproduces the identical
/// signature — that is how the "same command" is replayed in vector 1.
fn signed_draft(
    sig: &FakeSig,
    action_id: &str,
    actor: &str,
    session: &str,
    seq: u64,
) -> ControlCommand {
    let mut cmd = ControlCommand {
        action_id: action_id.into(),
        kind: CommandKind::Draft(Box::new(action(action_id))),
        actor: actor.into(),
        session: session.into(),
        seq,
        schedule: None,
        signature: String::new(),
    };
    cmd.signature = sig.sign(&cmd.payload(), &cmd.actor);
    cmd
}

/// Vector 1 — COMMAND REPLAY. Open a session, `dispatch_fresh` a genuine signed
/// command (seq=1) → Ok and the draft lands. Re-send the SAME command (byte-identical,
/// deterministically re-signed) → rejected by the guard. Assert the bridge state did
/// NOT change on the replay and a replay-rejection was audited.
#[test]
fn command_replay_is_rejected_by_the_guard() {
    let sig = FakeSig("secret");
    let mut guard = ReplayGuard::new();
    guard.open_session("s1", 0); // accept seq >= 1
    let mut bridge = Bridge::new(VecAuditSink::default());

    let cmd = signed_draft(&sig, "a", "secops", "s1", 1);
    dispatch_fresh(&mut bridge, &mut guard, cmd, &sig, &AllowAll).unwrap();
    assert_eq!(
        bridge.state("a"),
        Some(ActionState::Drafted),
        "genuine fresh command applied"
    );
    let audits_after_first = bridge.audit().events.len();

    // Replay the SAME command (re-built identically → identical signature).
    let replay = signed_draft(&sig, "a", "secops", "s1", 1);
    let out = dispatch_fresh(&mut bridge, &mut guard, replay, &sig, &AllowAll);
    assert!(
        out.is_err(),
        "a replayed (session, seq) is rejected by the freshness guard"
    );

    assert_eq!(
        bridge.state("a"),
        Some(ActionState::Drafted),
        "replay did not change bridge state"
    );
    let last = bridge.audit().events.last().unwrap();
    assert_eq!(last.outcome, Outcome::Rejected);
    assert!(
        last.detail.contains("replayed") || last.detail.contains("stale"),
        "replay audited distinctly as a freshness rejection: {}",
        last.detail
    );
    assert_eq!(
        bridge.audit().events.len(),
        audits_after_first + 1,
        "exactly one extra (rejection) audit event"
    );
}

/// Vector 2 — STALE / OUT-OF-ORDER. After admitting seq=5, a command with seq=5
/// (equal, not strictly newer) and seq=3 (lower) are BOTH rejected. Exercised directly
/// on the guard: admission is strictly-monotonic per session.
#[test]
fn stale_and_out_of_order_seqs_are_rejected() {
    let mut guard = ReplayGuard::new();
    guard.open_session("s2", 0);
    assert!(
        guard.admit("s2", 5),
        "seq=5 is the first admitted; advances high-water mark to 5"
    );
    assert!(
        !guard.admit("s2", 5),
        "seq=5 again (equal) is not strictly newer → rejected"
    );
    assert!(
        !guard.admit("s2", 3),
        "seq=3 (lower than 5) is stale → rejected"
    );
    assert!(guard.admit("s2", 6), "seq=6 after 5 is fresh → admitted");
}

/// Vector 3 — FRESH NEXT-SEQ. seq=6 after seq=5 is admitted and the guard advances.
#[test]
fn fresh_next_seq_is_admitted_and_advances() {
    let mut guard = ReplayGuard::new();
    guard.open_session("s3", 0);
    assert!(guard.admit("s3", 5), "seq=5 admitted");
    assert!(guard.admit("s3", 6), "seq=6 (strictly newer) admitted");
    assert!(
        !guard.admit("s3", 6),
        "seq=6 again is now stale → rejected (guard advanced to 6)"
    );
}

/// Vector 4 — UNKNOWN / UNOPENED SESSION. A command on a session that was never opened
/// is rejected fail-closed, EVEN with a perfectly valid signature — the guard refuses
/// admission, so dispatch (and the bridge) are never reached.
#[test]
fn unknown_session_is_rejected_fail_closed_even_with_valid_signature() {
    let sig = FakeSig("secret");
    let mut guard = ReplayGuard::new(); // note: "never-opened" is NOT opened
    let mut bridge = Bridge::new(VecAuditSink::default());

    let cmd = signed_draft(&sig, "a", "secops", "never-opened", 1);
    // Sanity: the signature itself is genuine — the ONLY thing refusing this is the guard.
    assert!(
        sig.verify(&cmd.payload(), &cmd.signature, &cmd.actor),
        "the command carries a valid signature"
    );

    let out = dispatch_fresh(&mut bridge, &mut guard, cmd, &sig, &AllowAll);
    assert!(out.is_err(), "unopened session is refused fail-closed");
    assert_eq!(
        bridge.state("a"),
        None,
        "the command never reached the bridge"
    );
    let last = bridge.audit().events.last().unwrap();
    assert_eq!(last.outcome, Outcome::Rejected);
    assert!(
        last.detail.contains("stale") || last.detail.contains("replayed"),
        "audited as a freshness rejection"
    );
}

/// Vector 8 — FRESHNESS CANNOT BE FORGED (post-reorder: authn precedes freshness).
/// Take a genuine command, bump its `seq`, and keep the OLD signature. The command is
/// now rejected at the SIGNATURE gate — and, crucially, it does NOT advance the
/// high-water mark (the guard is only reached by authentic commands). We prove the mark
/// is unchanged by then admitting a genuine command at the ORIGINAL next seq.
#[test]
fn a_bumped_seq_with_a_stale_signature_is_rejected_at_signature_and_does_not_advance_the_mark() {
    let sig = FakeSig("secret");
    let mut guard = ReplayGuard::new();
    guard.open_session("s8", 0);
    let mut bridge = Bridge::new(VecAuditSink::default());

    // A genuine command at seq=1 (signed over the seq=1 payload).
    let genuine = signed_draft(&sig, "a", "secops", "s8", 1);

    // Attacker bumps seq → 2 but reuses the seq=1 signature — the payload now differs,
    // so the signature no longer binds.
    let forged_fresh = ControlCommand {
        action_id: genuine.action_id.clone(),
        kind: CommandKind::Draft(Box::new(action("a"))),
        actor: genuine.actor.clone(),
        session: "s8".into(),
        seq: 2, // a "fresh" seq...
        schedule: None,
        signature: genuine.signature.clone(), // ...but the OLD signature
    };

    let out = dispatch_fresh(&mut bridge, &mut guard, forged_fresh, &sig, &AllowAll);
    assert!(
        out.is_err(),
        "a bumped seq with a stale signature is rejected"
    );
    assert_eq!(
        bridge.state("a"),
        None,
        "nothing drafted — rejected at the signature gate before the bridge"
    );
    // Rejected at the SIGNATURE gate (authn precedes freshness), not the freshness gate.
    let last = bridge.audit().events.last().unwrap();
    assert_eq!(last.outcome, Outcome::Rejected);
    assert!(
        last.detail.contains("signature"),
        "rejected at the SIGNATURE gate, not the freshness gate: {}",
        last.detail
    );

    // THE KEY POST-REORDER ASSERTION: the mark was NOT advanced by the forged seq=2.
    // A genuine, correctly-signed command at seq=2 still admits and applies.
    let genuine_seq2 = signed_draft(&sig, "a", "secops", "s8", 2);
    dispatch_fresh(&mut bridge, &mut guard, genuine_seq2, &sig, &AllowAll).unwrap();
    assert_eq!(
        bridge.state("a"),
        Some(ActionState::Drafted),
        "seq=2 still admits — the stale-signed command did NOT burn the mark"
    );
}

/// Vector 9 (regression trap for the authn-before-freshness fix) — SEQ-EXHAUSTION DoS
/// RESISTANCE. On an open session at high-water 0, an UNAUTHENTICATED command (garbage
/// signature) claiming `seq = u64::MAX` must be rejected AND must NOT advance the mark.
/// Then a genuine command at seq=2 is still admitted — the session is not bricked. If
/// the gate order were reverted (admit before authn), the MAX would be consumed and
/// seq=2 would be refused as stale forever; this test would then fail.
#[test]
fn unauthenticated_max_seq_cannot_brick_the_session() {
    let sig = FakeSig("secret");
    let mut guard = ReplayGuard::new();
    guard.open_session("dos", 0);
    let mut bridge = Bridge::new(VecAuditSink::default());

    // Attacker knows the (cleartext) session id and injects seq=u64::MAX with a garbage
    // signature — no valid key needed. Authn runs first, so `admit` is never reached.
    let poison = ControlCommand {
        action_id: "x".into(),
        kind: CommandKind::Draft(Box::new(action("x"))),
        actor: "attacker".into(),
        session: "dos".into(),
        seq: u64::MAX,
        schedule: None,
        signature: "garbage-not-a-valid-signature".into(),
    };
    let out = dispatch_fresh(&mut bridge, &mut guard, poison, &sig, &AllowAll);
    assert!(
        out.is_err(),
        "the unauthenticated poison command is rejected"
    );
    assert_eq!(
        bridge.state("x"),
        None,
        "poison command never reached the bridge"
    );
    assert!(
        bridge
            .audit()
            .events
            .last()
            .unwrap()
            .detail
            .contains("signature"),
        "rejected at the SIGNATURE gate — it never touched the freshness guard",
    );

    // The mark was NOT advanced by the rejected MAX-seq: a genuine seq=1 then seq=2 admit.
    let cmd1 = signed_draft(&sig, "a", "secops", "dos", 1);
    dispatch_fresh(&mut bridge, &mut guard, cmd1, &sig, &AllowAll).unwrap();
    assert_eq!(
        bridge.state("a"),
        Some(ActionState::Drafted),
        "genuine seq=1 still admits — session not bricked"
    );
    let cmd2 = signed_draft(&sig, "b", "secops", "dos", 2);
    dispatch_fresh(&mut bridge, &mut guard, cmd2, &sig, &AllowAll).unwrap();
    assert_eq!(
        bridge.state("b"),
        Some(ActionState::Drafted),
        "genuine seq=2 still admits — the DoS was defeated"
    );
}
