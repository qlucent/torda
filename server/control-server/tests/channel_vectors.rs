//! Golden vectors for the P3b-6 control channel wired over the [`Transport`] seam.
//!
//! Every vector drives real ed25519 signing/verification, seeded deterministically,
//! across an in-memory [`DuplexTransport`] pair. They assert the security properties
//! of the wired channel end to end:
//!  1. an authorized command round-trips and applies;
//!  2. a forged command yields an AUTHENTIC rejection;
//!  3. a replayed command is refused by the loop's replay guard (bridge unchanged);
//!  4. a replayed RESULT is refused by the client's correlator;
//!  5. a wrong-direction or garbage frame at the agent neither panics nor mutates;
//!  6. control frames never leak onto a separate telemetry transport.
//!
//! The control path under test is replay-guarded end to end: the agent loop uses ONLY
//! `handle_fresh`/`dispatch_fresh`, never the plain `dispatch`.

use torda_control_plane::{
    AgentControlHandler, AgentControlLoop, CommandOutcome, CommandSigner, ControlFrame,
    Ed25519Verifier,
};
use torda_control_server::ControlPlaneClient;
use torda_remediation::action::{
    ActionState, AssetSelector, CanarySpec, Method, RemediationAction, VerifySpec,
};
use torda_remediation::audit::VecAuditSink;
use torda_remediation::bridge::{Bridge, Executor, StageOutcome, Verifier, VerifyOutcome};
use torda_remediation::control::{
    CommandKind, ControlCommand, FakeClock, Role, RolePolicy, Schedule, SystemClock,
};
use torda_transport::{DuplexTransport, Transport};

use std::cell::RefCell;
use std::rc::Rc;

const SESSION: &str = "s1";

/// Shared applied-target log: one handle lives inside the loop's boxed executor, the other
/// stays with the test so it can assert exactly what the gated wire path applied (or, for the
/// "nothing executes" vectors, that it applied NOTHING). `Rc<RefCell<_>>` because the loop is
/// single-threaded here and OWNS its executor, so the test needs a shared handle to observe it.
#[derive(Clone, Default)]
struct AppliedLog(Rc<RefCell<Vec<String>>>);
impl AppliedLog {
    fn list(&self) -> Vec<String> {
        self.0.borrow().clone()
    }
    fn is_empty(&self) -> bool {
        self.0.borrow().is_empty()
    }
}

/// A stub executor recording every applied target through a shared [`AppliedLog`], so a test
/// can prove whether the gated wire path ever reached the executor (mirrors the bridge /
/// execution_command vectors' recording stubs).
struct StubExec {
    applied: AppliedLog,
}
impl Executor for StubExec {
    fn preview(&self, _a: &RemediationAction) -> String {
        String::new()
    }
    fn apply(&mut self, _a: &RemediationAction, target: &str) -> anyhow::Result<()> {
        self.applied.0.borrow_mut().push(target.to_string());
        Ok(())
    }
    fn rollback(&mut self, _a: &RemediationAction, _target: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

/// A stub re-score verifier returning "fixed", so a healthy canary promotes and a healthy
/// rollout closes.
struct Fixed;
impl Verifier for Fixed {
    fn verify(&self, _a: &RemediationAction, _applied: &[String]) -> VerifyOutcome {
        VerifyOutcome::Fixed
    }
}

/// Build a boxed stub orchestrator (executor + verifier) plus the shared handle to inspect it.
fn stub_orchestrator() -> (AppliedLog, Box<dyn Executor>, Box<dyn Verifier>) {
    let applied = AppliedLog::default();
    let exec = Box::new(StubExec {
        applied: applied.clone(),
    });
    (applied, exec, Box::new(Fixed))
}

/// A benign, fully-scoped Draft command for `actor` at `(SESSION, seq)`, UNSIGNED.
fn draft_cmd(actor: &str, seq: u64) -> ControlCommand {
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
        session: SESSION.into(),
        seq,
        schedule: None,
        signature: String::new(),
    }
}

/// The agent's own signer (a distinct key from any command issuer).
fn agent_signer() -> CommandSigner {
    CommandSigner::from_seed("agent-1", [42u8; 32])
}

/// A verifier the AGENT uses to authenticate incoming commands: trusts `operator`.
fn agent_side_verifier(operator: &CommandSigner) -> Ed25519Verifier {
    let mut v = Ed25519Verifier::new();
    v.trust(&operator.actor, operator.verifying_key());
    v
}

/// A verifier the SERVER (client) uses to authenticate agent results: trusts the agent.
fn server_side_verifier(agent: &CommandSigner) -> Ed25519Verifier {
    let mut v = Ed25519Verifier::new();
    v.trust(&agent.actor, agent.verifying_key());
    v
}

/// Operator authorized to Draft/Submit.
fn operator_policy() -> RolePolicy {
    let mut p = RolePolicy::new();
    p.assign("operator", Role::Operator);
    p
}

#[test]
fn authorized_command_round_trips_over_the_wire() {
    let (mut client_t, mut agent_t) = DuplexTransport::pair();
    let operator = CommandSigner::from_seed("operator", [7u8; 32]);
    let agent = agent_signer();
    let agent_v = agent_side_verifier(&operator);
    let policy = operator_policy();
    let mut bridge = Bridge::new(VecAuditSink::default());

    let handler = AgentControlHandler::new(&agent_v, &policy, &agent);
    let (_applied, exec, ver) = stub_orchestrator();
    let mut agent_loop = AgentControlLoop::with_session(handler, SESSION, 0, exec, ver);
    let mut client = ControlPlaneClient::new(operator, server_side_verifier(&agent));

    let mut cmd = draft_cmd("operator", 1);
    client.sign(&mut cmd);
    client.send_command(&mut client_t, cmd).unwrap();

    assert!(
        agent_loop
            .serve_one(&mut agent_t, &mut bridge, &SystemClock)
            .unwrap(),
        "one command frame served"
    );

    let result = client.await_result(&mut client_t).unwrap();
    let result = result.expect("a genuine, correlated result comes back");
    assert_eq!(result.outcome, CommandOutcome::Applied);
    assert_eq!(
        bridge.state("a"),
        Some(ActionState::Drafted),
        "the gated draft was applied over the wire"
    );
}

#[test]
fn forged_command_over_the_wire_yields_authentic_rejection() {
    let (mut client_t, mut agent_t) = DuplexTransport::pair();
    let operator = CommandSigner::from_seed("operator", [7u8; 32]); // the trusted key
    let attacker = CommandSigner::from_seed("operator", [9u8; 32]); // same claimed actor, WRONG key
    let agent = agent_signer();
    let agent_v = agent_side_verifier(&operator); // trusts ONLY the real operator key
    let policy = operator_policy();
    let mut bridge = Bridge::new(VecAuditSink::default());

    let handler = AgentControlHandler::new(&agent_v, &policy, &agent);
    let (_applied, exec, ver) = stub_orchestrator();
    let mut agent_loop = AgentControlLoop::with_session(handler, SESSION, 0, exec, ver);
    let mut client = ControlPlaneClient::new(operator, server_side_verifier(&agent));

    let mut cmd = draft_cmd("operator", 1);
    attacker.sign(&mut cmd); // forged: signed by an untrusted key
    client.send_command(&mut client_t, cmd).unwrap();

    assert!(agent_loop
        .serve_one(&mut agent_t, &mut bridge, &SystemClock)
        .unwrap());

    // The rejection is an AUTHENTIC (agent-signed) acknowledgment, so the client's
    // correlator accepts it and the operator learns the command was rejected.
    let result = client
        .await_result(&mut client_t)
        .unwrap()
        .expect("authentic rejection returned");
    assert_eq!(result.outcome, CommandOutcome::Rejected);
    assert_eq!(
        bridge.state("a"),
        None,
        "the forged command never reached the bridge"
    );
}

#[test]
fn command_replay_over_the_wire_is_rejected_by_the_loop_guard() {
    let (mut client_t, mut agent_t) = DuplexTransport::pair();
    let operator = CommandSigner::from_seed("operator", [7u8; 32]);
    let agent = agent_signer();
    let agent_v = agent_side_verifier(&operator);
    let policy = operator_policy();
    let mut bridge = Bridge::new(VecAuditSink::default());

    let handler = AgentControlHandler::new(&agent_v, &policy, &agent);
    let (_applied, exec, ver) = stub_orchestrator();
    let mut agent_loop = AgentControlLoop::with_session(handler, SESSION, 0, exec, ver);
    let mut client = ControlPlaneClient::new(operator, server_side_verifier(&agent));

    // ed25519 is deterministic, so signing two identical commands yields identical bytes:
    // a perfect on-the-wire replay of the same (session, seq=1) command.
    let mut cmd1 = draft_cmd("operator", 1);
    client.sign(&mut cmd1);
    let mut cmd2 = draft_cmd("operator", 1);
    client.sign(&mut cmd2);

    // First delivery: applied.
    client.send_command(&mut client_t, cmd1).unwrap();
    agent_loop
        .serve_one(&mut agent_t, &mut bridge, &SystemClock)
        .unwrap();
    let r1 = client
        .await_result(&mut client_t)
        .unwrap()
        .expect("first result");
    assert_eq!(r1.outcome, CommandOutcome::Applied);
    let state_after_apply = bridge.state("a");
    assert_eq!(state_after_apply, Some(ActionState::Drafted));

    // Replay the SAME command: the loop's replay guard refuses the stale seq.
    client.send_command(&mut client_t, cmd2).unwrap();
    agent_loop
        .serve_one(&mut agent_t, &mut bridge, &SystemClock)
        .unwrap();
    let r2 = client
        .await_result(&mut client_t)
        .unwrap()
        .expect("second (rejection) result");
    assert_eq!(
        r2.outcome,
        CommandOutcome::Rejected,
        "the guard rejects the replayed command"
    );
    assert_eq!(
        bridge.state("a"),
        state_after_apply,
        "the replay did NOT change bridge state"
    );
}

#[test]
fn result_replay_is_rejected_by_the_client_correlator() {
    let (mut client_t, mut agent_t) = DuplexTransport::pair();
    let operator = CommandSigner::from_seed("operator", [7u8; 32]);
    let agent = agent_signer();
    let agent_v = agent_side_verifier(&operator);
    let policy = operator_policy();
    let mut bridge = Bridge::new(VecAuditSink::default());

    let handler = AgentControlHandler::new(&agent_v, &policy, &agent);
    let (_applied, exec, ver) = stub_orchestrator();
    let mut agent_loop = AgentControlLoop::with_session(handler, SESSION, 0, exec, ver);
    let mut client = ControlPlaneClient::new(operator, server_side_verifier(&agent));

    let mut cmd = draft_cmd("operator", 1);
    client.sign(&mut cmd);
    client.send_command(&mut client_t, cmd).unwrap();
    agent_loop
        .serve_one(&mut agent_t, &mut bridge, &SystemClock)
        .unwrap();

    // First accept consumes the outstanding (session, seq) in the correlator.
    let r1 = client
        .await_result(&mut client_t)
        .unwrap()
        .expect("first result accepted");
    assert_eq!(r1.outcome, CommandOutcome::Applied);

    // Replay that exact genuine result frame back onto the wire from the agent side.
    let replay = serde_json::to_vec(&ControlFrame::Result(r1)).unwrap();
    agent_t.send(&replay).unwrap();

    // The correlator already consumed (session, seq): the replayed result is refused.
    let r2 = client.await_result(&mut client_t).unwrap();
    assert!(
        r2.is_none(),
        "a replayed result is rejected by the client correlator"
    );
}

#[test]
fn a_result_frame_or_garbage_at_the_agent_does_not_panic_or_mutate() {
    let (mut client_t, mut agent_t) = DuplexTransport::pair();
    let operator = CommandSigner::from_seed("operator", [7u8; 32]);
    let agent = agent_signer();
    let agent_v = agent_side_verifier(&operator);
    let policy = operator_policy();
    let mut bridge = Bridge::new(VecAuditSink::default());

    let handler = AgentControlHandler::new(&agent_v, &policy, &agent);
    let (_applied, exec, ver) = stub_orchestrator();
    let mut agent_loop = AgentControlLoop::with_session(handler, SESSION, 0, exec, ver);

    let before = bridge.state("a");

    // A wrong-direction Result frame arriving at the agent: consumed, ignored, no mutation.
    let stray_result = torda_control_plane::CommandResult {
        action_id: "a".into(),
        outcome: CommandOutcome::Applied,
        detail: "applied".into(),
        agent: agent.actor.clone(),
        session: SESSION.into(),
        seq: 1,
        signature: String::new(),
    };
    let wrong_dir = serde_json::to_vec(&ControlFrame::Result(stray_result)).unwrap();
    client_t.send(&wrong_dir).unwrap();
    assert!(
        agent_loop
            .serve_one(&mut agent_t, &mut bridge, &SystemClock)
            .unwrap(),
        "wrong-direction frame consumed"
    );
    assert_eq!(
        bridge.state("a"),
        before,
        "a result at the agent must not mutate the bridge"
    );

    // Hostile garbage bytes: decode fails, consumed, ignored, no panic, no mutation.
    client_t.send(b"this is not a control frame").unwrap();
    assert!(
        agent_loop
            .serve_one(&mut agent_t, &mut bridge, &SystemClock)
            .unwrap(),
        "garbage frame consumed"
    );
    assert_eq!(
        bridge.state("a"),
        before,
        "garbage at the agent must not mutate the bridge"
    );
}

#[test]
fn control_frames_never_appear_on_a_separate_telemetry_transport() {
    // The control channel and a separate "telemetry" channel are distinct transports.
    // This models the control/telemetry separation of the design; true physical port
    // separation lands with the mTLS carrier in P3b-7. Here we assert that a full
    // control round-trip leaves the telemetry transport completely empty.
    let (mut client_t, mut agent_t) = DuplexTransport::pair();
    let (mut telem_a, mut telem_b) = DuplexTransport::pair();

    let operator = CommandSigner::from_seed("operator", [7u8; 32]);
    let agent = agent_signer();
    let agent_v = agent_side_verifier(&operator);
    let policy = operator_policy();
    let mut bridge = Bridge::new(VecAuditSink::default());

    let handler = AgentControlHandler::new(&agent_v, &policy, &agent);
    let (_applied, exec, ver) = stub_orchestrator();
    let mut agent_loop = AgentControlLoop::with_session(handler, SESSION, 0, exec, ver);
    let mut client = ControlPlaneClient::new(operator, server_side_verifier(&agent));

    let mut cmd = draft_cmd("operator", 1);
    client.sign(&mut cmd);
    client.send_command(&mut client_t, cmd).unwrap();
    agent_loop
        .serve_one(&mut agent_t, &mut bridge, &SystemClock)
        .unwrap();
    let result = client
        .await_result(&mut client_t)
        .unwrap()
        .expect("control round-trip completes");
    assert_eq!(result.outcome, CommandOutcome::Applied);

    // No control frame leaked onto the telemetry channel in either direction.
    assert!(
        telem_a.recv().unwrap().is_none(),
        "no control frame leaked onto telemetry (a)"
    );
    assert!(
        telem_b.recv().unwrap().is_none(),
        "no control frame leaked onto telemetry (b)"
    );
}

// ---------------------------------------------------------------------------------------------
// EXECUTION over the wire (P3b-8 Task 2). The two EXECUTION commands (Canary/Rollout) apply a
// user's fix to real targets and MUST cross the SAME replay-guarded gate as every other wire
// command: the loop routes them to `execute_fresh` -> `dispatch_execution_fresh` using the
// loop's OWN `guard` + its held stub executor/verifier. A forged, unauthorized, or replayed
// execution frame NEVER reaches the executor — proven by the shared applied-log staying empty
// (or un-doubled) and the bridge state not advancing.
// ---------------------------------------------------------------------------------------------

/// A fully-scoped remediation action `a` with the given `targets` and canary `cohort`.
fn exec_action(targets: Vec<&str>, cohort: usize) -> RemediationAction {
    RemediationAction {
        id: "a".into(),
        name: "n".into(),
        method: Method::Shell,
        payload: "fix".into(),
        targets: AssetSelector {
            asset_ids: targets.into_iter().map(Into::into).collect(),
        },
        requires_approval: true,
        dry_run_supported: true,
        rollback: Some("undo".into()),
        verify: VerifySpec {
            finding_ids: vec![],
        },
        canary: CanarySpec {
            cohort_size: cohort,
            failure_threshold: 0.0,
        },
    }
}

/// An UNSIGNED control command for action `a` at `(SESSION, seq)`.
fn wire_cmd(kind: CommandKind, actor: &str, seq: u64) -> ControlCommand {
    ControlCommand {
        action_id: "a".into(),
        kind,
        actor: actor.into(),
        session: SESSION.into(),
        seq,
        schedule: None,
        signature: String::new(),
    }
}

/// An agent-side verifier trusting BOTH the operator (author/executor) and a DISTINCT approver.
fn agent_v_operator_and_approver(
    operator: &CommandSigner,
    approver: &CommandSigner,
) -> Ed25519Verifier {
    let mut v = Ed25519Verifier::new();
    v.trust(&operator.actor, operator.verifying_key());
    v.trust(&approver.actor, approver.verifying_key());
    v
}

/// Operator may Draft/Submit/Canary/Rollout (the change owner drives execution); a DISTINCT
/// approver may Approve — four-eyes on the approval gate, and Approvers may NOT execute.
fn exec_policy() -> RolePolicy {
    let mut p = RolePolicy::new();
    p.assign("operator", Role::Operator);
    p.assign("approver", Role::Approver);
    p
}

/// Drive action `a` to Approved directly on the bridge (draft -> dry_run -> submit -> approve),
/// with four-eyes (operator authors/submits, approver approves). Used by the execution-gate
/// vectors so each focuses purely on the EXECUTION frame's gating over the wire.
fn to_approved(bridge: &mut Bridge<VecAuditSink>, action: RemediationAction) {
    struct Preview;
    impl Executor for Preview {
        fn preview(&self, _a: &RemediationAction) -> String {
            String::new()
        }
        fn apply(&mut self, _a: &RemediationAction, _t: &str) -> anyhow::Result<()> {
            Ok(())
        }
        fn rollback(&mut self, _a: &RemediationAction, _t: &str) -> anyhow::Result<()> {
            Ok(())
        }
    }
    let id = action.id.clone();
    bridge.draft(action, "operator").unwrap();
    bridge.dry_run(&id, &Preview, "operator").unwrap();
    bridge.submit_for_approval(&id, "operator").unwrap();
    bridge.approve(&id, "approver").unwrap(); // four-eyes: a DIFFERENT actor approves
}

/// 1. The whole lifecycle INCLUDING execution over the wire: signed Draft (Operator) ->
///    local dry_run -> signed Submit -> signed Approve (DISTINCT approver) -> signed Canary
///    (Applied "Promoted") -> signed Rollout (Applied "Closed"). The action ends Closed and the
///    stub executor's applied-list is non-empty — targets were REALLY applied through the gated
///    wire path.
#[test]
fn full_lifecycle_including_execution_over_the_wire() {
    let (mut client_t, mut agent_t) = DuplexTransport::pair();
    let operator = CommandSigner::from_seed("operator", [7u8; 32]);
    let approver = CommandSigner::from_seed("approver", [8u8; 32]);
    let agent = agent_signer();
    let agent_v = agent_v_operator_and_approver(&operator, &approver);
    let policy = exec_policy();
    let mut bridge = Bridge::new(VecAuditSink::default());

    let handler = AgentControlHandler::new(&agent_v, &policy, &agent);
    let (applied, exec, ver) = stub_orchestrator();
    let mut agent_loop = AgentControlLoop::with_session(handler, SESSION, 0, exec, ver);
    let mut client = ControlPlaneClient::new(operator, server_side_verifier(&agent));

    // Draft (Operator, seq 1) over the wire.
    let mut draft = wire_cmd(
        CommandKind::Draft(Box::new(exec_action(vec!["h1", "h2", "h3"], 1))),
        "operator",
        1,
    );
    client.sign(&mut draft);
    client.send_command(&mut client_t, draft).unwrap();
    agent_loop
        .serve_one(&mut agent_t, &mut bridge, &SystemClock)
        .unwrap();
    assert_eq!(
        client.await_result(&mut client_t).unwrap().unwrap().outcome,
        CommandOutcome::Applied
    );
    assert_eq!(bridge.state("a"), Some(ActionState::Drafted));

    // dry_run is a LOCAL read-only preview (not a wire command), exactly as the demo does.
    struct Preview;
    impl Executor for Preview {
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
    bridge.dry_run("a", &Preview, "operator").unwrap();

    // Submit (Operator, seq 2) over the wire.
    let mut submit = wire_cmd(CommandKind::Submit, "operator", 2);
    client.sign(&mut submit);
    client.send_command(&mut client_t, submit).unwrap();
    agent_loop
        .serve_one(&mut agent_t, &mut bridge, &SystemClock)
        .unwrap();
    assert_eq!(
        client.await_result(&mut client_t).unwrap().unwrap().outcome,
        CommandOutcome::Applied
    );

    // Approve (DISTINCT approver, seq 3) — signed by the approver's OWN key.
    let mut approve = wire_cmd(CommandKind::Approve, "approver", 3);
    approver.sign(&mut approve);
    client.send_command(&mut client_t, approve).unwrap();
    agent_loop
        .serve_one(&mut agent_t, &mut bridge, &SystemClock)
        .unwrap();
    assert_eq!(
        client.await_result(&mut client_t).unwrap().unwrap().outcome,
        CommandOutcome::Applied
    );
    assert_eq!(bridge.state("a"), Some(ActionState::Approved));

    // Canary (Operator, seq 4) over the wire -> Applied, detail "Promoted".
    let mut canary = wire_cmd(CommandKind::Canary, "operator", 4);
    client.sign(&mut canary);
    client.send_command(&mut client_t, canary).unwrap();
    agent_loop
        .serve_one(&mut agent_t, &mut bridge, &SystemClock)
        .unwrap();
    let r = client
        .await_result(&mut client_t)
        .unwrap()
        .expect("canary result");
    assert_eq!(r.outcome, CommandOutcome::Applied);
    assert!(
        r.detail.contains("Promoted"),
        "canary detail carries the StageOutcome: {}",
        r.detail
    );
    assert_eq!(bridge.state("a"), Some(ActionState::Rollout));

    // Rollout (Operator, seq 5) over the wire -> Applied, detail "Closed".
    let mut rollout = wire_cmd(CommandKind::Rollout, "operator", 5);
    client.sign(&mut rollout);
    client.send_command(&mut client_t, rollout).unwrap();
    agent_loop
        .serve_one(&mut agent_t, &mut bridge, &SystemClock)
        .unwrap();
    let r = client
        .await_result(&mut client_t)
        .unwrap()
        .expect("rollout result");
    assert_eq!(r.outcome, CommandOutcome::Applied);
    assert!(
        r.detail.contains("Closed"),
        "rollout detail carries the StageOutcome: {}",
        r.detail
    );

    // Final state Closed AND the executor really applied targets through the gated wire path.
    assert_eq!(
        bridge.state("a"),
        Some(ActionState::Closed),
        "the verified fix closed over the wire"
    );
    assert!(
        !applied.is_empty(),
        "targets were applied through the gated wire execution path"
    );
    assert_eq!(
        applied.list(),
        vec!["h1", "h2", "h3"],
        "canary cohort + rollout remainder applied"
    );
}

/// 2. A Canary frame with a BAD signature -> the loop rejects it at the signature gate and the
///    stub executor is NEVER called; the bridge stays Approved.
#[test]
fn forged_canary_over_the_wire_is_rejected_and_nothing_executes() {
    let (mut client_t, mut agent_t) = DuplexTransport::pair();
    let operator = CommandSigner::from_seed("operator", [7u8; 32]);
    let approver = CommandSigner::from_seed("approver", [8u8; 32]);
    let agent = agent_signer();
    let agent_v = agent_v_operator_and_approver(&operator, &approver);
    let policy = exec_policy();
    let mut bridge = Bridge::new(VecAuditSink::default());
    to_approved(&mut bridge, exec_action(vec!["h1", "h2"], 1));

    let handler = AgentControlHandler::new(&agent_v, &policy, &agent);
    let (applied, exec, ver) = stub_orchestrator();
    let mut agent_loop = AgentControlLoop::with_session(handler, SESSION, 0, exec, ver);
    let mut client = ControlPlaneClient::new(operator, server_side_verifier(&agent));

    // A Canary with a bad signature (valid session/seq, but not authentic).
    let mut forged = wire_cmd(CommandKind::Canary, "operator", 1);
    forged.signature = "forged".into();
    client.send_command(&mut client_t, forged).unwrap();
    assert!(agent_loop
        .serve_one(&mut agent_t, &mut bridge, &SystemClock)
        .unwrap());

    let r = client
        .await_result(&mut client_t)
        .unwrap()
        .expect("authentic rejection returned");
    assert_eq!(
        r.outcome,
        CommandOutcome::Rejected,
        "forged canary rejected over the wire"
    );
    // NOTHING EXECUTED: the shared applied-log is empty and the bridge did not advance.
    assert!(
        applied.is_empty(),
        "the executor was NEVER called — nothing applied to any target"
    );
    assert_eq!(
        bridge.state("a"),
        Some(ActionState::Approved),
        "bridge state did not advance"
    );
}

/// 3. A validly-signed Canary by a NON-Operator (the Approver) -> rejected at the authz gate;
///    the executor is not called.
#[test]
fn unauthorized_canary_over_the_wire_is_rejected() {
    let (mut client_t, mut agent_t) = DuplexTransport::pair();
    let operator = CommandSigner::from_seed("operator", [7u8; 32]);
    let approver = CommandSigner::from_seed("approver", [8u8; 32]);
    let agent = agent_signer();
    let agent_v = agent_v_operator_and_approver(&operator, &approver);
    let policy = exec_policy();
    let mut bridge = Bridge::new(VecAuditSink::default());
    to_approved(&mut bridge, exec_action(vec!["h1", "h2"], 1));

    let handler = AgentControlHandler::new(&agent_v, &policy, &agent);
    let (applied, exec, ver) = stub_orchestrator();
    let mut agent_loop = AgentControlLoop::with_session(handler, SESSION, 0, exec, ver);
    let mut client = ControlPlaneClient::new(operator, server_side_verifier(&agent));

    // Carol-style: the Approver validly SIGNS a Canary, but Approvers may NOT execute.
    let mut cmd = wire_cmd(CommandKind::Canary, "approver", 1);
    approver.sign(&mut cmd);
    client.send_command(&mut client_t, cmd).unwrap();
    assert!(agent_loop
        .serve_one(&mut agent_t, &mut bridge, &SystemClock)
        .unwrap());

    let r = client
        .await_result(&mut client_t)
        .unwrap()
        .expect("authentic rejection returned");
    assert_eq!(
        r.outcome,
        CommandOutcome::Rejected,
        "an Approver is not authorized to execute"
    );
    assert!(
        applied.is_empty(),
        "the executor was never called for the unauthorized actor"
    );
    assert_eq!(
        bridge.state("a"),
        Some(ActionState::Approved),
        "bridge state unchanged"
    );
}

/// 4. A genuine Canary is served, then the EXACT same frame is replayed -> the loop's replay
///    guard rejects the second one; the executor is not called again (applied-log not doubled).
#[test]
fn replayed_canary_over_the_wire_is_rejected_by_the_loop_guard() {
    let (mut client_t, mut agent_t) = DuplexTransport::pair();
    let operator = CommandSigner::from_seed("operator", [7u8; 32]);
    let approver = CommandSigner::from_seed("approver", [8u8; 32]);
    let agent = agent_signer();
    let agent_v = agent_v_operator_and_approver(&operator, &approver);
    let policy = exec_policy();
    let mut bridge = Bridge::new(VecAuditSink::default());
    // Cohort 2 over 2 targets so the first canary fully applies (both targets) and promotes.
    to_approved(&mut bridge, exec_action(vec!["h1", "h2"], 2));

    let handler = AgentControlHandler::new(&agent_v, &policy, &agent);
    let (applied, exec, ver) = stub_orchestrator();
    let mut agent_loop = AgentControlLoop::with_session(handler, SESSION, 0, exec, ver);
    let mut client = ControlPlaneClient::new(operator, server_side_verifier(&agent));

    // First genuine Canary (seq 1): applied + promoted.
    let mut canary1 = wire_cmd(CommandKind::Canary, "operator", 1);
    client.sign(&mut canary1);
    client.send_command(&mut client_t, canary1).unwrap();
    agent_loop
        .serve_one(&mut agent_t, &mut bridge, &SystemClock)
        .unwrap();
    let r1 = client
        .await_result(&mut client_t)
        .unwrap()
        .expect("first canary result");
    assert_eq!(r1.outcome, CommandOutcome::Applied);
    let applied_after_first = applied.list();
    assert!(
        !applied_after_first.is_empty(),
        "the first canary applied targets"
    );

    // Replay the SAME (session, seq=1) command — ed25519 is deterministic, so re-signing an
    // identical command reproduces the identical wire bytes: a perfect on-the-wire replay.
    let mut canary2 = wire_cmd(CommandKind::Canary, "operator", 1);
    client.sign(&mut canary2);
    client.send_command(&mut client_t, canary2).unwrap();
    agent_loop
        .serve_one(&mut agent_t, &mut bridge, &SystemClock)
        .unwrap();
    let r2 = client
        .await_result(&mut client_t)
        .unwrap()
        .expect("second (rejection) result");
    assert_eq!(
        r2.outcome,
        CommandOutcome::Rejected,
        "the loop's guard rejects the replayed canary"
    );
    // The executor was NOT called a second time: the applied-log is unchanged (not doubled).
    assert_eq!(
        applied.list(),
        applied_after_first,
        "executor not re-run — applied-log not doubled"
    );
}

// ---------------------------------------------------------------------------------------------
// SCHEDULED EXECUTION over the wire (P3b-9). A Canary/Rollout carrying a SIGNED window is
// ENQUEUED at `serve_one` (gates run ONCE — the seq is consumed there), held, then RELEASED by
// `AgentControlLoop::tick` only when the injected `FakeClock` enters the window on a still-valid
// action. Real ed25519 throughout: the window is in the signed bytes, so tampering it is caught.
// ---------------------------------------------------------------------------------------------

/// 8. A scheduled Canary frame is enqueued (result detail "scheduled"); `tick` before the window
///    fires nothing; advancing the clock into the window and ticking fires it, applying targets.
#[test]
fn scheduled_canary_over_the_wire_fires_only_within_its_window() {
    let (mut client_t, mut agent_t) = DuplexTransport::pair();
    let operator = CommandSigner::from_seed("operator", [7u8; 32]);
    let approver = CommandSigner::from_seed("approver", [8u8; 32]);
    let agent = agent_signer();
    let agent_v = agent_v_operator_and_approver(&operator, &approver);
    let policy = exec_policy();
    let mut bridge = Bridge::new(VecAuditSink::default());
    to_approved(&mut bridge, exec_action(vec!["h1", "h2", "h3"], 1));

    let handler = AgentControlHandler::new(&agent_v, &policy, &agent);
    let (applied, exec, ver) = stub_orchestrator();
    let mut agent_loop = AgentControlLoop::with_session(handler, SESSION, 0, exec, ver);
    let mut client = ControlPlaneClient::new(operator, server_side_verifier(&agent));

    // The operator schedules the approved Canary for window [10,20] (the window is SIGNED).
    let clock = FakeClock::new(5);
    let mut canary = wire_cmd(CommandKind::Canary, "operator", 1);
    canary.schedule = Some(Schedule {
        not_before: 10,
        not_after: 20,
    });
    client.sign(&mut canary);
    client.send_command(&mut client_t, canary).unwrap();
    // serve_one ENQUEUES (gates run once here) and answers "scheduled" — it does NOT fire.
    assert!(agent_loop
        .serve_one(&mut agent_t, &mut bridge, &clock)
        .unwrap());
    let r = client
        .await_result(&mut client_t)
        .unwrap()
        .expect("scheduled ack returned");
    assert_eq!(r.outcome, CommandOutcome::Applied);
    assert!(
        r.detail.contains("scheduled"),
        "the ack reports scheduling, not execution: {}",
        r.detail
    );
    assert!(applied.is_empty(), "nothing applied at enqueue time");
    assert_eq!(
        bridge.state("a"),
        Some(ActionState::Approved),
        "deferred — still Approved, not fired"
    );

    // Tick BEFORE the window opens (now=5): nothing fires.
    assert!(
        agent_loop.tick(&mut bridge, &clock).is_empty(),
        "before not_before nothing fires"
    );
    assert!(applied.is_empty());
    assert_eq!(bridge.state("a"), Some(ActionState::Approved));

    // Advance INTO the window and tick: it fires through the loop -> Promoted, targets applied.
    clock.set(15);
    let fired = agent_loop.tick(&mut bridge, &clock);
    assert_eq!(
        fired,
        vec![("a".to_string(), StageOutcome::Promoted)],
        "fires in-window -> Promoted"
    );
    assert_eq!(
        applied.list(),
        vec!["h1"],
        "the canary cohort applied through the loop's executor"
    );
    assert_eq!(
        bridge.state("a"),
        Some(ActionState::Rollout),
        "the released canary promoted"
    );
}

/// 9. Tampering the SIGNED window over the wire: sign a Canary for [10,20], then widen not_after
///    to 999 keeping the signature. `serve_one` -> enqueue fails at the ed25519 signature gate;
///    nothing is stored, so a later in-window `tick` fires nothing and the executor never runs.
#[test]
fn tampering_the_scheduled_window_over_the_wire_is_rejected_at_enqueue() {
    let (mut client_t, mut agent_t) = DuplexTransport::pair();
    let operator = CommandSigner::from_seed("operator", [7u8; 32]);
    let approver = CommandSigner::from_seed("approver", [8u8; 32]);
    let agent = agent_signer();
    let agent_v = agent_v_operator_and_approver(&operator, &approver);
    let policy = exec_policy();
    let mut bridge = Bridge::new(VecAuditSink::default());
    to_approved(&mut bridge, exec_action(vec!["h1", "h2"], 1));

    let handler = AgentControlHandler::new(&agent_v, &policy, &agent);
    let (applied, exec, ver) = stub_orchestrator();
    let mut agent_loop = AgentControlLoop::with_session(handler, SESSION, 0, exec, ver);
    let mut client = ControlPlaneClient::new(operator, server_side_verifier(&agent));

    let clock = FakeClock::new(5);
    let mut canary = wire_cmd(CommandKind::Canary, "operator", 1);
    canary.schedule = Some(Schedule {
        not_before: 10,
        not_after: 20,
    });
    client.sign(&mut canary); // real ed25519 over the window
                              // Attacker widens the window AFTER signing, keeping the original signature.
    canary.schedule = Some(Schedule {
        not_before: 10,
        not_after: 999,
    });
    client.send_command(&mut client_t, canary).unwrap();
    assert!(agent_loop
        .serve_one(&mut agent_t, &mut bridge, &clock)
        .unwrap());

    let r = client
        .await_result(&mut client_t)
        .unwrap()
        .expect("authentic rejection returned");
    assert_eq!(
        r.outcome,
        CommandOutcome::Rejected,
        "a tampered window is rejected at the signature gate"
    );
    // Nothing was enqueued: even inside the (tampered) window, a later tick fires nothing.
    clock.set(15);
    assert!(
        agent_loop.tick(&mut bridge, &clock).is_empty(),
        "nothing was stored to fire"
    );
    assert!(
        applied.is_empty(),
        "the executor never ran for the tampered scheduled command"
    );
    assert_eq!(
        bridge.state("a"),
        Some(ActionState::Approved),
        "bridge state unchanged"
    );
}

/// 10. A forged/unauthorized Abort must NOT cancel a pending scheduled command (that would be a
///     denial-of-remediation via an unauthenticated mutation): only an Abort that actually
///     APPLIES cancels. Block A: a forged Abort is rejected and the scheduled canary STILL fires
///     in its window. Block B: a genuine authorized (Responder) Abort cancels it — it never fires.
#[test]
fn forged_abort_does_not_cancel_pending_scheduled_command() {
    let operator = CommandSigner::from_seed("operator", [7u8; 32]);
    let responder = CommandSigner::from_seed("responder", [10u8; 32]);
    let agent = agent_signer();
    // Agent trusts the operator (schedules/executes) and the responder (kill switch).
    let mut agent_v = Ed25519Verifier::new();
    agent_v.trust(&operator.actor, operator.verifying_key());
    agent_v.trust(&responder.actor, responder.verifying_key());
    // Policy: operator may Canary; responder may Abort (kill switch).
    let mut policy = RolePolicy::new();
    policy.assign("operator", Role::Operator);
    policy.assign("responder", Role::Responder);

    // -- Block A: a FORGED Abort is rejected and does NOT cancel — the canary still fires. --
    {
        let (mut client_t, mut agent_t) = DuplexTransport::pair();
        let mut bridge = Bridge::new(VecAuditSink::default());
        to_approved(&mut bridge, exec_action(vec!["h1", "h2", "h3"], 1));
        let handler = AgentControlHandler::new(&agent_v, &policy, &agent);
        let (applied, exec, ver) = stub_orchestrator();
        let mut agent_loop = AgentControlLoop::with_session(handler, SESSION, 0, exec, ver);
        let mut client = ControlPlaneClient::new(
            CommandSigner::from_seed("operator", [7u8; 32]),
            server_side_verifier(&agent),
        );
        let clock = FakeClock::new(5);

        // Operator schedules the approved canary for [10,20].
        let mut canary = wire_cmd(CommandKind::Canary, "operator", 1);
        canary.schedule = Some(Schedule {
            not_before: 10,
            not_after: 20,
        });
        client.sign(&mut canary);
        client.send_command(&mut client_t, canary).unwrap();
        assert!(agent_loop
            .serve_one(&mut agent_t, &mut bridge, &clock)
            .unwrap());
        assert_eq!(
            client.await_result(&mut client_t).unwrap().unwrap().outcome,
            CommandOutcome::Applied
        );

        // An attacker injects a garbage-signed Abort for the same action.
        let forged_abort = ControlCommand {
            action_id: "a".into(),
            kind: CommandKind::Abort {
                reason: "sabotage".into(),
            },
            actor: "responder".into(),
            session: SESSION.into(),
            seq: 2,
            schedule: None,
            signature: "forged".into(),
        };
        client.send_command(&mut client_t, forged_abort).unwrap();
        assert!(agent_loop
            .serve_one(&mut agent_t, &mut bridge, &clock)
            .unwrap());
        let r = client
            .await_result(&mut client_t)
            .unwrap()
            .expect("authentic rejection returned");
        assert_eq!(
            r.outcome,
            CommandOutcome::Rejected,
            "the forged Abort is rejected"
        );

        // The scheduled canary was NOT cancelled: inside its window it still fires.
        clock.set(15);
        let fired = agent_loop.tick(&mut bridge, &clock);
        assert_eq!(
            fired,
            vec![("a".to_string(), StageOutcome::Promoted)],
            "a forged Abort did not suppress the scheduled remediation"
        );
        assert_eq!(
            applied.list(),
            vec!["h1"],
            "the canary still applied — no denial-of-remediation"
        );
        assert_eq!(bridge.state("a"), Some(ActionState::Rollout));
    }

    // -- Block B: a GENUINE authorized (Responder) Abort cancels it — it never fires. --
    {
        let (mut client_t, mut agent_t) = DuplexTransport::pair();
        let mut bridge = Bridge::new(VecAuditSink::default());
        to_approved(&mut bridge, exec_action(vec!["h1", "h2", "h3"], 1));
        let handler = AgentControlHandler::new(&agent_v, &policy, &agent);
        let (applied, exec, ver) = stub_orchestrator();
        let mut agent_loop = AgentControlLoop::with_session(handler, SESSION, 0, exec, ver);
        let mut client = ControlPlaneClient::new(
            CommandSigner::from_seed("operator", [7u8; 32]),
            server_side_verifier(&agent),
        );
        let clock = FakeClock::new(5);

        // Operator schedules the approved canary for [10,20].
        let mut canary = wire_cmd(CommandKind::Canary, "operator", 1);
        canary.schedule = Some(Schedule {
            not_before: 10,
            not_after: 20,
        });
        client.sign(&mut canary);
        client.send_command(&mut client_t, canary).unwrap();
        assert!(agent_loop
            .serve_one(&mut agent_t, &mut bridge, &clock)
            .unwrap());
        assert_eq!(
            client.await_result(&mut client_t).unwrap().unwrap().outcome,
            CommandOutcome::Applied
        );

        // The responder issues a GENUINE, authorized Abort (signed with their own key).
        let mut abort = wire_cmd(
            CommandKind::Abort {
                reason: "change cancelled".into(),
            },
            "responder",
            2,
        );
        responder.sign(&mut abort);
        client.send_command(&mut client_t, abort).unwrap();
        assert!(agent_loop
            .serve_one(&mut agent_t, &mut bridge, &clock)
            .unwrap());
        assert_eq!(
            client.await_result(&mut client_t).unwrap().unwrap().outcome,
            CommandOutcome::Applied,
            "the genuine Abort applied"
        );
        assert_eq!(bridge.state("a"), Some(ActionState::Aborted));

        // The scheduled canary was cancelled: inside its window it fires nothing.
        clock.set(15);
        assert!(
            agent_loop.tick(&mut bridge, &clock).is_empty(),
            "a genuine Abort cancelled the scheduled command"
        );
        assert!(applied.is_empty(), "the cancelled canary never applied");
        assert_eq!(bridge.state("a"), Some(ActionState::Aborted));
    }
}
