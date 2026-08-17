//! Signed-execution golden vectors. The execution
//! step (applying a fix to real targets) is behind the same signed/authorized/
//! replay gates as the rest of the control channel. Gate order for execution is
//! authn -> freshness -> authz -> run; authn is checked BEFORE the replay guard
//! mutates state (the P3b-5 fix). A forged / unauthorized / replayed / stale
//! execution command NEVER calls the executor — nothing is applied to any target.
use torda_remediation::action::*;
use torda_remediation::audit::*;
use torda_remediation::bridge::*;
use torda_remediation::control::*;

/// Accepts a signature iff it equals `sign(payload, actor)` for a shared secret —
/// a deterministic stand-in for real asymmetric verification.
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

/// A stub executor that records the targets it applied to, so a test can prove
/// whether the executor was consulted at all (empty applied-list == never ran).
#[derive(Default)]
struct StubExec {
    applied: Vec<String>,
    rolled_back: Vec<String>,
}
impl Executor for StubExec {
    fn preview(&self, _a: &RemediationAction) -> String {
        String::new()
    }
    fn apply(&mut self, _a: &RemediationAction, target: &str) -> anyhow::Result<()> {
        self.applied.push(target.to_string());
        Ok(())
    }
    fn rollback(&mut self, _a: &RemediationAction, target: &str) -> anyhow::Result<()> {
        self.rolled_back.push(target.to_string());
        Ok(())
    }
}

/// A stub verifier: the re-score always reports the finding fixed, so a healthy
/// canary promotes and a healthy rollout closes.
struct Fixed;
impl Verifier for Fixed {
    fn verify(&self, _a: &RemediationAction, _t: &[String]) -> VerifyOutcome {
        VerifyOutcome::Fixed
    }
}

fn action(id: &str, targets: Vec<&str>) -> RemediationAction {
    RemediationAction {
        id: id.into(),
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
            finding_ids: vec!["f1".into()],
        },
        canary: CanarySpec {
            cohort_size: 1,
            failure_threshold: 0.0,
        },
    }
}

/// Drive an action to `Approved` via the bridge's gated path (draft -> dry_run ->
/// submit -> approve). Executor-free preview stub for the dry-run.
fn to_approved(b: &mut Bridge<VecAuditSink>, a: RemediationAction) {
    struct P;
    impl Executor for P {
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
    let id = a.id.clone();
    b.draft(a, "alice").unwrap();
    b.dry_run(&id, &P, "alice").unwrap();
    b.submit_for_approval(&id, "alice").unwrap();
    b.approve(&id, "bob").unwrap(); // four-eyes: a different actor approves
}

/// Sign an execution command carrying a (session, seq) freshness token.
fn signed(
    sig: &FakeSig,
    action_id: &str,
    kind: CommandKind,
    actor: &str,
    session: &str,
    seq: u64,
) -> ControlCommand {
    let mut cmd = ControlCommand {
        action_id: action_id.into(),
        kind,
        actor: actor.into(),
        session: session.into(),
        seq,
        schedule: None,
        signature: String::new(),
    };
    cmd.signature = sig.sign(&cmd.payload(), &cmd.actor);
    cmd
}

fn operator_policy() -> RolePolicy {
    let mut p = RolePolicy::new();
    p.assign("alice", Role::Operator); // the change owner: may execute their approved change
    p.assign("carol", Role::Approver); // approves, but may NOT execute
    p
}

// 1. An authorized, freshly-signed canary runs and promotes; then a rollout closes.
#[test]
fn signed_authorized_canary_runs_and_promotes() {
    let sig = FakeSig("secret");
    let policy = operator_policy();
    let mut b = Bridge::new(VecAuditSink::default());
    to_approved(&mut b, action("a", vec!["h1", "h2", "h3"]));

    let mut guard = ReplayGuard::new();
    guard.open_session("s1", 0);
    let mut ex = StubExec::default();

    let canary = signed(&sig, "a", CommandKind::Canary, "alice", "s1", 1);
    let out = dispatch_execution_fresh(&mut b, &mut guard, canary, &sig, &policy, &mut ex, &Fixed)
        .unwrap();
    assert_eq!(out, StageOutcome::Promoted);
    assert!(
        !ex.applied.is_empty(),
        "the canary cohort was applied to real targets"
    );
    assert_eq!(
        ex.applied,
        vec!["h1"],
        "only the canary cohort (size 1) applied"
    );
    assert_eq!(b.state("a"), Some(ActionState::Rollout));

    let rollout = signed(&sig, "a", CommandKind::Rollout, "alice", "s1", 2);
    let out = dispatch_execution_fresh(&mut b, &mut guard, rollout, &sig, &policy, &mut ex, &Fixed)
        .unwrap();
    assert_eq!(out, StageOutcome::Closed);
    assert_eq!(
        ex.applied,
        vec!["h1", "h2", "h3"],
        "canary + remaining rollout applied"
    );
    assert_eq!(b.state("a"), Some(ActionState::Closed));
}

// 2. A forged canary is rejected at the signature gate and NEVER calls the executor.
#[test]
fn forged_canary_never_runs_the_executor() {
    let sig = FakeSig("secret");
    let policy = operator_policy();
    let mut b = Bridge::new(VecAuditSink::default());
    to_approved(&mut b, action("a", vec!["h1", "h2"]));

    let mut guard = ReplayGuard::new();
    guard.open_session("s1", 0);
    let mut ex = StubExec::default();

    // A canary with a bad signature (valid session/seq, but not authentic).
    let forged = ControlCommand {
        action_id: "a".into(),
        kind: CommandKind::Canary,
        actor: "alice".into(),
        session: "s1".into(),
        seq: 1,
        schedule: None,
        signature: "forged".into(),
    };
    let out = dispatch_execution_fresh(&mut b, &mut guard, forged, &sig, &policy, &mut ex, &Fixed);
    assert!(
        out.is_err(),
        "forged execution command rejected at the signature gate"
    );
    assert!(
        ex.applied.is_empty(),
        "nothing applied to any target — the executor was never called"
    );
    assert_eq!(
        b.state("a"),
        Some(ActionState::Approved),
        "bridge state unchanged (still Approved)"
    );
    assert_eq!(b.audit().events.last().unwrap().outcome, Outcome::Rejected);
}

// 3. A validly-signed canary by a role that may not execute is refused; executor untouched.
#[test]
fn unauthorized_actor_canary_is_refused() {
    let sig = FakeSig("secret");
    let policy = operator_policy();
    let mut b = Bridge::new(VecAuditSink::default());
    to_approved(&mut b, action("a", vec!["h1", "h2"]));

    let mut guard = ReplayGuard::new();
    guard.open_session("s1", 0);
    let mut ex = StubExec::default();

    // Carol is an Approver — validly signed, but Approvers may NOT execute.
    let cmd = signed(&sig, "a", CommandKind::Canary, "carol", "s1", 1);
    let out = dispatch_execution_fresh(&mut b, &mut guard, cmd, &sig, &policy, &mut ex, &Fixed);
    assert!(out.is_err(), "an Approver is not authorized to execute");
    assert!(ex.applied.is_empty(), "the executor was never called");
    assert_eq!(
        b.state("a"),
        Some(ActionState::Approved),
        "still Approved, nothing executed"
    );
    assert_eq!(b.audit().events.last().unwrap().outcome, Outcome::Rejected);
}

// 4. Replaying the exact same canary command is rejected by the freshness guard;
//    the executor is not called a second time (applied-list is not doubled).
#[test]
fn replayed_canary_is_rejected_by_the_guard() {
    let sig = FakeSig("secret");
    let policy = operator_policy();
    let mut b = Bridge::new(VecAuditSink::default());
    // Cohort size 3 so the canary covers all targets and the first run fully applies.
    let mut a = action("a", vec!["h1", "h2"]);
    a.canary.cohort_size = 2;
    to_approved(&mut b, a);

    let mut guard = ReplayGuard::new();
    guard.open_session("s1", 0);
    let mut ex = StubExec::default();

    let first = signed(&sig, "a", CommandKind::Canary, "alice", "s1", 1);
    dispatch_execution_fresh(&mut b, &mut guard, first, &sig, &policy, &mut ex, &Fixed).unwrap();
    let applied_after_first = ex.applied.clone();
    assert!(!applied_after_first.is_empty(), "the first canary applied");

    // Replay the identical (session, seq): the guard refuses it.
    let replay = signed(&sig, "a", CommandKind::Canary, "alice", "s1", 1);
    let out = dispatch_execution_fresh(&mut b, &mut guard, replay, &sig, &policy, &mut ex, &Fixed);
    assert!(
        out.is_err(),
        "a replayed (session, seq) is refused by the guard"
    );
    assert_eq!(
        ex.applied, applied_after_first,
        "executor not called again — applied-list unchanged"
    );
    assert_eq!(b.audit().events.last().unwrap().outcome, Outcome::Rejected);
}

// 5. P3b-5 DoS trap: an unauthenticated command with a huge seq must NOT advance
//    the guard, so a genuine command at the normal next seq still admits.
#[test]
fn unauthenticated_execution_command_does_not_advance_the_guard() {
    let sig = FakeSig("secret");
    let policy = operator_policy();
    let mut b = Bridge::new(VecAuditSink::default());
    to_approved(&mut b, action("a", vec!["h1", "h2", "h3"]));

    let mut guard = ReplayGuard::new();
    guard.open_session("s1", 0);
    let mut ex = StubExec::default();

    // A garbage-signed Canary with a huge seq: if it advanced the mark, every later
    // legitimate seq would be refused forever (seq-exhaustion DoS).
    let garbage = ControlCommand {
        action_id: "a".into(),
        kind: CommandKind::Canary,
        actor: "alice".into(),
        session: "s1".into(),
        seq: u64::MAX,
        schedule: None,
        signature: "garbage".into(),
    };
    assert!(
        dispatch_execution_fresh(&mut b, &mut guard, garbage, &sig, &policy, &mut ex, &Fixed)
            .is_err(),
        "garbage-signed command rejected at authn"
    );
    assert!(
        ex.applied.is_empty(),
        "nothing applied by the rejected command"
    );

    // The genuine command at the normal next seq still admits — the mark was NOT advanced.
    let genuine = signed(&sig, "a", CommandKind::Canary, "alice", "s1", 1);
    let out = dispatch_execution_fresh(&mut b, &mut guard, genuine, &sig, &policy, &mut ex, &Fixed)
        .unwrap();
    assert_eq!(
        out,
        StageOutcome::Promoted,
        "the unauthenticated command did not brick the session"
    );
    assert_eq!(ex.applied, vec!["h1"], "the genuine canary applied");
}

// 6. Plain `dispatch` refuses execution kinds (defense in depth — it has no executor).
#[test]
fn dispatch_refuses_execution_kinds() {
    let sig = FakeSig("secret");
    let policy = operator_policy();
    let mut b = Bridge::new(VecAuditSink::default());
    to_approved(&mut b, action("a", vec!["h1", "h2"]));

    // A validly-signed, authorized Canary routed through plain dispatch is refused.
    let canary = signed(&sig, "a", CommandKind::Canary, "alice", "s1", 1);
    let out = dispatch(&mut b, canary, &sig, &policy);
    assert!(out.is_err(), "dispatch refuses execution kinds");
    assert!(out
        .unwrap_err()
        .to_string()
        .contains("requires the orchestrator"));
    assert_eq!(
        b.state("a"),
        Some(ActionState::Approved),
        "dispatch did not run the canary"
    );

    let rollout = signed(&sig, "a", CommandKind::Rollout, "alice", "s1", 2);
    assert!(
        dispatch(&mut b, rollout, &sig, &policy).is_err(),
        "dispatch refuses Rollout too"
    );
}

// 7. A validly-signed, authorized SCHEDULED canary (schedule: Some) routed to the IMMEDIATE
//    execution path is refused — a windowed command may run ONLY via the scheduler within its
//    window, never fired at once here (structural window guard). The executor applies NOTHING.
#[test]
fn a_scheduled_command_cannot_be_executed_immediately() {
    let sig = FakeSig("secret");
    let policy = operator_policy();
    let mut b = Bridge::new(VecAuditSink::default());
    to_approved(&mut b, action("a", vec!["h1", "h2"]));

    let mut guard = ReplayGuard::new();
    guard.open_session("s1", 0);
    let mut ex = StubExec::default();

    // A canary carrying a SIGNED window — valid signature, authorized actor, fresh seq.
    let mut cmd = ControlCommand {
        action_id: "a".into(),
        kind: CommandKind::Canary,
        actor: "alice".into(),
        session: "s1".into(),
        seq: 1,
        schedule: Some(Schedule {
            not_before: 10,
            not_after: 20,
        }),
        signature: String::new(),
    };
    cmd.signature = sig.sign(&cmd.payload(), &cmd.actor);

    let out = dispatch_execution_fresh(&mut b, &mut guard, cmd, &sig, &policy, &mut ex, &Fixed);
    assert!(
        out.is_err(),
        "a windowed command cannot bypass its window via the immediate path"
    );
    assert!(
        ex.applied.is_empty(),
        "nothing applied — a scheduled command must go through the scheduler"
    );
    assert_eq!(
        b.state("a"),
        Some(ActionState::Approved),
        "bridge state unchanged"
    );
    assert_eq!(b.audit().events.last().unwrap().outcome, Outcome::Rejected);
}
