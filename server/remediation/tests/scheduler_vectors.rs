//! Scheduled-execution golden vectors (P3b-9). An operator may schedule an already-
//! approved execution command (`Canary`/`Rollout`) for a signed change window. The
//! [`Scheduler`] holds the gate-validated command and RELEASES it only when the injected
//! [`Clock`] enters its window on a still-valid action — never auto-executing anything the
//! user did not author + sign + approve + schedule.
//!
//! Security properties proven here (deterministic `FakeClock`; `FakeSig` stands in for real
//! asymmetric verification — the real-ed25519 over-the-wire scheduled + window-tamper vectors
//! live in `server/control-plane/tests/channel_vectors.rs`):
//!  1. a scheduled canary fires ONLY inside its window (nothing before `not_before`);
//!  2. a missed window EXPIRES — dropped, audited, the executor NEVER runs;
//!  3. an aborted action never fires — proven by BOTH `cancel` and the state-guard backstop;
//!  4. a forged scheduled command is rejected at `enqueue` (never stored, never fires);
//!  5. an unauthorized scheduled command is rejected at `enqueue`;
//!  6. tampering the signed window breaks `enqueue` at the signature gate;
//!  7. an unscheduled (`schedule: None`) execution still fires immediately (P3b-8 unchanged).
use torda_remediation::action::*;
use torda_remediation::audit::*;
use torda_remediation::bridge::*;
use torda_remediation::control::*;
use torda_remediation::scheduler::Scheduler;

/// Accepts a signature iff it equals `sign(payload, actor)` — a deterministic stand-in for
/// real asymmetric verification. Tampering any signed field (incl. the window) breaks it.
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

/// A stub executor recording the targets it applied to, so a test can prove whether the
/// executor was consulted AT ALL — an empty applied-list means it NEVER ran.
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

/// A stub re-score verifier: always "fixed", so a healthy canary promotes.
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

/// Drive an action to `Approved` via the bridge's gated path (four-eyes: alice authors, bob approves).
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
    b.approve(&id, "bob").unwrap();
}

/// Sign a scheduled execution command carrying a (session, seq) freshness token + window.
fn signed_scheduled(
    sig: &FakeSig,
    action_id: &str,
    kind: CommandKind,
    actor: &str,
    session: &str,
    seq: u64,
    schedule: Option<Schedule>,
) -> ControlCommand {
    let mut cmd = ControlCommand {
        action_id: action_id.into(),
        kind,
        actor: actor.into(),
        session: session.into(),
        seq,
        schedule,
        signature: String::new(),
    };
    cmd.signature = sig.sign(&cmd.payload(), &cmd.actor);
    cmd
}

fn operator_policy() -> RolePolicy {
    let mut p = RolePolicy::new();
    p.assign("alice", Role::Operator); // may execute their approved change
    p.assign("carol", Role::Approver); // approves, but may NOT execute
    p
}

fn open_guard(session: &str) -> ReplayGuard {
    let mut g = ReplayGuard::new();
    g.open_session(session, 0);
    g
}

// 1. A scheduled canary fires ONLY within its window: enqueue at now=5 with window [10,20];
//    tick at 5 -> nothing (window not open); advance to 15; tick -> Promoted, targets applied.
#[test]
fn scheduled_canary_fires_only_within_its_window() {
    let sig = FakeSig("secret");
    let policy = operator_policy();
    let mut b = Bridge::new(VecAuditSink::default());
    to_approved(&mut b, action("a", vec!["h1", "h2", "h3"]));
    let mut guard = open_guard("s1");
    let mut sched = Scheduler::new();
    let clock = FakeClock::new(5);

    // Enqueue a canary scheduled for [10, 20] at now=5.
    let cmd = signed_scheduled(
        &sig,
        "a",
        CommandKind::Canary,
        "alice",
        "s1",
        1,
        Some(Schedule {
            not_before: 10,
            not_after: 20,
        }),
    );
    let window = sched
        .enqueue(&mut b, &mut guard, cmd, &sig, &policy, &clock)
        .unwrap();
    assert_eq!(
        window,
        Schedule {
            not_before: 10,
            not_after: 20
        },
        "enqueue returns the signed window"
    );
    assert_eq!(sched.pending_len(), 1, "held pending — not fired yet");

    // Tick BEFORE the window opens: nothing fires, nothing applied.
    let mut ex = StubExec::default();
    let fired = sched.tick(&mut b, &clock, &mut ex, &Fixed);
    assert!(
        fired.is_empty(),
        "before not_before the command does not fire"
    );
    assert!(
        ex.applied.is_empty(),
        "the executor NEVER ran before the window opened"
    );
    assert_eq!(
        b.state("a"),
        Some(ActionState::Approved),
        "action still Approved, nothing executed"
    );
    assert_eq!(
        sched.pending_len(),
        1,
        "still pending until its window opens"
    );

    // Advance INTO the window and tick: it fires -> Promoted, targets applied.
    clock.advance(10); // now = 15
    let fired = sched.tick(&mut b, &clock, &mut ex, &Fixed);
    assert_eq!(
        fired,
        vec![("a".to_string(), StageOutcome::Promoted)],
        "fires in-window -> Promoted"
    );
    assert_eq!(
        ex.applied,
        vec!["h1"],
        "the canary cohort (size 1) was applied to a real target"
    );
    assert_eq!(
        b.state("a"),
        Some(ActionState::Rollout),
        "promoted to Rollout"
    );
    assert_eq!(sched.pending_len(), 0, "released — no longer pending");
}

// 2. A scheduled canary whose window is MISSED expires: never ticked in-window, advance past
//    not_after -> tick drops + audits it "expired", the executor NEVER ran, state unchanged.
#[test]
fn scheduled_canary_expires_if_window_missed() {
    let sig = FakeSig("secret");
    let policy = operator_policy();
    let mut b = Bridge::new(VecAuditSink::default());
    to_approved(&mut b, action("a", vec!["h1", "h2"]));
    let mut guard = open_guard("s1");
    let mut sched = Scheduler::new();
    let clock = FakeClock::new(5);

    let cmd = signed_scheduled(
        &sig,
        "a",
        CommandKind::Canary,
        "alice",
        "s1",
        1,
        Some(Schedule {
            not_before: 10,
            not_after: 20,
        }),
    );
    sched
        .enqueue(&mut b, &mut guard, cmd, &sig, &policy, &clock)
        .unwrap();

    // Never tick within [10,20]. Jump past not_after.
    clock.set(25);
    let mut ex = StubExec::default();
    let fired = sched.tick(&mut b, &clock, &mut ex, &Fixed);
    assert!(fired.is_empty(), "an expired command NEVER fires late");
    assert!(
        ex.applied.is_empty(),
        "the executor NEVER ran — nothing applied to any target"
    );
    assert_eq!(
        b.state("a"),
        Some(ActionState::Approved),
        "state unchanged by the expired command"
    );
    assert_eq!(
        sched.pending_len(),
        0,
        "the expired command was dropped from the queue"
    );
    // The expiry is audited.
    assert!(
        b.audit()
            .events
            .iter()
            .any(|e| e.outcome == Outcome::Rejected && e.detail.contains("expired")),
        "expiry is audited"
    );
}

// 3. An aborted action's scheduled canary never fires — proven BOTH ways:
//    (a) `cancel` removes it from the queue; and (b) with cancel SKIPPED, the release
//    state-guard (run_canary requires Approved) still stops it. Either way the executor never runs.
#[test]
fn aborted_action_scheduled_canary_never_fires() {
    let sig = FakeSig("secret");
    let policy = operator_policy();
    let window = Some(Schedule {
        not_before: 10,
        not_after: 20,
    });

    // (a) cancel() drops the pending command.
    {
        let mut b = Bridge::new(VecAuditSink::default());
        to_approved(&mut b, action("a", vec!["h1", "h2"]));
        let mut guard = open_guard("s1");
        let mut sched = Scheduler::new();
        let clock = FakeClock::new(5);
        let cmd = signed_scheduled(
            &sig,
            "a",
            CommandKind::Canary,
            "alice",
            "s1",
            1,
            window.clone(),
        );
        sched
            .enqueue(&mut b, &mut guard, cmd, &sig, &policy, &clock)
            .unwrap();
        // Operator aborts the action, and the loop cancels its scheduled commands.
        b.abort("a", "alice", "change cancelled").unwrap();
        sched.cancel(&mut b, "a");
        assert_eq!(sched.pending_len(), 0, "cancel removed the pending command");
        assert!(
            b.audit()
                .events
                .iter()
                .any(|e| e.detail.contains("cancelled by abort")),
            "the cancellation is audited"
        );
        // Advance INTO the window and tick: nothing pending, nothing fires.
        clock.set(15);
        let mut ex = StubExec::default();
        let fired = sched.tick(&mut b, &clock, &mut ex, &Fixed);
        assert!(
            fired.is_empty(),
            "a cancelled scheduled command never fires"
        );
        assert!(
            ex.applied.is_empty(),
            "the executor never ran for a cancelled change"
        );
        assert_eq!(b.state("a"), Some(ActionState::Aborted));
    }

    // (b) SKIP cancel: the release state-guard is the independent backstop.
    {
        let mut b = Bridge::new(VecAuditSink::default());
        to_approved(&mut b, action("a", vec!["h1", "h2"]));
        let mut guard = open_guard("s1");
        let mut sched = Scheduler::new();
        let clock = FakeClock::new(5);
        let cmd = signed_scheduled(
            &sig,
            "a",
            CommandKind::Canary,
            "alice",
            "s1",
            1,
            window.clone(),
        );
        sched
            .enqueue(&mut b, &mut guard, cmd, &sig, &policy, &clock)
            .unwrap();
        // Abort WITHOUT cancelling the scheduler — the command still sits pending.
        b.abort("a", "alice", "change cancelled").unwrap();
        assert_eq!(sched.pending_len(), 1, "still pending (cancel skipped)");
        // Advance into the window and tick: run_canary hits the state guard (not Approved)
        // and applies NOTHING; the command fires nothing.
        clock.set(15);
        let mut ex = StubExec::default();
        let fired = sched.tick(&mut b, &clock, &mut ex, &Fixed);
        assert!(
            fired.is_empty(),
            "the state-guard backstop stops an aborted action"
        );
        assert!(
            ex.applied.is_empty(),
            "the executor never ran — the aborted action applies nothing"
        );
        assert_eq!(b.state("a"), Some(ActionState::Aborted), "still Aborted");
    }
}

// 4. A forged scheduled command is rejected at enqueue (signature gate): not stored; a later tick fires nothing.
#[test]
fn forged_scheduled_command_is_rejected_at_enqueue() {
    let sig = FakeSig("secret");
    let policy = operator_policy();
    let mut b = Bridge::new(VecAuditSink::default());
    to_approved(&mut b, action("a", vec!["h1", "h2"]));
    let mut guard = open_guard("s1");
    let mut sched = Scheduler::new();
    let clock = FakeClock::new(5);

    // A scheduled canary with a BAD signature (valid session/seq/window, but not authentic).
    let forged = ControlCommand {
        action_id: "a".into(),
        kind: CommandKind::Canary,
        actor: "alice".into(),
        session: "s1".into(),
        seq: 1,
        schedule: Some(Schedule {
            not_before: 10,
            not_after: 20,
        }),
        signature: "forged".into(),
    };
    let out = sched.enqueue(&mut b, &mut guard, forged, &sig, &policy, &clock);
    assert!(
        out.is_err(),
        "forged scheduled command rejected at the signature gate"
    );
    assert_eq!(sched.pending_len(), 0, "a forged command is NEVER stored");
    assert_eq!(b.audit().events.last().unwrap().outcome, Outcome::Rejected);

    // Even inside the window, a later tick fires nothing (nothing was enqueued).
    clock.set(15);
    let mut ex = StubExec::default();
    assert!(sched.tick(&mut b, &clock, &mut ex, &Fixed).is_empty());
    assert!(
        ex.applied.is_empty(),
        "the executor never ran for the rejected forged command"
    );
    assert_eq!(b.state("a"), Some(ActionState::Approved));
}

// 5. A validly-signed scheduled command by a role that may NOT execute (carol, an Approver)
//    is rejected at enqueue (authz gate); not stored.
#[test]
fn unauthorized_scheduled_command_is_rejected_at_enqueue() {
    let sig = FakeSig("secret");
    let policy = operator_policy();
    let mut b = Bridge::new(VecAuditSink::default());
    to_approved(&mut b, action("a", vec!["h1", "h2"]));
    let mut guard = open_guard("s1");
    let mut sched = Scheduler::new();
    let clock = FakeClock::new(5);

    // Carol is an Approver — validly signs, but Approvers may NOT execute.
    let cmd = signed_scheduled(
        &sig,
        "a",
        CommandKind::Canary,
        "carol",
        "s1",
        1,
        Some(Schedule {
            not_before: 10,
            not_after: 20,
        }),
    );
    let out = sched.enqueue(&mut b, &mut guard, cmd, &sig, &policy, &clock);
    assert!(
        out.is_err(),
        "an Approver is not authorized to schedule an execution"
    );
    assert_eq!(
        sched.pending_len(),
        0,
        "an unauthorized command is NEVER stored"
    );
    assert_eq!(b.audit().events.last().unwrap().outcome, Outcome::Rejected);
}

// 6. Tampering the signed window breaks enqueue: sign with [10,20], bump not_after to 999
//    keeping the signature -> the recomputed payload no longer matches -> rejected at the
//    signature gate, never stored. (Real-ed25519 counterpart is in channel_vectors.rs.)
#[test]
fn tampering_the_window_breaks_enqueue() {
    let sig = FakeSig("secret");
    let policy = operator_policy();
    let mut b = Bridge::new(VecAuditSink::default());
    to_approved(&mut b, action("a", vec!["h1", "h2"]));
    let mut guard = open_guard("s1");
    let mut sched = Scheduler::new();
    let clock = FakeClock::new(5);

    // Sign a canary bound to window [10,20].
    let mut cmd = signed_scheduled(
        &sig,
        "a",
        CommandKind::Canary,
        "alice",
        "s1",
        1,
        Some(Schedule {
            not_before: 10,
            not_after: 20,
        }),
    );
    // Attacker widens the window AFTER signing, keeping the original signature.
    cmd.schedule = Some(Schedule {
        not_before: 10,
        not_after: 999,
    });
    let out = sched.enqueue(&mut b, &mut guard, cmd, &sig, &policy, &clock);
    assert!(
        out.is_err(),
        "a tampered window invalidates the signature -> rejected at enqueue"
    );
    assert_eq!(
        sched.pending_len(),
        0,
        "the tampered command is never stored"
    );
    assert_eq!(b.audit().events.last().unwrap().outcome, Outcome::Rejected);
}

// 7. Regression: an UNSCHEDULED (schedule: None) execution still fires immediately via
//    dispatch_execution_fresh (the P3b-8 path), untouched by the scheduler.
#[test]
fn unscheduled_execution_is_immediate() {
    let sig = FakeSig("secret");
    let policy = operator_policy();
    let mut b = Bridge::new(VecAuditSink::default());
    to_approved(&mut b, action("a", vec!["h1", "h2", "h3"]));
    let mut guard = open_guard("s1");
    let mut ex = StubExec::default();

    // schedule: None -> the immediate execution path applies at once, no scheduler involved.
    let canary = signed_scheduled(&sig, "a", CommandKind::Canary, "alice", "s1", 1, None);
    let out = dispatch_execution_fresh(&mut b, &mut guard, canary, &sig, &policy, &mut ex, &Fixed)
        .unwrap();
    assert_eq!(
        out,
        StageOutcome::Promoted,
        "an unscheduled execution fires immediately (P3b-8 unchanged)"
    );
    assert_eq!(
        ex.applied,
        vec!["h1"],
        "the canary cohort applied immediately"
    );
    assert_eq!(b.state("a"), Some(ActionState::Rollout));
}
