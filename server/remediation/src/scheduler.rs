//! Deferred, change-window-aligned release of approved execution commands.
//!
//! Ops teams must land production changes inside an approved **change window**, not
//! "whenever the operator clicks execute". The [`Scheduler`] holds a gate-validated,
//! approved-but-not-yet-fired execution command (`Canary`/`Rollout`) and RELEASES it
//! only when the injected [`Clock`] enters its signed window on a still-valid action.
//!
//! This stays true to "a bridge, never a decider": the scheduler ORIGINATES nothing.
//! It releases a command the user already authored, signed, got approved (via the
//! four-eyes action lifecycle), AND scheduled. A cancelled (aborted) or expired command
//! NEVER fires. The full gate stack runs ONCE, at enqueue — so the freshness `seq` is
//! consumed exactly once and the held command cannot be tampered in the queue.
use crate::audit::AuditSink;
use crate::bridge::{Bridge, Executor, StageOutcome, Verifier};
use crate::control::{
    gate_execution, Authorizer, Clock, CommandKind, ControlCommand, ReplayGuard, Schedule,
    SignatureVerifier,
};

/// A gate-validated execution command awaiting its window. The `cmd` is fully
/// authenticated + authorized (its gates ran at enqueue); `schedule` is the signed
/// window copied out for cheap window checks at each tick.
struct Pending {
    cmd: ControlCommand,
    schedule: Schedule,
}

/// Holds gate-validated, approved-but-not-yet-fired execution commands and releases
/// each when the clock enters its window on a still-valid action.
///
/// NEVER auto-executes: every held command was authored + signed + approved + scheduled
/// by a human. Cancelled or expired commands never fire. The ONLY time source consulted
/// is the injected [`Clock`] (read solely here — the dispatch gates stay clock-free).
#[derive(Default)]
pub struct Scheduler {
    pending: Vec<Pending>,
}

impl Scheduler {
    /// A scheduler with no pending commands.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of commands currently held pending (for observability / tests).
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Validate + enqueue a SCHEDULED execution command.
    ///
    /// Runs the FULL execution gate stack ONCE ([`gate_execution`]: authn → freshness →
    /// authz → is-execution) — so the freshness `seq` is consumed here and now, NOT
    /// re-admitted at release. Additionally requires `cmd.schedule.is_some()` and rejects
    /// (bail + audit) if `clock.now() > not_after` (the window already passed). Every
    /// rejection is audited and the command is NOT stored — a forged, unauthorized, stale,
    /// or already-expired scheduled command can never sit in the queue and can never fire.
    ///
    /// On success the verified command is stored and its [`Schedule`] is returned (so the
    /// caller can report "scheduled [nb,na]"). The clock is the ONLY time read.
    pub fn enqueue<A: AuditSink>(
        &mut self,
        bridge: &mut Bridge<A>,
        guard: &mut ReplayGuard,
        cmd: ControlCommand,
        sig: &dyn SignatureVerifier,
        authz: &dyn Authorizer,
        clock: &dyn Clock,
    ) -> anyhow::Result<Schedule> {
        // Gate ONCE (authn -> freshness -> authz -> is-execution). Consumes the seq.
        gate_execution(bridge, guard, &cmd, sig, authz)?;

        // A scheduled enqueue requires a signed window (defense in depth — the loop only
        // routes here when schedule.is_some(), but never fire an unscheduled command here).
        let Some(schedule) = cmd.schedule.clone() else {
            bridge.audit_rejected_command(
                &cmd.action_id,
                &cmd.actor,
                &format!(
                    "scheduled enqueue of {} requires a schedule window",
                    cmd.kind.label()
                ),
            );
            anyhow::bail!(
                "rejected: scheduled {} on {} has no window",
                cmd.kind.label(),
                cmd.action_id
            );
        };

        // Already expired at enqueue: never store it — it could never fire in-window.
        if clock.now() > schedule.not_after {
            bridge.audit_rejected_command(
                &cmd.action_id,
                &cmd.actor,
                &format!(
                    "expired: window [{},{}] already passed at enqueue (now {})",
                    schedule.not_before,
                    schedule.not_after,
                    clock.now()
                ),
            );
            anyhow::bail!(
                "rejected: {} on {} already expired (window [{},{}], now {})",
                cmd.kind.label(),
                cmd.action_id,
                schedule.not_before,
                schedule.not_after,
                clock.now()
            );
        }

        self.pending.push(Pending {
            cmd,
            schedule: schedule.clone(),
        });
        Ok(schedule)
    }

    /// Release every pending command whose window is OPEN (`not_before <= now <=
    /// not_after`), running its stage via `run_canary`/`run_rollout` with the given
    /// executor/verifier and the command's stored `actor`.
    ///
    /// The bridge's OWN state guard is the backstop: a released command against an
    /// aborted or wrong-state action fails inside `run_*` and applies NOTHING (its
    /// `Err` is dropped, the command discarded). A command past `not_after` that never
    /// fired is dropped + audited "expired" and NEVER fires late. A command whose window
    /// has not yet opened (`now < not_before`) stays pending. Returns `(action_id,
    /// outcome)` for each command that actually fired. The clock is the ONLY time read.
    pub fn tick<A: AuditSink>(
        &mut self,
        bridge: &mut Bridge<A>,
        clock: &dyn Clock,
        executor: &mut dyn Executor,
        verifier: &dyn Verifier,
    ) -> Vec<(String, StageOutcome)> {
        let now = clock.now();
        let mut fired = Vec::new();
        let mut still_pending = Vec::new();

        for p in std::mem::take(&mut self.pending) {
            if now > p.schedule.not_after {
                // EXPIRED: the window closed before it fired — drop + audit, never late.
                bridge.audit_rejected_command(
                    &p.cmd.action_id,
                    &p.cmd.actor,
                    &format!(
                        "expired: window [{},{}] missed (now {})",
                        p.schedule.not_before, p.schedule.not_after, now
                    ),
                );
                continue;
            }
            if now < p.schedule.not_before {
                // Window not open yet — leave it pending, fire nothing.
                still_pending.push(p);
                continue;
            }
            // Window OPEN: release the stage. run_* is state-guarded — an aborted /
            // wrong-state action applies nothing (the released command's Err is dropped).
            // Capture state before dispatch: a run that changed state actually RAN (and
            // then failed), vs a pre-gate state rejection which leaves state untouched.
            let before = bridge.state(&p.cmd.action_id);
            let result = match p.cmd.kind {
                CommandKind::Canary => {
                    bridge.run_canary(&p.cmd.action_id, executor, verifier, &p.cmd.actor)
                }
                CommandKind::Rollout => {
                    bridge.run_rollout(&p.cmd.action_id, executor, verifier, &p.cmd.actor)
                }
                // Operator-commanded rollback (no verifier — a rollback is not verified).
                CommandKind::Rollback => {
                    bridge.run_rollback(&p.cmd.action_id, executor, &p.cmd.actor)
                }
                // Unreachable: gate_execution guaranteed an execution kind at enqueue.
                _ => Err(anyhow::anyhow!("not an execution kind")),
            };
            match result {
                Ok(outcome) => fired.push((p.cmd.action_id.clone(), outcome)),
                Err(e) if bridge.state(&p.cmd.action_id) != before => {
                    // The command PASSED its state guard and ran, then FAILED mid-execution
                    // (e.g. a rollback that reverted some targets but not others — the action
                    // is now RollbackIncomplete). This is a real execution failure, NOT a
                    // pre-gate state rejection: surface it distinctly on the audit trail.
                    bridge.audit_execution_failure(
                        &p.cmd.action_id,
                        &p.cmd.actor,
                        &format!("scheduled {} executed but failed: {e}", p.cmd.kind.label()),
                    );
                }
                // The bridge state guard refused it (e.g. a Rollout whose window opened
                // before its Canary promoted, or an action aborted out of band): it applied
                // NOTHING and is dropped. Audit the drop so a scheduled command lost to a
                // state mismatch is visible (mirrors the expiry-drop audit above).
                Err(_) => bridge.audit_rejected_command(
                    &p.cmd.action_id,
                    &p.cmd.actor,
                    &format!(
                        "scheduled command dropped: action not in a valid state to run {}",
                        p.cmd.kind.label()
                    ),
                ),
            }
        }

        self.pending = still_pending;
        fired
    }

    /// Drop all pending commands for `action_id` — called when the action is Aborted (and
    /// the abort AUTHENTICATED + applied), so a cancelled change never fires. Each dropped
    /// command is AUDITED ("scheduled command cancelled by abort") so the suppression is
    /// visible on the trail. (The `run_*` state guard is a second, independent backstop for
    /// any command not dropped here.)
    pub fn cancel<A: AuditSink>(&mut self, bridge: &mut Bridge<A>, action_id: &str) {
        let (cancelled, keep): (Vec<Pending>, Vec<Pending>) = std::mem::take(&mut self.pending)
            .into_iter()
            .partition(|p| p.cmd.action_id == action_id);
        for p in &cancelled {
            bridge.audit_rejected_command(
                &p.cmd.action_id,
                &p.cmd.actor,
                &format!(
                    "scheduled command cancelled by abort ({})",
                    p.cmd.kind.label()
                ),
            );
        }
        self.pending = keep;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{
        ActionState, AssetSelector, CanarySpec, Method, RemediationAction, VerifySpec,
    };
    use crate::audit::VecAuditSink;
    use crate::bridge::VerifyOutcome;
    use crate::control::{FakeClock, Role, RolePolicy};

    /// Accept-all signature stub — the signature gate itself is exercised in
    /// `tests/scheduler_vectors.rs`; here we only need a validly-admitted command.
    struct AcceptAll;
    impl SignatureVerifier for AcceptAll {
        fn verify(&self, _p: &str, _s: &str, _a: &str) -> bool {
            true
        }
    }

    /// Records the targets it applied/rolled back so a test can prove the executor ran.
    #[derive(Default)]
    struct StubExec {
        applied: Vec<String>,
        rolled_back: Vec<String>,
    }
    impl Executor for StubExec {
        fn preview(&self, _a: &RemediationAction) -> String {
            String::new()
        }
        fn apply(&mut self, _a: &RemediationAction, t: &str) -> anyhow::Result<()> {
            self.applied.push(t.to_string());
            Ok(())
        }
        fn rollback(&mut self, _a: &RemediationAction, t: &str) -> anyhow::Result<()> {
            self.rolled_back.push(t.to_string());
            Ok(())
        }
    }

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
                finding_ids: vec![],
            },
            canary: CanarySpec {
                cohort_size: 1,
                failure_threshold: 0.0,
            },
        }
    }

    // P2 regression: a signed, windowed `Rollback` is enqueued (is_execution) and MUST
    // actually run when its window opens — not be dropped at tick's wildcard arm.
    #[test]
    fn scheduled_rollback_runs_when_window_opens() {
        let mut b = Bridge::new(VecAuditSink::default());
        // Drive "a" to an applied, Closed state via the gated lifecycle + staged apply.
        b.draft(action("a", vec!["h1", "h2"]), "alice").unwrap();
        b.dry_run("a", &StubExec::default(), "alice").unwrap();
        b.submit_for_approval("a", "alice").unwrap();
        b.approve("a", "bob").unwrap();
        let mut applyer = StubExec::default();
        b.run_canary("a", &mut applyer, &Fixed, "alice").unwrap();
        b.run_rollout("a", &mut applyer, &Fixed, "alice").unwrap();
        assert_eq!(b.state("a"), Some(ActionState::Closed));

        let mut policy = RolePolicy::new();
        policy.assign("alice", Role::Operator);
        let mut guard = ReplayGuard::new();
        guard.open_session("s1", 0);
        let sig = AcceptAll;
        let clock = FakeClock::new(5);
        let mut sched = Scheduler::new();

        let cmd = ControlCommand {
            action_id: "a".into(),
            kind: CommandKind::Rollback,
            actor: "alice".into(),
            session: "s1".into(),
            seq: 1,
            schedule: Some(Schedule {
                not_before: 10,
                not_after: 20,
            }),
            signature: String::new(),
        };
        sched
            .enqueue(&mut b, &mut guard, cmd, &sig, &policy, &clock)
            .unwrap();
        assert_eq!(sched.pending_len(), 1, "held pending — window not open yet");

        // Before the window: nothing fires, executor untouched.
        let mut ex = StubExec::default();
        assert!(sched.tick(&mut b, &clock, &mut ex, &Fixed).is_empty());
        assert!(ex.rolled_back.is_empty(), "rollback not run before window");
        assert_eq!(b.state("a"), Some(ActionState::Closed));

        // Advance into the window: the scheduled rollback RUNS.
        clock.set(15);
        let fired = sched.tick(&mut b, &clock, &mut ex, &Fixed);
        assert_eq!(
            fired,
            vec![("a".to_string(), StageOutcome::RolledBackByOperator)],
            "scheduled Rollback fires in-window via run_rollback"
        );
        assert_eq!(
            ex.rolled_back,
            vec!["h1", "h2"],
            "both applied targets were reverted by the executor"
        );
        assert_eq!(b.state("a"), Some(ActionState::RolledBack));
        assert_eq!(sched.pending_len(), 0, "released — no longer pending");
    }

    // P2 regression: a scheduled rollback on a VALID applied action whose executor FAILS
    // mid-revert is an execution failure, NOT a pre-gate "not in a valid state" rejection.
    #[test]
    fn scheduled_rollback_execution_failure_is_not_a_state_rejection() {
        /// Applies OK but every rollback fails.
        #[derive(Default)]
        struct FailRollback {
            applied: Vec<String>,
        }
        impl Executor for FailRollback {
            fn preview(&self, _a: &RemediationAction) -> String {
                String::new()
            }
            fn apply(&mut self, _a: &RemediationAction, t: &str) -> anyhow::Result<()> {
                self.applied.push(t.to_string());
                Ok(())
            }
            fn rollback(&mut self, _a: &RemediationAction, target: &str) -> anyhow::Result<()> {
                anyhow::bail!("simulated rollback failure on {target}")
            }
        }

        let mut b = Bridge::new(VecAuditSink::default());
        b.draft(action("a", vec!["h1", "h2"]), "alice").unwrap();
        b.dry_run("a", &StubExec::default(), "alice").unwrap();
        b.submit_for_approval("a", "alice").unwrap();
        b.approve("a", "bob").unwrap();
        let mut applyer = StubExec::default();
        b.run_canary("a", &mut applyer, &Fixed, "alice").unwrap();
        b.run_rollout("a", &mut applyer, &Fixed, "alice").unwrap();
        assert_eq!(b.state("a"), Some(ActionState::Closed));

        let mut policy = RolePolicy::new();
        policy.assign("alice", Role::Operator);
        let mut guard = ReplayGuard::new();
        guard.open_session("s1", 0);
        let sig = AcceptAll;
        let clock = FakeClock::new(5);
        let mut sched = Scheduler::new();

        let cmd = ControlCommand {
            action_id: "a".into(),
            kind: CommandKind::Rollback,
            actor: "alice".into(),
            session: "s1".into(),
            seq: 1,
            schedule: Some(Schedule {
                not_before: 10,
                not_after: 20,
            }),
            signature: String::new(),
        };
        sched
            .enqueue(&mut b, &mut guard, cmd, &sig, &policy, &clock)
            .unwrap();

        clock.set(15);
        let mut ex = FailRollback::default();
        let fired = sched.tick(&mut b, &clock, &mut ex, &Fixed);
        assert!(fired.is_empty(), "a failed rollback is not a fired success");
        assert_eq!(
            b.state("a"),
            Some(ActionState::RollbackIncomplete),
            "the rollback ran and failed -> RollbackIncomplete (it DID pass its state guard)"
        );

        let events = &b.audit().events;
        assert!(
            !events
                .iter()
                .any(|e| e.detail.contains("not in a valid state")),
            "a real execution failure must NOT be audited as a pre-gate state rejection"
        );
        assert!(
            events
                .iter()
                .any(|e| e.outcome == crate::audit::Outcome::Failed
                    && e.detail.contains("executed but failed")),
            "the execution failure is surfaced distinctly on the audit trail"
        );
    }
}
