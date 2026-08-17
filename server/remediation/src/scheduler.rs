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
            let result = match p.cmd.kind {
                CommandKind::Canary => {
                    bridge.run_canary(&p.cmd.action_id, executor, verifier, &p.cmd.actor)
                }
                CommandKind::Rollout => {
                    bridge.run_rollout(&p.cmd.action_id, executor, verifier, &p.cmd.actor)
                }
                // Unreachable: gate_execution guaranteed an execution kind at enqueue.
                _ => Err(anyhow::anyhow!("not an execution kind")),
            };
            match result {
                Ok(outcome) => fired.push((p.cmd.action_id.clone(), outcome)),
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
