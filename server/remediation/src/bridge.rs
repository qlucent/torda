//! The pre-execution state machine. It moves a user-authored action through
//! Drafted → Mapped → DryRun → PendingApproval → Approved (or Aborted), enforcing
//! the scope, dry-run, and approval gates as transition guards and auditing every
//! attempt. There is NO execution here — reaching `Approved` (the only state from
//! which execution will ever be permitted) requires a dry-run AND an approval.
use std::collections::HashMap;

use crate::action::{ActionState, RemediationAction};
use crate::audit::{AuditEvent, AuditSink, Outcome};

/// The seam to real execution. `preview` is side-effect-free (dry-run). `apply`
/// runs the user's payload on ONE target; `rollback` runs the user's rollback
/// payload on ONE target. `apply`/`rollback` are called ONLY from the post-Approval
/// execution flow (run_canary / run_rollout) — never before `Approved`.
pub trait Executor {
    fn preview(&self, action: &RemediationAction) -> String;
    /// Apply the user's payload to one target. Ok = applied; Err = failed on that target.
    fn apply(&mut self, action: &RemediationAction, target: &str) -> anyhow::Result<()>;
    /// Run the user's rollback payload on one target (best-effort on failure paths).
    fn rollback(&mut self, action: &RemediationAction, target: &str) -> anyhow::Result<()>;
}

/// Did the linked finding(s) re-score as fixed after applying to `applied` targets?
/// P3a-2 ships a stub/fake; P3a-3 wires the real Findings-Engine re-score here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyOutcome {
    Fixed,
    NotFixed,
}

/// The verification seam. Kept separate from `Executor` so the real re-score
/// (P3a-3) can be injected without touching the execution machinery.
pub trait Verifier {
    fn verify(&self, action: &RemediationAction, applied: &[String]) -> VerifyOutcome;
}

/// The result of applying to one target.
#[derive(Clone, Debug, PartialEq)]
pub struct TargetResult {
    pub target: String,
    pub applied: bool,
    pub error: Option<String>,
}

/// The outcome of an execution stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StageOutcome {
    Promoted,
    Closed,
    RolledBack,
    /// A full rollout applied, but the final re-score still found the issue. The
    /// fix is left APPLIED (not rolled back) and the action is not Closed — it is
    /// applied-but-unverified (state stays `Verify`); an operator investigates.
    AppliedUnverified,
}

/// The side-effect-free result of a dry run: the scoped targets and a preview.
#[derive(Clone, Debug, PartialEq)]
pub struct DryRunPreview {
    pub action_id: String,
    pub targets: Vec<String>,
    pub preview: String,
}

struct Record {
    action: RemediationAction,
    state: ActionState,
    applied: Vec<String>,
}

/// The pre-execution state machine over a set of actions, writing every attempted
/// transition to an audit sink.
pub struct Bridge<A: AuditSink> {
    actions: HashMap<String, Record>,
    audit: A,
    seq: u64,
}

impl<A: AuditSink> Bridge<A> {
    pub fn new(audit: A) -> Self {
        Self {
            actions: HashMap::new(),
            audit,
            seq: 0,
        }
    }

    pub fn state(&self, id: &str) -> Option<ActionState> {
        self.actions.get(id).map(|r| r.state)
    }

    pub fn audit(&self) -> &A {
        &self.audit
    }

    fn log(
        &mut self,
        action_id: &str,
        from: Option<ActionState>,
        to: ActionState,
        actor: &str,
        outcome: Outcome,
        detail: &str,
    ) {
        let seq = self.seq;
        self.seq += 1;
        self.audit.record(AuditEvent {
            seq,
            action_id: action_id.to_string(),
            from,
            to,
            actor: actor.to_string(),
            outcome,
            detail: detail.to_string(),
        });
    }

    /// Audits a control command rejected at the signature gate (no state change).
    pub fn audit_rejected_command(&mut self, action_id: &str, actor: &str, detail: &str) {
        let seq = self.seq;
        self.seq += 1;
        self.audit.record(crate::audit::AuditEvent {
            seq,
            action_id: action_id.to_string(),
            from: None,
            to: crate::action::ActionState::Aborted,
            actor: actor.to_string(),
            outcome: crate::audit::Outcome::Rejected,
            detail: detail.to_string(),
        });
    }

    /// Draft a user-authored action. Gate 2 (scope): an unscoped selector is
    /// refused and the action is NOT stored; the rejection is audited.
    pub fn draft(&mut self, action: RemediationAction, actor: &str) -> anyhow::Result<()> {
        if !action.targets.is_scoped() {
            self.log(
                &action.id,
                None,
                ActionState::Drafted,
                actor,
                Outcome::Rejected,
                "unscoped selector",
            );
            anyhow::bail!("action {} has no explicit targets", action.id);
        }
        let id = action.id.clone();
        self.actions.insert(
            id.clone(),
            Record {
                action,
                state: ActionState::Drafted,
                applied: Vec::new(),
            },
        );
        self.log(
            &id,
            None,
            ActionState::Drafted,
            actor,
            Outcome::Ok,
            "drafted",
        );
        Ok(())
    }

    /// Optionally link the action to a Remediation Item (Drafted -> Mapped).
    pub fn map_to_item(&mut self, id: &str, item_key: &str, actor: &str) -> anyhow::Result<()> {
        self.guarded(
            id,
            &[ActionState::Drafted],
            ActionState::Mapped,
            actor,
            &format!("mapped to {item_key}"),
        )
    }

    /// Gate 3 (dry-run): preview with zero side effects. Allowed from Drafted or
    /// Mapped; moves to DryRun. Returns the preview; changes nothing on any target.
    pub fn dry_run(
        &mut self,
        id: &str,
        executor: &dyn Executor,
        actor: &str,
    ) -> anyhow::Result<DryRunPreview> {
        let (from, preview) = {
            let rec = self
                .actions
                .get(id)
                .ok_or_else(|| anyhow::anyhow!("no action {id}"))?;
            if !matches!(rec.state, ActionState::Drafted | ActionState::Mapped) {
                let from = rec.state;
                self.log(
                    id,
                    Some(from),
                    ActionState::DryRun,
                    actor,
                    Outcome::Rejected,
                    "not draftable state for dry-run",
                );
                anyhow::bail!("action {id} cannot dry-run from {:?}", from);
            }
            (
                rec.state,
                DryRunPreview {
                    action_id: id.to_string(),
                    targets: rec.action.targets.asset_ids.clone(),
                    preview: executor.preview(&rec.action),
                },
            )
        };
        self.actions.get_mut(id).unwrap().state = ActionState::DryRun;
        self.log(
            id,
            Some(from),
            ActionState::DryRun,
            actor,
            Outcome::Ok,
            "dry-run preview (no side effects)",
        );
        Ok(preview)
    }

    /// Move a previewed action to PendingApproval (only from DryRun — dry-run is
    /// required before approval can even be requested).
    pub fn submit_for_approval(&mut self, id: &str, actor: &str) -> anyhow::Result<()> {
        self.guarded(
            id,
            &[ActionState::DryRun],
            ActionState::PendingApproval,
            actor,
            "submitted for approval",
        )
    }

    /// Gate 4 (approval): approve a pending action (only from PendingApproval).
    /// `Approved` is the sole state from which execution will ever be permitted.
    pub fn approve(&mut self, id: &str, approver: &str) -> anyhow::Result<()> {
        self.guarded(
            id,
            &[ActionState::PendingApproval],
            ActionState::Approved,
            approver,
            "approved",
        )
    }

    /// Reject a pending action (PendingApproval -> Aborted).
    pub fn reject(&mut self, id: &str, approver: &str, reason: &str) -> anyhow::Result<()> {
        self.guarded(
            id,
            &[ActionState::PendingApproval],
            ActionState::Aborted,
            approver,
            &format!("rejected: {reason}"),
        )
    }

    /// Executes the canary cohort of an Approved action. Applies the user's payload
    /// to the first `canary.cohort_size` targets; if the apply-failure rate exceeds
    /// the threshold, or verification returns NotFixed, rolls back the applied
    /// targets and moves to RolledBack. Otherwise promotes to Rollout.
    pub fn run_canary(
        &mut self,
        id: &str,
        executor: &mut dyn Executor,
        verifier: &dyn Verifier,
        actor: &str,
    ) -> anyhow::Result<StageOutcome> {
        // Gate: execution only from Approved.
        self.guarded(
            id,
            &[ActionState::Approved],
            ActionState::Canary,
            actor,
            "canary started",
        )?;

        let (cohort, threshold) = {
            let rec = self.actions.get(id).unwrap();
            let n = rec
                .action
                .canary
                .cohort_size
                .max(1)
                .min(rec.action.targets.asset_ids.len());
            (
                rec.action.targets.asset_ids[..n].to_vec(),
                rec.action.canary.failure_threshold,
            )
        };
        let failure_rate = self.apply_targets(id, executor, &cohort, ActionState::Canary, actor);
        self.set_state(id, ActionState::CanaryVerify, actor, "canary applied");

        if failure_rate > threshold {
            self.rollback_applied(id, executor, actor);
            self.set_state(
                id,
                ActionState::RolledBack,
                actor,
                "canary failure exceeded threshold",
            );
            return Ok(StageOutcome::RolledBack);
        }
        let applied = self.actions.get(id).unwrap().applied.clone();
        match verifier.verify(&self.actions.get(id).unwrap().action, &applied) {
            VerifyOutcome::Fixed => {
                self.set_state(
                    id,
                    ActionState::Rollout,
                    actor,
                    "canary verified; promoting to rollout",
                );
                Ok(StageOutcome::Promoted)
            }
            VerifyOutcome::NotFixed => {
                self.rollback_applied(id, executor, actor);
                self.set_state(
                    id,
                    ActionState::RolledBack,
                    actor,
                    "canary verification failed",
                );
                Ok(StageOutcome::RolledBack)
            }
        }
    }

    /// Executes the staged rollout over the targets not covered by the canary.
    /// Requires state Rollout (a promoted canary). Rolls back ALL applied targets
    /// and moves to RolledBack if the rollout apply-failure rate exceeds the
    /// threshold or verification fails; otherwise moves to Closed.
    pub fn run_rollout(
        &mut self,
        id: &str,
        executor: &mut dyn Executor,
        verifier: &dyn Verifier,
        actor: &str,
    ) -> anyhow::Result<StageOutcome> {
        // Gate: rollout only from Rollout (reached only via a promoted canary).
        let rec = self
            .actions
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("no action {id}"))?;
        if rec.state != ActionState::Rollout {
            self.log(
                id,
                Some(rec.state),
                ActionState::Rollout,
                actor,
                Outcome::Rejected,
                "rollout requires a promoted canary",
            );
            anyhow::bail!("action {id} not in Rollout");
        }
        let remaining: Vec<String> = {
            let rec = self.actions.get(id).unwrap();
            let applied: std::collections::HashSet<&String> = rec.applied.iter().collect();
            rec.action
                .targets
                .asset_ids
                .iter()
                .filter(|t| !applied.contains(t))
                .cloned()
                .collect()
        };
        let threshold = self
            .actions
            .get(id)
            .unwrap()
            .action
            .canary
            .failure_threshold;
        let failure_rate =
            self.apply_targets(id, executor, &remaining, ActionState::Rollout, actor);
        self.set_state(id, ActionState::Verify, actor, "rollout applied");

        if failure_rate > threshold {
            self.rollback_applied(id, executor, actor);
            self.set_state(
                id,
                ActionState::RolledBack,
                actor,
                "rollout failure exceeded threshold",
            );
            return Ok(StageOutcome::RolledBack);
        }
        let applied = self.actions.get(id).unwrap().applied.clone();
        match verifier.verify(&self.actions.get(id).unwrap().action, &applied) {
            VerifyOutcome::Fixed => {
                self.set_state(id, ActionState::Closed, actor, "rollout verified; closed");
                Ok(StageOutcome::Closed)
            }
            VerifyOutcome::NotFixed => {
                // TV-8: the fix applied across the fleet but the re-score still finds
                // the issue. Do NOT blindly roll back a full rollout — leave it
                // APPLIED and mark it applied-but-unverified (stays `Verify`, not
                // Closed). The linked finding remains present (reopened); an operator
                // investigates or explicitly aborts.
                self.log(
                    id,
                    Some(ActionState::Verify),
                    ActionState::Verify,
                    actor,
                    Outcome::Rejected,
                    "rollout applied but verification failed (applied-but-unverified)",
                );
                Ok(StageOutcome::AppliedUnverified)
            }
        }
    }

    /// Global kill switch. Aborts an in-flight action; no further target is touched.
    /// Applied targets are left as-is (an explicit operator rollback is a separate
    /// action) — the partial state is audited.
    pub fn abort(&mut self, id: &str, actor: &str, reason: &str) -> anyhow::Result<()> {
        self.guarded(
            id,
            &[
                ActionState::Approved,
                ActionState::Canary,
                ActionState::CanaryVerify,
                ActionState::Rollout,
                ActionState::Verify,
            ],
            ActionState::Aborted,
            actor,
            &format!("kill switch: {reason}"),
        )
    }

    /// Applies the user's payload to each target, recording per-target results and
    /// accumulating successfully-applied targets. Returns the failure rate.
    fn apply_targets(
        &mut self,
        id: &str,
        executor: &mut dyn Executor,
        targets: &[String],
        stage: ActionState,
        actor: &str,
    ) -> f32 {
        let action = self.actions.get(id).unwrap().action.clone();
        let mut failures = 0usize;
        for t in targets {
            match executor.apply(&action, t) {
                Ok(()) => {
                    self.actions.get_mut(id).unwrap().applied.push(t.clone());
                    self.log(
                        id,
                        Some(stage),
                        stage,
                        actor,
                        Outcome::Ok,
                        &format!("applied to {t}"),
                    );
                }
                Err(e) => {
                    failures += 1;
                    self.log(
                        id,
                        Some(stage),
                        stage,
                        actor,
                        Outcome::Failed,
                        &format!("apply failed on {t}: {e}"),
                    );
                }
            }
        }
        if targets.is_empty() {
            0.0
        } else {
            failures as f32 / targets.len() as f32
        }
    }

    /// Runs the user's rollback payload on every successfully-applied target
    /// (best-effort — a rollback error is audited but does not stop the others).
    fn rollback_applied(&mut self, id: &str, executor: &mut dyn Executor, actor: &str) {
        let action = self.actions.get(id).unwrap().action.clone();
        let applied = self.actions.get(id).unwrap().applied.clone();
        for t in &applied {
            let (outcome, detail) = match executor.rollback(&action, t) {
                Ok(()) => (Outcome::Ok, format!("rolled back {t}")),
                Err(e) => (Outcome::Failed, format!("rollback error on {t}: {e}")),
            };
            self.log(id, None, ActionState::RolledBack, actor, outcome, &detail);
        }
        self.actions.get_mut(id).unwrap().applied.clear();
    }

    /// Unguarded internal state set with audit (used inside a stage after its entry
    /// guard has already run). NOT public — external callers use the guarded API.
    fn set_state(&mut self, id: &str, to: ActionState, actor: &str, detail: &str) {
        let from = self.actions.get(id).map(|r| r.state);
        if let Some(rec) = self.actions.get_mut(id) {
            rec.state = to;
        }
        self.log(id, from, to, actor, Outcome::Ok, detail);
    }

    /// Applies a guarded transition: only if the current state is in `allowed`.
    /// On success the state changes and an `Ok` event is audited; otherwise the
    /// state is left untouched and a `Rejected` event is audited.
    fn guarded(
        &mut self,
        id: &str,
        allowed: &[ActionState],
        to: ActionState,
        actor: &str,
        detail: &str,
    ) -> anyhow::Result<()> {
        let from = self.actions.get(id).map(|r| r.state);
        match from {
            Some(s) if allowed.contains(&s) => {
                self.actions.get_mut(id).unwrap().state = to;
                self.log(id, Some(s), to, actor, Outcome::Ok, detail);
                Ok(())
            }
            Some(s) => {
                self.log(
                    id,
                    Some(s),
                    to,
                    actor,
                    Outcome::Rejected,
                    "illegal transition",
                );
                anyhow::bail!("action {id} cannot move {:?} -> {:?}", s, to);
            }
            None => anyhow::bail!("no action {id}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{AssetSelector, CanarySpec, Method, VerifySpec};

    /// A preview-only executor that records how many times it was consulted, so a
    /// test can prove dry-run previews without any apply path existing.
    #[derive(Default)]
    struct RecordingExecutor {
        previews: std::cell::Cell<u32>,
        applied: std::cell::RefCell<Vec<String>>,
        rolled_back: std::cell::RefCell<Vec<String>>,
    }
    impl Executor for RecordingExecutor {
        fn preview(&self, action: &RemediationAction) -> String {
            self.previews.set(self.previews.get() + 1);
            format!(
                "would run `{}` on {} target(s)",
                action.payload,
                action.targets.asset_ids.len()
            )
        }
        fn apply(&mut self, _action: &RemediationAction, target: &str) -> anyhow::Result<()> {
            self.applied.borrow_mut().push(target.to_string());
            Ok(())
        }
        fn rollback(&mut self, _action: &RemediationAction, target: &str) -> anyhow::Result<()> {
            self.rolled_back.borrow_mut().push(target.to_string());
            Ok(())
        }
    }

    fn action(id: &str, targets: Vec<&str>) -> RemediationAction {
        RemediationAction {
            id: id.into(),
            name: "n".into(),
            method: Method::Shell,
            payload: "echo hi".into(),
            targets: AssetSelector {
                asset_ids: targets.into_iter().map(Into::into).collect(),
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

    fn advance_to_dry_run(
        b: &mut Bridge<crate::audit::VecAuditSink>,
        ex: &RecordingExecutor,
        id: &str,
    ) {
        b.draft(action(id, vec!["h1"]), "user").unwrap();
        b.dry_run(id, ex, "user").unwrap();
    }

    #[test]
    fn draft_refuses_unscoped_action_and_audits_rejection() {
        let mut b = Bridge::new(crate::audit::VecAuditSink::default());
        let err = b.draft(action("a", vec![]), "user"); // empty selector
        assert!(
            err.is_err(),
            "unscoped action is refused (no implicit fleet-wide)"
        );
        assert_eq!(b.state("a"), None, "rejected action is not stored");
        let last = b.audit().events.last().unwrap();
        assert_eq!(last.outcome, Outcome::Rejected);
    }

    #[test]
    fn dry_run_previews_with_no_state_leak_and_stays_in_dry_run() {
        let ex = RecordingExecutor::default();
        let mut b = Bridge::new(crate::audit::VecAuditSink::default());
        b.draft(action("a", vec!["h1", "h2"]), "user").unwrap();
        let preview = b.dry_run("a", &ex, "user").unwrap();
        assert_eq!(preview.targets, vec!["h1", "h2"]);
        assert!(preview.preview.contains("would run"));
        assert_eq!(ex.previews.get(), 1, "preview consulted exactly once");
        assert_eq!(
            b.state("a"),
            Some(ActionState::DryRun),
            "TV-5: stays in DryRun, no execution"
        );
    }

    #[test]
    fn cannot_approve_without_dry_run_then_submit() {
        let ex = RecordingExecutor::default();
        let mut b = Bridge::new(crate::audit::VecAuditSink::default());
        b.draft(action("a", vec!["h1"]), "user").unwrap();
        // Approving straight from Drafted is refused.
        assert!(b.approve("a", "approver").is_err());
        assert_eq!(b.state("a"), Some(ActionState::Drafted));
        // Even after dry-run, must submit for approval first.
        b.dry_run("a", &ex, "user").unwrap();
        assert!(
            b.approve("a", "approver").is_err(),
            "must be PendingApproval to approve"
        );
        assert_eq!(b.state("a"), Some(ActionState::DryRun));
    }

    #[test]
    fn full_gate_path_reaches_approved() {
        let ex = RecordingExecutor::default();
        let mut b = Bridge::new(crate::audit::VecAuditSink::default());
        advance_to_dry_run(&mut b, &ex, "a");
        b.submit_for_approval("a", "user").unwrap();
        assert_eq!(b.state("a"), Some(ActionState::PendingApproval));
        b.approve("a", "secops").unwrap();
        assert_eq!(
            b.state("a"),
            Some(ActionState::Approved),
            "only reachable via dry-run + approval"
        );
        // The approving actor is on the audit trail.
        let approved = b
            .audit()
            .events
            .iter()
            .find(|e| e.to == ActionState::Approved && e.outcome == Outcome::Ok)
            .unwrap();
        assert_eq!(approved.actor, "secops");
    }

    #[test]
    fn reject_aborts_from_pending_approval() {
        let ex = RecordingExecutor::default();
        let mut b = Bridge::new(crate::audit::VecAuditSink::default());
        advance_to_dry_run(&mut b, &ex, "a");
        b.submit_for_approval("a", "user").unwrap();
        b.reject("a", "secops", "risky").unwrap();
        assert_eq!(b.state("a"), Some(ActionState::Aborted));
    }

    struct AlwaysFixed;
    impl Verifier for AlwaysFixed {
        fn verify(&self, _a: &RemediationAction, _applied: &[String]) -> VerifyOutcome {
            VerifyOutcome::Fixed
        }
    }

    #[test]
    fn extended_executor_and_verifier_are_usable() {
        let ex = RecordingExecutor::default();
        let mut b = Bridge::new(crate::audit::VecAuditSink::default());
        b.draft(action("a", vec!["h1"]), "user").unwrap();
        b.dry_run("a", &ex, "user").unwrap();
        assert_eq!(ex.previews.get(), 1);
        assert_eq!(
            AlwaysFixed.verify(&action("a", vec!["h1"]), &[]),
            VerifyOutcome::Fixed
        );
    }

    struct AlwaysNotFixed;
    impl Verifier for AlwaysNotFixed {
        fn verify(&self, _a: &RemediationAction, _a2: &[String]) -> VerifyOutcome {
            VerifyOutcome::NotFixed
        }
    }
    /// Executor whose `apply` fails for a named target.
    #[derive(Default)]
    struct FailingExecutor {
        fail: std::cell::RefCell<Vec<String>>,
        applied: std::cell::RefCell<Vec<String>>,
        rolled_back: std::cell::RefCell<Vec<String>>,
    }
    impl Executor for FailingExecutor {
        fn preview(&self, _a: &RemediationAction) -> String {
            String::new()
        }
        fn apply(&mut self, _a: &RemediationAction, target: &str) -> anyhow::Result<()> {
            if self.fail.borrow().iter().any(|t| t == target) {
                anyhow::bail!("apply failed on {target}");
            }
            self.applied.borrow_mut().push(target.to_string());
            Ok(())
        }
        fn rollback(&mut self, _a: &RemediationAction, target: &str) -> anyhow::Result<()> {
            self.rolled_back.borrow_mut().push(target.to_string());
            Ok(())
        }
    }

    fn approved(
        b: &mut Bridge<crate::audit::VecAuditSink>,
        ex: &RecordingExecutor,
        id: &str,
        targets: Vec<&str>,
    ) {
        b.draft(action(id, targets), "user").unwrap();
        b.dry_run(id, ex, "user").unwrap();
        b.submit_for_approval(id, "user").unwrap();
        b.approve(id, "secops").unwrap();
    }

    #[test]
    fn canary_promotes_when_applied_and_verified() {
        let ro = RecordingExecutor::default();
        let mut b = Bridge::new(crate::audit::VecAuditSink::default());
        approved(&mut b, &ro, "a", vec!["h1", "h2", "h3"]); // cohort_size 1 (from action())
        let mut ex = RecordingExecutor::default();
        let out = b.run_canary("a", &mut ex, &AlwaysFixed, "secops").unwrap();
        assert_eq!(out, StageOutcome::Promoted);
        assert_eq!(b.state("a"), Some(ActionState::Rollout));
        assert_eq!(
            *ex.applied.borrow(),
            vec!["h1"],
            "only the canary cohort (size 1) applied"
        );
        assert!(ex.rolled_back.borrow().is_empty());
    }

    #[test]
    fn canary_rolls_back_when_verification_fails() {
        let ro = RecordingExecutor::default();
        let mut b = Bridge::new(crate::audit::VecAuditSink::default());
        approved(&mut b, &ro, "a", vec!["h1", "h2"]);
        let mut ex = RecordingExecutor::default();
        let out = b
            .run_canary("a", &mut ex, &AlwaysNotFixed, "secops")
            .unwrap();
        assert_eq!(out, StageOutcome::RolledBack);
        assert_eq!(b.state("a"), Some(ActionState::RolledBack));
        assert_eq!(*ex.applied.borrow(), vec!["h1"], "canary applied");
        assert_eq!(*ex.rolled_back.borrow(), vec!["h1"], "and was rolled back");
    }

    #[test]
    fn canary_rolls_back_when_apply_failure_exceeds_threshold() {
        let ro = RecordingExecutor::default();
        let mut b = Bridge::new(crate::audit::VecAuditSink::default());
        approved(&mut b, &ro, "a", vec!["h1", "h2"]); // cohort size 1, threshold 0.0
        let mut ex = FailingExecutor::default();
        ex.fail.borrow_mut().push("h1".into());
        let out = b.run_canary("a", &mut ex, &AlwaysFixed, "secops").unwrap();
        assert_eq!(
            out,
            StageOutcome::RolledBack,
            "100% canary failure > threshold 0.0"
        );
        assert_eq!(b.state("a"), Some(ActionState::RolledBack));
        assert!(
            ex.applied.borrow().is_empty(),
            "nothing successfully applied to roll back"
        );
    }

    #[test]
    fn run_canary_requires_approved_state() {
        let mut b = Bridge::new(crate::audit::VecAuditSink::default());
        b.draft(action("a", vec!["h1"]), "user").unwrap(); // still Drafted
        let mut ex = RecordingExecutor::default();
        assert!(
            b.run_canary("a", &mut ex, &AlwaysFixed, "secops").is_err(),
            "cannot execute an unapproved action"
        );
        assert_eq!(b.state("a"), Some(ActionState::Drafted));
    }

    #[test]
    fn rollout_applies_remaining_and_closes_when_verified() {
        let ro = RecordingExecutor::default();
        let mut b = Bridge::new(crate::audit::VecAuditSink::default());
        approved(&mut b, &ro, "a", vec!["h1", "h2", "h3"]);
        let mut ex = RecordingExecutor::default();
        b.run_canary("a", &mut ex, &AlwaysFixed, "secops").unwrap(); // applies h1
        let out = b.run_rollout("a", &mut ex, &AlwaysFixed, "secops").unwrap();
        assert_eq!(out, StageOutcome::Closed);
        assert_eq!(b.state("a"), Some(ActionState::Closed));
        assert_eq!(
            *ex.applied.borrow(),
            vec!["h1", "h2", "h3"],
            "canary + remaining rollout applied"
        );
    }

    #[test]
    fn rollout_rolls_back_all_when_failure_exceeds_threshold() {
        let ro = RecordingExecutor::default();
        let mut b = Bridge::new(crate::audit::VecAuditSink::default());
        approved(&mut b, &ro, "a", vec!["h1", "h2"]); // cohort 1, threshold 0.0
        let mut ex = FailingExecutor::default();
        ex.fail.borrow_mut().push("h2".into()); // canary h1 ok, rollout h2 fails
        b.run_canary("a", &mut ex, &AlwaysFixed, "secops").unwrap();
        let out = b.run_rollout("a", &mut ex, &AlwaysFixed, "secops").unwrap();
        assert_eq!(out, StageOutcome::RolledBack);
        assert_eq!(b.state("a"), Some(ActionState::RolledBack));
        assert_eq!(
            *ex.rolled_back.borrow(),
            vec!["h1"],
            "the successfully-applied canary target is rolled back"
        );
    }

    #[test]
    fn run_rollout_requires_rollout_state() {
        let ro = RecordingExecutor::default();
        let mut b = Bridge::new(crate::audit::VecAuditSink::default());
        approved(&mut b, &ro, "a", vec!["h1"]);
        let mut ex = RecordingExecutor::default();
        assert!(
            b.run_rollout("a", &mut ex, &AlwaysFixed, "secops").is_err(),
            "rollout only after a promoted canary"
        );
    }

    #[test]
    fn abort_kills_in_flight_and_leaves_untouched_targets_untouched() {
        let ro = RecordingExecutor::default();
        let mut b = Bridge::new(crate::audit::VecAuditSink::default());
        approved(&mut b, &ro, "a", vec!["h1", "h2", "h3"]);
        let mut ex = RecordingExecutor::default();
        b.run_canary("a", &mut ex, &AlwaysFixed, "secops").unwrap(); // state Rollout, h1 applied
        b.abort("a", "secops", "kill switch").unwrap();
        assert_eq!(b.state("a"), Some(ActionState::Aborted));
        assert_eq!(
            *ex.applied.borrow(),
            vec!["h1"],
            "no rollout targets executed after kill"
        );
    }

    #[test]
    fn abort_rejected_on_terminal_state() {
        let ro = RecordingExecutor::default();
        let mut b = Bridge::new(crate::audit::VecAuditSink::default());
        approved(&mut b, &ro, "a", vec!["h1"]);
        let mut ex = RecordingExecutor::default();
        b.run_canary("a", &mut ex, &AlwaysFixed, "secops").unwrap();
        b.run_rollout("a", &mut ex, &AlwaysFixed, "secops").unwrap(); // Closed
        assert!(
            b.abort("a", "secops", "too late").is_err(),
            "cannot kill a Closed action"
        );
    }

    #[test]
    fn rollout_verify_fail_is_applied_but_unverified_not_rolled_back() {
        let ro = RecordingExecutor::default();
        let mut b = Bridge::new(crate::audit::VecAuditSink::default());
        approved(&mut b, &ro, "a", vec!["h1", "h2"]); // cohort 1
        let mut ex = RecordingExecutor::default();
        b.run_canary("a", &mut ex, &AlwaysFixed, "secops").unwrap(); // canary h1 verified -> Rollout
                                                                     // Rollout applies h2; the FINAL re-score still finds the issue -> NotFixed.
        let out = b
            .run_rollout("a", &mut ex, &AlwaysNotFixed, "secops")
            .unwrap();
        assert_eq!(
            out,
            StageOutcome::AppliedUnverified,
            "TV-8: applied but not verified"
        );
        assert_eq!(
            b.state("a"),
            Some(ActionState::Verify),
            "stays applied-but-unverified, NOT Closed, NOT RolledBack"
        );
        assert_eq!(
            *ex.applied.borrow(),
            vec!["h1", "h2"],
            "the fix stayed applied across the fleet"
        );
        assert!(
            ex.rolled_back.borrow().is_empty(),
            "a full rollout is NOT blindly rolled back on verify-fail"
        );
    }

    #[test]
    fn applied_but_unverified_action_can_still_be_aborted() {
        let ro = RecordingExecutor::default();
        let mut b = Bridge::new(crate::audit::VecAuditSink::default());
        approved(&mut b, &ro, "a", vec!["h1", "h2"]);
        let mut ex = RecordingExecutor::default();
        b.run_canary("a", &mut ex, &AlwaysFixed, "secops").unwrap();
        b.run_rollout("a", &mut ex, &AlwaysNotFixed, "secops")
            .unwrap(); // -> Verify (applied-but-unverified)
        b.abort("a", "secops", "unverified; reverting manually")
            .unwrap();
        assert_eq!(
            b.state("a"),
            Some(ActionState::Aborted),
            "operator can abort an applied-but-unverified action"
        );
    }

    /// AUDIT-1 regression: a rollout-stage apply must be audited with
    /// `from == Some(ActionState::Rollout)`, not hardcoded `Canary`.
    #[test]
    fn rollout_apply_is_audited_with_rollout_stage_not_canary() {
        let ro = RecordingExecutor::default();
        let mut b = Bridge::new(crate::audit::VecAuditSink::default());
        approved(&mut b, &ro, "a", vec!["h1", "h2", "h3"]);
        let mut ex = RecordingExecutor::default();
        b.run_canary("a", &mut ex, &AlwaysFixed, "secops").unwrap(); // applies h1 (Canary stage)
        b.run_rollout("a", &mut ex, &AlwaysFixed, "secops").unwrap(); // applies h2, h3 (Rollout stage)

        let rollout_applies: Vec<_> = b
            .audit()
            .events
            .iter()
            .filter(|e| e.detail.contains("applied to"))
            .collect();
        assert!(
            rollout_applies
                .iter()
                .any(|e| e.from == Some(ActionState::Rollout) && e.to == ActionState::Rollout),
            "expected a rollout-stage apply audit event with from == Some(Rollout)"
        );
        // Direct check: every "applied to h2"/"applied to h3" event (the
        // rollout-stage targets) must be attributed to Rollout, never Canary.
        for e in &rollout_applies {
            if e.detail.contains("applied to h2") || e.detail.contains("applied to h3") {
                assert_eq!(e.from, Some(ActionState::Rollout));
                assert_ne!(e.from, Some(ActionState::Canary));
            }
        }
    }

    /// AUDIT-2 regression: a failed rollback must be audited with `Outcome::Failed`,
    /// never silently recorded as `Outcome::Ok`.
    #[test]
    fn failed_rollback_is_audited_as_failed_outcome() {
        /// Executor whose `apply` always succeeds but whose `rollback` always fails.
        #[derive(Default)]
        struct RollbackFailsExecutor {
            applied: std::cell::RefCell<Vec<String>>,
        }
        impl Executor for RollbackFailsExecutor {
            fn preview(&self, _a: &RemediationAction) -> String {
                String::new()
            }
            fn apply(&mut self, _a: &RemediationAction, target: &str) -> anyhow::Result<()> {
                self.applied.borrow_mut().push(target.to_string());
                Ok(())
            }
            fn rollback(&mut self, _a: &RemediationAction, target: &str) -> anyhow::Result<()> {
                anyhow::bail!("simulated rollback failure on {target}")
            }
        }

        let ro = RecordingExecutor::default();
        let mut b = Bridge::new(crate::audit::VecAuditSink::default());
        approved(&mut b, &ro, "a", vec!["h1", "h2"]);
        let mut ex = RollbackFailsExecutor::default();
        // Canary applies successfully but verification fails, triggering rollback.
        let out = b
            .run_canary("a", &mut ex, &AlwaysNotFixed, "secops")
            .unwrap();
        assert_eq!(out, StageOutcome::RolledBack);

        let failed_rollback = b
            .audit()
            .events
            .iter()
            .find(|e| e.to == ActionState::RolledBack && e.outcome == Outcome::Failed);
        assert!(
            failed_rollback.is_some(),
            "expected a rollback event audited with Outcome::Failed"
        );
    }
}
