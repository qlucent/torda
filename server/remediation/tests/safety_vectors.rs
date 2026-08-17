//! Pre-execution safety golden vectors (the subset
//! provable before execution exists). They pin the invariant that no user-authored
//! action can reach the execution-permitted state (`Approved`) without passing the
//! scope, dry-run, and approval gates — and that every attempt is audited.
use torda_remediation::action::*;
use torda_remediation::audit::*;
use torda_remediation::bridge::*;

struct StubExecutor;
impl Executor for StubExecutor {
    fn preview(&self, action: &RemediationAction) -> String {
        format!("preview: {}", action.payload)
    }
    fn apply(&mut self, _action: &RemediationAction, _target: &str) -> anyhow::Result<()> {
        Ok(())
    }
    fn rollback(&mut self, _action: &RemediationAction, _target: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

fn action(id: &str, targets: Vec<&str>, requires_approval: bool) -> RemediationAction {
    RemediationAction {
        id: id.into(),
        name: "n".into(),
        method: Method::Shell,
        payload: "echo hi".into(),
        targets: AssetSelector {
            asset_ids: targets.into_iter().map(Into::into).collect(),
        },
        requires_approval,
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

fn fresh() -> Bridge<VecAuditSink> {
    Bridge::new(VecAuditSink::default())
}

// TV (scope): an unscoped action is refused at the door.
#[test]
fn tv_scope_gate_refuses_unscoped_action() {
    let mut b = fresh();
    assert!(b.draft(action("a", vec![], true), "user").is_err());
    assert_eq!(b.state("a"), None);
}

// TV-5 (dry-run only): dry-run returns a preview and leaves the action in DryRun
// with no progression toward execution.
#[test]
fn tv5_dry_run_only_changes_nothing() {
    let mut b = fresh();
    b.draft(action("a", vec!["h1"], true), "user").unwrap();
    let p = b.dry_run("a", &StubExecutor, "user").unwrap();
    assert_eq!(p.preview, "preview: echo hi");
    assert_eq!(b.state("a"), Some(ActionState::DryRun));
}

// TV-6 (approval withheld): a submitted action with no approval is stuck in
// PendingApproval; it never reaches Approved.
#[test]
fn tv6_approval_withheld_blocks_execution() {
    let mut b = fresh();
    b.draft(action("a", vec!["h1"], true), "user").unwrap();
    b.dry_run("a", &StubExecutor, "user").unwrap();
    b.submit_for_approval("a", "user").unwrap();
    // No approve() call.
    assert_eq!(
        b.state("a"),
        Some(ActionState::PendingApproval),
        "blocked until approved"
    );
    assert_ne!(b.state("a"), Some(ActionState::Approved));
}

// The core safety invariant: Approved is unreachable except via draft -> dry-run
// -> submit -> approve, and every hop is audited.
#[test]
fn approved_requires_the_full_gated_path_and_is_fully_audited() {
    let mut b = fresh();
    b.draft(action("a", vec!["h1"], true), "user").unwrap();
    b.dry_run("a", &StubExecutor, "user").unwrap();
    b.submit_for_approval("a", "user").unwrap();
    b.approve("a", "secops").unwrap();
    assert_eq!(b.state("a"), Some(ActionState::Approved));

    // Audit completeness: one Ok event per hop, in order, ending at Approved.
    let states: Vec<ActionState> = b
        .audit()
        .events
        .iter()
        .filter(|e| e.outcome == Outcome::Ok)
        .map(|e| e.to)
        .collect();
    assert_eq!(
        states,
        vec![
            ActionState::Drafted,
            ActionState::DryRun,
            ActionState::PendingApproval,
            ActionState::Approved,
        ]
    );
}

// Rejected transitions leave state untouched AND are audited (gate 8).
#[test]
fn illegal_transitions_are_rejected_and_audited() {
    let mut b = fresh();
    b.draft(action("a", vec!["h1"], true), "user").unwrap();
    assert!(
        b.approve("a", "secops").is_err(),
        "cannot approve a Drafted action"
    );
    assert_eq!(
        b.state("a"),
        Some(ActionState::Drafted),
        "state unchanged after rejection"
    );
    let rejected = b
        .audit()
        .events
        .iter()
        .filter(|e| e.outcome == Outcome::Rejected)
        .count();
    assert_eq!(rejected, 1);
}
