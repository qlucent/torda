//! Least-privilege / separation-of-duties golden vectors: a role policy decides
//! WHICH commands each authenticated actor may issue. Authentication (signature)
//! is stubbed open here (AllowAll signer) — these vectors target authorization.
use torda_remediation::action::*;
use torda_remediation::audit::{Outcome, VecAuditSink};
use torda_remediation::bridge::*;
use torda_remediation::control::*;

// Signature-open: these vectors test authorization, not authentication.
struct AnySig;
impl SignatureVerifier for AnySig {
    fn verify(&self, _p: &str, _s: &str, _a: &str) -> bool {
        true
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
fn cmd(action_id: &str, kind: CommandKind, actor: &str) -> ControlCommand {
    ControlCommand {
        action_id: action_id.into(),
        kind,
        actor: actor.into(),
        session: "s1".into(),
        seq: 1,
        schedule: None,
        signature: "ok".into(),
    }
}

#[test]
fn operator_may_draft_but_not_approve() {
    let mut policy = RolePolicy::new();
    policy.assign("alice", Role::Operator);
    let mut b = Bridge::new(VecAuditSink::default());
    // Draft is permitted.
    dispatch(
        &mut b,
        cmd("a", CommandKind::Draft(Box::new(action("a"))), "alice"),
        &AnySig,
        &policy,
    )
    .unwrap();
    assert_eq!(b.state("a"), Some(ActionState::Drafted));
    // Approve is refused for an operator (separation of duties), even validly signed.
    assert!(dispatch(
        &mut b,
        cmd("a", CommandKind::Approve, "alice"),
        &AnySig,
        &policy
    )
    .is_err());
    assert_eq!(b.audit().events.last().unwrap().outcome, Outcome::Rejected);
}

#[test]
fn approver_may_not_author() {
    let mut policy = RolePolicy::new();
    policy.assign("bob", Role::Approver);
    let mut b = Bridge::new(VecAuditSink::default());
    assert!(
        dispatch(
            &mut b,
            cmd("a", CommandKind::Draft(Box::new(action("a"))), "bob"),
            &AnySig,
            &policy
        )
        .is_err(),
        "an approver cannot author actions"
    );
    assert_eq!(b.state("a"), None);
}

// The four-eyes flow: an operator authors + submits, an approver approves.
#[test]
fn four_eyes_operator_authors_approver_approves() {
    let mut policy = RolePolicy::new();
    policy.assign("alice", Role::Operator);
    policy.assign("bob", Role::Approver);
    let mut b = Bridge::new(VecAuditSink::default());

    dispatch(
        &mut b,
        cmd("a", CommandKind::Draft(Box::new(action("a"))), "alice"),
        &AnySig,
        &policy,
    )
    .unwrap();
    b.dry_run("a", &NoExec, "alice").unwrap(); // dry-run is a direct op, not a signed command
    dispatch(
        &mut b,
        cmd("a", CommandKind::Submit, "alice"),
        &AnySig,
        &policy,
    )
    .unwrap();
    // Alice (operator) cannot approve her own action.
    assert!(dispatch(
        &mut b,
        cmd("a", CommandKind::Approve, "alice"),
        &AnySig,
        &policy
    )
    .is_err());
    assert_eq!(b.state("a"), Some(ActionState::PendingApproval));
    // Bob (approver) can.
    dispatch(
        &mut b,
        cmd("a", CommandKind::Approve, "bob"),
        &AnySig,
        &policy,
    )
    .unwrap();
    assert_eq!(
        b.state("a"),
        Some(ActionState::Approved),
        "four-eyes: different actor approves"
    );
}

// A preview-only executor for the dry-run step above.
struct NoExec;
impl Executor for NoExec {
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
