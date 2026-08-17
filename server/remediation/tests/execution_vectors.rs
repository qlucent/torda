//! Execution golden vectors (the execution subset).
//! Fake Executor/Verifier drive the post-approval flow deterministically.
use torda_remediation::action::*;
use torda_remediation::audit::*;
use torda_remediation::bridge::*;

#[derive(Default)]
struct FakeExec {
    applied: std::cell::RefCell<Vec<String>>,
    rolled_back: std::cell::RefCell<Vec<String>>,
    fail: Vec<String>,
}
impl Executor for FakeExec {
    fn preview(&self, _a: &RemediationAction) -> String {
        String::new()
    }
    fn apply(&mut self, _a: &RemediationAction, target: &str) -> anyhow::Result<()> {
        if self.fail.iter().any(|t| t == target) {
            anyhow::bail!("fail {target}");
        }
        self.applied.borrow_mut().push(target.to_string());
        Ok(())
    }
    fn rollback(&mut self, _a: &RemediationAction, target: &str) -> anyhow::Result<()> {
        self.rolled_back.borrow_mut().push(target.to_string());
        Ok(())
    }
}
struct Fixed;
impl Verifier for Fixed {
    fn verify(&self, _a: &RemediationAction, _t: &[String]) -> VerifyOutcome {
        VerifyOutcome::Fixed
    }
}
struct NotFixed;
impl Verifier for NotFixed {
    fn verify(&self, _a: &RemediationAction, _t: &[String]) -> VerifyOutcome {
        VerifyOutcome::NotFixed
    }
}

fn approved_action(
    id: &str,
    targets: Vec<&str>,
    cohort: usize,
    threshold: f32,
) -> RemediationAction {
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
            cohort_size: cohort,
            failure_threshold: threshold,
        },
    }
}
fn to_approved(b: &mut Bridge<VecAuditSink>, a: RemediationAction) {
    let id = a.id.clone();
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
    b.draft(a, "user").unwrap();
    b.dry_run(&id, &P, "user").unwrap();
    b.submit_for_approval(&id, "user").unwrap();
    b.approve(&id, "secops").unwrap();
}

// TV-1 happy path: approved -> canary -> verify -> rollout -> verify -> Closed.
#[test]
fn tv1_happy_path_closes() {
    let mut b = Bridge::new(VecAuditSink::default());
    to_approved(&mut b, approved_action("a", vec!["h1", "h2", "h3"], 1, 0.0));
    let mut ex = FakeExec::default();
    assert_eq!(
        b.run_canary("a", &mut ex, &Fixed, "secops").unwrap(),
        StageOutcome::Promoted
    );
    assert_eq!(
        b.run_rollout("a", &mut ex, &Fixed, "secops").unwrap(),
        StageOutcome::Closed
    );
    assert_eq!(b.state("a"), Some(ActionState::Closed));
    assert_eq!(*ex.applied.borrow(), vec!["h1", "h2", "h3"]);
    assert!(ex.rolled_back.borrow().is_empty());
}

// TV-2 canary fails verification: auto-rollback; RolledBack; remaining untouched.
#[test]
fn tv2_canary_verify_fail_rolls_back() {
    let mut b = Bridge::new(VecAuditSink::default());
    to_approved(&mut b, approved_action("a", vec!["h1", "h2"], 1, 0.0));
    let mut ex = FakeExec::default();
    assert_eq!(
        b.run_canary("a", &mut ex, &NotFixed, "secops").unwrap(),
        StageOutcome::RolledBack
    );
    assert_eq!(b.state("a"), Some(ActionState::RolledBack));
    assert_eq!(*ex.applied.borrow(), vec!["h1"], "only canary applied");
    assert_eq!(*ex.rolled_back.borrow(), vec!["h1"], "canary rolled back");
}

// TV-3 kill switch mid-flight: Aborted; no further targets executed.
#[test]
fn tv3_kill_switch_aborts_before_rollout() {
    let mut b = Bridge::new(VecAuditSink::default());
    to_approved(&mut b, approved_action("a", vec!["h1", "h2", "h3"], 1, 0.0));
    let mut ex = FakeExec::default();
    b.run_canary("a", &mut ex, &Fixed, "secops").unwrap(); // state Rollout, h1 applied
    b.abort("a", "secops", "kill").unwrap();
    assert_eq!(b.state("a"), Some(ActionState::Aborted));
    assert_eq!(
        *ex.applied.borrow(),
        vec!["h1"],
        "rollout targets never executed"
    );
    // Kill switch does not auto-rollback (explicit operator follow-up).
    assert!(ex.rolled_back.borrow().is_empty());
}

// TV-7 rollout failure exceeds threshold: halt -> RolledBack; applied reverted.
#[test]
fn tv7_rollout_threshold_rolls_back() {
    let mut b = Bridge::new(VecAuditSink::default());
    to_approved(&mut b, approved_action("a", vec!["h1", "h2"], 1, 0.0));
    let mut ex = FakeExec {
        fail: vec!["h2".into()],
        ..Default::default()
    }; // canary h1 ok, rollout h2 fails -> 100% > 0.0
    b.run_canary("a", &mut ex, &Fixed, "secops").unwrap();
    assert_eq!(
        b.run_rollout("a", &mut ex, &Fixed, "secops").unwrap(),
        StageOutcome::RolledBack
    );
    assert_eq!(b.state("a"), Some(ActionState::RolledBack));
    assert_eq!(
        *ex.rolled_back.borrow(),
        vec!["h1"],
        "the applied canary target is reverted"
    );
}
