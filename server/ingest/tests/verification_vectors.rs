//! End-to-end verification loop (TV-1 + TV-8).
//! A user-authored action is approved and executed; the EngineVerifier re-scores
//! the post-fix state via the real Findings Engine; the action closes ONLY when
//! the linked finding is gone.
use torda_ingest::verify::{CurrentState, EngineVerifier};
use torda_ocsf::OcsfEnvelope;
use torda_remediation::action::*;
use torda_remediation::audit::VecAuditSink;
use torda_remediation::bridge::*;

fn sbom(host: &str, name: &str, version: &str) -> OcsfEnvelope {
    OcsfEnvelope::new(
        torda_ocsf::class::SOFTWARE_INVENTORY_INFO,
        "Software Inventory Info",
        torda_ocsf::Metadata {
            product: "torda".into(),
            version: "0".into(),
            tenant_id: "t".into(),
        },
        torda_ocsf::Device {
            hostname: host.into(),
            os: "Test".into(),
            os_version: "1".into(),
        },
        serde_json::json!({ "sbom": { "components": [{"name": name, "version": version, "source": "dpkg"}], "component_count": 1 } }),
    )
}

/// A static post-fix state (same envelopes on every `envelopes()` call) — used for
/// the TV-1 happy path where the fix genuinely worked before either verify call.
struct PostFix(Vec<OcsfEnvelope>);
impl CurrentState for PostFix {
    fn envelopes(&self, _asset: &str) -> Vec<OcsfEnvelope> {
        self.0.clone()
    }
}

/// A post-fix state that the TEST can explicitly flip between the canary-verify
/// and the rollout-verify, instead of relying on call-order/call-count within
/// `EngineVerifier` (which re-runs `run_ingest` once per target asset, so a
/// call-counting fake is fragile). While un-tripped it reports openssl upgraded
/// (fixed); once `trip()`'d it reports openssl still on the vulnerable version.
/// This drives a REAL canary-Fixed -> rollout-NotFixed transition through the
/// real `EngineVerifier`/`run_ingest`, proving TV-8's applied-but-unverified path
/// end-to-end rather than asserting it only at the bridge-unit level.
struct TrippableState {
    tripped: std::cell::Cell<bool>,
}
impl TrippableState {
    fn new() -> Self {
        Self {
            tripped: std::cell::Cell::new(false),
        }
    }
    fn trip(&self) {
        self.tripped.set(true);
    }
}
impl CurrentState for TrippableState {
    fn envelopes(&self, _asset: &str) -> Vec<OcsfEnvelope> {
        if self.tripped.get() {
            vec![sbom("host-1", "openssl", "3.0.2")] // regressed: CVE still present
        } else {
            vec![sbom("host-1", "openssl", "3.0.14")] // fixed
        }
    }
}

// A no-op executor (apply/rollback succeed) — execution correctness is P3a-2's concern.
#[derive(Default)]
struct OkExec {
    applied: std::cell::RefCell<Vec<String>>,
    rolled_back: std::cell::RefCell<Vec<String>>,
}
impl Executor for OkExec {
    fn preview(&self, _a: &RemediationAction) -> String {
        String::new()
    }
    fn apply(&mut self, _a: &RemediationAction, t: &str) -> anyhow::Result<()> {
        self.applied.borrow_mut().push(t.into());
        Ok(())
    }
    fn rollback(&mut self, _a: &RemediationAction, t: &str) -> anyhow::Result<()> {
        self.rolled_back.borrow_mut().push(t.into());
        Ok(())
    }
}

const OPENSSL_FINDING: &str = "host-1|CVE-2022-3602|openssl|dpkg";

fn upgrade_openssl_action(targets: Vec<&str>) -> RemediationAction {
    RemediationAction {
        id: "fix-openssl".into(),
        name: "upgrade openssl".into(),
        method: Method::PackageMgr,
        payload: "apt-get install -y openssl=3.0.14".into(),
        targets: AssetSelector {
            asset_ids: targets.into_iter().map(Into::into).collect(),
        },
        requires_approval: true,
        dry_run_supported: true,
        rollback: Some("apt-get install -y openssl=3.0.2".into()),
        verify: VerifySpec {
            finding_ids: vec![OPENSSL_FINDING.into()],
        },
        canary: CanarySpec {
            cohort_size: 1,
            failure_threshold: 0.0,
        },
    }
}

fn approve(b: &mut Bridge<VecAuditSink>, a: RemediationAction) {
    let id = a.id.clone();
    let p = OkExec::default();
    b.draft(a, "user").unwrap();
    b.dry_run(&id, &p, "user").unwrap();
    b.submit_for_approval(&id, "user").unwrap();
    b.approve(&id, "secops").unwrap();
}

// TV-1 happy path: the fix works, re-score finds openssl upgraded, action CLOSES.
#[test]
fn tv1_verified_fix_closes_the_action() {
    let mut b = Bridge::new(VecAuditSink::default());
    approve(&mut b, upgrade_openssl_action(vec!["host-1"]));
    // Post-fix state: openssl is now 3.0.14 -> the CVE finding is gone.
    let state = PostFix(vec![sbom("host-1", "openssl", "3.0.14")]);
    let verifier = EngineVerifier::new(&state);
    let mut ex = OkExec::default();
    assert_eq!(
        b.run_canary("fix-openssl", &mut ex, &verifier, "secops")
            .unwrap(),
        StageOutcome::Promoted
    );
    assert_eq!(
        b.run_rollout("fix-openssl", &mut ex, &verifier, "secops")
            .unwrap(),
        StageOutcome::Closed
    );
    assert_eq!(
        b.state("fix-openssl"),
        Some(ActionState::Closed),
        "verified fix -> Closed"
    );
    assert!(ex.rolled_back.borrow().is_empty());
}

// TV-8: the fix is applied fleet-wide (canary promotes on a genuinely-fixed
// re-score) but by the time the rollout's FINAL re-score runs, the state has
// regressed and the linked finding is present again -> applied-but-unverified,
// NOT Closed, NOT rolled back. Two targets so the canary (host-1) and the
// rollout (host-2) are genuinely distinct stages driving two separate
// `EngineVerifier::verify` calls through the real engine.
#[test]
fn tv8_applied_fix_that_regresses_by_rollout_is_applied_but_unverified() {
    let mut b = Bridge::new(VecAuditSink::default());
    approve(&mut b, upgrade_openssl_action(vec!["host-1", "host-2"]));

    let state = TrippableState::new();
    let verifier = EngineVerifier::new(&state);
    let mut ex = OkExec::default();

    // Canary (cohort_size 1) applies host-1; state is still un-tripped (fixed) ->
    // real re-score finds no openssl CVE -> Fixed -> promote to Rollout.
    let canary_out = b
        .run_canary("fix-openssl", &mut ex, &verifier, "secops")
        .unwrap();
    assert_eq!(
        canary_out,
        StageOutcome::Promoted,
        "canary verifies fixed against the real engine"
    );
    assert_eq!(b.state("fix-openssl"), Some(ActionState::Rollout));
    assert_eq!(
        *ex.applied.borrow(),
        vec!["host-1"],
        "only the canary target applied so far"
    );

    // Between canary and rollout, the post-fix state regresses (e.g. a later
    // collection cycle finds the package reverted / never actually upgraded).
    state.trip();

    // Rollout applies the remaining target (host-2); the FINAL re-score now runs
    // against tripped state -> the linked finding is present again -> NotFixed.
    let rollout_out = b
        .run_rollout("fix-openssl", &mut ex, &verifier, "secops")
        .unwrap();
    assert_eq!(
        rollout_out,
        StageOutcome::AppliedUnverified,
        "TV-8: applied fleet-wide but re-score still finds the vuln"
    );
    assert_eq!(
        b.state("fix-openssl"),
        Some(ActionState::Verify),
        "applied-but-unverified stays at Verify, not Closed"
    );
    assert_eq!(
        *ex.applied.borrow(),
        vec!["host-1", "host-2"],
        "the fix stayed applied across the whole fleet"
    );
    assert!(
        ex.rolled_back.borrow().is_empty(),
        "a full rollout is not blindly rolled back on verify-fail"
    );
}
