//! The user-authored remediation action and the lifecycle states it moves through.
use serde::{Deserialize, Serialize};

/// How the user's remediation is delivered. The bridge executes the user's own
/// payload via this method; it never substitutes vendor patch content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Method {
    Shell,
    PackageMgr,
    Ansible,
    CustomTool,
    Webhook,
}

/// The explicit set of assets an action targets. There is NO default-all: an
/// empty selector is not scoped and the bridge refuses to draft it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AssetSelector {
    pub asset_ids: Vec<String>,
}

impl AssetSelector {
    /// True only if the selector names at least one explicit asset.
    pub fn is_scoped(&self) -> bool {
        !self.asset_ids.is_empty()
    }
}

/// Canary cohort sizing + the failure threshold that halts a rollout. Used when
/// execution lands (P3a-2); carried on the action from authoring time.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CanarySpec {
    pub cohort_size: usize,
    pub failure_threshold: f32,
}

/// Which finding(s) should close when this action verifies successfully. The
/// verification loop (P3a-3) re-scores these; no re-score, no closure.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VerifySpec {
    pub finding_ids: Vec<String>,
}

/// A user-authored remediation action. Every field is supplied by the user or the
/// authoring UI; the bridge adds only targeting, gating, audit, and verification.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RemediationAction {
    pub id: String,
    pub name: String,
    pub method: Method,
    /// The user's OWN script/command/playbook reference — never authored here.
    pub payload: String,
    pub targets: AssetSelector,
    pub requires_approval: bool,
    pub dry_run_supported: bool,
    pub rollback: Option<String>,
    pub verify: VerifySpec,
    pub canary: CanarySpec,
}

/// The action lifecycle. This slice drives the
/// pre-execution states; the post-approval states are reserved for P3a-2/P3a-3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionState {
    Drafted,
    Mapped,
    DryRun,
    PendingApproval,
    Approved,
    Canary,
    CanaryVerify,
    Rollout,
    Verify,
    Closed,
    Aborted,
    RolledBack,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RemediationAction {
        RemediationAction {
            id: "act-1".into(),
            name: "disable telnet".into(),
            method: Method::PackageMgr,
            payload: "apt-get remove -y telnetd".into(),
            targets: AssetSelector {
                asset_ids: vec!["host-1".into()],
            },
            requires_approval: true,
            dry_run_supported: true,
            rollback: Some("apt-get install -y telnetd".into()),
            verify: VerifySpec {
                finding_ids: vec!["host-1|telnet-not-installed|telnet|packages".into()],
            },
            canary: CanarySpec {
                cohort_size: 1,
                failure_threshold: 0.0,
            },
        }
    }

    #[test]
    fn explicit_selector_is_scoped_empty_is_not() {
        assert!(AssetSelector {
            asset_ids: vec!["h1".into()]
        }
        .is_scoped());
        assert!(
            !AssetSelector { asset_ids: vec![] }.is_scoped(),
            "empty selector is NOT scoped (no implicit fleet-wide)"
        );
    }

    #[test]
    fn action_round_trips_through_serde() {
        let a = sample();
        let back: RemediationAction =
            serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn action_carries_the_users_own_payload_and_rollback() {
        // The bridge never authors these — they come from the user.
        let a = sample();
        assert_eq!(a.payload, "apt-get remove -y telnetd");
        assert_eq!(a.rollback.as_deref(), Some("apt-get install -y telnetd"));
        assert!(a.requires_approval, "approval defaults on");
    }

    #[test]
    fn action_state_is_comparable_and_copy() {
        let s = ActionState::PendingApproval;
        let t = s; // Copy
        assert_eq!(s, t);
        assert_ne!(ActionState::Approved, ActionState::Aborted);
    }
}
