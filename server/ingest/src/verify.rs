//! The real remediation Verifier: re-runs the Findings Engine over the current
//! (post-fix) OCSF for an action's targets and reports Fixed iff the action's
//! linked findings are no longer produced. No verification -> no closure. It
//! re-uses the actual ingest/score pipeline — it never re-implements scoring.
use torda_ocsf::OcsfEnvelope;
use torda_remediation::action::RemediationAction;
use torda_remediation::bridge::{Verifier, VerifyOutcome};

use crate::fixtures::{default_assets, default_enrichment, default_feed};
use crate::pipeline::run_ingest;

/// The current (post-fix) OCSF for an asset — in production the agent re-collects
/// and re-emits after applying the fix; here it is injected. The verifier re-scores
/// these to decide whether the linked findings are gone.
pub trait CurrentState {
    fn envelopes(&self, asset_id: &str) -> Vec<OcsfEnvelope>;
}

/// Verifies a remediation by re-running the Findings Engine over the post-fix
/// state of the action's targets. `Fixed` iff NONE of the action's linked
/// `finding_ids` are still produced; otherwise `NotFixed`. Uses the offline
/// fixture feed/enrichment/assets (the real feed-synced inputs land with the
/// server infrastructure).
pub struct EngineVerifier<'a> {
    state: &'a dyn CurrentState,
}

impl<'a> EngineVerifier<'a> {
    pub fn new(state: &'a dyn CurrentState) -> Self {
        Self { state }
    }
}

impl Verifier for EngineVerifier<'_> {
    fn verify(&self, action: &RemediationAction, _applied: &[String]) -> VerifyOutcome {
        // Nothing to verify -> nothing is confirmed fixed. An action that links no
        // findings must never close on a vacuous "Fixed" (no verification -> no closure).
        if action.verify.finding_ids.is_empty() {
            return VerifyOutcome::NotFixed;
        }

        // Re-collect + re-ingest the current state for every target asset.
        let feed = default_feed();
        let enrichment = default_enrichment();
        let assets = default_assets();
        let mut present: std::collections::HashSet<String> = std::collections::HashSet::new();
        for asset in &action.targets.asset_ids {
            let envelopes = self.state.envelopes(asset);
            let report = run_ingest(&envelopes, &feed, &enrichment, &assets, &[]);
            for f in &report.findings {
                present.insert(f.finding_id.clone());
            }
        }
        // Fixed iff none of the linked findings are still produced.
        if action
            .verify
            .finding_ids
            .iter()
            .any(|id| present.contains(id))
        {
            VerifyOutcome::NotFixed
        } else {
            VerifyOutcome::Fixed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // An SBOM envelope for `host` carrying one component (name, version).
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

    struct FixedState(Vec<OcsfEnvelope>);
    impl CurrentState for FixedState {
        fn envelopes(&self, _asset_id: &str) -> Vec<OcsfEnvelope> {
            self.0.clone()
        }
    }

    // The finding_id the engine produces for openssl 3.0.2 on host-1 (see default_feed).
    const OPENSSL_FINDING: &str = "host-1|CVE-2022-3602|openssl|dpkg";

    fn action_verifying(finding: &str) -> RemediationAction {
        use torda_remediation::action::*;
        RemediationAction {
            id: "a".into(),
            name: "upgrade openssl".into(),
            method: Method::PackageMgr,
            payload: "apt-get install -y openssl=3.0.14".into(),
            targets: AssetSelector {
                asset_ids: vec!["host-1".into()],
            },
            requires_approval: true,
            dry_run_supported: true,
            rollback: None,
            verify: VerifySpec {
                finding_ids: vec![finding.into()],
            },
            canary: CanarySpec {
                cohort_size: 1,
                failure_threshold: 0.0,
            },
        }
    }

    #[test]
    fn verifies_fixed_when_the_finding_is_gone_after_rescore() {
        // Post-fix state: openssl upgraded to 3.0.14 -> the feed no longer matches -> no finding.
        let state = FixedState(vec![sbom("host-1", "openssl", "3.0.14")]);
        let v = EngineVerifier::new(&state);
        assert_eq!(
            v.verify(&action_verifying(OPENSSL_FINDING), &["host-1".into()]),
            VerifyOutcome::Fixed
        );
    }

    #[test]
    fn verifies_notfixed_when_the_finding_persists() {
        // Post-fix state: openssl STILL 3.0.2 -> the CVE finding is still produced.
        let state = FixedState(vec![sbom("host-1", "openssl", "3.0.2")]);
        let v = EngineVerifier::new(&state);
        assert_eq!(
            v.verify(&action_verifying(OPENSSL_FINDING), &["host-1".into()]),
            VerifyOutcome::NotFixed
        );
    }

    #[test]
    fn empty_verify_spec_never_verifies_fixed() {
        // Even with a fully-clean post-fix state, an action linking NO findings
        // cannot verify Fixed (would be a vacuous closure).
        let state = FixedState(vec![sbom("host-1", "openssl", "3.0.14")]);
        let v = EngineVerifier::new(&state);
        let mut a = action_verifying("unused");
        a.verify.finding_ids.clear();
        assert_eq!(v.verify(&a, &["host-1".into()]), VerifyOutcome::NotFixed);
    }

    #[test]
    fn unrelated_persisting_findings_do_not_block_verification() {
        // Post-fix state still has vulnerable openssl 3.0.2 -> the openssl CVE
        // finding IS produced (present is non-empty). But the action links a
        // DIFFERENT finding that is not produced -> that specific finding is
        // fixed, regardless of the unrelated one persisting.
        let state = FixedState(vec![sbom("host-1", "openssl", "3.0.2")]);
        let v = EngineVerifier::new(&state);
        let action = action_verifying("host-1|CVE-9999|other-pkg|dpkg");
        assert_eq!(
            v.verify(&action, &["host-1".into()]),
            VerifyOutcome::Fixed,
            "the linked finding is absent even though an UNRELATED finding (openssl CVE) persists"
        );
    }
}
