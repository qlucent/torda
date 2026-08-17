//! Compliance ingest: parse an OCSF Compliance Finding envelope, score each
//! FAILED control from its weight (never the framework's stock severity), and
//! group by fix — reusing the findings engine's decide/group/id.
use torda_compliance::record::ComplianceRecord;
use torda_findings::{Finding, FindingState};
use torda_findings_engine::aggregate::group_by_fix;
use torda_findings_engine::input::AssetContextSource;
use torda_findings_engine::lifecycle::reconcile;
use torda_ocsf::OcsfEnvelope;

use crate::pipeline::IngestReport;

/// Parses one OCSF Compliance Finding envelope (class 2003) into findings for its
/// FAILED controls. Non-compliance envelopes and passing controls yield nothing.
pub fn compliance_findings_from_envelope(
    env: &OcsfEnvelope,
    assets: &dyn AssetContextSource,
) -> Vec<Finding> {
    if env.class_uid != torda_ocsf::class::COMPLIANCE_FINDING {
        return Vec::new();
    }
    let asset_id = env.device.hostname.clone();
    let records: Vec<ComplianceRecord> =
        crate::scoring::parse_lenient(&env.data["compliance"]["records"]);

    records
        .iter()
        .filter(|r| !r.passed)
        .map(|r| {
            crate::scoring::weighted_finding(
                &asset_id,
                r.control_id.clone(),
                r.subject.clone(),
                r.location.clone(),
                r.weight,
                r.remediation_key.clone(),
                assets,
            )
        })
        .collect()
}

/// Runs the compliance ingest over a batch of OCSF Compliance Finding envelopes:
/// parse → score failed controls → `reconcile(prior)` → filter Suppressed →
/// group by fix — mirrors `run_process_ingest`'s composition (order is
/// load-bearing: reconcile must precede grouping).
pub fn run_compliance_ingest(
    envelopes: &[OcsfEnvelope],
    assets: &dyn AssetContextSource,
    prior: &[Finding],
) -> IngestReport {
    let fresh: Vec<Finding> = envelopes
        .iter()
        .flat_map(|e| compliance_findings_from_envelope(e, assets))
        .collect();
    let findings = reconcile(prior, fresh, crate::pipeline::batch_time(envelopes));
    let actionable: Vec<Finding> = findings
        .iter()
        .filter(|f| f.status != FindingState::Suppressed)
        .cloned()
        .collect();
    let remediation_items = group_by_fix(&actionable);
    IngestReport {
        findings,
        remediation_items,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::default_assets;
    use torda_findings::{Decision, FindingState};

    // A real agent Compliance Finding record (OCSF class 2003), one failed control.
    const AGENT_COMPLIANCE_NDJSON: &str = r#"{"class_uid":2003,"class_name":"Compliance Finding","time":0,"severity_id":1,"metadata":{"product":"torda","version":"0","tenant_id":"t"},"device":{"hostname":"host-1","os":"Test","os_version":"1"},"data":{"compliance":{"records":[{"control_id":"telnet-not-installed","passed":false,"weight":0.6,"subject":"telnet","location":"package-manager","remediation_key":"remove:telnet","frameworks":[{"framework":"CIS","control_ids":["CIS-2.3.1"]}]}]}}}"#;

    #[test]
    fn end_to_end_compliance_finding_scored_from_weight() {
        let env: OcsfEnvelope = serde_json::from_str(AGENT_COMPLIANCE_NDJSON).unwrap();
        let report = run_compliance_ingest(&[env], &default_assets(), &[]);

        assert_eq!(
            report.findings.len(),
            1,
            "one failed control -> one finding"
        );
        let f = &report.findings[0];
        assert_eq!(
            f.identity.vuln_id, "telnet-not-installed",
            "control id -> vuln_id"
        );
        assert_eq!(f.identity.component, "telnet", "subject -> component");
        assert_eq!(f.remediation_key, "remove:telnet");
        // Framework stock severity discarded: no reported_severity on provenance.
        assert_eq!(f.provenance[0].reported_severity, None);
        // Score from weight only: 0.6 * exposure(1.4) * crit(1.2 High) = 1.008 -> R=100.
        assert_eq!(f.score.r, 100);
        assert_eq!(f.score.explain.sev, 0.6);
        assert_eq!(f.decision, Decision::Act);
        assert_eq!(f.status, FindingState::Open);

        assert_eq!(report.remediation_items.len(), 1);
        assert_eq!(report.remediation_items[0].remediation_key, "remove:telnet");
    }

    #[test]
    fn one_malformed_record_does_not_drop_the_batch() {
        // A valid failed control alongside a garbage array element: the valid one
        // must still become a finding (fail-safe), not be dropped with the bad one.
        let mut env: OcsfEnvelope = serde_json::from_str(AGENT_COMPLIANCE_NDJSON).unwrap();
        let good = env.data["compliance"]["records"][0].clone();
        env.data["compliance"]["records"] =
            serde_json::json!([good, "garbage", {"unexpected": true}]);
        let report = run_compliance_ingest(&[env], &default_assets(), &[]);
        assert_eq!(
            report.findings.len(),
            1,
            "valid record survives a malformed sibling"
        );
        assert_eq!(report.findings[0].identity.vuln_id, "telnet-not-installed");
    }

    #[test]
    fn passed_controls_and_non_compliance_envelopes_yield_nothing() {
        // A passing control produces no finding.
        let mut env: OcsfEnvelope = serde_json::from_str(AGENT_COMPLIANCE_NDJSON).unwrap();
        env.data["compliance"]["records"][0]["passed"] = serde_json::json!(true);
        assert!(run_compliance_ingest(&[env], &default_assets(), &[])
            .findings
            .is_empty());
        // A non-compliance class yields nothing.
        let mut other: OcsfEnvelope = serde_json::from_str(AGENT_COMPLIANCE_NDJSON).unwrap();
        other.class_uid = torda_ocsf::class::INVENTORY_INFO;
        assert!(run_compliance_ingest(&[other], &default_assets(), &[])
            .findings
            .is_empty());
    }

    #[test]
    fn prior_closed_compliance_finding_is_reopened_else_open() {
        // A recurring failed control: with no prior it is Open; with a prior CLOSED
        // finding of the SAME identity (telnet-not-installed) it Reopens rather than
        // duplicating — proves the mapper now reconciles natively.
        let env: OcsfEnvelope = serde_json::from_str(AGENT_COMPLIANCE_NDJSON).unwrap();
        let assets = default_assets();

        // No prior -> Open.
        let first = run_compliance_ingest(std::slice::from_ref(&env), &assets, &[]);
        assert_eq!(first.findings.len(), 1);
        assert_eq!(first.findings[0].identity.vuln_id, "telnet-not-installed");
        assert_eq!(
            first.findings[0].status,
            FindingState::Open,
            "no prior -> Open"
        );

        // Same identity previously Closed -> the fresh recurrence Reopens.
        let mut prior = first.findings[0].clone();
        prior.status = FindingState::Closed;
        let second = run_compliance_ingest(&[env], &assets, &[prior]);
        assert_eq!(
            second.findings.len(),
            1,
            "reopen does not duplicate the finding"
        );
        assert_eq!(
            second.findings[0].status,
            FindingState::Reopened,
            "closed + reappeared -> Reopened"
        );
    }
}
