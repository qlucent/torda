//! Drift ingest: parse an OCSF Device Config State envelope, score each DRIFTED
//! baseline entry from its weight (never a source severity), and group by fix —
//! reusing the shared weighted-finding path.
use torda_compliance::drift::DriftRecord;
use torda_findings::{Finding, FindingState};
use torda_findings_engine::aggregate::group_by_fix;
use torda_findings_engine::input::AssetContextSource;
use torda_findings_engine::lifecycle::reconcile;
use torda_ocsf::OcsfEnvelope;

use crate::pipeline::IngestReport;
use crate::scoring::weighted_finding;

/// Parses one OCSF Device Config State envelope (class 5002) into findings for its
/// DRIFTED entries. Non-drift envelopes and in-spec entries yield nothing.
pub fn drift_findings_from_envelope(
    env: &OcsfEnvelope,
    assets: &dyn AssetContextSource,
) -> Vec<Finding> {
    if env.class_uid != torda_ocsf::class::DEVICE_CONFIG_STATE {
        return Vec::new();
    }
    let asset_id = env.device.hostname.clone();
    let records: Vec<DriftRecord> = crate::scoring::parse_lenient(&env.data["drift"]["records"]);

    records
        .iter()
        .filter(|r| r.drifted)
        .map(|r| {
            weighted_finding(
                &asset_id,
                r.entry_id.clone(),
                r.subject.clone(),
                r.location.clone(),
                r.weight,
                r.remediation_key.clone(),
                assets,
            )
        })
        .collect()
}

/// Runs the drift ingest over a batch of Device Config State envelopes: parse →
/// score drifted entries → `reconcile(prior)` → filter Suppressed → group by
/// fix — mirrors `run_process_ingest`'s composition (order is load-bearing:
/// reconcile must precede grouping).
pub fn run_drift_ingest(
    envelopes: &[OcsfEnvelope],
    assets: &dyn AssetContextSource,
    prior: &[Finding],
) -> IngestReport {
    let fresh: Vec<Finding> = envelopes
        .iter()
        .flat_map(|e| drift_findings_from_envelope(e, assets))
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

    // A real agent Device Config State envelope (class 5002): openssl drifted, telnet in-spec.
    const AGENT_DRIFT_NDJSON: &str = r#"{"class_uid":5002,"class_name":"Device Config State","time":0,"severity_id":1,"metadata":{"product":"torda","version":"0","tenant_id":"t"},"device":{"hostname":"host-1","os":"Test","os_version":"1"},"data":{"drift":{"records":[{"entry_id":"openssl-pinned","drifted":true,"subject":"openssl","location":"packages","weight":0.7,"expected":"3.0.14","actual":"3.0.2","remediation_key":"upgrade:openssl=3.0.14"},{"entry_id":"telnet-absent","drifted":false,"subject":"telnet","location":"packages","weight":0.6,"expected":"absent","actual":null,"remediation_key":"remove:telnet"}]}}}"#;

    #[test]
    fn end_to_end_drift_scored_from_weight() {
        let env: OcsfEnvelope = serde_json::from_str(AGENT_DRIFT_NDJSON).unwrap();
        let report = run_drift_ingest(&[env], &default_assets(), &[]);

        assert_eq!(
            report.findings.len(),
            1,
            "only the drifted entry becomes a finding"
        );
        let f = &report.findings[0];
        assert_eq!(f.identity.vuln_id, "openssl-pinned", "entry id -> vuln_id");
        assert_eq!(f.identity.component, "openssl", "subject -> component");
        assert_eq!(f.remediation_key, "upgrade:openssl=3.0.14");
        assert_eq!(
            f.provenance[0].reported_severity, None,
            "no source severity trusted"
        );
        // weight 0.7 * exposure(1.4) * crit(1.2 High) = 1.176 -> clamp -> R=100.
        assert_eq!(f.score.r, 100);
        assert_eq!(f.score.explain.sev, 0.7);
        assert_eq!(f.decision, Decision::Act);
        assert_eq!(f.status, FindingState::Open);

        assert_eq!(report.remediation_items.len(), 1);
        assert_eq!(
            report.remediation_items[0].remediation_key,
            "upgrade:openssl=3.0.14"
        );
    }

    #[test]
    fn one_malformed_record_does_not_drop_the_batch() {
        let mut env: OcsfEnvelope = serde_json::from_str(AGENT_DRIFT_NDJSON).unwrap();
        let good = env.data["drift"]["records"][0].clone();
        env.data["drift"]["records"] = serde_json::json!([good, "garbage"]);
        let report = run_drift_ingest(&[env], &default_assets(), &[]);
        assert_eq!(
            report.findings.len(),
            1,
            "valid drift survives a malformed sibling"
        );
        assert_eq!(report.findings[0].identity.vuln_id, "openssl-pinned");
    }

    #[test]
    fn non_drifted_records_and_other_classes_yield_nothing() {
        // Flip the drifted entry to in-spec -> no findings.
        let mut env: OcsfEnvelope = serde_json::from_str(AGENT_DRIFT_NDJSON).unwrap();
        env.data["drift"]["records"][0]["drifted"] = serde_json::json!(false);
        assert!(run_drift_ingest(&[env], &default_assets(), &[])
            .findings
            .is_empty());
        // A non-drift class yields nothing.
        let mut other: OcsfEnvelope = serde_json::from_str(AGENT_DRIFT_NDJSON).unwrap();
        other.class_uid = torda_ocsf::class::INVENTORY_INFO;
        assert!(run_drift_ingest(&[other], &default_assets(), &[])
            .findings
            .is_empty());
    }

    #[test]
    fn prior_closed_drift_finding_is_reopened_else_open() {
        // A recurring drift entry: with no prior it is Open; with a prior CLOSED
        // finding of the SAME identity (openssl-pinned) it Reopens rather than
        // duplicating — proves the mapper now reconciles natively.
        let env: OcsfEnvelope = serde_json::from_str(AGENT_DRIFT_NDJSON).unwrap();
        let assets = default_assets();

        // No prior -> Open.
        let first = run_drift_ingest(std::slice::from_ref(&env), &assets, &[]);
        assert_eq!(first.findings.len(), 1);
        assert_eq!(first.findings[0].identity.vuln_id, "openssl-pinned");
        assert_eq!(
            first.findings[0].status,
            FindingState::Open,
            "no prior -> Open"
        );

        // Same identity previously Closed -> the fresh recurrence Reopens.
        let mut prior = first.findings[0].clone();
        prior.status = FindingState::Closed;
        let second = run_drift_ingest(&[env], &assets, &[prior]);
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
