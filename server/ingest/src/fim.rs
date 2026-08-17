//! FIM ingest: parse an OCSF File Integrity Finding envelope, score each VIOLATED
//! watch entry from its weight (never a source severity), and group by fix —
//! reusing the shared weighted-finding path.
use torda_compliance::fim::FimRecord;
use torda_findings::{Finding, FindingState};
use torda_findings_engine::aggregate::group_by_fix;
use torda_findings_engine::input::AssetContextSource;
use torda_findings_engine::lifecycle::reconcile;
use torda_ocsf::OcsfEnvelope;

use crate::pipeline::IngestReport;
use crate::scoring::weighted_finding;

/// The location tag for a file-integrity finding's identity.
const FILESYSTEM: &str = "filesystem";

/// Parses one OCSF File Integrity Finding envelope (class 2004) into findings for
/// its VIOLATED entries. Non-FIM envelopes and intact entries yield nothing.
pub fn fim_findings_from_envelope(
    env: &OcsfEnvelope,
    assets: &dyn AssetContextSource,
) -> Vec<Finding> {
    if env.class_uid != torda_ocsf::class::FILE_INTEGRITY_FINDING {
        return Vec::new();
    }
    let asset_id = env.device.hostname.clone();
    let records: Vec<FimRecord> = crate::scoring::parse_lenient(&env.data["fim"]["records"]);

    records
        .iter()
        .filter(|r| r.violated)
        .map(|r| {
            weighted_finding(
                &asset_id,
                r.entry_id.clone(),
                r.path.clone(),
                FILESYSTEM.to_string(),
                r.weight,
                r.remediation_key.clone(),
                assets,
            )
        })
        .collect()
}

/// Runs the FIM ingest over a batch of File Integrity Finding envelopes: parse →
/// score violated entries → `reconcile(prior)` → filter Suppressed → group by
/// fix — mirrors `run_process_ingest`'s composition (order is load-bearing:
/// reconcile must precede grouping).
pub fn run_fim_ingest(
    envelopes: &[OcsfEnvelope],
    assets: &dyn AssetContextSource,
    prior: &[Finding],
) -> IngestReport {
    let fresh: Vec<Finding> = envelopes
        .iter()
        .flat_map(|e| fim_findings_from_envelope(e, assets))
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

    // A real agent File Integrity Finding envelope (class 2004): passwd violated, sshd intact.
    const AGENT_FIM_NDJSON: &str = r#"{"class_uid":2004,"class_name":"File Integrity Finding","time":0,"severity_id":1,"metadata":{"product":"torda","version":"0","tenant_id":"t"},"device":{"hostname":"host-1","os":"Test","os_version":"1"},"data":{"fim":{"records":[{"entry_id":"fim-passwd","violated":true,"path":"/etc/passwd","weight":0.9,"expected_sha256":"2222222222222222222222222222222222222222222222222222222222222222","actual_sha256":"9999999999999999999999999999999999999999999999999999999999999999","remediation_key":"investigate:/etc/passwd"},{"entry_id":"fim-sshd-config","violated":false,"path":"/etc/ssh/sshd_config","weight":0.8,"expected_sha256":"1111111111111111111111111111111111111111111111111111111111111111","actual_sha256":"1111111111111111111111111111111111111111111111111111111111111111","remediation_key":"restore:/etc/ssh/sshd_config"}]}}}"#;

    #[test]
    fn end_to_end_fim_violation_scored_from_weight() {
        let env: OcsfEnvelope = serde_json::from_str(AGENT_FIM_NDJSON).unwrap();
        let report = run_fim_ingest(&[env], &default_assets(), &[]);

        assert_eq!(
            report.findings.len(),
            1,
            "only the violated entry becomes a finding"
        );
        let f = &report.findings[0];
        assert_eq!(f.identity.vuln_id, "fim-passwd", "entry id -> vuln_id");
        assert_eq!(f.identity.component, "/etc/passwd", "path -> component");
        assert_eq!(f.identity.location, "filesystem");
        assert_eq!(f.remediation_key, "investigate:/etc/passwd");
        assert_eq!(
            f.provenance[0].reported_severity, None,
            "no source severity trusted"
        );
        // weight 0.9 * exposure(1.4) * crit(1.2 High) = 1.512 -> clamp -> R=100.
        assert_eq!(f.score.r, 100);
        assert_eq!(f.score.explain.sev, 0.9);
        assert_eq!(f.decision, Decision::Act);
        assert_eq!(f.status, FindingState::Open);

        assert_eq!(report.remediation_items.len(), 1);
        assert_eq!(
            report.remediation_items[0].remediation_key,
            "investigate:/etc/passwd"
        );
    }

    #[test]
    fn one_malformed_record_does_not_drop_the_batch() {
        let mut env: OcsfEnvelope = serde_json::from_str(AGENT_FIM_NDJSON).unwrap();
        let good = env.data["fim"]["records"][0].clone();
        env.data["fim"]["records"] = serde_json::json!([good, "garbage"]);
        let report = run_fim_ingest(&[env], &default_assets(), &[]);
        assert_eq!(
            report.findings.len(),
            1,
            "valid violation survives a malformed sibling"
        );
        assert_eq!(report.findings[0].identity.vuln_id, "fim-passwd");
    }

    #[test]
    fn intact_records_and_other_classes_yield_nothing() {
        // Flip the violated entry to intact -> no findings.
        let mut env: OcsfEnvelope = serde_json::from_str(AGENT_FIM_NDJSON).unwrap();
        env.data["fim"]["records"][0]["violated"] = serde_json::json!(false);
        assert!(run_fim_ingest(&[env], &default_assets(), &[])
            .findings
            .is_empty());
        // A non-FIM class yields nothing.
        let mut other: OcsfEnvelope = serde_json::from_str(AGENT_FIM_NDJSON).unwrap();
        other.class_uid = torda_ocsf::class::INVENTORY_INFO;
        assert!(run_fim_ingest(&[other], &default_assets(), &[])
            .findings
            .is_empty());
    }

    #[test]
    fn prior_closed_fim_finding_is_reopened_else_open() {
        // A recurring FIM violation: with no prior it is Open; with a prior CLOSED
        // finding of the SAME identity (fim-passwd) it Reopens rather than
        // duplicating — proves the mapper now reconciles natively.
        let env: OcsfEnvelope = serde_json::from_str(AGENT_FIM_NDJSON).unwrap();
        let assets = default_assets();

        // No prior -> Open.
        let first = run_fim_ingest(std::slice::from_ref(&env), &assets, &[]);
        assert_eq!(first.findings.len(), 1);
        assert_eq!(first.findings[0].identity.vuln_id, "fim-passwd");
        assert_eq!(
            first.findings[0].status,
            FindingState::Open,
            "no prior -> Open"
        );

        // Same identity previously Closed -> the fresh recurrence Reopens.
        let mut prior = first.findings[0].clone();
        prior.status = FindingState::Closed;
        let second = run_fim_ingest(&[env], &assets, &[prior]);
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
