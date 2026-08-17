//! File Activity ingest: parse OCSF File System Activity envelopes (class
//! 1001), score FLAGGED file records from a canonical per-rule weight (never
//! the source `severity_id`), AGGREGATE per path, reconcile against prior
//! state, and group by fix — reusing the shared weighted-finding + lifecycle
//! path. The file-activity counterpart of `network.rs`.
//!
//! **Identity is the path, not the event.** A finding's `vuln_id` is
//! `file:{path}` — the pid, the op (write/open), the image, and the source
//! `severity_id` are EVIDENCE, not identity. A host with N flagged events
//! (different pids/ops/rules) against the SAME path is ONE problem, so it
//! collapses to ONE finding whose weight is the MAX rule-weight across every
//! rule on every one of that path's records. Stable identity → within-batch
//! aggregation → `reconcile` so a recurring detection that was Closed Reopens
//! instead of duplicating.
//!
//! filemon's `severity_id` is DELIBERATELY not read here:
//! the score is recomputed from the policy weight table below so it is
//! explainable and cannot be inflated or suppressed by a source's own label.
use std::collections::BTreeMap;

use serde::Deserialize;
use torda_findings::{Finding, FindingState};
use torda_findings_engine::aggregate::group_by_fix;
use torda_findings_engine::input::AssetContextSource;
use torda_findings_engine::lifecycle::reconcile;
use torda_ocsf::OcsfEnvelope;

use crate::pipeline::IngestReport;
use crate::scoring::weighted_finding;

/// The triage remediation bucket for suspicious file-activity detections.
/// File detections lead to INVESTIGATION, never an auto-fix — "remediation is
/// a bridge, never a decider".
const TRIAGE_REMEDIATION_KEY: &str = "triage-suspicious-file-activity";

// Canonical per-rule weights (v0 constants, calibratable; range 0.0..=1.0).
// These are the policy's own judgement of how much each detector matters —
// NOT derived from filemon's `severity_id`. A path's finding weight is the
// MAX over every rule on every one of that path's records (strongest signal
// governs).
/// A write to a system/binary directory (e.g. `/usr/bin/`,
/// `\windows\system32\`) — a strong tampering signal.
const WRITE_TO_SYSTEM_DIR_WEIGHT: f32 = 0.8;
/// A write to a startup/autorun/cron/systemd/init location — a persistence
/// signal.
const WRITE_TO_PERSISTENCE_WEIGHT: f32 = 0.8;
/// A write to a sensitive config/credential path (e.g. `/etc/`, `.ssh/`) —
/// can plant/alter trust material.
const WRITE_TO_SENSITIVE_CONFIG_WEIGHT: f32 = 0.8;
/// A read of a specific credential/secret file (e.g. `/etc/shadow`) — a
/// credential-theft signal, weighted lower than the write rules since nothing
/// was changed.
const READ_OF_SENSITIVE_FILE_WEIGHT: f32 = 0.5;
/// Forward-compatible floor: an unrecognized/future rule still scores a real
/// finding rather than silently vanishing, but at the lowest weight until the
/// table is calibrated for it.
const UNKNOWN_RULE_FLOOR: f32 = 0.3;

/// Canonical weight for a single detection rule (documented table above).
/// Unknown rules fall to the forward-compatible floor. Kept explicit for
/// testability and so the mapping never touches the source `severity_id`.
fn rule_weight(rule: &str) -> f32 {
    match rule {
        "write_to_system_dir" => WRITE_TO_SYSTEM_DIR_WEIGHT,
        "write_to_persistence_location" => WRITE_TO_PERSISTENCE_WEIGHT,
        "write_to_sensitive_config" => WRITE_TO_SENSITIVE_CONFIG_WEIGHT,
        "read_of_sensitive_file" => READ_OF_SENSITIVE_FILE_WEIGHT,
        _ => UNKNOWN_RULE_FLOOR,
    }
}

/// One detector hit on a file event. Only `rule` drives scoring; `reason` is
/// carried for auditability. `reason` defaults so a missing one never drops
/// the hit.
#[derive(Deserialize)]
struct Detection {
    rule: String,
    #[serde(default)]
    #[allow(dead_code)]
    reason: String,
}

/// The flagged-record contribution of ONE envelope toward its path's finding:
/// `(asset_id, path, max_rule_weight)`, or `None` when the record is benign
/// (no detections), not a File System Activity envelope, or missing its file
/// path. Only `rule` drives the weight (MAX over the record's rules); the pid,
/// op, image, and `severity_id` are deliberately NOT read — they are evidence,
/// not identity, and the source label is never trusted.
fn flagged_contribution(env: &OcsfEnvelope) -> Option<(String, String, f32)> {
    if env.class_uid != torda_ocsf::class::FILE_SYSTEM_ACTIVITY {
        return None;
    }
    // Benign telemetry (no detections) is not a finding. An absent/non-array
    // `detections` yields nothing too.
    let detections: Vec<Detection> = crate::scoring::parse_lenient(&env.data["detections"]);
    // MAX weight over the record's rules: the strongest detector governs.
    let weight = detections
        .iter()
        .map(|d| rule_weight(&d.rule))
        .fold(None, |acc: Option<f32>, w| {
            Some(acc.map_or(w, |m| m.max(w)))
        })?;

    // Path is the identity; a record missing it contributes nothing
    // (panic-free — never unwrap on untrusted payload).
    let path = env.data["file"]["path"].as_str()?;

    let asset_id = env.device.hostname.clone();
    Some((asset_id, path.to_string(), weight))
}

/// Collapses every flagged file record in the batch into ONE finding per
/// `(asset_id, path)`: the path is the identity (`file:{path}`), so N events
/// (all pids/ops/rules) against one suspicious path become a single finding
/// whose weight is the MAX rule-weight ACROSS every one of that path's
/// records — not one near-duplicate finding per record. Benign records
/// contribute nothing. Output is ordered by `(asset_id, path)` (BTreeMap) for
/// determinism.
fn aggregate_file_activity_findings(
    envelopes: &[OcsfEnvelope],
    assets: &dyn AssetContextSource,
) -> Vec<Finding> {
    let mut max_weight: BTreeMap<(String, String), f32> = BTreeMap::new();
    for env in envelopes {
        if let Some((asset_id, path, weight)) = flagged_contribution(env) {
            max_weight
                .entry((asset_id, path))
                .and_modify(|w| *w = w.max(weight))
                .or_insert(weight);
        }
    }
    max_weight
        .into_iter()
        .map(|((asset_id, path), weight)| {
            let vuln_id = format!("file:{path}");
            weighted_finding(
                &asset_id,
                vuln_id,
                path.clone(),
                path,
                weight,
                TRIAGE_REMEDIATION_KEY.to_string(),
                assets,
            )
        })
        .collect()
}

/// Runs the file-activity ingest over a batch of File System Activity
/// envelopes. Composed exactly like the network path (order is load-bearing):
/// `aggregate → reconcile(prior) → filter(!Suppressed) → group_by_fix`.
/// Reconcile must precede grouping so a Reopened recurrence lands in the same
/// triage item rather than spawning a duplicate. File-activity findings
/// aren't Suppressed here, but the filter is kept for parity with
/// `run_ingest`/`run_network_ingest`.
pub fn run_file_activity_ingest(
    envelopes: &[OcsfEnvelope],
    assets: &dyn AssetContextSource,
    prior: &[Finding],
) -> IngestReport {
    let aggregated = aggregate_file_activity_findings(envelopes, assets);
    let findings = reconcile(prior, aggregated, crate::pipeline::batch_time(envelopes));
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
    use torda_findings::{Decision, FindingState};
    use torda_findings_engine::score::recompute_compliance_score;
    use torda_ocsf::{class, Device, Metadata};

    use crate::fixtures::default_assets;

    /// Builds a File System Activity envelope. `severity_id` is set purely so
    /// the tests can PROVE production code ignores it — the mapper never
    /// reads this field.
    fn file_env(
        host: &str,
        path: &str,
        op: &str,
        pid: u64,
        image: &str,
        detections: serde_json::Value,
        severity_id: u8,
    ) -> OcsfEnvelope {
        let mut e = OcsfEnvelope::new(
            class::FILE_SYSTEM_ACTIVITY,
            "File System Activity",
            Metadata {
                product: "torda".into(),
                version: "0".into(),
                tenant_id: "t".into(),
            },
            Device {
                hostname: host.into(),
                os: "Test".into(),
                os_version: "1".into(),
            },
            serde_json::json!({
                "file": { "path": path, "op": op },
                "pid": pid,
                "image": image,
                "detections": detections,
            }),
        );
        e.severity_id = severity_id;
        e
    }

    fn det(rule: &str) -> serde_json::Value {
        serde_json::json!({ "rule": rule, "reason": format!("{rule} fired") })
    }

    #[test]
    fn flagged_write_to_sensitive_config_scored_from_weight_not_severity() {
        // Envelope carries severity_id=1 (Informational) but the score MUST
        // come from weight 0.8, not the (inconsistent, low) label.
        let env = file_env(
            "host-1",
            "/etc/passwd",
            "write",
            42,
            "vim",
            serde_json::json!([det("write_to_sensitive_config")]),
            1,
        );
        let assets = default_assets();
        let report = run_file_activity_ingest(&[env], &assets, &[]);

        assert_eq!(report.findings.len(), 1, "one flagged path -> one finding");
        let f = &report.findings[0];
        // Identity is the PATH — no pid, op, or image.
        assert_eq!(f.identity.vuln_id, "file:/etc/passwd");
        assert_eq!(f.identity.component, "/etc/passwd");
        assert_eq!(f.identity.location, "/etc/passwd", "location == path");
        assert_eq!(f.remediation_key, "triage-suspicious-file-activity");
        assert_eq!(
            f.provenance[0].reported_severity, None,
            "no source severity trusted"
        );

        // The score is EXACTLY what weight 0.8 yields for this asset context —
        // the canonical recompute, independent of severity_id=1.
        let expected = recompute_compliance_score(0.8, &assets.context("host-1"));
        assert_eq!(f.score.r, expected.r);
        assert_eq!(
            f.score.explain.sev, 0.8,
            "sev is the rule weight, not a severity band"
        );
        assert_eq!(f.decision, Decision::Act);
        assert_eq!(f.status, FindingState::Open);
    }

    #[test]
    fn each_rule_scores_its_own_weight() {
        let cases: [(&str, f32); 4] = [
            ("write_to_system_dir", WRITE_TO_SYSTEM_DIR_WEIGHT),
            ("write_to_persistence_location", WRITE_TO_PERSISTENCE_WEIGHT),
            (
                "write_to_sensitive_config",
                WRITE_TO_SENSITIVE_CONFIG_WEIGHT,
            ),
            ("read_of_sensitive_file", READ_OF_SENSITIVE_FILE_WEIGHT),
        ];
        let assets = default_assets();
        for (i, (rule, weight)) in cases.iter().enumerate() {
            let path = format!("/etc/case-{i}");
            let env = file_env(
                "host-1",
                &path,
                "write",
                i as u64,
                "x",
                serde_json::json!([det(rule)]),
                3,
            );
            let report = run_file_activity_ingest(&[env], &assets, &[]);
            assert_eq!(report.findings.len(), 1, "rule {rule}");
            assert_eq!(
                report.findings[0].score.explain.sev, *weight,
                "rule {rule} -> weight {weight}"
            );
        }
    }

    #[test]
    fn unknown_rule_scores_at_the_floor() {
        let env = file_env(
            "host-1",
            "/etc/mystery",
            "write",
            100,
            "x",
            serde_json::json!([det("some_new_rule")]),
            3,
        );
        let assets = default_assets();
        let report = run_file_activity_ingest(&[env], &assets, &[]);
        let f = &report.findings[0];
        assert_eq!(
            f.score.explain.sev, 0.3,
            "unknown rule -> 0.3 forward-compatible floor"
        );
        let expected = recompute_compliance_score(0.3, &assets.context("host-1"));
        assert_eq!(f.score.r, expected.r);
    }

    #[test]
    fn non_1001_envelope_yields_no_finding() {
        // A network (4001) envelope with a `file`-shaped payload must not be
        // mistaken for file activity.
        let mut env = file_env(
            "host-1",
            "/etc/passwd",
            "write",
            1,
            "x",
            serde_json::json!([det("write_to_sensitive_config")]),
            4,
        );
        env.class_uid = class::NETWORK_ACTIVITY;
        assert!(run_file_activity_ingest(&[env], &default_assets(), &[])
            .findings
            .is_empty());

        // A process (1007) envelope likewise.
        let mut env2 = file_env(
            "host-1",
            "/etc/passwd",
            "write",
            1,
            "x",
            serde_json::json!([det("write_to_sensitive_config")]),
            4,
        );
        env2.class_uid = class::PROCESS_ACTIVITY;
        assert!(run_file_activity_ingest(&[env2], &default_assets(), &[])
            .findings
            .is_empty());
    }

    #[test]
    fn empty_detections_yields_no_finding() {
        let env = file_env(
            "host-1",
            "/etc/passwd",
            "write",
            1,
            "x",
            serde_json::json!([]),
            4,
        );
        assert!(run_file_activity_ingest(&[env], &default_assets(), &[])
            .findings
            .is_empty());
    }

    #[test]
    fn absent_detections_yields_no_finding() {
        let mut env = file_env(
            "host-1",
            "/etc/passwd",
            "write",
            1,
            "x",
            serde_json::json!([]),
            1,
        );
        env.data.as_object_mut().unwrap().remove("detections");
        assert!(run_file_activity_ingest(&[env], &default_assets(), &[])
            .findings
            .is_empty());
    }

    #[test]
    fn missing_path_yields_no_finding() {
        let mut env = file_env(
            "host-1",
            "/etc/passwd",
            "write",
            1,
            "x",
            serde_json::json!([det("write_to_sensitive_config")]),
            3,
        );
        env.data["file"].as_object_mut().unwrap().remove("path");
        assert!(run_file_activity_ingest(&[env], &default_assets(), &[])
            .findings
            .is_empty());
    }

    #[test]
    fn two_events_same_path_different_pids_collapse_to_one_finding() {
        // Two envelopes, SAME path, different pids, both hitting
        // write_to_system_dir -> ONE finding, not two.
        let envelopes = [
            file_env(
                "host-1",
                "/usr/bin/evil",
                "write",
                11,
                "a",
                serde_json::json!([det("write_to_system_dir")]),
                1,
            ),
            file_env(
                "host-1",
                "/usr/bin/evil",
                "write",
                22,
                "b",
                serde_json::json!([det("write_to_system_dir")]),
                4,
            ),
        ];
        let assets = default_assets();
        let report = run_file_activity_ingest(&envelopes, &assets, &[]);
        assert_eq!(
            report.findings.len(),
            1,
            "same path across pids collapses to one finding"
        );
        assert_eq!(report.findings[0].identity.vuln_id, "file:/usr/bin/evil");
    }

    #[test]
    fn two_different_rules_same_path_collapse_with_max_weight() {
        // One write_to_system_dir (0.8) + one read_of_sensitive_file (0.5) on
        // the SAME path -> ONE finding, weight = MAX = 0.8.
        let envelopes = [
            file_env(
                "host-1",
                "/etc/shadow",
                "write",
                1,
                "a",
                serde_json::json!([det("write_to_system_dir")]),
                1,
            ),
            file_env(
                "host-1",
                "/etc/shadow",
                "open",
                2,
                "b",
                serde_json::json!([det("read_of_sensitive_file")]),
                4,
            ),
        ];
        let assets = default_assets();
        let report = run_file_activity_ingest(&envelopes, &assets, &[]);
        assert_eq!(
            report.findings.len(),
            1,
            "same path across rules collapses to one finding"
        );
        assert_eq!(
            report.findings[0].score.explain.sev, 0.8,
            "weight = MAX across records/rules"
        );
        let expected = recompute_compliance_score(0.8, &assets.context("host-1"));
        assert_eq!(report.findings[0].score.r, expected.r);
    }

    #[test]
    fn distinct_paths_stay_distinct() {
        let envelopes = [
            file_env(
                "host-1",
                "/etc/passwd",
                "write",
                1,
                "a",
                serde_json::json!([det("write_to_sensitive_config")]),
                1,
            ),
            file_env(
                "host-1",
                "/usr/bin/evil",
                "write",
                2,
                "b",
                serde_json::json!([det("write_to_system_dir")]),
                1,
            ),
        ];
        let assets = default_assets();
        let report = run_file_activity_ingest(&envelopes, &assets, &[]);
        assert_eq!(
            report.findings.len(),
            2,
            "two distinct paths -> two findings"
        );
    }

    #[test]
    fn batch_ignores_non_1001_and_groups_flagged_into_one_triage_item() {
        let flagged_a = file_env(
            "host-1",
            "/etc/passwd",
            "write",
            1,
            "a",
            serde_json::json!([det("write_to_sensitive_config")]),
            1,
        );
        let flagged_b = file_env(
            "host-1",
            "/usr/bin/evil",
            "write",
            2,
            "b",
            serde_json::json!([det("write_to_system_dir")]),
            1,
        );
        let mut other = file_env(
            "host-1",
            "/etc/shadow",
            "open",
            3,
            "c",
            serde_json::json!([det("read_of_sensitive_file")]),
            4,
        );
        other.class_uid = class::NETWORK_ACTIVITY;

        let report =
            run_file_activity_ingest(&[flagged_a, other, flagged_b], &default_assets(), &[]);
        assert_eq!(
            report.findings.len(),
            2,
            "only the two 1001 flagged paths score"
        );
        assert_eq!(
            report.remediation_items.len(),
            1,
            "all flagged group into one triage item"
        );
        assert_eq!(
            report.remediation_items[0].remediation_key,
            "triage-suspicious-file-activity"
        );
    }

    #[test]
    fn prior_closed_file_finding_is_reopened_else_open() {
        // A recurring /etc/passwd detection: with no prior it is Open; with a
        // prior CLOSED finding of the SAME identity (file:/etc/passwd) it
        // Reopens rather than duplicating — parity with the network lifecycle.
        let env = file_env(
            "host-1",
            "/etc/passwd",
            "write",
            1,
            "vim",
            serde_json::json!([det("write_to_sensitive_config")]),
            1,
        );
        let assets = default_assets();

        // No prior -> Open.
        let first = run_file_activity_ingest(std::slice::from_ref(&env), &assets, &[]);
        assert_eq!(first.findings.len(), 1);
        assert_eq!(first.findings[0].identity.vuln_id, "file:/etc/passwd");
        assert_eq!(
            first.findings[0].status,
            FindingState::Open,
            "no prior -> Open"
        );

        // Same identity previously Closed -> the fresh recurrence Reopens.
        let mut prior = first.findings[0].clone();
        prior.status = FindingState::Closed;
        let second = run_file_activity_ingest(&[env], &assets, &[prior]);
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
