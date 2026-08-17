//! Process Activity ingest: parse OCSF Process Activity envelopes (class 1007),
//! score FLAGGED process records from a canonical per-rule weight (never the
//! source `severity_id`), AGGREGATE per binary, reconcile against prior state,
//! and group by fix — reusing the shared weighted-finding + lifecycle path.
//!
//! **Identity is the binary, not the execution.** A finding's `vuln_id` is
//! `process:{image}` — the pid, the activity (exec vs exit), and the source
//! `severity_id` are EVIDENCE, not identity. A host that runs one suspicious
//! binary N times (N pids, exec+exit) is ONE problem, so it collapses to ONE
//! finding whose weight is the MAX rule-weight across every rule on every one of
//! that binary's records. This brings process findings to parity with the vuln
//! path (`run_ingest`): stable identity → within-batch aggregation → `reconcile`
//! so a recurring detection that was Closed Reopens instead of duplicating.
//!
//! procmon's `severity_id` is DELIBERATELY not read here: the
//! score is recomputed from the policy weight table below so it is explainable and
//! cannot be inflated or suppressed by a source's own label.
use std::collections::BTreeMap;

use serde::Deserialize;
use torda_findings::{Finding, FindingState};
use torda_findings_engine::aggregate::group_by_fix;
use torda_findings_engine::input::AssetContextSource;
use torda_findings_engine::lifecycle::reconcile;
use torda_ocsf::OcsfEnvelope;

use crate::pipeline::IngestReport;
use crate::scoring::weighted_finding;

/// The location tag for a process-activity finding's identity.
const PROCESS: &str = "process";

/// The triage remediation bucket for suspicious-process detections. Process
/// detections lead to INVESTIGATION, never an auto-fix — "remediation is a bridge,
/// never a decider".
const TRIAGE_REMEDIATION_KEY: &str = "triage-suspicious-process";

// Canonical per-rule weights (v0 constants, calibratable; range 0.0..=1.0). These
// are the policy's own judgement of how much each detector matters — NOT derived
// from procmon's `severity_id`. A binary's finding weight is the MAX over every
// rule on every one of that binary's records (the strongest signal governs).
/// A known living-off-the-land binary executed (e.g. powershell, certutil). A
/// LOLBin alone is common in benign automation, so a moderate weight.
const LOLBIN_WEIGHT: f32 = 0.4;
/// Execution from a suspicious path (e.g. a world-writable temp dir). Location
/// alone is a moderate signal.
const SUSPICIOUS_PATH_WEIGHT: f32 = 0.4;
/// A LOLBin running FROM a suspicious path — the two weak signals compound into a
/// strong one, so the highest weight in the table.
const LOLBIN_IN_SUSPICIOUS_PATH_WEIGHT: f32 = 0.7;
/// A suspicious process that exited almost immediately (dropper/stager pattern).
const SHORT_LIVED_SUSPICIOUS_WEIGHT: f32 = 0.5;
/// Forward-compatible floor: an unrecognized/future rule still scores a real
/// finding rather than silently vanishing, but at the lowest weight until the
/// table is calibrated for it.
const UNKNOWN_RULE_FLOOR: f32 = 0.3;

/// Canonical weight for a single detection rule (documented table above). Unknown
/// rules fall to the forward-compatible floor. Kept explicit for testability and
/// so the mapping never touches the source `severity_id`.
fn rule_weight(rule: &str) -> f32 {
    match rule {
        "lolbin" => LOLBIN_WEIGHT,
        "suspicious_path" => SUSPICIOUS_PATH_WEIGHT,
        "lolbin_in_suspicious_path" => LOLBIN_IN_SUSPICIOUS_PATH_WEIGHT,
        "short_lived_suspicious" => SHORT_LIVED_SUSPICIOUS_WEIGHT,
        _ => UNKNOWN_RULE_FLOOR,
    }
}

/// One detector hit on a process record. Only `rule` drives scoring; `reason` is
/// carried for auditability. `reason` defaults so a missing one never drops the hit.
#[derive(Deserialize)]
struct Detection {
    rule: String,
    #[serde(default)]
    #[allow(dead_code)]
    reason: String,
}

/// The flagged-record contribution of ONE envelope toward its binary's finding:
/// `(asset_id, image, max_rule_weight)`, or `None` when the record is benign
/// (no detections) or not a Process Activity envelope. Only `rule` drives the
/// weight (MAX over the record's rules); pid, activity, and `severity_id` are
/// deliberately NOT read — they are evidence, not identity, and the source label
/// is never trusted.
fn flagged_contribution(env: &OcsfEnvelope) -> Option<(String, String, f32)> {
    if env.class_uid != torda_ocsf::class::PROCESS_ACTIVITY {
        return None;
    }
    // Benign telemetry (no detections) is not a finding — mirrors fim's "only
    // violated entries". An absent/non-array `detections` yields nothing too.
    let detections: Vec<Detection> = crate::scoring::parse_lenient(&env.data["detections"]);
    // MAX weight over the record's rules: the strongest detector governs.
    let weight = detections
        .iter()
        .map(|d| rule_weight(&d.rule))
        .fold(None, |acc: Option<f32>, w| {
            Some(acc.map_or(w, |m| m.max(w)))
        })?;

    let asset_id = env.device.hostname.clone();
    let image = env.data["process"]["image"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    Some((asset_id, image, weight))
}

/// Collapses every flagged process record in the batch into ONE finding per
/// `(asset_id, image)`: the binary is the identity (`process:{image}`), so N
/// executions (all pids, exec + exit) of one suspicious binary become a single
/// finding whose weight is the MAX rule-weight ACROSS every one of that binary's
/// records — not one near-duplicate finding per record. Benign records contribute
/// nothing. Output is ordered by `(asset_id, image)` (BTreeMap) for determinism.
fn aggregate_process_findings(
    envelopes: &[OcsfEnvelope],
    assets: &dyn AssetContextSource,
) -> Vec<Finding> {
    let mut max_weight: BTreeMap<(String, String), f32> = BTreeMap::new();
    for env in envelopes {
        if let Some((asset_id, image, weight)) = flagged_contribution(env) {
            max_weight
                .entry((asset_id, image))
                .and_modify(|w| *w = w.max(weight))
                .or_insert(weight);
        }
    }
    max_weight
        .into_iter()
        .map(|((asset_id, image), weight)| {
            let vuln_id = format!("process:{image}");
            weighted_finding(
                &asset_id,
                vuln_id,
                image,
                PROCESS.to_string(),
                weight,
                TRIAGE_REMEDIATION_KEY.to_string(),
                assets,
            )
        })
        .collect()
}

/// Runs the process ingest over a batch of Process Activity envelopes. Composed
/// exactly like the vuln path's `run_ingest` (order is load-bearing):
/// `aggregate → reconcile(prior) → filter(!Suppressed) → group_by_fix`. Reconcile
/// must precede grouping so a Reopened recurrence lands in the same triage item
/// rather than spawning a duplicate. Process findings aren't Suppressed here, but
/// the filter is kept for parity with `run_ingest`.
pub fn run_process_ingest(
    envelopes: &[OcsfEnvelope],
    assets: &dyn AssetContextSource,
    prior: &[Finding],
) -> IngestReport {
    let aggregated = aggregate_process_findings(envelopes, assets);
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
    use std::collections::HashMap;
    use torda_findings::{AssetContext, Criticality, Decision, FindingState};
    use torda_findings_engine::input::MapAssetContext;
    use torda_findings_engine::score::recompute_compliance_score;
    use torda_ocsf::{class, Device, Metadata};

    use crate::fixtures::default_assets;

    /// Builds a Process Activity envelope. `severity_id` is set purely so the tests
    /// can PROVE production code ignores it — the mapper never reads this field.
    fn proc_env(
        host: &str,
        image: &str,
        activity: &str,
        pid: u64,
        lifetime_ms: serde_json::Value,
        detections: serde_json::Value,
        severity_id: u8,
    ) -> OcsfEnvelope {
        let mut e = OcsfEnvelope::new(
            class::PROCESS_ACTIVITY,
            "Process Activity",
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
                "process": { "pid": pid, "image": image },
                "activity": activity,
                "lifetime_ms": lifetime_ms,
                "detections": detections,
            }),
        );
        e.severity_id = severity_id;
        e
    }

    fn det(rule: &str) -> serde_json::Value {
        serde_json::json!({ "rule": rule, "reason": format!("{rule} fired") })
    }

    fn tiered_assets() -> MapAssetContext {
        // Same exposure flags on both, differing only in criticality, so the score
        // delta is purely the criticality axis. Internal (exposure 0.8) so neither
        // saturates to R=100 at weight 0.4.
        let ac = |crit| AssetContext {
            internet_facing: false,
            criticality: crit,
            compensating_controls: false,
        };
        let mut by = HashMap::new();
        by.insert("crown".to_string(), ac(Criticality::CrownJewel));
        by.insert("normal".to_string(), ac(Criticality::Normal));
        MapAssetContext {
            by_asset: by,
            default: ac(Criticality::Normal),
        }
    }

    #[test]
    fn flagged_lolbin_in_suspicious_path_scored_from_weight_not_severity() {
        // Envelope carries severity_id=4 (High band) but the score MUST come from
        // weight 0.7, not the band.
        let env = proc_env(
            "host-1",
            "/tmp/x/powershell",
            "exec",
            4242,
            serde_json::Value::Null,
            serde_json::json!([det("lolbin_in_suspicious_path")]),
            4,
        );
        let assets = default_assets();
        let report = run_process_ingest(&[env], &assets, &[]);

        assert_eq!(
            report.findings.len(),
            1,
            "one flagged binary -> one finding"
        );
        let f = &report.findings[0];
        // Identity is the BINARY — no pid, no activity.
        assert_eq!(f.identity.vuln_id, "process:/tmp/x/powershell");
        assert_eq!(
            f.identity.component, "/tmp/x/powershell",
            "image -> component"
        );
        assert_eq!(f.identity.location, "process");
        assert_eq!(f.remediation_key, "triage-suspicious-process");
        assert_eq!(
            f.provenance[0].reported_severity, None,
            "no source severity trusted"
        );

        // The score is EXACTLY what weight 0.7 yields for this asset context — the
        // canonical recompute, independent of severity_id=4.
        let expected = recompute_compliance_score(0.7, &assets.context("host-1"));
        assert_eq!(f.score.r, expected.r);
        assert_eq!(
            f.score.explain.sev, 0.7,
            "sev is the rule weight, not a severity band"
        );
        assert_eq!(f.decision, Decision::Act);
        assert_eq!(f.status, FindingState::Open);
    }

    #[test]
    fn three_execs_of_same_binary_collapse_to_one_finding_with_max_weight() {
        // THREE /tmp/nc execs (different pids); one also hits
        // lolbin_in_suspicious_path (0.7). Plus a benign echo (no detections).
        // Expect EXACTLY ONE finding for process:/tmp/nc at the MAX weight (0.7),
        // and NO finding for echo.
        let envelopes = [
            proc_env(
                "host-1",
                "/tmp/nc",
                "exec",
                11,
                serde_json::Value::Null,
                serde_json::json!([det("lolbin")]),
                1,
            ),
            proc_env(
                "host-1",
                "/tmp/nc",
                "exec",
                22,
                serde_json::Value::Null,
                serde_json::json!([det("suspicious_path")]),
                4,
            ),
            proc_env(
                "host-1",
                "/tmp/nc",
                "exec",
                33,
                serde_json::Value::Null,
                serde_json::json!([det("lolbin_in_suspicious_path")]),
                1,
            ),
            proc_env(
                "host-1",
                "/usr/bin/echo",
                "exec",
                44,
                serde_json::Value::Null,
                serde_json::json!([]),
                4,
            ),
        ];
        let assets = default_assets();
        let report = run_process_ingest(&envelopes, &assets, &[]);

        let nc: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.identity.vuln_id == "process:/tmp/nc")
            .collect();
        assert_eq!(
            nc.len(),
            1,
            "three /tmp/nc execs collapse to ONE finding, not three"
        );
        assert_eq!(
            nc[0].score.explain.sev, 0.7,
            "weight = MAX rule-weight across all records"
        );
        let expected = recompute_compliance_score(0.7, &assets.context("host-1"));
        assert_eq!(
            nc[0].score.r, expected.r,
            "scored from the max weight, not severity_id"
        );

        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.identity.component == "/usr/bin/echo"),
            "benign echo must not become a finding"
        );
        // All flagged records collapse under the single triage remediation item.
        assert_eq!(report.remediation_items.len(), 1);
        assert_eq!(
            report.remediation_items[0].remediation_key,
            "triage-suspicious-process"
        );
    }

    #[test]
    fn distinct_binaries_stay_distinct() {
        // Two different flagged images in one batch -> TWO findings, each with its
        // own max weight (aggregation is per (asset,image), not global).
        let envelopes = [
            proc_env(
                "host-1",
                "/tmp/nc",
                "exec",
                1,
                serde_json::Value::Null,
                serde_json::json!([det("lolbin_in_suspicious_path")]),
                1,
            ),
            proc_env(
                "host-1",
                "powershell",
                "exec",
                2,
                serde_json::Value::Null,
                serde_json::json!([det("lolbin")]),
                1,
            ),
        ];
        let assets = default_assets();
        let report = run_process_ingest(&envelopes, &assets, &[]);

        assert_eq!(
            report.findings.len(),
            2,
            "two distinct binaries -> two findings"
        );
        let nc = report
            .findings
            .iter()
            .find(|f| f.identity.vuln_id == "process:/tmp/nc")
            .expect("nc finding");
        let ps = report
            .findings
            .iter()
            .find(|f| f.identity.vuln_id == "process:powershell")
            .expect("powershell finding");
        assert_eq!(
            nc.score.explain.sev, 0.7,
            "/tmp/nc keeps its own max weight"
        );
        assert_eq!(
            ps.score.explain.sev, 0.4,
            "powershell keeps its own max weight"
        );
    }

    #[test]
    fn max_weight_is_taken_across_records_not_just_within() {
        // Record A hits only lolbin (0.4); record B (different pid) hits
        // lolbin_in_suspicious_path (0.7). The single finding must weigh 0.7 — the
        // max ACROSS records, proving cross-record aggregation (not per-record).
        let envelopes = [
            proc_env(
                "host-1",
                "/tmp/nc",
                "exec",
                1,
                serde_json::Value::Null,
                serde_json::json!([det("lolbin")]),
                1,
            ),
            proc_env(
                "host-1",
                "/tmp/nc",
                "exit",
                1,
                serde_json::json!(3),
                serde_json::json!([det("lolbin_in_suspicious_path")]),
                1,
            ),
        ];
        let assets = default_assets();
        let report = run_process_ingest(&envelopes, &assets, &[]);
        assert_eq!(
            report.findings.len(),
            1,
            "same binary across records -> one finding"
        );
        assert_eq!(
            report.findings[0].score.explain.sev, 0.7,
            "max ACROSS records, not within one"
        );
    }

    #[test]
    fn low_severity_id_does_not_suppress_a_flagged_record() {
        // Rule #5, low side: severity_id=1 (Informational) but a real detection ->
        // the weight-scored finding still appears; the low label is ignored.
        let env = proc_env(
            "host-1",
            "/usr/bin/certutil",
            "exec",
            7,
            serde_json::Value::Null,
            serde_json::json!([det("lolbin")]),
            1,
        );
        let assets = default_assets();
        let report = run_process_ingest(&[env], &assets, &[]);
        assert_eq!(
            report.findings.len(),
            1,
            "low severity_id must not suppress a real detection"
        );
        let expected = recompute_compliance_score(0.4, &assets.context("host-1"));
        assert_eq!(report.findings[0].score.r, expected.r);
    }

    #[test]
    fn inflated_severity_id_with_no_detections_yields_nothing() {
        // Rule #5, high side: severity_id=4 but EMPTY detections -> benign record is
        // NOT promoted to a finding by its label.
        let env = proc_env(
            "host-1",
            "/bin/ls",
            "exec",
            9,
            serde_json::Value::Null,
            serde_json::json!([]),
            4,
        );
        assert!(run_process_ingest(&[env], &default_assets(), &[])
            .findings
            .is_empty());
    }

    #[test]
    fn benign_exec_with_no_detections_yields_no_finding() {
        // Absent detections key entirely — still benign.
        let mut env = proc_env(
            "host-1",
            "/bin/cat",
            "exec",
            10,
            serde_json::Value::Null,
            serde_json::json!([]),
            1,
        );
        env.data.as_object_mut().unwrap().remove("detections");
        assert!(run_process_ingest(&[env], &default_assets(), &[])
            .findings
            .is_empty());
    }

    #[test]
    fn short_lived_suspicious_exit_scored_at_point_five() {
        let env = proc_env(
            "host-1",
            "/tmp/dropper",
            "exit",
            55,
            serde_json::json!(3),
            serde_json::json!([det("short_lived_suspicious")]),
            2,
        );
        let assets = default_assets();
        let report = run_process_ingest(&[env], &assets, &[]);
        let f = &report.findings[0];
        assert_eq!(f.identity.vuln_id, "process:/tmp/dropper");
        let expected = recompute_compliance_score(0.5, &assets.context("host-1"));
        assert_eq!(f.score.r, expected.r);
        assert_eq!(
            f.score.explain.sev, 0.5,
            "weight 0.5 for short_lived_suspicious"
        );
    }

    #[test]
    fn unknown_rule_scores_at_the_floor() {
        let env = proc_env(
            "host-1",
            "/opt/app/thing",
            "exec",
            100,
            serde_json::Value::Null,
            serde_json::json!([det("some_new_rule")]),
            3,
        );
        let assets = default_assets();
        let report = run_process_ingest(&[env], &assets, &[]);
        let f = &report.findings[0];
        assert_eq!(
            f.score.explain.sev, 0.3,
            "unknown rule -> 0.3 forward-compatible floor"
        );
        let expected = recompute_compliance_score(0.3, &assets.context("host-1"));
        assert_eq!(f.score.r, expected.r);
    }

    #[test]
    fn multiple_rules_on_one_record_take_the_max_weight() {
        // lolbin(0.4) + suspicious_path(0.4) + lolbin_in_suspicious_path(0.7) -> 0.7,
        // asserted to be the MAX (not the first, 0.4, nor a sum > 0.7).
        let env = proc_env(
            "host-1",
            "/tmp/x/pwsh",
            "exec",
            321,
            serde_json::Value::Null,
            serde_json::json!([
                det("lolbin"),
                det("suspicious_path"),
                det("lolbin_in_suspicious_path")
            ]),
            1,
        );
        let assets = default_assets();
        let report = run_process_ingest(&[env], &assets, &[]);
        let f = &report.findings[0];
        assert_eq!(
            f.score.explain.sev, 0.7,
            "weight = max over rules, not first or sum"
        );
        let expected = recompute_compliance_score(0.7, &assets.context("host-1"));
        assert_eq!(f.score.r, expected.r);
    }

    #[test]
    fn crown_jewel_scores_strictly_higher_than_normal_for_same_detection() {
        let detections = serde_json::json!([det("lolbin")]);
        let crown = proc_env(
            "crown",
            "/tmp/x/pwsh",
            "exec",
            1,
            serde_json::Value::Null,
            detections.clone(),
            1,
        );
        let normal = proc_env(
            "normal",
            "/tmp/x/pwsh",
            "exec",
            1,
            serde_json::Value::Null,
            detections,
            1,
        );
        let assets = tiered_assets();
        let crown_f = &run_process_ingest(&[crown], &assets, &[]).findings[0];
        let normal_f = &run_process_ingest(&[normal], &assets, &[]).findings[0];
        assert!(
            crown_f.score.r > normal_f.score.r,
            "crown jewel ({}) must outscore normal ({}) for the same detection",
            crown_f.score.r,
            normal_f.score.r,
        );
    }

    #[test]
    fn batch_ignores_non_1007_and_groups_flagged_into_one_triage_item() {
        let flagged_a = proc_env(
            "host-1",
            "/tmp/x/pwsh",
            "exec",
            11,
            serde_json::Value::Null,
            serde_json::json!([det("lolbin")]),
            1,
        );
        let flagged_b = proc_env(
            "host-1",
            "/tmp/x/certutil",
            "exec",
            22,
            serde_json::Value::Null,
            serde_json::json!([det("suspicious_path")]),
            1,
        );
        // A non-Process-Activity envelope in the batch must be ignored.
        let mut other = proc_env(
            "host-1",
            "/tmp/x/pwsh",
            "exec",
            33,
            serde_json::Value::Null,
            serde_json::json!([det("lolbin")]),
            4,
        );
        other.class_uid = class::SOFTWARE_INVENTORY_INFO;

        let report = run_process_ingest(&[flagged_a, other, flagged_b], &default_assets(), &[]);
        assert_eq!(
            report.findings.len(),
            2,
            "only the two 1007 flagged binaries score"
        );
        assert_eq!(
            report.remediation_items.len(),
            1,
            "all flagged group into one triage item"
        );
        assert_eq!(
            report.remediation_items[0].remediation_key,
            "triage-suspicious-process"
        );
    }

    #[test]
    fn prior_closed_process_finding_is_reopened_else_open() {
        // A recurring /tmp/nc detection: with no prior it is Open; with a prior
        // CLOSED finding of the SAME identity (process:/tmp/nc) it Reopens rather
        // than duplicating — parity with the vuln path's lifecycle.
        let env = proc_env(
            "host-1",
            "/tmp/nc",
            "exec",
            1,
            serde_json::Value::Null,
            serde_json::json!([det("lolbin_in_suspicious_path")]),
            1,
        );
        let assets = default_assets();

        // No prior -> Open.
        let first = run_process_ingest(std::slice::from_ref(&env), &assets, &[]);
        assert_eq!(first.findings.len(), 1);
        assert_eq!(first.findings[0].identity.vuln_id, "process:/tmp/nc");
        assert_eq!(
            first.findings[0].status,
            FindingState::Open,
            "no prior -> Open"
        );

        // Same identity previously Closed -> the fresh recurrence Reopens.
        let mut prior = first.findings[0].clone();
        prior.status = FindingState::Closed;
        let second = run_process_ingest(&[env], &assets, &[prior]);
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
