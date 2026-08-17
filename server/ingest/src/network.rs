//! Network Activity ingest: parse OCSF Network Activity envelopes (class 4001),
//! score FLAGGED connection records from a canonical per-rule weight (never the
//! source `severity_id`), AGGREGATE per destination, reconcile against prior
//! state, and group by fix — reusing the shared weighted-finding + lifecycle
//! path. The network counterpart of `process.rs`.
//!
//! **Identity is the destination, not the connection.** A finding's `vuln_id` is
//! `network:{daddr}:{dport}` — the source port, the pid, and the source
//! `severity_id` are EVIDENCE, not identity. A host that opens N suspicious
//! connections to the SAME `daddr:dport` (N pids/flows) is ONE problem, so it
//! collapses to ONE finding whose weight is the MAX rule-weight across every rule
//! on every one of that destination's records. Stable identity → within-batch
//! aggregation → `reconcile` so a recurring detection that was Closed Reopens
//! instead of duplicating.
//!
//! netmon's `severity_id` is DELIBERATELY not read here: the
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

/// The location tag for a network-activity finding's identity.
const NETWORK: &str = "network";

/// The triage remediation bucket for suspicious-connection detections. Network
/// detections lead to INVESTIGATION, never an auto-fix — "remediation is a bridge,
/// never a decider".
const TRIAGE_REMEDIATION_KEY: &str = "triage-suspicious-connection";

// Canonical per-rule weights (v0 constants, calibratable; range 0.0..=1.0). These
// are the policy's own judgement of how much each detector matters — NOT derived
// from netmon's `severity_id`. A destination's finding weight is the MAX over
// every rule on every one of that destination's records (strongest signal governs).
/// A connection to a suspicious destination port (e.g. a known-bad or unusual
/// service port). Port alone is a moderate signal.
const SUSPICIOUS_PORT_WEIGHT: f32 = 0.4;
/// A connection to a suspicious port that ALSO leaves to an external/untrusted
/// address — the two signals compound, so the highest weight in the table.
const SUSPICIOUS_PORT_TO_EXTERNAL_WEIGHT: f32 = 0.7;
/// Forward-compatible floor: an unrecognized/future rule still scores a real
/// finding rather than silently vanishing, but at the lowest weight until the
/// table is calibrated for it.
const UNKNOWN_RULE_FLOOR: f32 = 0.3;

/// Canonical weight for a single detection rule (documented table above). Unknown
/// rules fall to the forward-compatible floor. Kept explicit for testability and
/// so the mapping never touches the source `severity_id`.
fn rule_weight(rule: &str) -> f32 {
    match rule {
        "suspicious_port" => SUSPICIOUS_PORT_WEIGHT,
        "suspicious_port_to_external" => SUSPICIOUS_PORT_TO_EXTERNAL_WEIGHT,
        _ => UNKNOWN_RULE_FLOOR,
    }
}

/// One detector hit on a connection record. Only `rule` drives scoring; `reason`
/// is carried for auditability. `reason` defaults so a missing one never drops the
/// hit.
#[derive(Deserialize)]
struct Detection {
    rule: String,
    #[serde(default)]
    #[allow(dead_code)]
    reason: String,
}

/// The flagged-record contribution of ONE envelope toward its destination's
/// finding: `(asset_id, dest_key, max_rule_weight)` where `dest_key` is
/// `{daddr}:{dport}`, or `None` when the record is benign (no detections), not a
/// Network Activity envelope, or missing its destination address/port. Only `rule`
/// drives the weight (MAX over the record's rules); the source port, pid, and
/// `severity_id` are deliberately NOT read — they are evidence, not identity, and
/// the source label is never trusted.
fn flagged_contribution(env: &OcsfEnvelope) -> Option<(String, String, f32)> {
    if env.class_uid != torda_ocsf::class::NETWORK_ACTIVITY {
        return None;
    }
    // Benign telemetry (no detections) is not a finding — mirrors process's "only
    // flagged records". An absent/non-array `detections` yields nothing too.
    let detections: Vec<Detection> = crate::scoring::parse_lenient(&env.data["detections"]);
    // MAX weight over the record's rules: the strongest detector governs.
    let weight = detections
        .iter()
        .map(|d| rule_weight(&d.rule))
        .fold(None, |acc: Option<f32>, w| {
            Some(acc.map_or(w, |m| m.max(w)))
        })?;

    // Destination is the identity; a record missing either half contributes
    // nothing (panic-free — never unwrap on untrusted payload).
    let conn = &env.data["connection"];
    let daddr = conn["daddr"].as_str()?;
    let dport = conn["dport"].as_u64()? as u16;
    let dest_key = format!("{daddr}:{dport}");

    let asset_id = env.device.hostname.clone();
    Some((asset_id, dest_key, weight))
}

/// Collapses every flagged connection record in the batch into ONE finding per
/// `(asset_id, dest_key)`: the destination is the identity
/// (`network:{daddr}:{dport}`), so N connections (all source ports/pids) to one
/// suspicious destination become a single finding whose weight is the MAX
/// rule-weight ACROSS every one of that destination's records — not one
/// near-duplicate finding per record. Benign records contribute nothing. Output is
/// ordered by `(asset_id, dest_key)` (BTreeMap) for determinism.
///
/// `component` is the destination address (`daddr`), recovered from `dest_key`'s
/// last-colon split so it is correct for IPv4 and IPv6 alike (the dport is always
/// the final `:`-segment).
fn aggregate_network_findings(
    envelopes: &[OcsfEnvelope],
    assets: &dyn AssetContextSource,
) -> Vec<Finding> {
    let mut max_weight: BTreeMap<(String, String), f32> = BTreeMap::new();
    for env in envelopes {
        if let Some((asset_id, dest_key, weight)) = flagged_contribution(env) {
            max_weight
                .entry((asset_id, dest_key))
                .and_modify(|w| *w = w.max(weight))
                .or_insert(weight);
        }
    }
    max_weight
        .into_iter()
        .map(|((asset_id, dest_key), weight)| {
            let vuln_id = format!("network:{dest_key}");
            // daddr = everything before the final ':' (the dport); IPv6-safe.
            let daddr = dest_key
                .rsplit_once(':')
                .map_or(dest_key.as_str(), |(a, _)| a);
            weighted_finding(
                &asset_id,
                vuln_id,
                daddr.to_string(),
                NETWORK.to_string(),
                weight,
                TRIAGE_REMEDIATION_KEY.to_string(),
                assets,
            )
        })
        .collect()
}

/// Runs the network ingest over a batch of Network Activity envelopes. Composed
/// exactly like the process/vuln paths (order is load-bearing):
/// `aggregate → reconcile(prior) → filter(!Suppressed) → group_by_fix`. Reconcile
/// must precede grouping so a Reopened recurrence lands in the same triage item
/// rather than spawning a duplicate. Network findings aren't Suppressed here, but
/// the filter is kept for parity with `run_ingest`.
pub fn run_network_ingest(
    envelopes: &[OcsfEnvelope],
    assets: &dyn AssetContextSource,
    prior: &[Finding],
) -> IngestReport {
    let aggregated = aggregate_network_findings(envelopes, assets);
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

    /// Builds a Network Activity envelope. `severity_id` is set purely so the tests
    /// can PROVE production code ignores it — the mapper never reads this field.
    fn net_env(
        host: &str,
        daddr: &str,
        dport: u64,
        proto: &str,
        pid: u64,
        detections: serde_json::Value,
        severity_id: u8,
    ) -> OcsfEnvelope {
        let mut e = OcsfEnvelope::new(
            class::NETWORK_ACTIVITY,
            "Network Activity",
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
                "connection": { "daddr": daddr, "dport": dport, "proto": proto, "pid": pid },
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
        // delta is purely the criticality axis. Internal (not internet-facing) so
        // neither saturates at weight 0.4.
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
    fn flagged_external_connection_scored_from_weight_not_severity() {
        // Envelope carries severity_id=4 (High band) but the score MUST come from
        // weight 0.7, not the band.
        let env = net_env(
            "host-1",
            "203.0.113.1",
            4444,
            "tcp",
            4242,
            serde_json::json!([det("suspicious_port_to_external")]),
            4,
        );
        let assets = default_assets();
        let report = run_network_ingest(&[env], &assets, &[]);

        assert_eq!(
            report.findings.len(),
            1,
            "one flagged destination -> one finding"
        );
        let f = &report.findings[0];
        // Identity is the DESTINATION — no source port, no pid.
        assert_eq!(f.identity.vuln_id, "network:203.0.113.1:4444");
        assert_eq!(f.identity.component, "203.0.113.1", "daddr -> component");
        assert_eq!(f.identity.location, "network");
        assert_eq!(f.remediation_key, "triage-suspicious-connection");
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
    fn three_connections_to_same_dest_collapse_to_one_finding_with_max_weight() {
        // THREE connections to 203.0.113.1:4444 (different pids); one also hits
        // suspicious_port_to_external (0.7). Plus a benign connection (no
        // detections). Expect EXACTLY ONE finding for network:203.0.113.1:4444 at
        // the MAX weight (0.7), and NO finding for the benign dest.
        let envelopes = [
            net_env(
                "host-1",
                "203.0.113.1",
                4444,
                "tcp",
                11,
                serde_json::json!([det("suspicious_port")]),
                1,
            ),
            net_env(
                "host-1",
                "203.0.113.1",
                4444,
                "tcp",
                22,
                serde_json::json!([det("suspicious_port")]),
                4,
            ),
            net_env(
                "host-1",
                "203.0.113.1",
                4444,
                "tcp",
                33,
                serde_json::json!([det("suspicious_port_to_external")]),
                1,
            ),
            net_env(
                "host-1",
                "10.0.0.5",
                443,
                "tcp",
                44,
                serde_json::json!([]),
                4,
            ),
        ];
        let assets = default_assets();
        let report = run_network_ingest(&envelopes, &assets, &[]);

        let dest: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.identity.vuln_id == "network:203.0.113.1:4444")
            .collect();
        assert_eq!(
            dest.len(),
            1,
            "three connections to one dest collapse to ONE finding, not three"
        );
        assert_eq!(
            dest[0].score.explain.sev, 0.7,
            "weight = MAX rule-weight across all records"
        );
        let expected = recompute_compliance_score(0.7, &assets.context("host-1"));
        assert_eq!(
            dest[0].score.r, expected.r,
            "scored from the max weight, not severity_id"
        );

        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.identity.vuln_id == "network:10.0.0.5:443"),
            "benign connection must not become a finding"
        );
        // All flagged records collapse under the single triage remediation item.
        assert_eq!(report.remediation_items.len(), 1);
        assert_eq!(
            report.remediation_items[0].remediation_key,
            "triage-suspicious-connection"
        );
    }

    #[test]
    fn distinct_destinations_stay_distinct() {
        // Two different flagged destinations in one batch -> TWO findings, each with
        // its own max weight (aggregation is per (asset,dest), not global).
        let envelopes = [
            net_env(
                "host-1",
                "203.0.113.1",
                4444,
                "tcp",
                1,
                serde_json::json!([det("suspicious_port_to_external")]),
                1,
            ),
            net_env(
                "host-1",
                "198.51.100.7",
                8080,
                "tcp",
                2,
                serde_json::json!([det("suspicious_port")]),
                1,
            ),
        ];
        let assets = default_assets();
        let report = run_network_ingest(&envelopes, &assets, &[]);

        assert_eq!(
            report.findings.len(),
            2,
            "two distinct destinations -> two findings"
        );
        let a = report
            .findings
            .iter()
            .find(|f| f.identity.vuln_id == "network:203.0.113.1:4444")
            .expect("dest a finding");
        let b = report
            .findings
            .iter()
            .find(|f| f.identity.vuln_id == "network:198.51.100.7:8080")
            .expect("dest b finding");
        assert_eq!(
            a.score.explain.sev, 0.7,
            "203.0.113.1:4444 keeps its own max weight"
        );
        assert_eq!(
            b.score.explain.sev, 0.4,
            "198.51.100.7:8080 keeps its own max weight"
        );
    }

    #[test]
    fn max_weight_is_taken_across_records_not_just_within() {
        // Record A hits only suspicious_port (0.4); record B (different pid) hits
        // suspicious_port_to_external (0.7) to the SAME dest. The single finding must
        // weigh 0.7 — the max ACROSS records, proving cross-record aggregation.
        let envelopes = [
            net_env(
                "host-1",
                "203.0.113.1",
                4444,
                "tcp",
                1,
                serde_json::json!([det("suspicious_port")]),
                1,
            ),
            net_env(
                "host-1",
                "203.0.113.1",
                4444,
                "tcp",
                2,
                serde_json::json!([det("suspicious_port_to_external")]),
                1,
            ),
        ];
        let assets = default_assets();
        let report = run_network_ingest(&envelopes, &assets, &[]);
        assert_eq!(
            report.findings.len(),
            1,
            "same dest across records -> one finding"
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
        let env = net_env(
            "host-1",
            "203.0.113.9",
            6667,
            "tcp",
            7,
            serde_json::json!([det("suspicious_port")]),
            1,
        );
        let assets = default_assets();
        let report = run_network_ingest(&[env], &assets, &[]);
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
        let env = net_env(
            "host-1",
            "10.0.0.5",
            443,
            "tcp",
            9,
            serde_json::json!([]),
            4,
        );
        assert!(run_network_ingest(&[env], &default_assets(), &[])
            .findings
            .is_empty());
    }

    #[test]
    fn benign_connection_with_no_detections_yields_no_finding() {
        // Absent detections key entirely — still benign.
        let mut env = net_env(
            "host-1",
            "10.0.0.6",
            80,
            "tcp",
            10,
            serde_json::json!([]),
            1,
        );
        env.data.as_object_mut().unwrap().remove("detections");
        assert!(run_network_ingest(&[env], &default_assets(), &[])
            .findings
            .is_empty());
    }

    #[test]
    fn missing_destination_yields_no_finding() {
        // A flagged record missing daddr/dport must not panic and must not score.
        let mut env = net_env(
            "host-1",
            "203.0.113.1",
            4444,
            "tcp",
            5,
            serde_json::json!([det("suspicious_port")]),
            3,
        );
        env.data["connection"]
            .as_object_mut()
            .unwrap()
            .remove("daddr");
        assert!(run_network_ingest(&[env], &default_assets(), &[])
            .findings
            .is_empty());
    }

    #[test]
    fn unknown_rule_scores_at_the_floor() {
        let env = net_env(
            "host-1",
            "203.0.113.50",
            9999,
            "tcp",
            100,
            serde_json::json!([det("some_new_rule")]),
            3,
        );
        let assets = default_assets();
        let report = run_network_ingest(&[env], &assets, &[]);
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
        // suspicious_port(0.4) + suspicious_port_to_external(0.7) -> 0.7, asserted to
        // be the MAX (not the first, 0.4, nor a sum > 0.7).
        let env = net_env(
            "host-1",
            "203.0.113.1",
            4444,
            "tcp",
            321,
            serde_json::json!([det("suspicious_port"), det("suspicious_port_to_external")]),
            1,
        );
        let assets = default_assets();
        let report = run_network_ingest(&[env], &assets, &[]);
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
        let detections = serde_json::json!([det("suspicious_port")]);
        let crown = net_env(
            "crown",
            "203.0.113.1",
            4444,
            "tcp",
            1,
            detections.clone(),
            1,
        );
        let normal = net_env("normal", "203.0.113.1", 4444, "tcp", 1, detections, 1);
        let assets = tiered_assets();
        let crown_f = &run_network_ingest(&[crown], &assets, &[]).findings[0];
        let normal_f = &run_network_ingest(&[normal], &assets, &[]).findings[0];
        assert!(
            crown_f.score.r > normal_f.score.r,
            "crown jewel ({}) must outscore normal ({}) for the same detection",
            crown_f.score.r,
            normal_f.score.r,
        );
    }

    #[test]
    fn batch_ignores_non_4001_and_groups_flagged_into_one_triage_item() {
        let flagged_a = net_env(
            "host-1",
            "203.0.113.1",
            4444,
            "tcp",
            11,
            serde_json::json!([det("suspicious_port")]),
            1,
        );
        let flagged_b = net_env(
            "host-1",
            "198.51.100.7",
            8080,
            "tcp",
            22,
            serde_json::json!([det("suspicious_port_to_external")]),
            1,
        );
        // A non-Network-Activity envelope in the batch must be ignored.
        let mut other = net_env(
            "host-1",
            "203.0.113.1",
            4444,
            "tcp",
            33,
            serde_json::json!([det("suspicious_port")]),
            4,
        );
        other.class_uid = class::SOFTWARE_INVENTORY_INFO;

        let report = run_network_ingest(&[flagged_a, other, flagged_b], &default_assets(), &[]);
        assert_eq!(
            report.findings.len(),
            2,
            "only the two 4001 flagged destinations score"
        );
        assert_eq!(
            report.remediation_items.len(),
            1,
            "all flagged group into one triage item"
        );
        assert_eq!(
            report.remediation_items[0].remediation_key,
            "triage-suspicious-connection"
        );
    }

    #[test]
    fn prior_closed_network_finding_is_reopened_else_open() {
        // A recurring 203.0.113.1:4444 detection: with no prior it is Open; with a
        // prior CLOSED finding of the SAME identity (network:203.0.113.1:4444) it
        // Reopens rather than duplicating — parity with the process/vuln lifecycle.
        let env = net_env(
            "host-1",
            "203.0.113.1",
            4444,
            "tcp",
            1,
            serde_json::json!([det("suspicious_port_to_external")]),
            1,
        );
        let assets = default_assets();

        // No prior -> Open.
        let first = run_network_ingest(std::slice::from_ref(&env), &assets, &[]);
        assert_eq!(first.findings.len(), 1);
        assert_eq!(
            first.findings[0].identity.vuln_id,
            "network:203.0.113.1:4444"
        );
        assert_eq!(
            first.findings[0].status,
            FindingState::Open,
            "no prior -> Open"
        );

        // Same identity previously Closed -> the fresh recurrence Reopens.
        let mut prior = first.findings[0].clone();
        prior.status = FindingState::Closed;
        let second = run_network_ingest(&[env], &assets, &[prior]);
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
