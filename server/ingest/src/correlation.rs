//! Correlated Activity ingest: parse OCSF Correlated Activity envelopes
//! (class 9002 — the cross-sensor attack chain), score the FLAGGED attack-chain
//! records from a canonical per-rule weight (never the source `severity_id`),
//! AGGREGATE per attack-chain edge, reconcile against prior state, and group by
//! fix — reusing the shared weighted-finding + lifecycle path. The correlation
//! counterpart of `process.rs` / `network.rs`.
//!
//! **Only the attack chain scores here — never its halves.** A 9002 record's
//! TOP-LEVEL `data["detections"]` array is the correlated-rule array: it is
//! non-empty ONLY when both a suspicious process AND a suspicious connection fired
//! and were joined (by pid). A 9002 record with an EMPTY top-level array means at
//! most one half was suspicious — and each half is ALREADY scored by the process
//! ingest (procmon 1007) and the network ingest (netmon 4001). Scoring an empty
//! top-level record here would DOUBLE- (triple-) count. So the gate reads ONLY the
//! top-level array; empty → no finding. The per-record `process.detections` /
//! `connection.detections` sub-arrays are EVIDENCE for the halves, never the
//! finding gate.
//!
//! **Identity is the attack-chain edge, not the execution.** A finding's `vuln_id`
//! is `correlation:{image}->{daddr}:{dport}` — the pid and the source `severity_id`
//! are EVIDENCE, not identity. A host that walks the SAME edge N times (N pids)
//! is ONE problem, so it collapses to ONE finding whose weight is the MAX
//! rule-weight across every top-level rule on every one of that edge's records.
//! Stable identity → within-batch aggregation → `reconcile` so a recurring chain
//! that was Closed Reopens instead of duplicating.
//!
//! **The chain outscores either half.** The correlated rule weighs 0.9 — strictly
//! above any single-sensor rule's max (0.7) — so a joined process+connection is
//! ranked higher than either signal alone. The correlator's `severity_id` is
//! DELIBERATELY not read: the score is recomputed from the
//! policy weight table below so it is explainable and cannot be inflated or
//! suppressed by a source's own label.
use std::collections::BTreeMap;

use serde::Deserialize;
use torda_findings::{Finding, FindingState};
use torda_findings_engine::aggregate::group_by_fix;
use torda_findings_engine::input::AssetContextSource;
use torda_findings_engine::lifecycle::reconcile;
use torda_ocsf::OcsfEnvelope;

use crate::pipeline::IngestReport;
use crate::scoring::weighted_finding;

/// The location tag for a correlated-activity finding's identity.
const CORRELATION: &str = "correlation";

/// The triage remediation bucket for attack-chain detections. A correlated chain
/// leads to INVESTIGATION, never an auto-fix — "remediation is a bridge, never a
/// decider".
const TRIAGE_REMEDIATION_KEY: &str = "triage-attack-chain";

// Canonical per-rule weights (v0 constants, calibratable; range 0.0..=1.0). These
// are the policy's own judgement of how much each correlated detector matters —
// NOT derived from the correlator's `severity_id`. An edge's finding weight is the
// MAX over every top-level rule on every one of that edge's records.
/// A suspicious process joined (by pid) to a suspicious connection — the defining
/// attack chain. Set STRICTLY above any single-sensor rule's max (process/network
/// top out at 0.7) so a correlated chain always outranks either half alone.
const SUSPICIOUS_PROCESS_SUSPICIOUS_CONNECTION_WEIGHT: f32 = 0.9;
/// The triple chain: a suspicious process that BOTH wrote a suspicious file AND
/// opened a suspicious connection (the dropper-then-C2 sequence). A strict SUPERSET
/// of the process<->connection chain, so it scores STRICTLY ABOVE it (0.9) — the
/// strongest single correlated signal the agent emits.
///
/// Without this arm the triple's OWN record falls to `UNKNOWN_RULE_FLOOR` (0.3).
/// Today the agent only fires the triple AFTER the connection half already fired,
/// so a `suspicious_process_suspicious_connection` (0.9) record co-occurs on the
/// same edge and MAX-aggregation lifts the finding to 0.9 regardless — the real
/// effect on current output is modest (the correlated fix moves R 65 -> R 68, the
/// triple's edge now carrying its TRUE weight rather than a sibling's). The point
/// of the arm is to make the triple self-sufficient: if the conjunction semantics
/// ever decouple (a genuine triple-only edge, as the regression test constructs),
/// the marquee detection still tops the fix-first queue instead of sinking to the
/// 0.3 floor.
const SUSPICIOUS_PROCESS_WROTE_FILE_AND_CONNECTED_WEIGHT: f32 = 0.95;
/// The exfil chain: a suspicious process that BOTH read a sensitive file AND opened
/// a suspicious connection (the read-secret-then-beacon sequence). The read analog
/// of the write triple and, like it, a strict SUPERSET of the process<->connection
/// chain — an exfil chain is as strong a signal as the dropper chain, so it scores
/// at the SAME top tier (0.95, strictly above the 0.9 connection chain and the 0.7
/// single-sensor max). Same rationale as the write triple: without this arm a
/// genuine exfil-only edge (no co-located plain-connection record) would fall to
/// `UNKNOWN_RULE_FLOOR` (0.3) and sink to the bottom of the fix-first queue.
const SUSPICIOUS_PROCESS_READ_SENSITIVE_AND_CONNECTED_WEIGHT: f32 = 0.95;
/// Forward-compatible floor: an unrecognized/future correlated rule still scores a
/// real finding rather than silently vanishing, but at the lowest weight until the
/// table is calibrated for it.
const UNKNOWN_RULE_FLOOR: f32 = 0.3;

/// Canonical weight for a single top-level correlated rule (documented table
/// above). Unknown rules fall to the forward-compatible floor. Kept explicit for
/// testability and so the mapping never touches the source `severity_id`.
fn rule_weight(rule: &str) -> f32 {
    match rule {
        "suspicious_process_suspicious_connection" => {
            SUSPICIOUS_PROCESS_SUSPICIOUS_CONNECTION_WEIGHT
        }
        "suspicious_process_wrote_file_and_connected" => {
            SUSPICIOUS_PROCESS_WROTE_FILE_AND_CONNECTED_WEIGHT
        }
        "suspicious_process_read_sensitive_and_connected" => {
            SUSPICIOUS_PROCESS_READ_SENSITIVE_AND_CONNECTED_WEIGHT
        }
        _ => UNKNOWN_RULE_FLOOR,
    }
}

/// One top-level correlated-rule hit. Only `rule` drives scoring; `reason` is
/// carried for auditability and defaults so a missing one never drops the hit.
#[derive(Deserialize)]
struct Detection {
    rule: String,
    #[serde(default)]
    #[allow(dead_code)]
    reason: String,
}

/// The flagged-record contribution of ONE envelope toward its edge's finding:
/// `(asset_id, edge_key, max_rule_weight)` where `edge_key` is
/// `{image}->{daddr}:{dport}`, or `None` when the record is NOT an attack chain
/// (empty top-level detections), not a Correlated Activity envelope, or missing
/// its process image / connection destination.
///
/// The gate reads ONLY `data["detections"]` (the TOP-LEVEL correlated array). It
/// deliberately does NOT read `process.detections` / `connection.detections` — an
/// empty top-level array means only one half (already scored by the process/network
/// ingest) was suspicious, and scoring it here would double-count. Only `rule`
/// drives the weight (MAX over the record's top-level rules); the pid and
/// `severity_id` are deliberately NOT read — they are evidence, not identity, and
/// the source label is never trusted.
fn flagged_contribution(env: &OcsfEnvelope) -> Option<(String, String, f32)> {
    if env.class_uid != torda_ocsf::class::CORRELATED_ACTIVITY {
        return None;
    }
    // ONLY the top-level correlated array gates a finding. Empty/absent/non-array
    // -> the chain did not fire -> no finding (no double-count of a single half).
    let detections: Vec<Detection> = crate::scoring::parse_lenient(&env.data["detections"]);
    // MAX weight over the record's top-level rules: the strongest detector governs.
    let weight = detections
        .iter()
        .map(|d| rule_weight(&d.rule))
        .fold(None, |acc: Option<f32>, w| {
            Some(acc.map_or(w, |m| m.max(w)))
        })?;

    // The edge (process image -> connection destination) is the identity; a record
    // missing any half contributes nothing (panic-free — never unwrap untrusted
    // payload).
    let image = env.data["process"]["image"].as_str()?;
    let conn = &env.data["connection"];
    let daddr = conn["daddr"].as_str()?;
    let dport = conn["dport"].as_u64()? as u16;
    let edge_key = format!("{image}->{daddr}:{dport}");

    let asset_id = env.device.hostname.clone();
    Some((asset_id, edge_key, weight))
}

/// Collapses every flagged attack-chain record in the batch into ONE finding per
/// `(asset_id, edge_key)`: the edge is the identity
/// (`correlation:{image}->{daddr}:{dport}`), so N traversals (all pids) of one
/// chain become a single finding whose weight is the MAX rule-weight ACROSS every
/// one of that edge's records — not one near-duplicate finding per record.
/// Non-chain records (empty top-level detections) contribute nothing. Output is
/// ordered by `(asset_id, edge_key)` (BTreeMap) for determinism.
///
/// `component` is the process image, recovered from `edge_key`'s first `->`
/// split (the image is always the leading segment; the `daddr:dport` follows).
fn aggregate_correlation_findings(
    envelopes: &[OcsfEnvelope],
    assets: &dyn AssetContextSource,
) -> Vec<Finding> {
    let mut max_weight: BTreeMap<(String, String), f32> = BTreeMap::new();
    for env in envelopes {
        if let Some((asset_id, edge_key, weight)) = flagged_contribution(env) {
            max_weight
                .entry((asset_id, edge_key))
                .and_modify(|w| *w = w.max(weight))
                .or_insert(weight);
        }
    }
    max_weight
        .into_iter()
        .map(|((asset_id, edge_key), weight)| {
            let vuln_id = format!("correlation:{edge_key}");
            // image = everything before the first "->" (the connection dest).
            let image = edge_key
                .split_once("->")
                .map_or(edge_key.as_str(), |(i, _)| i);
            weighted_finding(
                &asset_id,
                vuln_id,
                image.to_string(),
                CORRELATION.to_string(),
                weight,
                TRIAGE_REMEDIATION_KEY.to_string(),
                assets,
            )
        })
        .collect()
}

/// Runs the correlation ingest over a batch of Correlated Activity envelopes.
/// Composed exactly like the process/network paths (order is load-bearing):
/// `aggregate → reconcile(prior) → filter(!Suppressed) → group_by_fix`. Reconcile
/// must precede grouping so a Reopened recurrence lands in the same triage item
/// rather than spawning a duplicate. Correlation findings aren't Suppressed here,
/// but the filter is kept for parity with `run_ingest`.
pub fn run_correlation_ingest(
    envelopes: &[OcsfEnvelope],
    assets: &dyn AssetContextSource,
    prior: &[Finding],
) -> IngestReport {
    let aggregated = aggregate_correlation_findings(envelopes, assets);
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
    use torda_findings::{AssetContext, Criticality, FindingState};
    use torda_findings_engine::input::MapAssetContext;
    use torda_findings_engine::score::recompute_compliance_score;
    use torda_ocsf::{class, Device, Metadata};

    use crate::fixtures::default_assets;

    /// Builds a Correlated Activity envelope (class 9002). `severity_id` is set
    /// purely so the tests can PROVE production code ignores it — the mapper never
    /// reads this field. `top` is the TOP-LEVEL correlated-rule array (the finding
    /// gate); `proc_det`/`conn_det` are the per-half sub-arrays (evidence only).
    #[allow(clippy::too_many_arguments)]
    fn corr_env(
        host: &str,
        image: &str,
        daddr: &str,
        dport: u64,
        pid: u64,
        top: serde_json::Value,
        proc_det: serde_json::Value,
        conn_det: serde_json::Value,
        severity_id: u8,
    ) -> OcsfEnvelope {
        let mut e = OcsfEnvelope::new(
            class::CORRELATED_ACTIVITY,
            "Correlated Activity",
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
                "activity": "process_network",
                "process": { "pid": pid, "image": image, "detections": proc_det, "attributed": true },
                "connection": { "daddr": daddr, "dport": dport, "proto": "tcp", "detections": conn_det },
                "detections": top,
            }),
        );
        e.severity_id = severity_id;
        e
    }

    fn det(rule: &str) -> serde_json::Value {
        serde_json::json!({ "rule": rule, "reason": format!("{rule} fired") })
    }

    /// The correlated rule as a single-element top-level array.
    fn chain() -> serde_json::Value {
        serde_json::json!([det("suspicious_process_suspicious_connection")])
    }

    /// Internal + Normal asset context: weight 0.9 (0.648) and 0.7 (0.504) both
    /// stay BELOW saturation here, so `0.9 > 0.7` is observable in `score.r`
    /// (default_assets, internet-facing High, saturates both to 100 — useless for
    /// the strictly-higher proof).
    fn scored_assets() -> MapAssetContext {
        let ac = AssetContext {
            internet_facing: false,
            criticality: Criticality::Normal,
            compensating_controls: false,
        };
        MapAssetContext {
            by_asset: HashMap::new(),
            default: ac,
        }
    }

    fn tiered_assets() -> MapAssetContext {
        // Same exposure flags on both, differing only in criticality, so the score
        // delta is purely the criticality axis. Internal so neither saturates.
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
    fn attack_chain_scores_from_weight_and_higher_than_either_half() {
        // The core value proposition. A 9002 record whose TOP-LEVEL detection is the
        // correlated rule, carrying severity_id=4 (High band) that must be ignored.
        let env = corr_env(
            "host-1",
            "powershell",
            "203.0.113.1",
            4444,
            4242,
            chain(),
            serde_json::json!([det("lolbin")]),
            serde_json::json!([det("suspicious_port")]),
            4,
        );
        let assets = scored_assets();
        let report = run_correlation_ingest(&[env], &assets, &[]);

        assert_eq!(report.findings.len(), 1, "one attack chain -> one finding");
        let f = &report.findings[0];
        // Identity is the EDGE — no pid, no severity band.
        assert_eq!(
            f.identity.vuln_id,
            "correlation:powershell->203.0.113.1:4444"
        );
        assert_eq!(f.identity.component, "powershell", "image -> component");
        assert_eq!(f.identity.location, "correlation");
        assert_eq!(f.remediation_key, "triage-attack-chain");
        assert_eq!(
            f.provenance[0].reported_severity, None,
            "no source severity trusted"
        );

        // The score is EXACTLY what weight 0.9 yields for this asset context —
        // recomputed, independent of severity_id=4.
        let ctx = assets.context("host-1");
        let expected = recompute_compliance_score(0.9, &ctx);
        assert_eq!(f.score.r, expected.r);
        assert_eq!(
            f.score.explain.sev, 0.9,
            "sev is the 0.9 chain weight, not a severity band"
        );
        assert_eq!(f.status, FindingState::Open);

        // STRICTLY higher than a single-sensor half's max weight (0.7), same ctx —
        // the chain outranks either signal alone. Non-vacuous: 65 > 50 here.
        let half = recompute_compliance_score(0.7, &ctx);
        assert!(
            f.score.r > half.r,
            "attack chain (0.9 -> {}) must outscore a single-sensor half (0.7 -> {})",
            f.score.r,
            half.r,
        );
    }

    #[test]
    fn empty_top_level_detections_yields_no_finding_no_double_count() {
        // Only ONE half suspicious: the top-level correlated array is EMPTY, but the
        // per-half sub-arrays ARE populated (already scored by process/network
        // ingest). Scoring here would double-count -> must yield NO finding.
        let env = corr_env(
            "host-1",
            "powershell",
            "203.0.113.1",
            4444,
            1,
            serde_json::json!([]),
            serde_json::json!([det("lolbin")]),
            serde_json::json!([det("suspicious_port")]),
            4,
        );
        assert!(
            run_correlation_ingest(&[env], &default_assets(), &[])
                .findings
                .is_empty(),
            "empty top-level detections -> no finding (halves already scored elsewhere)"
        );
    }

    #[test]
    fn absent_top_level_detections_key_yields_no_finding() {
        // The whole `detections` key absent from data -> still no chain.
        let mut env = corr_env(
            "host-1",
            "powershell",
            "203.0.113.1",
            4444,
            1,
            chain(),
            serde_json::json!([]),
            serde_json::json!([]),
            1,
        );
        env.data.as_object_mut().unwrap().remove("detections");
        assert!(run_correlation_ingest(&[env], &default_assets(), &[])
            .findings
            .is_empty());
    }

    #[test]
    fn low_severity_id_does_not_suppress_the_chain() {
        // Rule #5, low side: severity_id=1 (Informational) but a real correlated
        // detection -> the 0.9 finding still appears; the low label is ignored.
        let env = corr_env(
            "host-1",
            "powershell",
            "203.0.113.1",
            4444,
            7,
            chain(),
            serde_json::json!([]),
            serde_json::json!([]),
            1,
        );
        let assets = default_assets();
        let report = run_correlation_ingest(&[env], &assets, &[]);
        assert_eq!(
            report.findings.len(),
            1,
            "low severity_id must not suppress a real chain"
        );
        let expected = recompute_compliance_score(0.9, &assets.context("host-1"));
        assert_eq!(report.findings[0].score.r, expected.r);
    }

    #[test]
    fn inflated_severity_id_with_empty_top_level_yields_nothing() {
        // Rule #5, high side: severity_id=4 but EMPTY top-level detections -> the
        // record is NOT promoted to a finding by its label.
        let env = corr_env(
            "host-1",
            "powershell",
            "203.0.113.1",
            4444,
            9,
            serde_json::json!([]),
            serde_json::json!([det("lolbin")]),
            serde_json::json!([det("suspicious_port")]),
            4,
        );
        assert!(run_correlation_ingest(&[env], &default_assets(), &[])
            .findings
            .is_empty());
    }

    #[test]
    fn three_traversals_of_same_edge_collapse_to_one_finding() {
        // THREE correlated records for the SAME powershell->203.0.113.1:4444 edge
        // (different pids). Expect EXACTLY ONE finding at weight 0.9.
        let envelopes = [
            corr_env(
                "host-1",
                "powershell",
                "203.0.113.1",
                4444,
                11,
                chain(),
                serde_json::json!([]),
                serde_json::json!([]),
                1,
            ),
            corr_env(
                "host-1",
                "powershell",
                "203.0.113.1",
                4444,
                22,
                chain(),
                serde_json::json!([]),
                serde_json::json!([]),
                4,
            ),
            corr_env(
                "host-1",
                "powershell",
                "203.0.113.1",
                4444,
                33,
                chain(),
                serde_json::json!([]),
                serde_json::json!([]),
                2,
            ),
        ];
        let assets = default_assets();
        let report = run_correlation_ingest(&envelopes, &assets, &[]);

        let edge: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.identity.vuln_id == "correlation:powershell->203.0.113.1:4444")
            .collect();
        assert_eq!(
            edge.len(),
            1,
            "three traversals of one edge collapse to ONE finding"
        );
        assert_eq!(
            edge[0].score.explain.sev, 0.9,
            "weight 0.9 for the correlated chain"
        );
        // All flagged records collapse under the single triage remediation item.
        assert_eq!(report.remediation_items.len(), 1);
        assert_eq!(
            report.remediation_items[0].remediation_key,
            "triage-attack-chain"
        );
    }

    #[test]
    fn distinct_edges_stay_distinct() {
        // Two different attack-chain edges in one batch -> TWO findings.
        let envelopes = [
            corr_env(
                "host-1",
                "powershell",
                "203.0.113.1",
                4444,
                1,
                chain(),
                serde_json::json!([]),
                serde_json::json!([]),
                1,
            ),
            corr_env(
                "host-1",
                "/tmp/nc",
                "198.51.100.7",
                8080,
                2,
                chain(),
                serde_json::json!([]),
                serde_json::json!([]),
                1,
            ),
        ];
        let assets = default_assets();
        let report = run_correlation_ingest(&envelopes, &assets, &[]);

        assert_eq!(
            report.findings.len(),
            2,
            "two distinct edges -> two findings"
        );
        assert!(report
            .findings
            .iter()
            .any(|f| f.identity.vuln_id == "correlation:powershell->203.0.113.1:4444"));
        assert!(report
            .findings
            .iter()
            .any(|f| f.identity.vuln_id == "correlation:/tmp/nc->198.51.100.7:8080"));
    }

    #[test]
    fn unknown_top_level_rule_scores_at_the_floor() {
        let env = corr_env(
            "host-1",
            "powershell",
            "203.0.113.50",
            9999,
            100,
            serde_json::json!([det("some_new_correlated_rule")]),
            serde_json::json!([]),
            serde_json::json!([]),
            3,
        );
        let assets = default_assets();
        let report = run_correlation_ingest(&[env], &assets, &[]);
        let f = &report.findings[0];
        assert_eq!(
            f.score.explain.sev, 0.3,
            "unknown rule -> 0.3 forward-compatible floor"
        );
        let expected = recompute_compliance_score(0.3, &assets.context("host-1"));
        assert_eq!(f.score.r, expected.r);
    }

    #[test]
    fn triple_chain_scores_above_the_plain_connection_chain_without_max_rescue() {
        // The triple `suspicious_process_wrote_file_and_connected` (dropper-then-C2)
        // is a STRICT SUPERSET of the process<->connection chain, so it must score
        // STRICTLY ABOVE the plain-connection weight (0.9). Critically this edge
        // carries ONLY the triple rule — no co-located
        // `suspicious_process_suspicious_connection` record — so nothing rescues it
        // via MAX-aggregation: the weight comes from the triple arm alone. Regression
        // guard: without the triple arm this edge falls to the 0.3 floor and the
        // marquee detection sinks to the BOTTOM of the fix-first queue.
        let env = corr_env(
            "host-1",
            "curl",
            "203.0.113.9",
            9001,
            4242,
            serde_json::json!([det("suspicious_process_wrote_file_and_connected")]),
            serde_json::json!([]),
            serde_json::json!([]),
            1,
        );
        let assets = scored_assets();
        let report = run_correlation_ingest(&[env], &assets, &[]);

        assert_eq!(report.findings.len(), 1, "one triple chain -> one finding");
        let f = &report.findings[0];
        assert_eq!(
            f.score.explain.sev, 0.95,
            "triple weight, not the 0.3 floor"
        );
        let ctx = assets.context("host-1");
        let expected = recompute_compliance_score(0.95, &ctx);
        assert_eq!(f.score.r, expected.r);
        // Strictly above the plain-connection chain (0.9) — the superset outranks the
        // pair — and above a single-sensor half (0.7), non-vacuously.
        assert!(
            f.score.explain.sev > 0.9,
            "triple must weigh above the 0.9 connection chain"
        );
        let half = recompute_compliance_score(0.7, &ctx);
        assert!(
            f.score.r > half.r,
            "triple (0.95 -> {}) must outscore a single-sensor half (0.7 -> {})",
            f.score.r,
            half.r,
        );
    }

    #[test]
    fn exfil_chain_scores_at_the_top_tier_without_max_rescue() {
        // The exfil chain `suspicious_process_read_sensitive_and_connected`
        // (read-secret-then-beacon) is the read analog of the write triple — also a
        // strict SUPERSET of the process<->connection chain. This edge carries ONLY
        // the exfil rule (no co-located `suspicious_process_suspicious_connection`
        // record), so nothing rescues it via MAX-aggregation: the weight comes from
        // the exfil arm alone. Regression guard: without the exfil arm this edge falls
        // to the 0.3 floor and the exfil detection sinks to the BOTTOM of the queue.
        let env = corr_env(
            "host-1",
            "curl",
            "203.0.113.9",
            9001,
            4242,
            serde_json::json!([det("suspicious_process_read_sensitive_and_connected")]),
            serde_json::json!([]),
            serde_json::json!([]),
            1,
        );
        let assets = scored_assets();
        let report = run_correlation_ingest(&[env], &assets, &[]);

        assert_eq!(report.findings.len(), 1, "one exfil chain -> one finding");
        let f = &report.findings[0];
        assert_eq!(f.score.explain.sev, 0.95, "exfil weight, not the 0.3 floor");
        // Exfil is the SAME top tier as the write triple (both 0.95).
        assert_eq!(
            f.score.explain.sev, SUSPICIOUS_PROCESS_WROTE_FILE_AND_CONNECTED_WEIGHT,
            "exfil chain scores at the same top tier as the write triple",
        );
        let ctx = assets.context("host-1");
        let expected = recompute_compliance_score(0.95, &ctx);
        assert_eq!(f.score.r, expected.r);
        assert!(
            f.score.explain.sev > 0.9,
            "exfil must weigh above the 0.9 connection chain"
        );
        let half = recompute_compliance_score(0.7, &ctx);
        assert!(
            f.score.r > half.r,
            "exfil (0.95 -> {}) must outscore a single-sensor half (0.7 -> {})",
            f.score.r,
            half.r,
        );
    }

    #[test]
    fn max_weight_is_taken_across_records() {
        // Record A: unknown rule (0.3); record B (same edge, different pid): the
        // correlated rule (0.9). The single finding must weigh 0.9 — max ACROSS
        // records, proving cross-record aggregation.
        let envelopes = [
            corr_env(
                "host-1",
                "powershell",
                "203.0.113.1",
                4444,
                1,
                serde_json::json!([det("some_new_correlated_rule")]),
                serde_json::json!([]),
                serde_json::json!([]),
                1,
            ),
            corr_env(
                "host-1",
                "powershell",
                "203.0.113.1",
                4444,
                2,
                chain(),
                serde_json::json!([]),
                serde_json::json!([]),
                1,
            ),
        ];
        let report = run_correlation_ingest(&envelopes, &default_assets(), &[]);
        assert_eq!(
            report.findings.len(),
            1,
            "same edge across records -> one finding"
        );
        assert_eq!(
            report.findings[0].score.explain.sev, 0.9,
            "max ACROSS records"
        );
    }

    #[test]
    fn missing_destination_yields_no_finding() {
        // A flagged chain record missing daddr must not panic and must not score.
        let mut env = corr_env(
            "host-1",
            "powershell",
            "203.0.113.1",
            4444,
            5,
            chain(),
            serde_json::json!([]),
            serde_json::json!([]),
            3,
        );
        env.data["connection"]
            .as_object_mut()
            .unwrap()
            .remove("daddr");
        assert!(run_correlation_ingest(&[env], &default_assets(), &[])
            .findings
            .is_empty());
    }

    #[test]
    fn missing_image_yields_no_finding() {
        let mut env = corr_env(
            "host-1",
            "powershell",
            "203.0.113.1",
            4444,
            5,
            chain(),
            serde_json::json!([]),
            serde_json::json!([]),
            3,
        );
        env.data["process"].as_object_mut().unwrap().remove("image");
        assert!(run_correlation_ingest(&[env], &default_assets(), &[])
            .findings
            .is_empty());
    }

    #[test]
    fn crown_jewel_scores_strictly_higher_than_normal_for_same_chain() {
        let crown = corr_env(
            "crown",
            "powershell",
            "203.0.113.1",
            4444,
            1,
            chain(),
            serde_json::json!([]),
            serde_json::json!([]),
            1,
        );
        let normal = corr_env(
            "normal",
            "powershell",
            "203.0.113.1",
            4444,
            1,
            chain(),
            serde_json::json!([]),
            serde_json::json!([]),
            1,
        );
        let assets = tiered_assets();
        let crown_f = &run_correlation_ingest(&[crown], &assets, &[]).findings[0];
        let normal_f = &run_correlation_ingest(&[normal], &assets, &[]).findings[0];
        assert!(
            crown_f.score.r > normal_f.score.r,
            "crown jewel ({}) must outscore normal ({}) for the same chain",
            crown_f.score.r,
            normal_f.score.r,
        );
    }

    #[test]
    fn batch_ignores_non_9002_and_groups_flagged_into_one_triage_item() {
        let flagged_a = corr_env(
            "host-1",
            "powershell",
            "203.0.113.1",
            4444,
            11,
            chain(),
            serde_json::json!([]),
            serde_json::json!([]),
            1,
        );
        let flagged_b = corr_env(
            "host-1",
            "/tmp/nc",
            "198.51.100.7",
            8080,
            22,
            chain(),
            serde_json::json!([]),
            serde_json::json!([]),
            1,
        );
        // A non-Correlated-Activity envelope in the batch must be ignored (even
        // though it carries a top-level correlated detection).
        let mut other = corr_env(
            "host-1",
            "powershell",
            "203.0.113.1",
            4444,
            33,
            chain(),
            serde_json::json!([]),
            serde_json::json!([]),
            4,
        );
        other.class_uid = class::NETWORK_ACTIVITY;

        let report = run_correlation_ingest(&[flagged_a, other, flagged_b], &default_assets(), &[]);
        assert_eq!(report.findings.len(), 2, "only the two 9002 chains score");
        assert_eq!(
            report.remediation_items.len(),
            1,
            "all flagged group into one triage item"
        );
        assert_eq!(
            report.remediation_items[0].remediation_key,
            "triage-attack-chain"
        );
    }

    #[test]
    fn prior_closed_correlation_finding_is_reopened_else_open() {
        // A recurring powershell->203.0.113.1:4444 chain: no prior -> Open; a prior
        // CLOSED finding of the SAME identity -> Reopens rather than duplicating.
        let env = corr_env(
            "host-1",
            "powershell",
            "203.0.113.1",
            4444,
            1,
            chain(),
            serde_json::json!([]),
            serde_json::json!([]),
            1,
        );
        let assets = default_assets();

        // No prior -> Open.
        let first = run_correlation_ingest(std::slice::from_ref(&env), &assets, &[]);
        assert_eq!(first.findings.len(), 1);
        assert_eq!(
            first.findings[0].identity.vuln_id,
            "correlation:powershell->203.0.113.1:4444"
        );
        assert_eq!(
            first.findings[0].status,
            FindingState::Open,
            "no prior -> Open"
        );

        // Same identity previously Closed -> the fresh recurrence Reopens.
        let mut prior = first.findings[0].clone();
        prior.status = FindingState::Closed;
        let second = run_correlation_ingest(&[env], &assets, &[prior]);
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
