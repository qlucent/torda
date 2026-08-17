//! Small, honest demo of the Correlated Activity ingest path
//! (`torda_ingest::correlation::run_correlation_ingest`): builds a batch of
//! representative OCSF Correlated Activity (class 9002) envelopes INLINE — in
//! the exact shape `torda_mod_corr::CorrModule` emits them — runs them through
//! the REAL production ingest path, and prints each scored attack-chain
//! finding plus the triage remediation group.
//!
//! Deliberately uses ONLY the crate's existing production dependencies
//! (`torda-ocsf`, `torda-findings`, `torda-findings-engine`, `serde_json`) — it does NOT
//! pull in `torda-mod-corr` / `torda-mod-procmon` / `torda-mod-netmon` / `torda-substrate`;
//! the end-to-end proof that REAL corr envelopes flow through this same path
//! lives in `server/ingest/tests/correlation_e2e.rs`. This binary is just the
//! visible, standalone loop: envelopes in -> canonical, aggregated,
//! lifecycle-aware findings out.
//!
//! It demonstrates the behaviors Task 1 added for the correlation class:
//!   1. GATE — only the TOP-LEVEL correlated rule scores a finding; a 9002
//!      record with an empty top-level `detections` array (only one half
//!      suspicious) produces NO finding (its half is already scored
//!      elsewhere; scoring it here would double-count).
//!   2. OUTRANK — the correlated chain (weight 0.9) scores STRICTLY higher
//!      than a single-sensor component's max weight (0.7), for the same asset
//!      context.
//!   3. COLLAPSE — many attack-chain records to the SAME edge (different
//!      pids) aggregate into ONE finding at the MAX rule-weight.
//!   4. LIFECYCLE — a fresh detection with no prior state is `Open`; the same
//!      edge identity recurring after a prior `Closed` finding is `Reopened`
//!      instead of duplicating.
use std::collections::HashMap;

use torda_findings::{AssetContext, Criticality, FindingState};
use torda_findings_engine::input::{AssetContextSource, MapAssetContext};
use torda_findings_engine::score::recompute_compliance_score;
use torda_ocsf::{class, Device, Metadata, OcsfEnvelope};

use torda_ingest::correlation::run_correlation_ingest;

/// Builds one Correlated Activity envelope (class 9002) in the agent's real
/// shape. `severity_id` is set to a deliberately WRONG/irrelevant value on the
/// flagged records to make the point visible: ingest never reads it. `top` is
/// the TOP-LEVEL correlated-rule array (the finding gate); `proc_det` /
/// `conn_det` are the per-half sub-arrays (evidence only, never the gate).
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

/// A minimal fixed asset context: internal + Normal criticality, so weight 0.9
/// and weight 0.7 both stay BELOW saturation — the 0.9-outranks-0.7 contrast
/// is visible in `score.r`, not masked by both clamping to 100.
fn assets() -> MapAssetContext {
    MapAssetContext {
        by_asset: HashMap::new(),
        default: AssetContext {
            internet_facing: false,
            criticality: Criticality::Normal,
            compensating_controls: false,
        },
    }
}

fn main() {
    println!("== correlation-findings-demo — OCSF Correlated Activity (9002) -> canonical scored findings ==\n");

    // ---------------------------------------------------------------
    // Part 1: GATE + COLLAPSE + OUTRANK. Three records to the SAME
    // powershell->203.0.113.1:4444 edge (different pids) carry the top-level
    // correlated rule and must collapse into ONE finding at weight 0.9. A
    // fourth record (echo->203.0.113.1:4444) has an EMPTY top-level array —
    // only the connection half was suspicious — and must produce NO finding.
    // ---------------------------------------------------------------
    let batch = vec![
        corr_env(
            "host-1",
            "powershell",
            "203.0.113.1",
            4444,
            4242,
            chain(),
            serde_json::json!([det("lolbin")]),
            serde_json::json!([det("suspicious_port")]),
            4,
        ),
        corr_env(
            "host-1",
            "powershell",
            "203.0.113.1",
            4444,
            5001,
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
            5002,
            chain(),
            serde_json::json!([]),
            serde_json::json!([]),
            2,
        ),
        corr_env(
            "host-1",
            "echo",
            "203.0.113.1",
            4444,
            8,
            serde_json::json!([]),
            serde_json::json!([]),
            serde_json::json!([det("suspicious_port")]),
            4,
        ),
    ];

    println!("--- Part 1: gate + collapse ---");
    println!(
        "input envelopes ({}): three attack-chain records to powershell->203.0.113.1:4444 (pids 4242,5001,5002), one benign-process record (echo->203.0.113.1:4444, empty top-level detections)",
        batch.len()
    );
    for env in &batch {
        println!(
            "  image={:<12} daddr={:<15} dport={:<5} pid={:<5} top_level_detections={:<2} severity_id(source, IGNORED)={}",
            env.data["process"]["image"].as_str().unwrap_or("?"),
            env.data["connection"]["daddr"].as_str().unwrap_or("?"),
            env.data["connection"]["dport"].as_u64().unwrap_or(0),
            env.data["process"]["pid"].as_u64().unwrap_or(0),
            env.data["detections"].as_array().map(|a| a.len()).unwrap_or(0),
            env.severity_id,
        );
    }
    println!();

    let assets = assets();
    let report = run_correlation_ingest(&batch, &assets, &[]);

    println!("scored findings ({}):", report.findings.len());
    for f in &report.findings {
        println!(
            "  id={:<28} vuln_id={:<40} score.r={:<3} sev(weight)={:<4} status={:?} reported_severity={:?}",
            f.finding_id,
            f.identity.vuln_id,
            f.score.r,
            f.score.explain.sev,
            f.status,
            f.provenance[0].reported_severity,
        );
        assert_eq!(
            f.provenance[0].reported_severity, None,
            "source severity_id must never be trusted"
        );
    }
    println!();

    // GATE: the benign-process record (empty top-level detections) never
    // becomes a finding — its connection half is already scored by network
    // ingest; scoring it here would double-count.
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.identity.vuln_id == "correlation:echo->203.0.113.1:4444"),
        "benign-process 9002 (empty top-level detections) must not become a finding"
    );

    // COLLAPSE: three attack-chain records, same edge -> ONE finding.
    let edge: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.identity.vuln_id == "correlation:powershell->203.0.113.1:4444")
        .collect();
    println!(
        "GATE: benign-process record (echo->203.0.113.1:4444, empty top-level detections) -> no finding (its connection half is already scored by network ingest).",
    );
    println!(
        "COLLAPSE: 3 attack-chain records to powershell->203.0.113.1:4444 (pids 4242, 5001, 5002) -> {} finding(s), at weight {:?}",
        edge.len(),
        edge.first().map(|f| f.score.explain.sev),
    );
    assert_eq!(
        edge.len(),
        1,
        "three attack-chain records to the same edge must collapse into exactly ONE finding"
    );
    assert_eq!(
        edge[0].score.explain.sev, 0.9,
        "the correlated rule weighs 0.9"
    );
    assert_eq!(
        report.findings.len(),
        1,
        "only the attack-chain edge scores; the benign-process record does not"
    );

    // OUTRANK: the chain (0.9) scores STRICTLY higher than a single-sensor
    // component's max weight (0.7), same asset context.
    let ctx = assets.context("host-1");
    let chain_score = recompute_compliance_score(0.9, &ctx);
    let half_score = recompute_compliance_score(0.7, &ctx);
    println!(
        "OUTRANK: weight 0.9 (correlated chain) -> R={}, weight 0.7 (single-sensor component) -> R={} (same asset context)",
        chain_score.r, half_score.r
    );
    assert_eq!(
        edge[0].score.r, chain_score.r,
        "the finding's score must equal the recomputed 0.9 weight"
    );
    assert!(
        chain_score.r > half_score.r,
        "attack chain (0.9 -> {}) must outscore a single-sensor component (0.7 -> {})",
        chain_score.r,
        half_score.r,
    );

    println!(
        "\ntriage remediation group(s) ({}):",
        report.remediation_items.len()
    );
    for item in &report.remediation_items {
        println!(
            "  remediation_key={:<28} risk={:<3} closes={:?} assets={:?}",
            item.remediation_key, item.risk, item.closes, item.assets
        );
    }
    assert_eq!(
        report.remediation_items.len(),
        1,
        "the attack-chain edge groups under one triage item"
    );
    assert_eq!(
        report.remediation_items[0].remediation_key,
        "triage-attack-chain"
    );

    // ---------------------------------------------------------------
    // Part 2: LIFECYCLE (Open -> Reopened). Run the SAME single attack-chain
    // detection once with no prior state (-> Open), then again with that
    // finding's prior state marked Closed (-> Reopened, not a fresh
    // duplicate).
    // ---------------------------------------------------------------
    println!("\n--- Part 2: lifecycle (Open -> Reopened) ---");
    let recurring = vec![corr_env(
        "host-1",
        "/tmp/nc",
        "203.0.113.1",
        4444,
        4242,
        chain(),
        serde_json::json!([]),
        serde_json::json!([]),
        1,
    )];

    let first_run = run_correlation_ingest(&recurring, &assets, &[]);
    assert_eq!(
        first_run.findings.len(),
        1,
        "one attack-chain edge -> one finding"
    );
    let first_finding = &first_run.findings[0];
    println!(
        "run 1 (prior=[]):        vuln_id={:<32} status={:?}",
        first_finding.identity.vuln_id, first_finding.status
    );
    assert_eq!(
        first_finding.status,
        FindingState::Open,
        "no prior state -> Open"
    );

    // Simulate ops having closed this finding, then the SAME detection
    // recurring in a later batch.
    let mut closed_prior = first_finding.clone();
    closed_prior.status = FindingState::Closed;

    let second_run = run_correlation_ingest(&recurring, &assets, &[closed_prior]);
    assert_eq!(
        second_run.findings.len(),
        1,
        "the recurrence must not duplicate the finding"
    );
    let second_finding = &second_run.findings[0];
    println!(
        "run 2 (prior=[Closed]):  vuln_id={:<32} status={:?}",
        second_finding.identity.vuln_id, second_finding.status
    );
    assert_eq!(
        second_finding.status,
        FindingState::Reopened,
        "same identity recurring after Closed must Reopen, not duplicate"
    );
    println!(
        "\nLIFECYCLE: Open -> Closed (ops) -> {:?} on recurrence (no duplicate finding created).",
        second_finding.status
    );

    println!("\nOK: 3 attack-chain records to powershell->203.0.113.1:4444 collapsed to 1 finding at weight 0.9");
    println!("(R={} > single-sensor component R={} for the same asset); the benign-process record produced no", chain_score.r, half_score.r);
    println!("finding; the recurring /tmp/nc->203.0.113.1:4444 detection went Open -> Reopened across runs.");
}
