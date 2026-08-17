//! Small, honest demo of the Network Activity ingest path
//! (`torda_ingest::network::run_network_ingest`): builds a batch of representative
//! OCSF Network Activity (class 4001) envelopes INLINE — in the exact shape
//! netmon emits them — runs them through the REAL production ingest path, and
//! prints each scored finding plus the triage remediation group.
//!
//! Deliberately uses ONLY the crate's existing production dependencies
//! (`torda-ocsf`, `torda-findings`, `torda-findings-engine`, `serde_json`) — it does NOT
//! pull in `torda-mod-netmon` / `torda-substrate`; the end-to-end proof that REAL
//! netmon envelopes flow through this same path lives in
//! `server/ingest/tests/network_e2e.rs`. This binary is just the visible,
//! standalone loop: envelopes in -> canonical, aggregated, lifecycle-aware
//! findings out.
//!
//! It demonstrates the two behaviors Task 1 added on top of the vuln/process
//! paths, for the network class:
//!   1. COLLAPSE — many flagged connection records to the SAME destination
//!      (different pids/source ports) aggregate into ONE finding at the MAX
//!      rule-weight, not one finding per connection.
//!   2. LIFECYCLE — a fresh detection with no prior state is `Open`; the same
//!      destination identity recurring after a prior `Closed` finding is
//!      `Reopened` instead of duplicating.
use std::collections::HashMap;

use torda_findings::{AssetContext, Criticality, FindingState};
use torda_findings_engine::input::MapAssetContext;
use torda_ocsf::{class, Device, Metadata, OcsfEnvelope};

use torda_ingest::network::run_network_ingest;

/// Builds one Network Activity envelope (class 4001) in the agent's real
/// shape. `severity_id` is set to a deliberately WRONG/irrelevant value on
/// the flagged records to make the point visible: ingest never reads it.
fn net_env(
    host: &str,
    daddr: &str,
    dport: u64,
    pid: u64,
    image: &str,
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
            "activity": "connect",
            "connection": { "daddr": daddr, "dport": dport, "proto": "tcp" },
            "process": { "pid": pid, "image": image },
            "detections": detections,
        }),
    );
    e.severity_id = severity_id;
    e
}

fn det(rule: &str) -> serde_json::Value {
    serde_json::json!({ "rule": rule, "reason": format!("{rule} fired") })
}

/// A minimal fixed asset context (mirrors the process/fim/drift unit-test
/// fixtures): every host gets the same context so the printed score is
/// entirely explained by the per-rule weight, not by asset variation.
fn assets() -> MapAssetContext {
    MapAssetContext {
        by_asset: HashMap::new(),
        default: AssetContext {
            internet_facing: true,
            criticality: Criticality::Normal,
            compensating_controls: false,
        },
    }
}

fn main() {
    println!(
        "== network-findings-demo — OCSF Network Activity (4001) -> canonical scored findings ==\n"
    );

    // ---------------------------------------------------------------
    // Part 1: COLLAPSE. Three connections to 203.0.113.1:4444 (different
    // pids/source contexts) — one plain suspicious_port, one also hitting
    // suspicious_port_to_external (weight 0.7, the strongest) — plus a
    // distinct suspicious loopback destination (127.0.0.1:4444, weight 0.4,
    // private so only the base rule fires) and a benign connection
    // (93.184.216.34:443). All three 203.0.113.1:4444 records share ONE
    // destination identity and must aggregate into ONE finding at the MAX
    // weight (0.7), not three near-duplicate findings.
    // ---------------------------------------------------------------
    let flood = vec![
        net_env(
            "host-1",
            "93.184.216.34",
            443,
            1001,
            "curl",
            serde_json::json!([]),
            1,
        ),
        net_env(
            "host-1",
            "203.0.113.1",
            4444,
            2001,
            "implant-a",
            serde_json::json!([det("suspicious_port")]),
            1,
        ),
        net_env(
            "host-1",
            "203.0.113.1",
            4444,
            2002,
            "implant-b",
            serde_json::json!([det("suspicious_port")]),
            4,
        ),
        net_env(
            "host-1",
            "203.0.113.1",
            4444,
            2003,
            "implant-c",
            serde_json::json!([det("suspicious_port_to_external")]),
            1,
        ),
        net_env(
            "host-1",
            "127.0.0.1",
            4444,
            3001,
            "nc",
            serde_json::json!([det("suspicious_port")]),
            1,
        ),
    ];

    println!("--- Part 1: collapse ---");
    println!(
        "input envelopes ({}): one benign :443, three flagged connects to 203.0.113.1:4444 (pids 2001,2002,2003), one suspicious loopback 127.0.0.1:4444",
        flood.len()
    );
    for env in &flood {
        println!(
            "  daddr={:<15} dport={:<5} pid={:<5} image={:<12} severity_id(source, IGNORED)={}",
            env.data["connection"]["daddr"].as_str().unwrap_or("?"),
            env.data["connection"]["dport"].as_u64().unwrap_or(0),
            env.data["process"]["pid"].as_u64().unwrap_or(0),
            env.data["process"]["image"].as_str().unwrap_or("?"),
            env.severity_id,
        );
    }
    println!();

    let assets = assets();
    let flood_report = run_network_ingest(&flood, &assets, &[]);

    println!("scored findings ({}):", flood_report.findings.len());
    for f in &flood_report.findings {
        println!(
            "  id={:<28} vuln_id={:<28} score.r={:<3} sev(weight)={:<4} status={:?} reported_severity={:?}",
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

    let dest_findings: Vec<_> = flood_report
        .findings
        .iter()
        .filter(|f| f.identity.vuln_id == "network:203.0.113.1:4444")
        .collect();
    println!(
        "COLLAPSE: {} connection records to 203.0.113.1:4444 (pids 2001, 2002, 2003) -> {} finding(s), at weight {:?}",
        3,
        dest_findings.len(),
        dest_findings.first().map(|f| f.score.explain.sev),
    );
    assert_eq!(
        dest_findings.len(),
        1,
        "three connections to 203.0.113.1:4444 must collapse into exactly ONE finding"
    );
    assert_eq!(
        dest_findings[0].score.explain.sev, 0.7,
        "aggregated weight must be the MAX across all three records (suspicious_port_to_external=0.7)"
    );

    let loopback_finding = flood_report
        .findings
        .iter()
        .find(|f| f.identity.vuln_id == "network:127.0.0.1:4444")
        .expect("loopback finding must be present");
    assert_eq!(
        loopback_finding.score.explain.sev, 0.4,
        "loopback destination is private, so only suspicious_port (0.4) fires"
    );

    assert!(
        !flood_report
            .findings
            .iter()
            .any(|f| f.identity.vuln_id == "network:93.184.216.34:443"),
        "benign connection must not become a finding"
    );
    assert_eq!(
        flood_report.findings.len(),
        2,
        "two distinct flagged destinations -> two findings (203.0.113.1:4444, 127.0.0.1:4444)"
    );

    println!(
        "triage remediation group(s) ({}):",
        flood_report.remediation_items.len()
    );
    for item in &flood_report.remediation_items {
        println!(
            "  remediation_key={:<28} risk={:<3} closes={:?} assets={:?}",
            item.remediation_key, item.risk, item.closes, item.assets
        );
    }
    assert_eq!(
        flood_report.remediation_items.len(),
        1,
        "all flagged destinations group under one triage item"
    );
    assert_eq!(
        flood_report.remediation_items[0].remediation_key,
        "triage-suspicious-connection"
    );

    // ---------------------------------------------------------------
    // Part 2: LIFECYCLE (Open -> Reopened). Run the SAME single detection
    // once with no prior state (-> Open), then again with that finding's
    // prior state marked Closed (-> Reopened, not a fresh duplicate).
    // ---------------------------------------------------------------
    println!("\n--- Part 2: lifecycle (Open -> Reopened) ---");
    let recurring = vec![net_env(
        "host-1",
        "203.0.113.1",
        4444,
        4242,
        "implant",
        serde_json::json!([det("suspicious_port_to_external")]),
        1,
    )];

    let first_run = run_network_ingest(&recurring, &assets, &[]);
    assert_eq!(
        first_run.findings.len(),
        1,
        "one flagged destination -> one finding"
    );
    let first_finding = &first_run.findings[0];
    println!(
        "run 1 (prior=[]):        vuln_id={:<24} status={:?}",
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

    let second_run = run_network_ingest(&recurring, &assets, &[closed_prior]);
    assert_eq!(
        second_run.findings.len(),
        1,
        "the recurrence must not duplicate the finding"
    );
    let second_finding = &second_run.findings[0];
    println!(
        "run 2 (prior=[Closed]):  vuln_id={:<24} status={:?}",
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

    println!("\nOK: 3 connection records to 203.0.113.1:4444 collapsed to 1 finding at weight 0.7; the recurring");
    println!(
        "203.0.113.1:4444 detection went Open -> Reopened across runs instead of duplicating."
    );
}
