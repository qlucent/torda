//! Small, honest demo of the Process Activity ingest path
//! (`torda_ingest::process::run_process_ingest`): builds a batch of representative
//! OCSF Process Activity (class 1007) envelopes INLINE — in the exact shape
//! procmon emits them — runs them through the REAL production ingest path,
//! and prints each scored finding plus the triage remediation group.
//!
//! Deliberately uses ONLY the crate's existing production dependencies
//! (`torda-ocsf`, `torda-findings`, `torda-findings-engine`, `serde_json`) — it does
//! NOT pull in `torda-mod-procmon` / `torda-substrate`; the end-to-end proof that
//! REAL procmon envelopes flow through this same path lives in
//! `server/ingest/tests/process_e2e.rs`. This binary is just the visible,
//! standalone loop: envelopes in -> canonical, aggregated, lifecycle-aware
//! findings out.
//!
//! It demonstrates the two behaviors Task 1 added on top of the vuln path:
//!   1. COLLAPSE — many flagged records of the SAME binary (different pids)
//!      aggregate into ONE finding at the MAX rule-weight, not one finding
//!      per record.
//!   2. LIFECYCLE — a fresh detection with no prior state is `Open`; the same
//!      identity recurring after a prior `Closed` finding is `Reopened`
//!      instead of duplicating.
use std::collections::HashMap;

use torda_findings::{AssetContext, Criticality, FindingState};
use torda_findings_engine::input::MapAssetContext;
use torda_ocsf::{class, Device, Metadata, OcsfEnvelope};

use torda_ingest::process::run_process_ingest;

/// Builds one Process Activity envelope (class 1007) in the agent's real
/// shape. `severity_id` is set to a deliberately WRONG/irrelevant value on
/// the flagged records to make the point visible: ingest never reads it.
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

/// A minimal fixed asset context (mirrors the fim/drift/process unit-test
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
        "== process-findings-demo — OCSF Process Activity (1007) -> canonical scored findings ==\n"
    );

    // ---------------------------------------------------------------
    // Part 1: COLLAPSE. Three /tmp/x/powershell execs (different pids) —
    // one plain lolbin, one plain suspicious_path, one the combined
    // lolbin_in_suspicious_path (weight 0.7, the strongest) — plus a distinct
    // binary (certutil, weight 0.4) and a benign echo. All three powershell
    // records share ONE binary identity and must aggregate into ONE finding
    // at the MAX weight (0.7), not three near-duplicate findings.
    // ---------------------------------------------------------------
    let flood = vec![
        proc_env(
            "host-1",
            "/usr/bin/echo",
            "exec",
            1001,
            serde_json::Value::Null,
            serde_json::json!([]),
            1,
        ),
        proc_env(
            "host-1",
            "/tmp/x/powershell",
            "exec",
            2001,
            serde_json::Value::Null,
            serde_json::json!([det("lolbin")]),
            1,
        ),
        proc_env(
            "host-1",
            "/tmp/x/powershell",
            "exec",
            2002,
            serde_json::Value::Null,
            serde_json::json!([det("suspicious_path")]),
            4,
        ),
        proc_env(
            "host-1",
            "/tmp/x/powershell",
            "exec",
            2003,
            serde_json::Value::Null,
            serde_json::json!([det("lolbin_in_suspicious_path")]),
            1,
        ),
        proc_env(
            "host-1",
            "/usr/bin/certutil",
            "exec",
            3001,
            serde_json::Value::Null,
            serde_json::json!([det("lolbin")]),
            1,
        ),
    ];

    println!("--- Part 1: collapse ---");
    println!("input envelopes ({}): three /tmp/x/powershell execs (pids 2001,2002,2003), one certutil, one benign echo", flood.len());
    for env in &flood {
        println!(
            "  activity={:<4} pid={:<5} image={:<20} severity_id(source, IGNORED)={}",
            env.data["activity"].as_str().unwrap_or("?"),
            env.data["process"]["pid"].as_u64().unwrap_or(0),
            env.data["process"]["image"].as_str().unwrap_or("?"),
            env.severity_id,
        );
    }
    println!();

    let assets = assets();
    let flood_report = run_process_ingest(&flood, &assets, &[]);

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

    let powershell_findings: Vec<_> = flood_report
        .findings
        .iter()
        .filter(|f| f.identity.vuln_id == "process:/tmp/x/powershell")
        .collect();
    println!(
        "COLLAPSE: {} /tmp/x/powershell exec records (pids 2001, 2002, 2003) -> {} finding(s), at weight {:?}",
        3,
        powershell_findings.len(),
        powershell_findings.first().map(|f| f.score.explain.sev),
    );
    assert_eq!(
        powershell_findings.len(),
        1,
        "three /tmp/x/powershell execs must collapse into exactly ONE finding"
    );
    assert_eq!(
        powershell_findings[0].score.explain.sev, 0.7,
        "aggregated weight must be the MAX across all three records (lolbin_in_suspicious_path=0.7)"
    );
    assert!(
        !flood_report
            .findings
            .iter()
            .any(|f| f.identity.component == "/usr/bin/echo"),
        "benign exec must not become a finding"
    );
    assert_eq!(
        flood_report.findings.len(),
        2,
        "two distinct flagged binaries -> two findings (powershell, certutil)"
    );

    println!(
        "triage remediation group(s) ({}):",
        flood_report.remediation_items.len()
    );
    for item in &flood_report.remediation_items {
        println!(
            "  remediation_key={:<26} risk={:<3} closes={:?} assets={:?}",
            item.remediation_key, item.risk, item.closes, item.assets
        );
    }
    assert_eq!(
        flood_report.remediation_items.len(),
        1,
        "all flagged binaries group under one triage item"
    );
    assert_eq!(
        flood_report.remediation_items[0].remediation_key,
        "triage-suspicious-process"
    );

    // ---------------------------------------------------------------
    // Part 2: LIFECYCLE (Open -> Reopened). Run the SAME single detection
    // once with no prior state (-> Open), then again with that finding's
    // prior state marked Closed (-> Reopened, not a fresh duplicate).
    // ---------------------------------------------------------------
    println!("\n--- Part 2: lifecycle (Open -> Reopened) ---");
    let recurring = vec![proc_env(
        "host-1",
        "/tmp/nc",
        "exec",
        4242,
        serde_json::Value::Null,
        serde_json::json!([det("lolbin_in_suspicious_path")]),
        1,
    )];

    let first_run = run_process_ingest(&recurring, &assets, &[]);
    assert_eq!(
        first_run.findings.len(),
        1,
        "one flagged binary -> one finding"
    );
    let first_finding = &first_run.findings[0];
    println!(
        "run 1 (prior=[]):        vuln_id={:<20} status={:?}",
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

    let second_run = run_process_ingest(&recurring, &assets, &[closed_prior]);
    assert_eq!(
        second_run.findings.len(),
        1,
        "the recurrence must not duplicate the finding"
    );
    let second_finding = &second_run.findings[0];
    println!(
        "run 2 (prior=[Closed]):  vuln_id={:<20} status={:?}",
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

    println!(
        "\nOK: {} /tmp/x/powershell records collapsed to 1 finding at weight 0.7; the recurring",
        3
    );
    println!("/tmp/nc detection went Open -> Reopened across runs instead of duplicating.");
}
