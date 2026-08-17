//! End-to-end integration test: substrate -> module -> OCSF -> ingest -> scored
//! finding, using the agent's ACTUAL emitted envelopes — never hand-built
//! fixtures. Mirrors `crates/agent/src/bin/procmon-demo.rs`'s ModuleCtx/StubBus/
//! CapturingEmitter/ZeroSampler wiring exactly, then feeds the REAL
//! `torda_mod_procmon::ProcMonModule` output straight into
//! `torda_ingest::process::run_process_ingest`.
//!
//! Proves (never trust a source's severity label; and the
//! Task 1 identity rework — the binary, not the pid/activity, is identity):
//!   - a benign exec (`/usr/bin/echo`, no detections) yields NO finding;
//!   - the REAL module emits SEVERAL flagged `/tmp/nc` records — a suspicious
//!     exec (`lolbin_in_suspicious_path`), a second suspicious exec, and a
//!     correlated exec->exit pair (ts 0 -> ts 4) whose exit fires
//!     `short_lived_suspicious` — and every one of them COLLAPSES into a
//!     SINGLE `process:/tmp/nc` finding (aggregation proven on the real
//!     emitted stream, not a fabricated one);
//!   - that single finding's canonical score is the MAX rule-weight across
//!     ALL of the binary's records (0.7, from `lolbin_in_suspicious_path`),
//!     never procmon's own `severity_id`;
//!   - the finding's `provenance[0].reported_severity` is `None` — the
//!     source severity is discarded, not merely unused;
//!   - the flagged records group under the single `triage-suspicious-process`
//!     remediation item.
//!
//! `torda-mod-procmon` / `torda-substrate` / `torda-core` / `tokio` are dev-dependencies
//! only (see `server/ingest/Cargo.toml`) — this proves the chain without
//! pulling substrate/module crates into the ingest crate's production graph.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use torda_core::{
    EventBus, EventKind, Module, ModuleCtx, OcsfEmitter, ResourceBudget, ResourceGovernor,
    ResourceSampler, ResourceUsage, SubstrateEvent,
};
use torda_findings::{AssetContext, Criticality};
use torda_findings_engine::input::MapAssetContext;
use torda_ocsf::OcsfEnvelope;
use torda_substrate::{StubBus, StubSnapshot};

use torda_ingest::process::run_process_ingest;

/// Captures every OCSF envelope the REAL module emits (same role as
/// procmon-demo's `CapturingEmitter`) so the test can feed them into ingest.
#[derive(Default)]
struct CapturingEmitter {
    records: Arc<Mutex<Vec<OcsfEnvelope>>>,
}
impl OcsfEmitter for CapturingEmitter {
    fn emit(&self, rec: OcsfEnvelope) {
        self.records.lock().expect("emitter lock").push(rec);
    }
}

/// A constant-ZERO sampler: the governor needs one but this test never
/// exercises throttling (mirrors procmon-demo's `ZeroSampler`).
struct ZeroSampler;
impl ResourceSampler for ZeroSampler {
    fn sample(&self) -> ResourceUsage {
        ResourceUsage::ZERO
    }
}

fn exec_event_ts(pid: u64, image: &str, ts: i64) -> SubstrateEvent {
    SubstrateEvent {
        kind: EventKind::ProcessExec,
        ts,
        fields: serde_json::json!({ "pid": pid, "image": image }),
    }
}

fn exit_event_ts(pid: u64, image: &str, ts: i64) -> SubstrateEvent {
    SubstrateEvent {
        kind: EventKind::ProcessExit,
        ts,
        fields: serde_json::json!({ "pid": pid, "image": image }),
    }
}

/// A minimal fixed `AssetContextSource` (mirrors the fim/drift/process
/// unit-test fixtures under `crate::fixtures::default_assets`): every asset
/// gets the same context, so the finding's score is fully determined by the
/// canonical weight under test, not by per-asset variation.
fn assets() -> MapAssetContext {
    MapAssetContext {
        by_asset: std::collections::HashMap::new(),
        default: AssetContext {
            internet_facing: false,
            criticality: Criticality::Normal,
            compensating_controls: false,
        },
    }
}

/// Stands up the SAME shared substrate stub the agent's collection cycle
/// uses, registers the REAL `ProcMonModule`, publishes the synthetic
/// exec/exit stream, lets its background task drain the bus, and returns the
/// OCSF Process Activity envelopes it ACTUALLY emitted — the full
/// substrate -> module -> OCSF leg, unmocked.
async fn run_procmon_and_capture(events: &[SubstrateEvent]) -> Vec<OcsfEnvelope> {
    let records: Arc<Mutex<Vec<OcsfEnvelope>>> = Arc::new(Mutex::new(Vec::new()));
    let emitter: Arc<dyn OcsfEmitter> = Arc::new(CapturingEmitter {
        records: records.clone(),
    });
    let bus = StubBus::new();
    let governor = Arc::new(ResourceGovernor::new(
        ResourceBudget::from_env(),
        Box::new(ZeroSampler),
    ));

    let ctx = ModuleCtx {
        bus: bus.clone(),
        snapshot: StubSnapshot::new(),
        emitter,
        governor,
        tenant_id: "tenant-e2e".to_string(),
        product: "torda".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };

    let mut procmon = torda_mod_procmon::ProcMonModule::new();
    procmon.init(ctx).await.expect("procmon init");
    procmon
        .start()
        .await
        .expect("procmon start (subscribes before we publish)");

    for ev in events {
        bus.publish(ev.clone());
    }

    // Let the module's background task drain the bounded broadcast channel.
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(2)).await;
        if records.lock().unwrap().len() >= events.len() {
            break;
        }
    }

    procmon.stop().await.expect("procmon clean shutdown");

    let out = records.lock().unwrap().clone();
    out
}

#[tokio::test]
async fn real_procmon_envelopes_flow_end_to_end_into_scored_findings() {
    // Synthetic stream published in order on the (serially-drained) StubBus:
    //   1001 /usr/bin/echo — a single benign exec (no matching exit): must
    //                        produce NO finding.
    //   1002 /tmp/nc        — a suspicious exec ONLY (LOLBin in a suspicious
    //                        path): must score from the weight table.
    //   1003 /tmp/nc        — a suspicious exec -> exit PAIR (ts 0 -> ts 4)
    //                        short-lived enough to fire
    //                        `short_lived_suspicious` on the correlated exit.
    let events = [
        exec_event_ts(1001, "/usr/bin/echo", 0),
        exec_event_ts(1002, "/tmp/nc", 0),
        exec_event_ts(1003, "/tmp/nc", 0),
        exit_event_ts(1003, "/tmp/nc", 4),
    ];

    let envelopes = run_procmon_and_capture(&events).await;
    assert_eq!(
        envelopes.len(),
        events.len(),
        "procmon must emit one OCSF record per substrate event"
    );

    // Every envelope really is the agent's Process Activity class — the real
    // module's own shape, not a fixture we hand-built.
    for env in &envelopes {
        assert_eq!(env.class_uid, torda_ocsf::class::PROCESS_ACTIVITY);
    }

    // Sanity: the module itself flagged the /tmp/nc records with real
    // detections (proves we're exercising the detection path, not a no-op).
    let flagged_by_module = envelopes
        .iter()
        .filter(|e| {
            e.data["detections"]
                .as_array()
                .map(|a| !a.is_empty())
                .unwrap_or(false)
        })
        .count();
    assert!(
        flagged_by_module >= 2,
        "the real module must have flagged the /tmp/nc exec and exit"
    );

    // Feed the REAL captured envelopes through the production ingest path.
    let assets = assets();
    let report = run_process_ingest(&envelopes, &assets, &[]);

    // The benign /usr/bin/echo exec produced no finding at all.
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.identity.component == "/usr/bin/echo"),
        "benign exec must not become a finding"
    );

    // THE COLLAPSE: three flagged /tmp/nc records (exec pid 1002, exec pid
    // 1003, and the correlated exit for pid 1003) all share the binary
    // identity `process:/tmp/nc` and must aggregate into EXACTLY ONE finding
    // — proven on the real module's emitted stream, not a hand-built one.
    let nc_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.identity.vuln_id == "process:/tmp/nc")
        .collect();
    assert_eq!(
        nc_findings.len(),
        1,
        "every flagged /tmp/nc record (multiple execs + the correlated exit) must collapse into ONE finding"
    );

    // Only that one aggregated finding exists in the whole report — the
    // benign echo produced nothing and there is no other flagged binary.
    assert_eq!(
        report.findings.len(),
        1,
        "only the single aggregated /tmp/nc finding should score"
    );

    let nc = nc_findings[0];
    // Canonical scoring: the MAX rule-weight across every one of the binary's
    // records — the exec's `lolbin_in_suspicious_path` (0.7) beats the exit's
    // `short_lived_suspicious` (0.5) — never procmon's own `severity_id`.
    assert_eq!(
        nc.score.explain.sev, 0.7,
        "aggregated weight is the MAX across all /tmp/nc records (lolbin_in_suspicious_path=0.7 beats short_lived_suspicious=0.5)"
    );
    // The source severity is discarded entirely (provenance carries None),
    // never merely unused.
    assert_eq!(
        nc.provenance[0].reported_severity, None,
        "source severity_id must be discarded"
    );

    // The flagged records group under the single triage remediation bucket.
    assert_eq!(report.remediation_items.len(), 1);
    assert_eq!(
        report.remediation_items[0].remediation_key,
        "triage-suspicious-process"
    );
}
