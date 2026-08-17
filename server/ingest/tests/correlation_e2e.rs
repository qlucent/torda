//! End-to-end integration test: substrate -> module -> OCSF -> ingest -> scored
//! finding, using the agent's ACTUAL emitted envelopes — never hand-built
//! fixtures. Mirrors `server/ingest/tests/network_e2e.rs`'s (and
//! `crates/agent/src/bin/corr-demo.rs`'s) ModuleCtx/StubBus/CapturingEmitter/
//! ZeroSampler wiring exactly, then feeds the REAL `torda_mod_corr::CorrModule`
//! output straight into `torda_ingest::correlation::run_correlation_ingest`.
//!
//! Proves (never trust a source's severity label; and the
//! Task 1 gate — only the TOP-LEVEL correlated rule scores, never a half):
//!   - an ordered ProcessExec("/tmp/nc") -> NetConnect(203.0.113.1:4444) attack
//!     chain makes the REAL module emit a 9002 whose TOP-LEVEL `detections`
//!     carries `suspicious_process_suspicious_connection` -> ONE
//!     `correlation:/tmp/nc->203.0.113.1:4444` finding at canonical weight 0.9,
//!     `provenance[0].reported_severity == None`;
//!   - that finding's `score.r` is STRICTLY higher than what a single-sensor
//!     0.7 component would score for the same asset context (the chain
//!     outranks either half alone) — using a NON-SATURATING asset context so
//!     the delta is observable in `score.r`, not masked by clamping to 100;
//!   - a benign-process contrast (ProcessExec("/usr/bin/echo") ->
//!     NetConnect(203.0.113.1:4444)) makes the REAL module emit a 9002 with an
//!     EMPTY top-level `detections` array (the connection alone was flagged,
//!     the process was not, so the correlated rule never fires) — and that
//!     record produces NO finding (proving the real module's non-correlated
//!     record is correctly skipped — no double-count of the connection half,
//!     which the network ingest already scores separately);
//!   - the attack-chain edge groups under the single `triage-attack-chain`
//!     remediation item.
//!
//! `torda-mod-corr` / `torda-substrate` / `torda-core` / `tokio` are dev-dependencies
//! only (see `server/ingest/Cargo.toml`) — this proves the chain without
//! pulling module crates into the ingest crate's production graph.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use torda_core::{
    EventBus, EventKind, Module, ModuleCtx, OcsfEmitter, ResourceBudget, ResourceGovernor,
    ResourceSampler, ResourceUsage, SubstrateEvent,
};
use torda_findings::{AssetContext, Criticality};
use torda_findings_engine::input::{AssetContextSource, MapAssetContext};
use torda_findings_engine::score::recompute_compliance_score;
use torda_ocsf::OcsfEnvelope;
use torda_substrate::{StubBus, StubSnapshot};

use torda_ingest::correlation::run_correlation_ingest;

/// Captures every OCSF envelope the REAL module emits (same role as
/// corr-demo's `CapturingEmitter`) so the test can feed them into ingest.
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
/// exercises throttling (mirrors network_e2e's `ZeroSampler`).
struct ZeroSampler;
impl ResourceSampler for ZeroSampler {
    fn sample(&self) -> ResourceUsage {
        ResourceUsage::ZERO
    }
}

fn exec_event(pid: u64, image: &str) -> SubstrateEvent {
    SubstrateEvent {
        kind: EventKind::ProcessExec,
        ts: 0,
        fields: serde_json::json!({ "pid": pid, "image": image }),
    }
}

fn connect_event(pid: u64, image: &str, daddr: &str, dport: u16) -> SubstrateEvent {
    SubstrateEvent {
        kind: EventKind::NetConnect,
        ts: 0,
        fields: serde_json::json!({
            "pid": pid, "image": image, "daddr": daddr, "dport": dport, "proto": "tcp"
        }),
    }
}

/// A minimal fixed `AssetContextSource` (mirrors `correlation.rs`'s
/// `scored_assets` unit-test fixture): internal + Normal criticality so weight
/// 0.9 and weight 0.7 both stay BELOW saturation, keeping `0.9 -> R > 0.7 -> R`
/// observable rather than both clamped to 100.
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
/// uses, registers the REAL `CorrModule`, publishes the synthetic
/// ProcessExec/NetConnect stream, lets its background task drain the bus, and
/// returns the OCSF Correlated Activity envelopes it ACTUALLY emitted — the
/// full substrate -> module -> OCSF leg, unmocked.
async fn run_corr_and_capture(events: &[SubstrateEvent]) -> Vec<OcsfEnvelope> {
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

    let mut corr = torda_mod_corr::CorrModule::new();
    corr.init(ctx).await.expect("corr init");
    corr.start()
        .await
        .expect("corr start (subscribes before we publish)");

    for ev in events {
        bus.publish(ev.clone());
    }

    // Let the module's background task drain the bounded broadcast channel.
    // Only NetConnect events yield a 9002 record; ProcessExec produces none.
    let expected_records = events
        .iter()
        .filter(|e| e.kind == EventKind::NetConnect)
        .count();
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(2)).await;
        if records.lock().unwrap().len() >= expected_records {
            break;
        }
    }

    corr.stop().await.expect("corr clean shutdown");

    let out = records.lock().unwrap().clone();
    out
}

#[tokio::test]
async fn real_corr_envelopes_flow_end_to_end_into_scored_findings() {
    // Ordered attack-chain sequence + a benign contrast, published on the
    // (serially-drained) StubBus. Each pid's ProcessExec precedes its
    // NetConnect so corr's pid-join populates the process context before the
    // connect arrives:
    //   pid=7 /tmp/nc      exec -> connect 203.0.113.1:4444  — ATTACK CHAIN:
    //                       suspicious process + suspicious external
    //                       connection. Expect a 9002 whose TOP-LEVEL
    //                       detections carry `suspicious_process_suspicious_connection`.
    //   pid=8 /usr/bin/echo exec -> connect 203.0.113.1:4444 — benign process
    //                       + suspicious connection: a 9002 IS emitted, but
    //                       the correlated rule does NOT fire (empty
    //                       top-level detections).
    let events = [
        exec_event(7, "/tmp/nc"),
        connect_event(7, "nc", "203.0.113.1", 4444),
        exec_event(8, "/usr/bin/echo"),
        connect_event(8, "echo", "203.0.113.1", 4444),
    ];

    let envelopes = run_corr_and_capture(&events).await;
    assert_eq!(
        envelopes.len(),
        2,
        "corr must emit one 9002 per NetConnect event"
    );

    // Every envelope really is the agent's Correlated Activity class — the
    // real module's own shape, not a fixture we hand-built.
    for env in &envelopes {
        assert_eq!(env.class_uid, torda_ocsf::class::CORRELATED_ACTIVITY);
    }

    // Sanity: exactly one of the two records was actually flagged by the
    // real module's top-level correlated rule (proves we're exercising the
    // correlation path, not a no-op / both-fire bug).
    let flagged_by_module = envelopes
        .iter()
        .filter(|e| {
            e.data["detections"]
                .as_array()
                .map(|a| !a.is_empty())
                .unwrap_or(false)
        })
        .count();
    assert_eq!(
        flagged_by_module, 1,
        "only the /tmp/nc attack chain must carry a top-level correlated detection"
    );

    // Feed the REAL captured envelopes through the production ingest path.
    let assets = assets();
    let report = run_correlation_ingest(&envelopes, &assets, &[]);

    // The benign-process record (pid=8, echo) produced no finding at all —
    // the correlated rule never fired for it, so ingest correctly skips it
    // (its connection half is already scored separately by network ingest).
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.identity.vuln_id == "correlation:echo->203.0.113.1:4444"),
        "benign-process 9002 (empty top-level detections) must not become a finding"
    );

    // The attack chain becomes exactly one finding at the canonical edge
    // identity — no pid, no severity band.
    assert_eq!(report.findings.len(), 1, "only the attack chain scores");
    let f = &report.findings[0];
    assert_eq!(f.identity.vuln_id, "correlation:/tmp/nc->203.0.113.1:4444");
    assert_eq!(
        f.score.explain.sev, 0.9,
        "the correlated rule weighs 0.9, not a severity band"
    );
    assert_eq!(
        f.provenance[0].reported_severity, None,
        "source severity_id must be discarded"
    );

    // STRICTLY higher than a single-sensor half's max weight (0.7), same
    // asset context — the chain outranks either signal alone. Non-vacuous
    // under the non-saturating context configured above.
    let ctx = assets.context("host-e2e");
    let half = recompute_compliance_score(0.7, &ctx);
    assert!(
        f.score.r > half.r,
        "attack chain (0.9 -> {}) must outscore a single-sensor half (0.7 -> {})",
        f.score.r,
        half.r,
    );

    // The flagged edge groups under the single triage remediation bucket.
    assert_eq!(report.remediation_items.len(), 1);
    assert_eq!(
        report.remediation_items[0].remediation_key,
        "triage-attack-chain"
    );
}
