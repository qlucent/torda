//! End-to-end integration test: substrate -> module -> OCSF -> ingest -> scored
//! finding, using the agent's ACTUAL emitted envelopes — never hand-built
//! fixtures. Mirrors `crates/agent/src/bin/netmon-demo.rs`'s ModuleCtx/StubBus/
//! CapturingEmitter/ZeroSampler wiring exactly, then feeds the REAL
//! `torda_mod_netmon::NetMonModule` output straight into
//! `torda_ingest::network::run_network_ingest`.
//!
//! Proves (never trust a source's severity label; and the
//! Task 1 identity rework — the destination, not the source port/pid, is
//! identity):
//!   - a benign connect (`93.184.216.34:443`, no detections) yields NO finding;
//!   - the REAL module emits SEVERAL flagged connects to the SAME external
//!     destination `203.0.113.1:4444` (different pids/images) — one hitting
//!     only `suspicious_port`, one hitting the correlated
//!     `suspicious_port_to_external` — and every one of them COLLAPSES into a
//!     SINGLE `network:203.0.113.1:4444` finding (aggregation proven on the
//!     real emitted stream, not a fabricated one);
//!   - that single finding's canonical score is the MAX rule-weight across
//!     ALL of the destination's records (0.7, from
//!     `suspicious_port_to_external`), never netmon's own `severity_id`;
//!   - a suspicious loopback connect (`127.0.0.1:4444`, private -> only the
//!     base `suspicious_port` rule fires) becomes its own
//!     `network:127.0.0.1:4444` finding at weight 0.4;
//!   - every finding's `provenance[0].reported_severity` is `None` — the
//!     source severity is discarded, not merely unused;
//!   - the flagged destinations group under the single
//!     `triage-suspicious-connection` remediation item.
//!
//! `torda-mod-netmon` / `torda-substrate` / `torda-core` / `tokio` are dev-dependencies
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

use torda_ingest::network::run_network_ingest;

/// Captures every OCSF envelope the REAL module emits (same role as
/// netmon-demo's `CapturingEmitter`) so the test can feed them into ingest.
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
/// exercises throttling (mirrors netmon-demo's `ZeroSampler`).
struct ZeroSampler;
impl ResourceSampler for ZeroSampler {
    fn sample(&self) -> ResourceUsage {
        ResourceUsage::ZERO
    }
}

fn net_connect_event(pid: u64, image: &str, daddr: &str, dport: u16) -> SubstrateEvent {
    SubstrateEvent {
        kind: EventKind::NetConnect,
        ts: 0,
        fields: serde_json::json!({
            "pid": pid, "image": image, "daddr": daddr, "dport": dport, "proto": "tcp"
        }),
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
/// uses, registers the REAL `NetMonModule`, publishes the synthetic
/// NetConnect stream, lets its background task drain the bus, and returns the
/// OCSF Network Activity envelopes it ACTUALLY emitted — the full
/// substrate -> module -> OCSF leg, unmocked.
async fn run_netmon_and_capture(events: &[SubstrateEvent]) -> Vec<OcsfEnvelope> {
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

    let mut netmon = torda_mod_netmon::NetMonModule::new();
    netmon.init(ctx).await.expect("netmon init");
    netmon
        .start()
        .await
        .expect("netmon start (subscribes before we publish)");

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

    netmon.stop().await.expect("netmon clean shutdown");

    let out = records.lock().unwrap().clone();
    out
}

#[tokio::test]
async fn real_netmon_envelopes_flow_end_to_end_into_scored_findings() {
    // Synthetic stream published in order on the (serially-drained) StubBus:
    //   100 curl     -> 93.184.216.34:443   — a single benign external connect
    //                    (no detections): must produce NO finding.
    //   200 implant-a -> 203.0.113.1:4444   — suspicious external connect #1
    //                    (both rules fire, weight 0.7).
    //   201 implant-b -> 203.0.113.1:4444   — suspicious external connect #2
    //                    to the SAME destination (different pid/image): must
    //                    collapse with #1 into ONE finding.
    //   300 nc        -> 127.0.0.1:4444     — suspicious LOOPBACK connect:
    //                    private, so only `suspicious_port` fires (weight 0.4).
    let events = [
        net_connect_event(100, "curl", "93.184.216.34", 443),
        net_connect_event(200, "implant-a", "203.0.113.1", 4444),
        net_connect_event(201, "implant-b", "203.0.113.1", 4444),
        net_connect_event(300, "nc", "127.0.0.1", 4444),
    ];

    let envelopes = run_netmon_and_capture(&events).await;
    assert_eq!(
        envelopes.len(),
        events.len(),
        "netmon must emit one OCSF record per substrate event"
    );

    // Every envelope really is the agent's Network Activity class — the real
    // module's own shape, not a fixture we hand-built.
    for env in &envelopes {
        assert_eq!(env.class_uid, torda_ocsf::class::NETWORK_ACTIVITY);
    }

    // Sanity: the module itself flagged the 203.0.113.1:4444 and 127.0.0.1:4444
    // records with real detections (proves we're exercising the detection
    // path, not a no-op).
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
        flagged_by_module, 3,
        "the real module must have flagged both 203.0.113.1:4444 connects and the loopback connect"
    );

    // Feed the REAL captured envelopes through the production ingest path.
    let assets = assets();
    let report = run_network_ingest(&envelopes, &assets, &[]);

    // The benign 93.184.216.34:443 connect produced no finding at all.
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.identity.vuln_id == "network:93.184.216.34:443"),
        "benign connection must not become a finding"
    );

    // THE COLLAPSE: two flagged 203.0.113.1:4444 records (pids 200 and 201,
    // different images) share the destination identity
    // `network:203.0.113.1:4444` and must aggregate into EXACTLY ONE finding
    // — proven on the real module's emitted stream, not a hand-built one.
    let dest_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.identity.vuln_id == "network:203.0.113.1:4444")
        .collect();
    assert_eq!(
        dest_findings.len(),
        1,
        "both flagged connects to 203.0.113.1:4444 (different pids/images) must collapse into ONE finding"
    );

    let dest = dest_findings[0];
    // Canonical scoring: the MAX rule-weight across the destination's records
    // — never netmon's own `severity_id`.
    assert_eq!(
        dest.score.explain.sev, 0.7,
        "203.0.113.1:4444 is external, so suspicious_port_to_external (0.7) governs"
    );
    // The source severity is discarded entirely (provenance carries None),
    // never merely unused.
    assert_eq!(
        dest.provenance[0].reported_severity, None,
        "source severity_id must be discarded"
    );

    // The suspicious loopback connect becomes its own finding at the lower
    // weight (private destination -> only the base rule fires).
    let loopback = report
        .findings
        .iter()
        .find(|f| f.identity.vuln_id == "network:127.0.0.1:4444")
        .expect("loopback finding must be present");
    assert_eq!(
        loopback.score.explain.sev, 0.4,
        "127.0.0.1 is private/loopback, so only suspicious_port (0.4) fires"
    );
    assert_eq!(
        loopback.provenance[0].reported_severity, None,
        "source severity_id must be discarded"
    );

    // Only these two findings exist in the whole report — the benign connect
    // produced nothing and there is no other flagged destination.
    assert_eq!(
        report.findings.len(),
        2,
        "only the two flagged destinations should score"
    );

    // The flagged destinations group under the single triage remediation
    // bucket.
    assert_eq!(report.remediation_items.len(), 1);
    assert_eq!(
        report.remediation_items[0].remediation_key,
        "triage-suspicious-connection"
    );
}
