//! P3f1 netmon StubBus detection demo — proves the module's subscribe -> assess
//! -> emit path end to end with NO backend, NO elevation, and NO OS access. It
//! stands up the SAME shared substrate stub the agent's collection cycle uses,
//! registers a REAL [`torda_mod_netmon::NetMonModule`], publishes a few synthetic
//! `NetConnect` events, and prints the OCSF Network Activity records the module
//! emits — showing a benign connect (severity 1, no detections) next to flagged
//! connects (Medium / High + detections).
//!
//! This is exactly the module the `torda` binary registers. On the
//! default StubBus the agent publishes no NetConnect events, so netmon is a
//! silent no-op there; this demo publishes synthetic events to make the
//! detection path VISIBLE.
//!
//! Self-asserting: if netmon ever stops flagging a known-suspicious connection,
//! the demo exits non-zero.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use torda_core::{
    EventBus, EventKind, Module, ModuleCtx, OcsfEmitter, ResourceBudget, ResourceGovernor,
    ResourceSampler, ResourceUsage, SubstrateEvent,
};
use torda_ocsf::OcsfEnvelope;
use torda_substrate::{StubBus, StubSnapshot};

/// Captures every OCSF envelope the module emits so the demo can print them and
/// self-assert (the production binary's `StdoutEmitter` writes NDJSON instead).
#[derive(Default)]
struct CapturingEmitter {
    records: Arc<Mutex<Vec<OcsfEnvelope>>>,
}
impl OcsfEmitter for CapturingEmitter {
    fn emit(&self, rec: OcsfEnvelope) {
        self.records.lock().expect("emitter lock").push(rec);
    }
}

/// A constant-ZERO sampler: the governor needs a sampler but this demo never
/// exercises throttling, so a zero reading keeps it dependency-free.
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

#[tokio::main]
async fn main() {
    println!(
        "== netmon StubBus detection demo (P3f1) — subscribe -> assess -> emit, \
         no backend / no elevation ==\n"
    );

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
        tenant_id: "tenant-demo".to_string(),
        product: "torda".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };

    // The SAME real module the agent registers. It subscribes to the shared bus and
    // never touches the OS — the substrate is the only door.
    let mut netmon = torda_mod_netmon::NetMonModule::new();
    netmon.init(ctx).await.expect("netmon init");
    netmon
        .start()
        .await
        .expect("netmon start (subscribes before we publish)");

    // Synthetic NetConnect stream published in order on the (serially-drained)
    // StubBus:
    //   100 curl     -> 93.184.216.34:443   — benign external connect (Informational).
    //   200 nc       -> 127.0.0.1:4444      — suspicious loopback (Medium, suspicious_port).
    //   300 implant  -> 203.0.113.1:4444    — suspicious external (High, both rules).
    let events = [
        net_connect_event(100, "curl", "93.184.216.34", 443),
        net_connect_event(200, "nc", "127.0.0.1", 4444),
        net_connect_event(300, "implant", "203.0.113.1", 4444),
    ];
    println!(
        "publishing {} synthetic NetConnect events on the StubBus:",
        events.len()
    );
    for ev in &events {
        println!(
            "  -> connect pid={} image={} daddr={} dport={} ts={}",
            ev.fields["pid"], ev.fields["image"], ev.fields["daddr"], ev.fields["dport"], ev.ts
        );
        bus.publish(ev.clone());
    }
    println!();

    // Let the module's background task drain the broadcast channel (bounded so a bug
    // can never hang the demo).
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(2)).await;
        if records.lock().unwrap().len() >= events.len() {
            break;
        }
    }

    netmon.stop().await.expect("netmon clean shutdown");

    // Print each emitted OCSF Network Activity record, labeling benign vs flagged.
    let emitted = records.lock().unwrap();
    println!(
        "netmon emitted {} OCSF Network Activity record(s):",
        emitted.len()
    );
    let mut flagged = 0usize;
    for env in emitted.iter() {
        let daddr = env.data["connection"]["daddr"].as_str().unwrap_or("?");
        let dport = env.data["connection"]["dport"].as_u64().unwrap_or(0);
        let detections = env.data["detections"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0);
        let label = if detections > 0 {
            flagged += 1;
            "FLAGGED"
        } else {
            "benign "
        };
        let line = serde_json::to_string(env).expect("serialize OCSF envelope");
        println!(
            "  [{label}] pid={} daddr={daddr} dport={dport} severity_id={} detections={detections}",
            env.data["process"]["pid"], env.severity_id
        );
        println!("            {line}");
    }
    println!();

    assert!(
        flagged >= 1,
        "netmon must flag at least one suspicious connection — the subscribe -> assess -> emit path is live"
    );
    println!(
        "OK: {flagged} flagged detection(s) vs {} benign — the subscribe -> assess -> emit path is \
         live with NO backend and NO elevation. On the default agent StubBus (no NetConnect events \
         published) this same module is a silent no-op.",
        emitted.len() - flagged
    );
}
