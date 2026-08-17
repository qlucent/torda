//! P3g1 corr StubBus attack-chain demo — proves the module's subscribe ->
//! correlate -> emit path end to end with NO backend, NO elevation, and NO OS
//! access. It stands up the SAME shared substrate stub the agent's collection
//! cycle uses, registers a REAL [`torda_mod_corr::CorrModule`], publishes a
//! synthetic `ProcessExec` -> `NetConnect` sequence (each pid's exec BEFORE its
//! connect, so the join populates), and prints the OCSF Correlated Activity
//! (9002) records the module emits — showing the flagged attack chain
//! (suspicious process + suspicious connection = High +
//! `suspicious_process_suspicious_connection`) next to two non-correlated
//! contrasts: a benign process making the same suspicious connection, and an
//! unknown pid making a benign connection.
//!
//! This is exactly the module the `torda` binary registers. On the
//! default StubBus the agent publishes no ProcessExec/NetConnect events, so
//! corr is a silent no-op there; this demo publishes synthetic events to make
//! the correlation path VISIBLE.
//!
//! Self-asserting: if corr ever stops flagging the attack chain, the demo
//! exits non-zero.

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

#[tokio::main]
async fn main() {
    println!(
        "== corr StubBus attack-chain demo (P3g1) — subscribe -> correlate -> emit, \
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
    let mut corr = torda_mod_corr::CorrModule::new();
    corr.init(ctx).await.expect("corr init");
    corr.start()
        .await
        .expect("corr start (subscribes before we publish)");

    // Synthetic ProcessExec/NetConnect stream published in order on the
    // (serially-drained) StubBus. Each pid's ProcessExec is published BEFORE its
    // NetConnect so the join populates the process context before the connect
    // arrives:
    //   1. pid=7 /tmp/nc      -> connect 203.0.113.1:4444  — ATTACK CHAIN: suspicious
    //                            process + suspicious external connection. Expect a
    //                            9002 with `suspicious_process_suspicious_connection`,
    //                            severity High.
    //   2. pid=8 /usr/bin/echo -> connect 203.0.113.1:4444 — benign process + suspicious
    //                            connection. 9002 emitted, correlated rule NOT fired.
    //   3. pid=999 (no exec)  -> connect 93.184.216.34:443 — unknown pid + benign
    //                            connection. attributed=false, no correlation.
    let events = [
        exec_event(7, "/tmp/nc"),
        connect_event(7, "nc", "203.0.113.1", 4444),
        exec_event(8, "/usr/bin/echo"),
        connect_event(8, "echo", "203.0.113.1", 4444),
        connect_event(999, "orphan", "93.184.216.34", 443),
    ];
    // Only NetConnect events produce a 9002 record; ProcessExec/Exit produce none.
    let expected_records = events
        .iter()
        .filter(|e| e.kind == EventKind::NetConnect)
        .count();

    println!(
        "publishing {} synthetic events on the StubBus:",
        events.len()
    );
    for ev in &events {
        let kind = match ev.kind {
            EventKind::ProcessExec => "exec",
            EventKind::NetConnect => "connect",
            _ => "other",
        };
        match ev.kind {
            EventKind::NetConnect => println!(
                "  -> {kind} pid={} image={} daddr={} dport={} ts={}",
                ev.fields["pid"], ev.fields["image"], ev.fields["daddr"], ev.fields["dport"], ev.ts
            ),
            _ => println!(
                "  -> {kind} pid={} image={} ts={}",
                ev.fields["pid"], ev.fields["image"], ev.ts
            ),
        }
        bus.publish(ev.clone());
    }
    println!();

    // Let the module's background task drain the broadcast channel (bounded so a bug
    // can never hang the demo).
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(2)).await;
        if records.lock().unwrap().len() >= expected_records {
            break;
        }
    }

    corr.stop().await.expect("corr clean shutdown");

    // Print each emitted OCSF Correlated Activity (9002) record, labeling the
    // correlated attack chain vs the non-correlated contrasts.
    let emitted = records.lock().unwrap();
    println!(
        "corr emitted {} OCSF Correlated Activity record(s):",
        emitted.len()
    );
    let mut flagged = 0usize;
    for env in emitted.iter() {
        let pid = &env.data["process"]["pid"];
        let image = env.data["process"]["image"].as_str().unwrap_or("?");
        let attributed = env.data["process"]["attributed"].as_bool().unwrap_or(false);
        let daddr = env.data["connection"]["daddr"].as_str().unwrap_or("?");
        let dport = env.data["connection"]["dport"].as_u64().unwrap_or(0);
        let has_correlated_rule = env.data["detections"]
            .as_array()
            .map(|a| {
                a.iter()
                    .any(|d| d["rule"] == "suspicious_process_suspicious_connection")
            })
            .unwrap_or(false);
        let label = if has_correlated_rule {
            flagged += 1;
            "FLAGGED"
        } else {
            "no-corr"
        };
        let line = serde_json::to_string(env).expect("serialize OCSF envelope");
        println!(
            "  [{label}] pid={pid} image={image} {daddr}:{dport} attributed={attributed} \
             severity_id={} detections={}",
            env.severity_id,
            env.data["detections"]
                .as_array()
                .map(|a| a.len())
                .unwrap_or(0)
        );
        println!("            {line}");
    }
    println!();

    assert!(
        flagged >= 1,
        "corr must flag at least one correlated attack chain — the subscribe -> correlate -> emit \
         path is live"
    );
    println!(
        "OK: {flagged} correlated attack-chain detection(s) vs {} non-correlated record(s) — the \
         subscribe -> correlate -> emit path is live with NO backend and NO elevation. On the \
         default agent StubBus (no ProcessExec/NetConnect events published) this same module is a \
         silent no-op.",
        emitted.len() - flagged
    );
}
