//! P3e procmon StubBus detection + correlation demo — proves the module's
//! subscribe -> assess -> emit path end to end with NO backend, NO elevation, and
//! NO OS access. It stands up the SAME shared substrate stub the agent's collection
//! cycle uses, registers a REAL [`torda_mod_procmon::ProcMonModule`], publishes a few
//! synthetic `ProcessExec` / `ProcessExit` events, and prints the OCSF Process
//! Activity records the module emits — showing a benign exec (severity 1, no
//! detections) next to flagged execs (Medium / High + detections), AND (P3e-2) the
//! exec->exit CORRELATION: a benign short-lived pair that reports a `lifetime_ms`
//! with no lifecycle detection, next to a suspicious short-lived pair whose exit
//! carries both `lifetime_ms` AND the `short_lived_suspicious` detection.
//!
//! This is exactly the module the `torda` binary registers. On the default
//! StubBus the agent publishes no exec/exit events, so procmon is a silent no-op
//! there; this demo publishes synthetic events to make the detection + correlation
//! paths VISIBLE.
//!
//! Self-asserting: if procmon ever stops flagging a known-suspicious exec, or stops
//! correlating an exec->exit pair into a numeric lifetime, or stops flagging a
//! correlated short-lived-suspicious exit, the demo exits non-zero.

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
    exec_event_ts(pid, image, 0)
}

fn exec_event_ts(pid: u64, image: &str, ts: i64) -> SubstrateEvent {
    SubstrateEvent {
        kind: EventKind::ProcessExec,
        ts,
        fields: serde_json::json!({ "pid": pid, "image": image }),
    }
}

fn exit_event(pid: u64, image: &str, ts: i64) -> SubstrateEvent {
    SubstrateEvent {
        kind: EventKind::ProcessExit,
        ts,
        fields: serde_json::json!({ "pid": pid, "image": image }),
    }
}

#[tokio::main]
async fn main() {
    println!(
        "== procmon StubBus detection + correlation demo (P3e-2) — subscribe -> assess -> correlate -> emit, \
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
    let mut procmon = torda_mod_procmon::ProcMonModule::new();
    procmon.init(ctx).await.expect("procmon init");
    procmon
        .start()
        .await
        .expect("procmon start (subscribes before we publish)");

    // Synthetic exec/exit stream published in order on the (serially-drained)
    // StubBus, so each exit is guaranteed to see its matching exec already
    // recorded in the module's pending map:
    //   1001 /usr/bin/echo   — benign exec -> benign short-lived exit (lifetime
    //                          reported, no lifecycle detection).
    //   1002 powershell.exe  — suspicious exec ONLY (no matching exit), still
    //                          demonstrating the plain exec-detection path.
    //   1003 /tmp/nc         — suspicious (LOLBin in a suspicious path, High) exec
    //                          -> suspicious short-lived exit (lifetime reported
    //                          AND `short_lived_suspicious` fires, High).
    let events = [
        exec_event_ts(1001, "/usr/bin/echo", 0),
        exit_event(1001, "/usr/bin/echo", 4),
        exec_event(1002, "powershell.exe"),
        exec_event_ts(1003, "/tmp/nc", 0),
        exit_event(1003, "/tmp/nc", 4),
    ];
    println!(
        "publishing {} synthetic ProcessExec/ProcessExit events on the StubBus:",
        events.len()
    );
    for ev in &events {
        let kind = match ev.kind {
            EventKind::ProcessExec => "exec",
            EventKind::ProcessExit => "exit",
            _ => "other",
        };
        println!(
            "  -> {kind} pid={} image={} ts={}",
            ev.fields["pid"], ev.fields["image"], ev.ts
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

    procmon.stop().await.expect("procmon clean shutdown");

    // Print each emitted OCSF Process Activity record (exec AND exit), labeling
    // activity, lifetime_ms (exit only), and tallying flagged vs benign.
    let emitted = records.lock().unwrap();
    println!(
        "procmon emitted {} OCSF Process Activity record(s):",
        emitted.len()
    );
    let mut flagged = 0usize;
    // Did any correlated exit report a NUMERIC lifetime_ms (correlation worked)?
    let mut saw_numeric_lifetime = false;
    // Did any exit carry the `short_lived_suspicious` lifecycle detection?
    let mut saw_short_lived_suspicious_exit = false;
    for env in emitted.iter() {
        let activity = env.data["activity"].as_str().unwrap_or("?");
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
        let lifetime_str = if activity == "exit" {
            match env.data["lifetime_ms"].as_i64() {
                Some(ms) => format!(" lifetime_ms={ms}"),
                None => " lifetime_ms=null".to_string(),
            }
        } else {
            String::new()
        };
        let line = serde_json::to_string(env).expect("serialize OCSF envelope");
        println!(
            "  [{label}] activity={activity} pid={} severity_id={} detections={detections}{lifetime_str}",
            env.data["process"]["pid"], env.severity_id
        );
        println!("            {line}");

        if activity == "exit" {
            if env.data["lifetime_ms"].as_i64().is_some() {
                saw_numeric_lifetime = true;
            }
            let has_short_lived_suspicious = env.data["detections"]
                .as_array()
                .map(|a| a.iter().any(|d| d["rule"] == "short_lived_suspicious"))
                .unwrap_or(false);
            if has_short_lived_suspicious {
                saw_short_lived_suspicious_exit = true;
            }
        }
    }
    println!();

    assert!(
        flagged >= 1,
        "procmon must flag at least one suspicious exec — the subscribe -> assess -> emit path is live"
    );
    assert!(
        saw_numeric_lifetime,
        "procmon must correlate at least one exec->exit pair into a NUMERIC lifetime_ms \
         (the benign echo pair should have produced one)"
    );
    assert!(
        saw_short_lived_suspicious_exit,
        "procmon must flag at least one correlated short-lived-suspicious exit \
         (the /tmp/nc pair should have fired `short_lived_suspicious`)"
    );
    println!(
        "OK: {flagged} flagged detection(s) vs {} benign; a correlated exec->exit pair produced a \
         numeric lifetime_ms, and the suspicious short-lived /tmp/nc exit fired \
         `short_lived_suspicious` — the subscribe -> assess -> correlate -> emit path is live with \
         NO backend and NO elevation. On the default agent StubBus (no exec/exit events published) \
         this same module is a silent no-op.",
        emitted.len() - flagged
    );
}
