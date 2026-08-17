//! P3e-2 LIVE eBPF CORRELATION proof (behind the `linux-ebpf` feature) — proves
//! the REAL exec<->exit CORRELATION over the real Linux eBPF EventBus.
//!
//! PURPOSE: `procmon-ebpf-demo.rs` (P3e-1) only calls `assess()` on captured
//! `ProcessExec` events directly — it never runs the module and never handles
//! `ProcessExit`, so it cannot prove correlation. This binary goes one step
//! further: it runs the REAL `torda_mod_procmon::ProcMonModule` (the exact module
//! the agent registers) against the real eBPF bus. The module subscribes to
//! BOTH `ProcessExec` and `ProcessExit`, correlates them by pid, computes a
//! `lifetime_ms` for each correlated exit, and — for a suspicious image that
//! was also short-lived — emits an exit record carrying the
//! `short_lived_suspicious` lifecycle detection. We self-assert both: a
//! numeric `lifetime_ms` on some exit (correlation worked) AND a
//! `short_lived_suspicious` hit on some exit (the lifecycle rule fired on
//! real events).
//!
//! HONEST about which path it is on (mirrors `procmon-ebpf-demo.rs`):
//!   * NON-root (or feature off / non-Linux): `Substrate::for_this_platform()`
//!     fell back to the stub bus (`bus_label != "ebpf"`). There are no real OS
//!     events to correlate, so the demo prints a clear "run as root" message
//!     and exits 0. It does NOT assert or fake a correlation/detection. THIS
//!     is the path a non-root (e.g. default Windows) run verifies.
//!   * ROOT with `--features linux-ebpf`: the real `EbpfBus` started
//!     (`bus_label == "ebpf"`). The demo wires a REAL `ProcMonModule` onto the
//!     real substrate + a capturing emitter, subscribes it to the bus BEFORE
//!     generating events, plants a benign `/bin/echo` copied to the LOLBin
//!     name `/tmp/nc`, spawns it plus a benign `/bin/echo` a few times, waits
//!     (bounded) for the capturing emitter to accumulate exec+exit records,
//!     stops the module, and self-asserts real correlation + real detection.
//!
//! NOTE on the eBPF `image` field: the backend reports the Linux task **comm**
//! (`bpf_get_current_comm`, up to 16 bytes short-name), NOT the full path. So
//! the planted `/tmp/nc` surfaces with `image == "nc"` -> `assess("nc")` fires
//! the `lolbin` rule (Medium, suspicious) -> a SHORT-LIVED `nc` exit carries
//! the `short_lived_suspicious` detection. `/bin/echo` surfaces as `"echo"`
//! (benign) -> its exit carries a numeric `lifetime_ms` but NO lifecycle
//! detection. Both processes exec and exit within milliseconds, so both exec
//! AND exit fire for each spawn.
//!
//! Every wait is bounded by a timeout so NEITHER path can hang. Dropping the
//! substrate tears eBPF collection down (EbpfBus `Drop` stops + joins).
//! DEMO-ONLY: no library was edited — it uses the public `ProcMonModule` +
//! `ModuleCtx` + `Substrate`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use torda_core::{
    Module, ModuleCtx, OcsfEmitter, ResourceBudget, ResourceGovernor, ResourceSampler,
    ResourceUsage,
};
use torda_ocsf::OcsfEnvelope;

/// Total wall-clock window to wait for the capturing emitter to accumulate
/// records on the root path.
const CAPTURE_WINDOW: Duration = Duration::from_secs(3);
/// Poll interval while waiting for the capturing emitter to fill up.
const POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Benign `/bin/echo` copied to a LOLBin name. Its task comm becomes `nc`, so
/// eBPF reports `image == "nc"` and `assess` flags `lolbin` (Medium,
/// suspicious) — a short-lived `nc` will trip `short_lived_suspicious`.
const PLANTED: &str = "/tmp/nc";
/// How many times to spawn each of the planted + benign binaries.
const SPAWN_ROUNDS: usize = 6;

/// Captures every OCSF envelope the module emits so the demo can inspect them
/// and self-assert (the production binary's `StdoutEmitter` writes NDJSON
/// instead).
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

#[tokio::main]
async fn main() {
    // 1) Build the shared substrate for THIS host and report the live bus.
    let sub = torda_substrate::Substrate::for_this_platform();
    println!("event bus: {}", sub.bus_label);

    // 2) Stub path (NON-root / feature off / non-Linux): be honest, instruct, exit 0.
    if sub.bus_label != "ebpf" {
        println!(
            "\neBPF event bus not active (running on the '{}' bus) — no real events to correlate.\n\
             To see REAL Linux exec<->exit CORRELATION + short-lived detection, build then run\n\
             as ROOT in WSL:\n\
             \x20   CARGO_TARGET_DIR=$HOME/torda-ebpf-target cargo run -p torda --features linux-ebpf \\\n\
             \x20       --bin procmon-lifecycle-ebpf-demo\n\
             \x20   (or: wsl -u root)\n\
             (loading eBPF requires root/CAP_BPF.)",
            sub.bus_label
        );
        // Nothing to assert: there are no real OS events on the stub bus.
        return;
    }

    // 3) eBPF path (ROOT): run the REAL ProcMonModule against the real bus and
    // prove real exec<->exit correlation + short-lived detection.
    println!(
        "eBPF collection live — wiring the real ProcMonModule onto the real bus, planting a \
         LOLBin-named binary, and capturing real exec<->exit CORRELATION for up to \
         {CAPTURE_WINDOW:?}..."
    );

    let records: Arc<Mutex<Vec<OcsfEnvelope>>> = Arc::new(Mutex::new(Vec::new()));
    let emitter: Arc<dyn OcsfEmitter> = Arc::new(CapturingEmitter {
        records: records.clone(),
    });
    let governor = Arc::new(ResourceGovernor::new(
        ResourceBudget::from_env(),
        Box::new(ZeroSampler),
    ));

    let ctx = ModuleCtx {
        bus: sub.bus.clone(),
        snapshot: sub.snapshot.clone(),
        emitter,
        governor,
        tenant_id: "tenant-demo".to_string(),
        product: "torda".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };

    // The SAME real module the agent registers. Subscribe BEFORE generating
    // events so we don't miss any exec/exit pairs.
    let mut procmon = torda_mod_procmon::ProcMonModule::new();
    procmon.init(ctx).await.expect("procmon init");
    procmon
        .start()
        .await
        .expect("procmon start (subscribes before we publish)");

    // Plant a benign /bin/echo under a LOLBin name (`nc`). Its task comm
    // becomes "nc", which `assess` flags as a lolbin (Medium, suspicious).
    match std::fs::copy("/bin/echo", PLANTED) {
        Ok(_) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(PLANTED, std::fs::Permissions::from_mode(0o755));
            }
            println!("planted {PLANTED} (a benign /bin/echo copy; comm will read as 'nc')");
        }
        Err(e) => eprintln!("warning: could not plant {PLANTED}: {e} (assert may not be met)"),
    }

    // Generate guaranteed process activity: interleave the planted LOLBin-named
    // exec with a benign /bin/echo so both fire exec AND exit within ms.
    std::thread::spawn(|| {
        for _ in 0..SPAWN_ROUNDS {
            let _ = std::process::Command::new(PLANTED)
                .arg("torda-probe")
                .status();
            let _ = std::process::Command::new("/bin/echo")
                .arg("hello")
                .status();
            std::thread::sleep(Duration::from_millis(120));
        }
    });

    // Collect for a bounded window: poll the capturing emitter's Vec length
    // rather than a raw rx, since the module itself is draining the bus.
    // Expect up to 2 * SPAWN_ROUNDS execs + 2 * SPAWN_ROUNDS exits.
    let expected = 4 * SPAWN_ROUNDS;
    let deadline = tokio::time::Instant::now() + CAPTURE_WINDOW;
    while tokio::time::Instant::now() < deadline {
        if records.lock().unwrap().len() >= expected {
            break;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    procmon.stop().await.expect("procmon clean shutdown");

    // Clean up the planted binary (best-effort) BEFORE asserting.
    let _ = std::fs::remove_file(PLANTED);

    // 4) Inspect the captured OCSF envelopes: separate exec from exit.
    let emitted = records.lock().unwrap().clone();
    let mut exec_count = 0usize;
    let mut exit_count = 0usize;
    let mut correlated = 0usize; // exits with a numeric lifetime_ms
    let mut flagged_exits = 0usize; // exits carrying short_lived_suspicious

    for env in emitted.iter() {
        let activity = env.data["activity"].as_str().unwrap_or("?");
        match activity {
            "exec" => {
                exec_count += 1;
            }
            "exit" => {
                exit_count += 1;
                let pid = env.data["process"]["pid"].as_u64().unwrap_or(0);
                let image = env.data["process"]["image"].as_str().unwrap_or("?");
                let lifetime = env
                    .data
                    .get("lifetime_ms")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                let is_numeric_lifetime = lifetime.is_number();
                if is_numeric_lifetime {
                    correlated += 1;
                }
                let rules: Vec<&str> = env.data["detections"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|d| d["rule"].as_str()).collect())
                    .unwrap_or_default();
                let has_short_lived_suspicious = rules.contains(&"short_lived_suspicious");
                if has_short_lived_suspicious {
                    flagged_exits += 1;
                }
                println!(
                    "pid={pid} image={image} lifetime_ms={} detections={:?}",
                    if is_numeric_lifetime {
                        lifetime.to_string()
                    } else {
                        "null".to_string()
                    },
                    rules
                );
            }
            _ => {}
        }
    }

    // 5) Self-assert the CRITICAL things: real correlation AND real
    // short-lived-suspicious detection over the real bus. Either missing =>
    // loud non-zero failure, so a broken correlation/detection path is caught,
    // never hidden.
    if correlated == 0 {
        eprintln!(
            "\nFAILURE: no correlated exit found.\n\
             Captured {exec_count} exec + {exit_count} exit record(s), but NONE of the exits carried \
             a numeric `lifetime_ms`. Expected the benign /bin/echo (and/or planted {PLANTED}) \
             exec->exit pair to correlate by pid and report a computed lifetime. Check that both \
             ProcessExec and ProcessExit fired for the spawned children within the capture window."
        );
        std::process::exit(1);
    }
    if flagged_exits == 0 {
        eprintln!(
            "\nFAILURE: no short_lived_suspicious detection captured.\n\
             Captured {exec_count} exec + {exit_count} exit record(s), {correlated} correlated \
             (numeric lifetime_ms), but NONE carried the `short_lived_suspicious` lifecycle \
             detection. Expected the planted '{PLANTED}' (comm 'nc', suspicious via `lolbin`) to be \
             short-lived and have its correlated exit flagged. Check that the planted binary was \
             captured within the window and that ProcMonModule's lifecycle rule ran on its exit."
        );
        std::process::exit(1);
    }

    // 6) Success summary.
    println!(
        "\nOK: captured {exec_count} exec + {exit_count} exit; {correlated} correlated (lifetime_ms \
         numeric); {flagged_exits} short_lived_suspicious flagged — real eBPF exec<->exit \
         correlation + short-lived detection is live"
    );

    // Drop the substrate -> EbpfBus Drop stops collection + joins.
    drop(sub);
}
