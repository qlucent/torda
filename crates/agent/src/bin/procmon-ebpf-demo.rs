//! LIVE eBPF DETECTION proof (behind the `linux-ebpf` feature) — combines the
//! REAL Linux eBPF EventBus with procmon's detection ruleset.
//!
//! PURPOSE: `ebpf-demo.rs` proves the eBPF backend captures real process events;
//! this binary goes one step further and proves those REAL events are DETECTED —
//! each captured `sched_process_exec` is routed through `torda_mod_procmon::assess`
//! (the same pure ruleset the agent's ProcMonModule uses), so we prove
//! real Linux exec -> OCSF-style Process Activity WITH detections, end to end.
//!
//! HONEST about which path it is on (mirrors `ebpf-demo.rs`):
//!   * NON-root (or feature off / non-Linux): `Substrate::for_this_platform()`
//!     fell back to the stub bus (`bus_label != "ebpf"`). There are NO real OS
//!     events to detect on, so the demo prints a clear "run as root" instruction
//!     and exits 0. It does NOT assert or fake a detection. THIS is the path a
//!     non-root run verifies.
//!   * ROOT with `--features linux-ebpf`: the real `EbpfBus` started
//!     (`bus_label == "ebpf"`). The demo plants a benign `/bin/echo` copied to the
//!     LOLBin name `/tmp/nc`, spawns it (plus a benign `/bin/echo`) a few times,
//!     captures the resulting `ProcessExec` events for a bounded window, runs each
//!     through `assess`, and self-asserts that at least one captured exec was
//!     FLAGGED (severity > 1). Zero flagged detections => a loud non-zero failure.
//!
//! NOTE on the eBPF `image` field: the backend reports the Linux task **comm**
//! (`bpf_get_current_comm`, up to 16 bytes short-name), NOT the full path. So the
//! planted `/tmp/nc` surfaces with `image == "nc"`, and `assess("nc")` fires the
//! `lolbin` rule (Medium) — a flagged detection (severity > 1). The path-based
//! `suspicious_path` / correlated HIGH rules need a full path and generally will
//! NOT fire on a bare comm; the lolbin comm match is what the assert relies on.
//!
//! Every wait is bounded by a timeout so NEITHER path can hang. Dropping the
//! substrate tears eBPF collection down (EbpfBus `Drop` stops + joins).
//! DEMO-ONLY: no library was edited — it uses the public `assess`.

use std::time::Duration;

use torda_core::{EventKind, SubstrateEvent};
use torda_mod_procmon::assess;

/// Total wall-clock window to collect events on the root path.
const CAPTURE_WINDOW: Duration = Duration::from_secs(3);
/// Per-`recv()` timeout so the collect loop can never block forever.
const RECV_TIMEOUT: Duration = Duration::from_millis(500);
/// Benign `/bin/echo` copied to a LOLBin name in a suspicious dir. Its task comm
/// becomes `nc`, so eBPF reports `image == "nc"` and `assess` flags `lolbin`.
const PLANTED: &str = "/tmp/nc";

#[tokio::main]
async fn main() {
    // 1) Build the shared substrate for THIS host and report the live bus.
    let sub = torda_substrate::Substrate::for_this_platform();
    println!("event bus: {}", sub.bus_label);

    // 2) Stub path (NON-root / feature off / non-Linux): be honest, instruct, exit 0.
    if sub.bus_label != "ebpf" {
        println!(
            "\neBPF event bus not active (running on the '{}' bus) — no real events to detect on.\n\
             To see REAL Linux process DETECTIONS, build then run as ROOT in WSL:\n\
             \x20   CARGO_TARGET_DIR=$HOME/torda-ebpf-target cargo build -p torda --features linux-ebpf --bin procmon-ebpf-demo\n\
             \x20   sudo -E env \"PATH=$PATH\" $HOME/torda-ebpf-target/debug/procmon-ebpf-demo   (or: wsl -u root)\n\
             (loading eBPF requires root/CAP_BPF.)",
            sub.bus_label
        );
        // Nothing to assert: there are no real OS events on the stub bus.
        return;
    }

    // 3) eBPF path (ROOT): capture real execs and DETECT on them.
    println!(
        "eBPF collection live — planting a LOLBin-named binary and capturing real \
         process DETECTIONS for {CAPTURE_WINDOW:?}..."
    );

    // Subscribe BEFORE generating events so we don't miss any.
    let mut rx = sub.bus.subscribe(&[EventKind::ProcessExec]);

    // Plant a benign /bin/echo under a LOLBin name (`nc`) in a suspicious dir.
    // Its task comm becomes "nc", which `assess` flags as a lolbin. Best-effort
    // executable bit (copy from /bin/echo already carries +x on most systems).
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
    // exec with a benign /bin/echo so we see both a FLAGGED and a benign result.
    std::thread::spawn(|| {
        for _ in 0..4 {
            let _ = std::process::Command::new(PLANTED)
                .arg("torda-probe")
                .status();
            let _ = std::process::Command::new("/bin/echo")
                .arg("hello")
                .status();
            std::thread::sleep(Duration::from_millis(120));
        }
    });

    // Collect for a bounded window. `recv()` is wrapped in a timeout so a quiet
    // bus can never hang the loop; the outer deadline caps total time.
    let mut captured: Vec<SubstrateEvent> = Vec::new();
    let mut flagged: Vec<(u64, String, u8, Vec<&'static str>)> = Vec::new();
    let deadline = tokio::time::Instant::now() + CAPTURE_WINDOW;

    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(RECV_TIMEOUT, rx.recv()).await {
            Ok(Ok(ev)) => {
                if ev.kind != EventKind::ProcessExec {
                    continue;
                }
                let pid = ev.fields.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
                let image = ev
                    .fields
                    .get("image")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                // Route the REAL captured exec through procmon's detection ruleset.
                let a = assess(&image);
                let rules: Vec<&'static str> = a.hits.iter().map(|h| h.rule).collect();
                println!(
                    "pid={pid} image={image} severity={} detections={:?}",
                    a.severity_id, rules
                );

                if a.severity_id > 1 {
                    flagged.push((pid, image, a.severity_id, rules));
                }
                captured.push(ev);
            }
            // Lagged (dropped some) — keep going; we only need a few.
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => continue,
            // Sender gone — collection ended; stop.
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => break,
            // No event within RECV_TIMEOUT — loop and re-check the deadline.
            Err(_elapsed) => continue,
        }
    }

    // Clean up the planted binary (best-effort) before asserting/exiting.
    let _ = std::fs::remove_file(PLANTED);

    // 4) Self-assert the CRITICAL thing: at least one REAL captured ProcessExec
    // was FLAGGED (severity > 1) by the detection ruleset. No flagged detection
    // (e.g. the planted exec was not captured, or assess did not flag it) => loud
    // non-zero failure, so a broken capture/detection path is caught, never hidden.
    if flagged.is_empty() {
        eprintln!(
            "\nFAILURE: no flagged detection captured.\n\
             Captured {} real ProcessExec event(s), but NONE were flagged (severity > 1) by\n\
             procmon's ruleset. Expected the planted '{PLANTED}' (comm 'nc') to fire the lolbin\n\
             rule. Check that the eBPF RingBuf extraction populated `image` and that the planted\n\
             exec was captured within the window.",
            captured.len()
        );
        std::process::exit(1);
    }

    // 5) Success summary. A sample flagged event shows the detection.
    let (pid, image, sev, rules) = &flagged[0];
    println!(
        "\nOK: captured {} ProcessExec, {} flagged; sample flagged: pid={} image={} severity={} rules={:?}",
        captured.len(),
        flagged.len(),
        pid,
        image,
        sev,
        rules
    );

    // Drop the substrate -> EbpfBus Drop stops collection + joins.
    drop(sub);
}
