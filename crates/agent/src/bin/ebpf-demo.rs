//! eBPF event-bus proof demo (behind the `linux-ebpf` feature) — the Linux
//! counterpart to `etw-demo.rs`.
//!
//! PURPOSE: prove the Linux eBPF backend REALLY captures live process events —
//! not just that a program loaded, but that the RingBuf extraction works (the
//! `ProcExecEvent` struct layout matches, so `pid`/`image` come out populated).
//! That final proof requires ROOT / `CAP_BPF` and is the operator's to run.
//!
//! This binary is HONEST about which path it is on:
//!   * NON-root (or feature off / non-Linux): `Substrate::for_this_platform()`
//!     fell back to the stub bus (`bus_label != "ebpf"`). There are NO real OS
//!     events on the stub, so the demo prints a clear "run as root" instruction
//!     and exits 0. It does NOT assert or fake a success.
//!   * ROOT with `--features linux-ebpf`: the real `EbpfBus` started
//!     (`bus_label == "ebpf"`). The demo spawns a few short-lived child processes
//!     to generate guaranteed events, captures them from the bus for a bounded
//!     window, and self-asserts BOTH: (a) at least one `ProcessExec` with a
//!     NON-EMPTY `pid` and `image`, AND (b) at least one `ProcessExit` — proving
//!     process-lifecycle parity (the P3d-3 "0 ProcessExit" gap is closed by the
//!     P3d Task 1 `sched_process_exit` tracepoint). Zero exec events, empty
//!     fields, OR zero exit events => a loud non-zero failure (so a silent
//!     RingBuf / struct-layout / tracepoint-attach mismatch is caught, never hidden).
//!
//! Every wait is bounded by a timeout so NEITHER path can hang. Dropping the
//! substrate tears the eBPF collection down (EbpfBus `Drop` stops + joins).
//! DEMO-ONLY: no library was edited.

use std::time::Duration;

use torda_core::{EventKind, SubstrateEvent};

/// Total wall-clock window to collect events on the root path.
const CAPTURE_WINDOW: Duration = Duration::from_secs(3);
/// Per-`recv()` timeout so the collect loop can never block forever.
const RECV_TIMEOUT: Duration = Duration::from_millis(500);

#[tokio::main]
async fn main() {
    // 1) Build the shared substrate for THIS host and report the live bus.
    let sub = torda_substrate::Substrate::for_this_platform();
    println!("event bus: {}", sub.bus_label);

    // 2) Stub path (NON-root / feature off / non-Linux): be honest, instruct, exit 0.
    if sub.bus_label != "ebpf" {
        println!(
            "\neBPF event bus not active (running on the '{}' bus).\n\
             To see REAL Linux process events, build then run as ROOT in WSL:\n\
             \x20   CARGO_TARGET_DIR=$HOME/torda-ebpf-target cargo build -p torda --features linux-ebpf --bin ebpf-demo\n\
             \x20   sudo $HOME/torda-ebpf-target/debug/ebpf-demo\n\
             (loading eBPF requires root/CAP_BPF.)",
            sub.bus_label
        );
        // Nothing to assert: there are no real OS events on the stub bus.
        return;
    }

    // 3) eBPF path (ROOT): capture real process events and prove extraction.
    println!("eBPF collection live — capturing real process events for {CAPTURE_WINDOW:?}...");

    // Subscribe BEFORE generating events so we don't miss any.
    let mut rx = sub
        .bus
        .subscribe(&[EventKind::ProcessExec, EventKind::ProcessExit]);

    // Generate guaranteed process activity: a few short-lived children. Each
    // exec + exit should surface on the process tracepoints.
    std::thread::spawn(|| {
        for _ in 0..3 {
            let _ = std::process::Command::new("/bin/echo")
                .arg("torda-ebpf-probe")
                .status();
            let _ = std::process::Command::new("/usr/bin/id").status();
            std::thread::sleep(Duration::from_millis(150));
        }
    });

    // Collect for a bounded window. `recv()` is wrapped in a timeout so a quiet
    // bus can never hang the loop; the outer deadline caps total time.
    let mut exec_events: Vec<SubstrateEvent> = Vec::new();
    let mut exit_count = 0usize;
    let deadline = tokio::time::Instant::now() + CAPTURE_WINDOW;

    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(RECV_TIMEOUT, rx.recv()).await {
            Ok(Ok(ev)) => match ev.kind {
                EventKind::ProcessExec => {
                    let pid = ev.fields.get("pid").cloned().unwrap_or_default();
                    let image = ev
                        .fields
                        .get("image")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    println!("pid={pid} image={image}");
                    exec_events.push(ev);
                }
                EventKind::ProcessExit => {
                    let pid = ev.fields.get("pid").cloned().unwrap_or_default();
                    let image = ev
                        .fields
                        .get("image")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    println!("ProcessExit pid={pid} image={image}");
                    exit_count += 1;
                }
                _ => {}
            },
            // Lagged (dropped some) — keep going; we only need a few.
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => continue,
            // Sender gone — collection ended; stop.
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => break,
            // No event within RECV_TIMEOUT — loop and re-check the deadline.
            Err(_elapsed) => continue,
        }
    }

    // 4) Self-assert the CRITICAL thing: at least one ProcessExec whose fields
    // carry a NON-EMPTY pid AND image. This proves the RingBuf `ProcExecEvent`
    // struct layout matches (extraction works), not merely that BPF loaded.
    let proven = exec_events.iter().any(|ev| {
        let pid_ok = ev
            .fields
            .get("pid")
            .and_then(|v| v.as_u64())
            .map(|p| p > 0)
            .unwrap_or(false);
        let image_ok = ev
            .fields
            .get("image")
            .and_then(|v| v.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        pid_ok && image_ok
    });

    if exec_events.is_empty() || !proven {
        eprintln!(
            "\nFAILURE: eBPF loaded but no events parsed — likely a RingBuf/struct-layout mismatch.\n\
             Captured {} ProcessExec event(s); none had BOTH a populated pid (>0) and a\n\
             non-empty image. Check the ProcExecEvent struct layout shared between the BPF\n\
             program and crates/substrate/src/ebpf.rs (RingBuf read path).",
            exec_events.len()
        );
        std::process::exit(1);
    }

    // Process-lifecycle PARITY: exec alone is not enough — the sched_process_exit
    // tracepoint (P3d Task 1) must also surface exits, or the P3d-3 "0 ProcessExit"
    // gap is still open. Require at least one ProcessExit too.
    if exit_count == 0 {
        eprintln!(
            "\nFAILURE: ProcessExec captured but NO ProcessExit — the sched_process_exit\n\
             tracepoint may not be attached/mapping. Captured {} ProcessExec event(s) but\n\
             0 ProcessExit. Process lifecycle is exec-only (the P3d-3 gap is NOT closed).\n\
             Check the sched_process_exit attach + RingBuf path in crates/substrate/src/ebpf.rs.",
            exec_events.len()
        );
        std::process::exit(1);
    }

    // 5) Success summary. A sample event shows the populated fields.
    let sample = &exec_events[0];
    let sample_pid = sample.fields.get("pid").cloned().unwrap_or_default();
    let sample_image = sample
        .fields
        .get("image")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    println!(
        "\nOK: captured {} ProcessExec + {} ProcessExit — process lifecycle (exec+exit) is\n\
         live from real eBPF. RingBuf extraction PROVEN (non-empty pid+image). sample: pid={} image={}",
        exec_events.len(),
        exit_count,
        sample_pid,
        sample_image
    );

    // Drop the substrate -> EbpfBus Drop stops collection + joins.
    drop(sub);
}
