//! ETW event-bus proof demo (behind the `windows-etw` feature).
//!
//! PURPOSE: prove the Windows ETW backend REALLY captures live process events —
//! not just that a session opened, but that the property extraction works (the
//! Kernel-Process manifest property NAMES match, so `pid`/`image` come out
//! populated). That final proof requires ELEVATION and is the operator's to run.
//!
//! This binary is HONEST about which path it is on:
//!   * NON-elevated (or feature off): `Substrate::for_this_platform()` fell back
//!     to the stub bus (`bus_label == "stub"`). There are NO real OS events on
//!     the stub, so the demo prints a clear "run elevated" instruction and exits
//!     0. It does NOT assert or fake a success.
//!   * ELEVATED with `--features windows-etw`: the real `EtwBus` started
//!     (`bus_label == "etw"`). The demo spawns a few child processes to generate
//!     guaranteed events, captures them from the bus for a bounded window, and
//!     self-asserts it saw at least one `ProcessExec` with a NON-EMPTY `pid` and
//!     `image`. Zero events or empty fields => a loud non-zero failure (so a
//!     silent property-name/id mismatch is caught, never hidden).
//!
//! Every wait is bounded by a timeout so NEITHER path can hang. Dropping the
//! substrate tears the ETW session down (EtwBus `Drop` stops + joins).
//! DEMO-ONLY: no library was edited.

use std::time::Duration;

use torda_core::{EventKind, SubstrateEvent};

/// Total wall-clock window to collect events on the elevated path.
const CAPTURE_WINDOW: Duration = Duration::from_secs(3);
/// Per-`recv()` timeout so the collect loop can never block forever.
const RECV_TIMEOUT: Duration = Duration::from_millis(500);

#[tokio::main]
async fn main() {
    // 1) Build the shared substrate for THIS host and report the live bus.
    let sub = torda_substrate::Substrate::for_this_platform();
    println!("event bus: {}", sub.bus_label);

    // 2) Stub path (NON-elevated / feature off): be honest, instruct, exit 0.
    if sub.bus_label == "stub" {
        println!(
            "\nETW event bus not active (running on the stub bus).\n\
             To see REAL Windows process events, run this in an ADMINISTRATOR terminal:\n\
             \x20   cargo run -p torda --features windows-etw --bin etw-demo\n\
             (kernel-process ETW requires elevation.)"
        );
        // Nothing to assert: there are no real OS events on the stub bus.
        return;
    }

    // 3) ETW path (ELEVATED): capture real process events and prove extraction.
    println!("ETW session live — capturing real process events for {CAPTURE_WINDOW:?}...");

    // Subscribe BEFORE generating events so we don't miss any.
    let mut rx = sub
        .bus
        .subscribe(&[EventKind::ProcessExec, EventKind::ProcessExit]);

    // Generate guaranteed process activity: a few short-lived children. Each
    // exec + exit should surface on the Kernel-Process provider.
    std::thread::spawn(|| {
        for _ in 0..3 {
            let _ = std::process::Command::new("cmd.exe")
                .args(["/c", "echo", "torda-etw-probe"])
                .status();
            let _ = std::process::Command::new("whoami.exe").status();
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
                    let cmdline = ev
                        .fields
                        .get("cmdline")
                        .and_then(|v| v.as_str())
                        .unwrap_or("<none>");
                    println!("ProcessExec pid={pid} image={image} cmdline={cmdline}");
                    exec_events.push(ev);
                }
                EventKind::ProcessExit => exit_count += 1,
                _ => {}
            },
            // Lagged (dropped some) — keep going; we only need a few.
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => continue,
            // Sender gone — the session ended; stop.
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => break,
            // No event within RECV_TIMEOUT — loop and re-check the deadline.
            Err(_elapsed) => continue,
        }
    }

    // 4) Self-assert the CRITICAL thing: at least one ProcessExec whose fields
    // carry a NON-EMPTY pid AND image. This proves the property NAMES match the
    // real manifest (extraction works), not merely that the session opened.
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

    if exec_events.is_empty() {
        eprintln!(
            "\nFAILURE: ETW session opened but ZERO ProcessExec events were parsed.\n\
             This is the silent-skip bug the reviewer flagged: the session is live but\n\
             no events came through — most likely a property-name / event-id mismatch\n\
             against the real Kernel-Process manifest (see crates/substrate/src/etw.rs\n\
             handle_record: EVENT_ID_PROCESS_START and the try_parse field names)."
        );
        std::process::exit(1);
    }
    if !proven {
        eprintln!(
            "\nFAILURE: captured {} ProcessExec event(s) but NONE had BOTH a populated\n\
             pid (>0) and a non-empty image. The event fired but property extraction\n\
             produced empty values — fix the property NAMES in etw.rs handle_record\n\
             (try_parse(\"ProcessID\") / try_parse(\"ImageName\")) to match the manifest.",
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
        "\nOK: captured {} ProcessExec + {} ProcessExit event(s) from real ETW.\n\
         Property extraction PROVEN (non-empty pid+image). Sample: pid={} image={}",
        exec_events.len(),
        exit_count,
        sample_pid,
        sample_image
    );

    // Drop the substrate -> EtwBus Drop stops the session + joins the consumer.
    drop(sub);
}
