//! ETW network event-bus proof demo (behind the `windows-etw` feature) — the
//! network counterpart to `etw-demo.rs`.
//!
//! PURPOSE: prove the Windows ETW backend REALLY captures live outbound TCP
//! `connect` events on the Kernel-Network provider — not just that the
//! session opened, but that the record extraction works (the manifest
//! property NAMES match, so `daddr`/`dport` come out populated and byte-order
//! correct). That final proof requires ELEVATION and is the operator's to run
//! (Task 3).
//!
//! This binary is HONEST about which path it is on:
//!   * NON-elevated (or feature off / non-Windows): `Substrate::for_this_platform()`
//!     fell back to the stub bus (`bus_label == "stub"`). There are NO real OS
//!     events on the stub, so the demo prints a clear "run elevated" instruction
//!     and exits 0. It does NOT assert or fake a success.
//!   * ELEVATED with `--features windows-etw`: the real `EtwBus` started
//!     (`bus_label == "etw"`). The demo subscribes to `NetConnect` on the raw
//!     bus, then generates a DETERMINISTIC, self-contained outbound TCP
//!     connect (no internet/external dependency): bind a `TcpListener` on
//!     `127.0.0.1:0` and `TcpStream::connect` to it a few times. A connect to
//!     an already-listening socket completes via the kernel backlog WITHOUT a
//!     userspace `accept()`, so no accept thread is needed. It captures
//!     `NetConnect` events for a bounded window and self-asserts at least one
//!     event whose `daddr == "127.0.0.1"` AND `dport == <the loopback
//!     listener's port>` — proving a REAL connect with a populated, correct,
//!     byte-order-correct destination was captured. Zero such events => a
//!     loud non-zero failure (never hidden).
//!
//! Note: the Kernel-Network connect record exposes no image/process-name
//! field, so `image` is expected to be `""` on every captured event — that is
//! honest, not a bug (see `crates/substrate/src/etw.rs` `handle_net_record`).
//!
//! Every wait is bounded by a timeout so NEITHER path can hang. Dropping the
//! substrate tears the ETW session down (EtwBus `Drop` stops + joins).
//! DEMO-ONLY: no library was edited.

use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use torda_core::{EventKind, SubstrateEvent};

/// Total wall-clock window to collect events on the elevated path.
const CAPTURE_WINDOW: Duration = Duration::from_secs(3);
/// Per-`recv()` timeout so the collect loop can never block forever.
const RECV_TIMEOUT: Duration = Duration::from_millis(500);
/// Number of deterministic benign loopback connections to generate.
const NUM_LOOPBACK_CONNECTS: usize = 3;

#[tokio::main]
async fn main() {
    // 1) Build the shared substrate for THIS host and report the live bus.
    let sub = torda_substrate::Substrate::for_this_platform();
    println!("event bus: {}", sub.bus_label);

    // 2) Stub path (NON-elevated / feature off): be honest, instruct, exit 0.
    if sub.bus_label != "etw" {
        println!(
            "\nETW event bus not active (running on the '{}' bus).\n\
             To see REAL Windows network-connect events, run this in an ADMINISTRATOR terminal:\n\
             \x20   cargo run -p torda --features windows-etw --bin net-etw-demo\n\
             (Kernel-Network ETW requires elevation.)",
            sub.bus_label
        );
        // Nothing to assert: there are no real OS events on the stub bus.
        return;
    }

    // 3) ETW path (ELEVATED): capture real network-connect events and prove extraction.
    println!("ETW session live — capturing real NetConnect events for {CAPTURE_WINDOW:?}...");

    // Subscribe BEFORE generating connections so we don't miss any.
    let mut rx = sub.bus.subscribe(&[EventKind::NetConnect]);

    // Bind a listener on an OS-assigned loopback port — deterministic, no
    // external/internet dependency. Capture the port so we know exactly what
    // destination to look for in the captured events. A connect to an
    // already-listening socket completes via the kernel backlog WITHOUT a
    // userspace `accept()`, so no accept thread (and no unbounded join) is
    // needed at all here.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0 failed");
    let loopback_port = listener.local_addr().expect("local_addr failed").port();
    println!("listening on 127.0.0.1:{loopback_port}");

    for _ in 0..NUM_LOOPBACK_CONNECTS {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", loopback_port)) {
            drop(stream);
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    // Keep the listener bound for the whole capture window so nothing resets
    // in-flight connections; drop it once we're done collecting.

    // Collect for a bounded window. `recv()` is wrapped in a timeout so a quiet
    // bus can never hang the loop; the outer deadline caps total time.
    let mut net_events: Vec<SubstrateEvent> = Vec::new();
    let deadline = tokio::time::Instant::now() + CAPTURE_WINDOW;

    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(RECV_TIMEOUT, rx.recv()).await {
            Ok(Ok(ev)) => {
                if ev.kind == EventKind::NetConnect {
                    let pid = ev.fields.get("pid").cloned().unwrap_or_default();
                    let image = ev
                        .fields
                        .get("image")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let daddr = ev
                        .fields
                        .get("daddr")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let dport = ev.fields.get("dport").cloned().unwrap_or_default();
                    println!("pid={pid} image={image} daddr={daddr} dport={dport}");
                    net_events.push(ev);
                }
            }
            // Lagged (dropped some) — keep going; we only need a few.
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => continue,
            // Sender gone — the session ended; stop.
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => break,
            // No event within RECV_TIMEOUT — loop and re-check the deadline.
            Err(_elapsed) => continue,
        }
    }

    // Done collecting; release the loopback listener (bounded lifetime).
    drop(listener);

    // 4) Self-assert the CRITICAL thing: at least one NetConnect whose fields
    // carry OUR OWN listener's destination — daddr == "127.0.0.1" AND
    // dport == loopback_port. This proves a REAL connect was captured with a
    // populated, byte-order-correct destination (not merely that the session
    // opened). Deliberately NOT "≥1 event" — a byte-order bug must not pass.
    let proven = net_events.iter().any(|ev| {
        let daddr_ok = ev
            .fields
            .get("daddr")
            .and_then(|v| v.as_str())
            .map(|s| s == "127.0.0.1")
            .unwrap_or(false);
        let dport_ok = ev
            .fields
            .get("dport")
            .and_then(|v| v.as_u64())
            .map(|p| p == loopback_port as u64)
            .unwrap_or(false);
        daddr_ok && dport_ok
    });

    if net_events.is_empty() {
        eprintln!(
            "\nFAILURE: ETW session opened but ZERO NetConnect events were parsed.\n\
             Most likely a Kernel-Network event-id/property mismatch (see\n\
             crates/substrate/src/etw.rs handle_net_record: EVENT_ID_TCP_CONNECT_V4\n\
             and the try_parse(\"PID\"/\"daddr\"/\"dport\") field names)."
        );
        std::process::exit(1);
    }
    if !proven {
        eprintln!(
            "\nFAILURE: captured {} NetConnect event(s) but NONE matched\n\
             daddr==\"127.0.0.1\" AND dport=={loopback_port} (our own listener).\n\
             The event fired but the destination came out wrong — most likely a\n\
             byte-order bug in the daddr/dport extraction. Check\n\
             crates/substrate/src/etw.rs handle_net_record's try_parse(\"daddr\")/\n\
             try_parse(\"dport\") and the net_event byte-order conversion.",
            net_events.len()
        );
        std::process::exit(1);
    }

    // 5) Success summary.
    let matched = net_events
        .iter()
        .filter(|ev| {
            let daddr_ok = ev
                .fields
                .get("daddr")
                .and_then(|v| v.as_str())
                .map(|s| s == "127.0.0.1")
                .unwrap_or(false);
            let dport_ok = ev
                .fields
                .get("dport")
                .and_then(|v| v.as_u64())
                .map(|p| p == loopback_port as u64)
                .unwrap_or(false);
            daddr_ok && dport_ok
        })
        .count();
    println!(
        "\nOK: captured {} NetConnect event(s); {} to 127.0.0.1:{loopback_port} — real ETW\n\
         network-connect capture is live",
        net_events.len(),
        matched
    );

    // Drop the substrate -> EtwBus Drop stops the session + joins the consumer.
    drop(sub);
}
