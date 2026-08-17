//! eBPF network-connect proof demo (behind the `linux-ebpf` feature) — the
//! network counterpart to `ebpf-demo.rs`.
//!
//! PURPOSE: prove the Linux eBPF backend REALLY captures live `connect(2)`
//! events — not just that the probe attached, but that the `NetEvent` RingBuf
//! extraction works (the `daddr`/`dport` fields come out populated and
//! correct). The proof is self-contained: this binary binds its OWN
//! `127.0.0.1:0` listener and connects to it a few times, so there is no
//! dependency on the internet or on any other host being reachable.
//!
//! This binary is HONEST about which path it is on:
//!   * NON-root (or feature off / non-Linux): `Substrate::for_this_platform()`
//!     fell back to the stub bus (`bus_label != "ebpf"`). There are NO real OS
//!     events on the stub, so the demo prints a clear "run as root" instruction
//!     and exits 0. It does NOT assert or fake a success.
//!   * ROOT with `--features linux-ebpf`: the real `EbpfBus` started
//!     (`bus_label == "ebpf"`). The demo binds a local `TcpListener` on an
//!     OS-assigned port, spawns an `accept()` loop, then connects to it a few
//!     times — each a real `connect(2)` the eBPF probe observes. It captures
//!     `NetConnect` events for a bounded window and self-asserts at least one
//!     event whose `daddr == "127.0.0.1"` AND `dport == target_port` — proving
//!     a REAL connect with a populated, correct destination was captured.
//!     Zero such events => a loud non-zero failure (never hidden).
//!
//! Every wait is bounded by a timeout so NEITHER path can hang. Dropping the
//! substrate tears the eBPF collection down (EbpfBus `Drop` stops + joins).
//! DEMO-ONLY: no library was edited.

use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use torda_core::{EventKind, SubstrateEvent};

/// Total wall-clock window to collect events on the root path.
const CAPTURE_WINDOW: Duration = Duration::from_secs(3);
/// Per-`recv()` timeout so the collect loop can never block forever.
const RECV_TIMEOUT: Duration = Duration::from_millis(500);
/// Number of deterministic local connections to generate.
const NUM_CONNECTS: usize = 5;

#[tokio::main]
async fn main() {
    // 1) Build the shared substrate for THIS host and report the live bus.
    let sub = torda_substrate::Substrate::for_this_platform();
    println!("event bus: {}", sub.bus_label);

    // 2) Stub path (NON-root / feature off / non-Linux): be honest, instruct, exit 0.
    if sub.bus_label != "ebpf" {
        println!(
            "\neBPF event bus not active (running on the '{}' bus).\n\
             To see REAL Linux network-connect events, build then run as ROOT in WSL:\n\
             \x20   CARGO_TARGET_DIR=$HOME/torda-ebpf-target cargo build -p torda --features linux-ebpf --bin net-demo\n\
             \x20   sudo $HOME/torda-ebpf-target/debug/net-demo\n\
             (loading eBPF requires root/CAP_BPF.)\n\
             Alternatively, from a non-root WSL shell:\n\
             \x20   CARGO_TARGET_DIR=$HOME/torda-ebpf-target cargo run -p torda --features linux-ebpf --bin net-demo\n\
             \x20   wsl -u root",
            sub.bus_label
        );
        // Nothing to assert: there are no real OS events on the stub bus.
        return;
    }

    // 3) eBPF path (ROOT): capture real network-connect events and prove extraction.
    println!("eBPF collection live — capturing real NetConnect events for {CAPTURE_WINDOW:?}...");

    // Subscribe BEFORE generating connections so we don't miss any.
    let mut rx = sub.bus.subscribe(&[EventKind::NetConnect]);

    // Bind a listener on an OS-assigned loopback port — deterministic, no
    // external/internet dependency. Capture the port so we know exactly what
    // destination to look for in the captured events.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0 failed");
    let target_port = listener.local_addr().expect("local_addr failed").port();
    println!("listening on 127.0.0.1:{target_port}");

    // Accept in a loop for the duration of the demo so every connect()
    // completes cleanly (no reset connections). This thread is deliberately
    // NOT joined (see below): after the NUM_CONNECTS deterministic
    // connections are consumed, `listener.incoming()` blocks forever in
    // `accept()` (nothing else connects, nothing closes the listener), so
    // there is no bounded point at which this thread finishes on its own.
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(s) => {
                    // Keep the accepted stream alive briefly, then drop it.
                    drop(s);
                }
                Err(_) => break,
            }
        }
    });

    // Generate guaranteed connect() activity: a few real connections to our
    // own listener, each observable by the eBPF connect(2) probe.
    std::thread::spawn(move || {
        for _ in 0..NUM_CONNECTS {
            if let Ok(stream) = TcpStream::connect(("127.0.0.1", target_port)) {
                drop(stream);
            }
            std::thread::sleep(Duration::from_millis(150));
        }
    });

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
            // Sender gone — collection ended; stop.
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => break,
            // No event within RECV_TIMEOUT — loop and re-check the deadline.
            Err(_elapsed) => continue,
        }
    }

    // Deliberately do NOT join the accept thread: it is parked in a blocking
    // `accept()` call with no further connections coming and nothing that
    // closes the listener, so joining it would hang forever. Rust does not
    // wait on un-joined threads at process exit — main simply returns and the
    // OS reclaims the still-blocked accept thread, so this can never hang.

    // 4) Self-assert the CRITICAL thing: at least one NetConnect whose fields
    // carry OUR OWN listener's destination — daddr == "127.0.0.1" AND
    // dport == target_port. This proves a REAL connect(2) was captured with a
    // populated, correct destination (not merely that BPF loaded).
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
            .map(|p| p == target_port as u64)
            .unwrap_or(false);
        daddr_ok && dport_ok
    });

    if net_events.is_empty() || !proven {
        eprintln!(
            "\nFAILURE: eBPF loaded but no matching NetConnect event was captured.\n\
             Expected at least one connect(2) to 127.0.0.1:{target_port} (our own\n\
             listener). Captured {} NetConnect event(s) total; none matched\n\
             daddr==\"127.0.0.1\" AND dport=={target_port}.\n\
             Check that the connect probe attached and that the AF_INET sockaddr\n\
             (daddr/dport) is being read correctly in crates/substrate/src/ebpf.rs.",
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
                .map(|p| p == target_port as u64)
                .unwrap_or(false);
            daddr_ok && dport_ok
        })
        .count();
    println!(
        "\nOK: captured {} NetConnect event(s); {} to 127.0.0.1:{target_port} — real eBPF\n\
         network-connect capture is live",
        net_events.len(),
        matched
    );

    // Drop the substrate -> EbpfBus Drop stops collection + joins.
    drop(sub);
}
