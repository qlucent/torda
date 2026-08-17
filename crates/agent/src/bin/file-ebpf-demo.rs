//! eBPF file-open/write-intent proof demo (behind the `linux-ebpf` feature) —
//! the file counterpart to `net-demo.rs`, and the eBPF analogue of
//! `file-etw-demo.rs`.
//!
//! PURPOSE: prove the Linux eBPF backend REALLY captures live `openat(2)`
//! events on the `syscalls/sys_enter_openat` tracepoint AND correctly decodes
//! the open `flags` into write-intent vs read-only — i.e. that
//! `crates/substrate/src/ebpf.rs`'s `is_write_open`/`map_file_record` flag
//! decode is wired correctly end-to-end, not just that the probe attached.
//! The proof is self-contained: this binary writes/reads its OWN unique probe
//! files under the OS temp dir, so there is no dependency on any other
//! host/process being active.
//!
//! This binary is HONEST about which path it is on:
//!   * NON-root (or feature off / non-Linux): `Substrate::for_this_platform()`
//!     fell back to the stub bus (`bus_label != "ebpf"`). There are NO real OS
//!     events on the stub, so the demo prints a clear "run as root in WSL"
//!     instruction and exits 0. It does NOT assert or fake a success. This is
//!     the path the controller runs on the Windows host to verify.
//!   * ROOT with `--features linux-ebpf`: the real `EbpfBus` started
//!     (`bus_label == "ebpf"`). The demo subscribes to BOTH `FileOpen` and
//!     `FileWrite` on the raw bus, then generates TWO DETERMINISTIC,
//!     self-contained probes. A WRITE probe is a unique file under the OS
//!     temp dir, written (open+write+close, a real write-intent
//!     `openat(2)`) a few times — expected to surface as `FileWrite`. A READ
//!     probe is a *different* unique file, first seed-created with a single
//!     `std::fs::write` (itself a write-intent open — a separate `FileWrite`
//!     this demo does not assert on), then opened read-only
//!     (`std::fs::File::open`) a few times — expected to surface as
//!     `FileOpen`. It captures events for a bounded window and self-asserts
//!     BOTH at least one `FileWrite` event whose `path` ends with the
//!     write-probe file's name, AND at least one `FileOpen` event whose
//!     `path` ends with the read-probe file's name. Each assert is a
//!     distinct, loud non-zero failure (never hidden) that points at the
//!     specific decode path to check (`is_write_open`/`map_file_record` in
//!     `crates/substrate/src/ebpf.rs`). `openat` is HIGH VOLUME (every file
//!     open on the box), so a bare "saw >=1 FileOpen/FileWrite" would pass
//!     trivially even with a broken flag decode or path-extraction path —
//!     the asserts deliberately require a match against the SPECIFIC probe
//!     file AND the SPECIFIC expected kind.
//!
//! Note: unlike the ETW Kernel-File record (which carries no initiating-
//! process image field), the eBPF `openat` tracepoint DOES carry the calling
//! task's `comm`, so `image` is expected to be POPULATED (e.g. "file-ebpf-dem"
//! — comm is truncated to 16 bytes in-kernel) on every captured event here.
//! Linux paths from `openat` are the real absolute/relative path as passed by
//! the caller, so a plain file-name suffix match is sufficient (no NT device
//! path normalization concern like ETW).
//!
//! Every wait is bounded by a timeout so NEITHER path can hang. No thread is
//! spawned and no unbounded `.join()`/`recv()` is used. Dropping the substrate
//! tears the eBPF collection down (EbpfBus `Drop` stops + joins).
//! DEMO-ONLY: no library was edited.

use std::time::Duration;

use torda_core::{EventKind, SubstrateEvent};

/// Total wall-clock window to collect events on the root path.
const CAPTURE_WINDOW: Duration = Duration::from_secs(3);
/// Per-`recv()` timeout so the collect loop can never block forever.
const RECV_TIMEOUT: Duration = Duration::from_millis(500);
/// Number of deterministic writes/reads to each probe file (each is a real `openat`).
const NUM_PROBE_OPENS: usize = 3;

#[tokio::main]
async fn main() {
    // 1) Build the shared substrate for THIS host and report the live bus.
    let sub = torda_substrate::Substrate::for_this_platform();
    println!("event bus: {}", sub.bus_label);

    // 2) Stub path (NON-root / feature off / non-Linux): be honest, instruct, exit 0.
    if sub.bus_label != "ebpf" {
        println!(
            "\neBPF event bus not active (running on the '{}' bus).\n\
             To see REAL Linux file-open/write events, build+run as ROOT in WSL:\n\
             \x20   CARGO_TARGET_DIR=$HOME/torda-ebpf-target cargo run -p torda --features linux-ebpf --bin file-ebpf-demo\n\
             (loading eBPF requires root/CAP_BPF; use e.g. `wsl -u root`.)",
            sub.bus_label
        );
        // Nothing to assert: there are no real OS events on the stub bus.
        return;
    }

    // 3) eBPF path (ROOT): capture real file-open/write events and prove both
    // the capture and the write-intent flag decode.
    println!(
        "eBPF collection live — capturing real FileOpen+FileWrite events for {CAPTURE_WINDOW:?}..."
    );

    // Subscribe BEFORE generating any activity so we don't miss any.
    let mut rx = sub
        .bus
        .subscribe(&[EventKind::FileOpen, EventKind::FileWrite]);

    // Two UNIQUE, deterministic probe files under the OS temp dir — no
    // external dependency. Include the pid so concurrent/repeat runs never
    // collide with each other.
    let pid = std::process::id();
    let write_probe = std::env::temp_dir().join(format!("torda-file-ebpf-wprobe-{pid}.tmp"));
    let read_probe = std::env::temp_dir().join(format!("torda-file-ebpf-rprobe-{pid}.tmp"));
    let write_probe_name = write_probe
        .file_name()
        .and_then(|n| n.to_str())
        .expect("write probe path has a file name")
        .to_string();
    let read_probe_name = read_probe
        .file_name()
        .and_then(|n| n.to_str())
        .expect("read probe path has a file name")
        .to_string();
    println!("write probe file: {}", write_probe.display());
    println!("read probe file: {}", read_probe.display());

    // Write-intent opens on the write probe — expected to surface as `FileWrite`.
    for _ in 0..NUM_PROBE_OPENS {
        let _ = std::fs::write(&write_probe, b"torda-file-ebpf-wprobe");
        std::thread::sleep(Duration::from_millis(150));
    }

    // Seed-create the read probe so it exists (this seed write is itself a
    // write-intent open — a separate FileWrite this demo does not assert on).
    let _ = std::fs::write(&read_probe, b"seed");
    std::thread::sleep(Duration::from_millis(150));

    // Read-only opens on the read probe — expected to surface as `FileOpen`.
    for _ in 0..NUM_PROBE_OPENS {
        let _ = std::fs::File::open(&read_probe);
        std::thread::sleep(Duration::from_millis(150));
    }

    // Collect for a bounded window. `recv()` is wrapped in a timeout so a quiet
    // bus can never hang the loop; the outer deadline caps total time.
    let mut file_events: Vec<SubstrateEvent> = Vec::new();
    let deadline = tokio::time::Instant::now() + CAPTURE_WINDOW;

    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(RECV_TIMEOUT, rx.recv()).await {
            Ok(Ok(ev)) => {
                if ev.kind == EventKind::FileOpen || ev.kind == EventKind::FileWrite {
                    let ev_pid = ev.fields.get("pid").cloned().unwrap_or_default();
                    let image = ev
                        .fields
                        .get("image")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let path = ev.fields.get("path").and_then(|v| v.as_str()).unwrap_or("");
                    let op = ev.fields.get("op").and_then(|v| v.as_str()).unwrap_or("");
                    println!(
                        "kind={:?} pid={ev_pid} image={image} path={path} op={op}",
                        ev.kind
                    );
                    file_events.push(ev);
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

    // Best-effort cleanup of BOTH probe files; do this before the asserts so a
    // failed assert still leaves no litter behind.
    let _ = std::fs::remove_file(&write_probe);
    let _ = std::fs::remove_file(&read_probe);

    // 4) Self-assert the CRITICAL things: at least one FileWrite whose `path`
    // ENDS WITH our write-probe's NAME, AND at least one FileOpen whose
    // `path` ENDS WITH our read-probe's NAME. Deliberately NOT "≥1 event" —
    // sys_enter_openat is high-volume and any-event would pass trivially,
    // hiding either a path-extraction bug or a write-intent flag decode bug.
    let write_matched: Vec<&SubstrateEvent> = file_events
        .iter()
        .filter(|ev| {
            ev.kind == EventKind::FileWrite
                && ev
                    .fields
                    .get("path")
                    .and_then(|v| v.as_str())
                    .map(|p| p.ends_with(&write_probe_name))
                    .unwrap_or(false)
        })
        .collect();
    let read_matched: Vec<&SubstrateEvent> = file_events
        .iter()
        .filter(|ev| {
            ev.kind == EventKind::FileOpen
                && ev
                    .fields
                    .get("path")
                    .and_then(|v| v.as_str())
                    .map(|p| p.ends_with(&read_probe_name))
                    .unwrap_or(false)
        })
        .collect();

    if file_events.is_empty() {
        eprintln!(
            "\nFAILURE: eBPF ring buffer active but ZERO FileOpen/FileWrite events were parsed.\n\
             Most likely a record layout/offset mismatch (see\n\
             crates/substrate/src/ebpf.rs map_file_record and the\n\
             sys_enter_openat tracepoint attach)."
        );
        std::process::exit(1);
    }
    if write_matched.is_empty() {
        eprintln!(
            "\nFAILURE: captured {} file event(s) but NONE was a FileWrite with a path ending\n\
             with \"{write_probe_name}\" (our write-intent probe file). The write-open either\n\
             wasn't captured, or came out with the wrong kind — check\n\
             crates/substrate/src/ebpf.rs's is_write_open flag decode and map_file_record's\n\
             path decoding.",
            file_events.len()
        );
        std::process::exit(1);
    }
    if read_matched.is_empty() {
        eprintln!(
            "\nFAILURE: captured {} file event(s) but NONE was a FileOpen with a path ending\n\
             with \"{read_probe_name}\" (our read-only probe file). The read-only open either\n\
             wasn't captured, or came out with the wrong kind (e.g. mis-decoded as FileWrite) —\n\
             check crates/substrate/src/ebpf.rs's is_write_open flag decode and\n\
             map_file_record's path decoding.",
            file_events.len()
        );
        std::process::exit(1);
    }

    // 5) Success summary. Sample matched events show the populated path + image.
    let write_sample = write_matched[0];
    let read_sample = read_matched[0];
    println!(
        "\nOK: captured {} file event(s); {} FileWrite matched write-probe \"{}\", {} FileOpen\n\
         matched read-probe \"{}\" — real eBPF file-open/write-intent capture is live.\n\
         FileWrite sample: pid={} image={} path={}\n\
         FileOpen sample:  pid={} image={} path={}",
        file_events.len(),
        write_matched.len(),
        write_probe_name,
        read_matched.len(),
        read_probe_name,
        write_sample.fields.get("pid").cloned().unwrap_or_default(),
        write_sample
            .fields
            .get("image")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
        write_sample
            .fields
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
        read_sample.fields.get("pid").cloned().unwrap_or_default(),
        read_sample
            .fields
            .get("image")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
        read_sample
            .fields
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
    );

    // Drop the substrate -> EbpfBus Drop stops collection + joins.
    drop(sub);
}
