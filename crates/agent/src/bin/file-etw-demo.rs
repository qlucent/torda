//! ETW file event-bus proof demo (behind the `windows-etw` feature) — the
//! file counterpart to `net-etw-demo.rs`.
//!
//! PURPOSE: prove the Windows ETW backend REALLY captures live file
//! create/open events on the `Microsoft-Windows-Kernel-File` provider AND
//! correctly decodes the Create event's `CreateOptions` disposition into
//! `FileWrite` (create/overwrite) vs `FileOpen` (open-existing) — i.e. that
//! `crates/substrate/src/etw.rs`'s `is_write_create`/`handle_file_record`
//! decode is wired correctly end-to-end, not just that the session opened.
//! The proof is self-contained: this binary creates/opens its OWN unique
//! probe files under the OS temp dir, so there is no dependency on any other
//! host/process being active.
//!
//! This binary is HONEST about which path it is on:
//!   * NON-elevated (or feature off / non-Windows): `Substrate::for_this_platform()`
//!     fell back to the stub bus (`bus_label != "etw"`). There are NO real OS
//!     events on the stub, so the demo prints a clear "run elevated" instruction
//!     and exits 0. It does NOT assert or fake a success.
//!   * ELEVATED with `--features windows-etw`: the real `EtwBus` started
//!     (`bus_label == "etw"`). The demo subscribes to BOTH `FileOpen` and
//!     `FileWrite` on the raw bus, then generates TWO DETERMINISTIC,
//!     self-contained probes. A WRITE probe is a unique file under the OS
//!     temp dir, written (`std::fs::write` — a create/overwrite disposition)
//!     a few times — expected to surface as `FileWrite`. A READ probe is a
//!     *different* unique file, first seed-created with a single
//!     `std::fs::write` (itself a create disposition — a separate
//!     `FileWrite` this demo does not assert on), then opened read-only
//!     (`std::fs::File::open`, which opens an EXISTING file — a plain
//!     `FILE_OPEN` disposition) a few times — expected to surface as
//!     `FileOpen`. It captures events for a bounded window and self-asserts
//!     BOTH at least one `FileWrite` event whose `path` ends with the
//!     write-probe file's name, AND at least one `FileOpen` event whose
//!     `path` ends with the read-probe file's name. Each assert is a
//!     distinct, loud non-zero failure (never hidden) that points at the
//!     specific decode path to check (`is_write_create`/`handle_file_record`
//!     in `crates/substrate/src/etw.rs`). Event 12 (Kernel-File Create) is
//!     HIGH VOLUME (every file open on the box), so a bare "saw >=1
//!     FileOpen/FileWrite" would pass trivially even with a broken
//!     disposition decode or path-extraction path — the asserts deliberately
//!     require a match against the SPECIFIC probe file AND the SPECIFIC
//!     expected kind.
//!
//! Note: the Kernel-File create record exposes no initiating-process image
//! field, so `image` is expected to be `""` on every captured event — that is
//! honest, not a bug (see `crates/substrate/src/etw.rs` `handle_file_record`).
//! Also, ETW file paths are frequently reported in the NT device form
//! (`\Device\HarddiskVolumeN\Users\...\<name>`) rather than a drive-letter DOS
//! path, so the asserts match on the trailing file name (case-insensitive),
//! not the full path.
//!
//! This run is also what confirms the disposition-packing assumption itself:
//! if `CreateDisposition` were not actually packed in the high byte of
//! `CreateOptions` (or the byte were misread), a create and a read-open could
//! not correctly split into `FileWrite` vs `FileOpen` — the dual-probe
//! bifurcation IS the proof, not merely a demonstration of it.
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
/// Number of deterministic creates/opens to each probe file (each is a create+open).
const NUM_PROBE_OPENS: usize = 3;

#[tokio::main]
async fn main() {
    // 1) Build the shared substrate for THIS host and report the live bus.
    let sub = torda_substrate::Substrate::for_this_platform();
    println!("event bus: {}", sub.bus_label);

    // 2) Stub path (NON-elevated / feature off): be honest, instruct, exit 0.
    if sub.bus_label != "etw" {
        println!(
            "\nETW event bus not active (running on the '{}' bus).\n\
             To see REAL Windows file create/open events, run this in an ADMINISTRATOR terminal:\n\
             \x20   cargo run -p torda --features windows-etw --bin file-etw-demo\n\
             (Kernel-File ETW requires elevation.)",
            sub.bus_label
        );
        // Nothing to assert: there are no real OS events on the stub bus.
        return;
    }

    // 3) ETW path (ELEVATED): capture real file create/open events and prove
    // both the capture and the disposition decode (FileWrite vs FileOpen).
    println!(
        "ETW session live — capturing real FileOpen+FileWrite events for {CAPTURE_WINDOW:?}..."
    );

    // Subscribe BEFORE generating any activity so we don't miss any.
    let mut rx = sub
        .bus
        .subscribe(&[EventKind::FileOpen, EventKind::FileWrite]);

    // Two UNIQUE, deterministic probe files under the OS temp dir — no
    // external dependency. Include the pid so concurrent/repeat runs never
    // collide with each other.
    let pid = std::process::id();
    let write_probe = std::env::temp_dir().join(format!("torda-file-etw-wprobe-{pid}.tmp"));
    let read_probe = std::env::temp_dir().join(format!("torda-file-etw-rprobe-{pid}.tmp"));
    let write_probe_name = write_probe
        .file_name()
        .and_then(|n| n.to_str())
        .expect("write probe path has a file name")
        .to_lowercase();
    let read_probe_name = read_probe
        .file_name()
        .and_then(|n| n.to_str())
        .expect("read probe path has a file name")
        .to_lowercase();
    println!("write probe file: {}", write_probe.display());
    println!("read probe file: {}", read_probe.display());

    // Create/overwrite the write probe — a create/overwrite disposition —
    // expected to surface as `FileWrite`.
    for _ in 0..NUM_PROBE_OPENS {
        let _ = std::fs::write(&write_probe, b"torda-file-etw-wprobe");
        std::thread::sleep(Duration::from_millis(150));
    }

    // Seed-create the read probe so it exists (this seed create is itself a
    // create disposition — a separate FileWrite this demo does not assert on).
    let _ = std::fs::write(&read_probe, b"seed");
    std::thread::sleep(Duration::from_millis(150));

    // Open the EXISTING read probe read-only — a plain FILE_OPEN disposition —
    // expected to surface as `FileOpen`.
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
            // Sender gone — the session ended; stop.
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
    // `path` ENDS WITH our read-probe's NAME (both case-insensitive, since
    // ETW paths are often the NT device form). Deliberately NOT "≥1 event" —
    // event 12 is high-volume and any-event would pass trivially, hiding
    // either a path-extraction bug or a disposition decode bug. Crucially,
    // the read-probe assert requires the FileOpen KIND specifically — the
    // read-probe's seed create emits a FileWrite for that same path, so a
    // path-only match would be vacuous.
    let write_matched: Vec<&SubstrateEvent> = file_events
        .iter()
        .filter(|ev| {
            ev.kind == EventKind::FileWrite
                && ev
                    .fields
                    .get("path")
                    .and_then(|v| v.as_str())
                    .map(|p| p.to_lowercase().ends_with(&write_probe_name))
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
                    .map(|p| p.to_lowercase().ends_with(&read_probe_name))
                    .unwrap_or(false)
        })
        .collect();

    if file_events.is_empty() {
        eprintln!(
            "\nFAILURE: ETW session opened but ZERO FileOpen/FileWrite events were parsed.\n\
             Most likely a Kernel-File event-id/property mismatch (see\n\
             crates/substrate/src/etw.rs handle_file_record: EVENT_ID_FILE_CREATE\n\
             and the try_parse(\"FileName\") field name)."
        );
        std::process::exit(1);
    }
    if write_matched.is_empty() {
        eprintln!(
            "\nFAILURE: captured {} file event(s) but NONE was a FileWrite with a path ending\n\
             with \"{write_probe_name}\" (our write-probe file). The create/overwrite disposition\n\
             did not decode as a write — most likely the CreateDisposition-in-high-byte-of-\n\
             CreateOptions packing does not hold on real records; check is_write_create in\n\
             crates/substrate/src/etw.rs. (If the write-probe instead showed up as FileOpen,\n\
             the disposition byte isn't landing in the write set at all.)",
            file_events.len()
        );
        std::process::exit(1);
    }
    if read_matched.is_empty() {
        eprintln!(
            "\nFAILURE: captured {} file event(s) but NONE was a FileOpen with a path ending\n\
             with \"{read_probe_name}\" (our read-probe file). The read-only open did not decode\n\
             as a read — if the read-probe only appeared as FileWrite, the high byte is likely\n\
             always resolving to a write disposition (e.g. always 0 = FILE_SUPERSEDE), meaning\n\
             the packing assumption is effectively absent; check is_write_create in\n\
             crates/substrate/src/etw.rs.",
            file_events.len()
        );
        std::process::exit(1);
    }

    // 5) Success summary. Sample matched events show the populated path.
    let write_sample = write_matched[0];
    let read_sample = read_matched[0];
    println!(
        "\nOK: captured {} file event(s); {} FileWrite matched write-probe \"{}\", {} FileOpen\n\
         matched read-probe \"{}\" — real ETW file create/open disposition decode is live.\n\
         FileWrite sample: pid={} path={}\n\
         FileOpen sample:  pid={} path={}",
        file_events.len(),
        write_matched.len(),
        write_probe_name,
        read_matched.len(),
        read_probe_name,
        write_sample.fields.get("pid").cloned().unwrap_or_default(),
        write_sample
            .fields
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
        read_sample.fields.get("pid").cloned().unwrap_or_default(),
        read_sample
            .fields
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
    );

    // Drop the substrate -> EtwBus Drop stops the session + joins the consumer.
    drop(sub);
}
