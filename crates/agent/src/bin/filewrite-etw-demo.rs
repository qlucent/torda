//! ETW BYTE-LEVEL file-write proof demo (behind the `windows-etw` feature) —
//! the P3d-11 counterpart to `file-etw-demo.rs`.
//!
//! WHY THIS DEMO EXISTS (the distinction it proves): the ETW backend can emit
//! a `FileWrite` `SubstrateEvent` from TWO different Kernel-File records:
//!   1. **write-INTENT** — from the **Create** event (id 12) when the
//!      disposition is create/overwrite. This `FileWrite` has NO `bytes` field
//!      (omitted, not null) because the Create record carries no byte count.
//!      That is the P3d-10 signal, proven by `file-etw-demo.rs`.
//!   2. **byte-level write** — from the **Write** event (id 16), which carries
//!      an `IOSize` byte count but NO filename. The substrate recovers the
//!      path via a bounded `FileObject -> path` correlation cache
//!      (`FileNameCache` in `crates/substrate/src/etw.rs`), populated when the
//!      Create (id 12) for that same `FileObject` was observed. This
//!      `FileWrite` carries `"bytes": N` with `N > 0`. THIS is the new P3d-11
//!      signal this demo proves.
//!
//! A demo that merely asserts "saw >=1 FileWrite whose path matches" would
//! pass VACUOUSLY off the write-intent Create record alone, without ever
//! exercising the Write-event-16 parse or the FileObject->path correlation
//! cache. So the self-assert here deliberately ALSO requires
//! `fields.get("bytes")` to be present and `> 0` — that is what can only be
//! satisfied by a real Kernel-File Write (id 16) whose `FileObject` correctly
//! round-tripped through the correlation cache back to the path cached at
//! Create time.
//!
//! This binary is HONEST about which path it is on:
//!   * NON-elevated (or feature off / non-Windows): `Substrate::for_this_platform()`
//!     fell back to the stub bus (`bus_label != "etw"`). There are NO real OS
//!     events on the stub, so the demo prints a clear "run elevated"
//!     instruction and exits 0. It does NOT assert or fake a success.
//!   * ELEVATED with `--features windows-etw`: the real `EtwBus` started
//!     (`bus_label == "etw"`). The demo subscribes to `FileWrite` BEFORE
//!     generating any activity, then writes a UNIQUE probe file under the OS
//!     temp dir with a large, known payload (`0x41` repeated 8192 bytes, a
//!     few times) so the Write event's `IOSize` is unambiguously > 0. Writing
//!     the file first opens it (Create id 12 -> cached `FileObject -> path`)
//!     then issues WriteFile calls (Write id 16 -> resolved path + IOSize).
//!     It captures events for a bounded window and self-asserts at least one
//!     `FileWrite` whose `path` ends with the probe file's name (matched on
//!     the trailing file name, case-insensitively, since ETW frequently
//!     reports NT-device-form paths like `\Device\HarddiskVolumeN\...`) AND
//!     whose `bytes` field is present and `> 0`.
//!
//! This elevated run is also what confirms the FileObject->path correlation
//! cache resolves REAL records end-to-end: if the Write event's `FileObject`
//! didn't correlate against the Create event's cached path (wrong field name,
//! wrong pointer width, cache eviction bug, etc.), the write would either be
//! silently dropped (no cached path -> no emit, per `handle_file_write`'s
//! "DROPPED (no pathless write)" policy) or show up with the WRONG path — in
//! neither case would the probe-suffix + bytes>0 assert below pass.
//!
//! Every wait is bounded by a timeout so NEITHER path can hang. Dropping the
//! substrate tears the ETW session down (EtwBus `Drop` stops + joins).
//! DEMO-ONLY: no library was edited.

use std::io::Write as _;
use std::time::Duration;

use torda_core::{EventKind, SubstrateEvent};

/// Total wall-clock window to collect events on the elevated path.
const CAPTURE_WINDOW: Duration = Duration::from_secs(3);
/// Per-`recv()` timeout so the collect loop can never block forever.
const RECV_TIMEOUT: Duration = Duration::from_millis(500);
/// Number of repeated WriteFile calls to the probe file (each -> a Write
/// event id 16). A few repeats make capture more robust against any single
/// dropped/lagged event.
const NUM_PROBE_WRITES: usize = 4;
/// Bytes written per WriteFile call — sizeable and known so IOSize is
/// unambiguously > 0.
const PROBE_PAYLOAD: [u8; 8192] = [0x41u8; 8192];

#[tokio::main]
async fn main() {
    // 1) Build the shared substrate for THIS host and report the live bus.
    let sub = torda_substrate::Substrate::for_this_platform();
    println!("event bus: {}", sub.bus_label);

    // 2) Stub path (NON-elevated / feature off): be honest, instruct, exit 0.
    if sub.bus_label != "etw" {
        println!(
            "\nETW event bus not active (running on the '{}' bus).\n\
             To see REAL Windows byte-level file-write events, run this in an ADMINISTRATOR terminal:\n\
             \x20   cargo run -p torda --features windows-etw --bin filewrite-etw-demo\n\
             (Kernel-File ETW requires elevation.)",
            sub.bus_label
        );
        // Nothing to assert: there are no real OS events on the stub bus.
        return;
    }

    // 3) ETW path (ELEVATED): capture a real byte-level FileWrite and prove
    // both the Write-event-16 parse and the FileObject->path correlation cache.
    println!(
        "ETW session live — capturing real byte-level FileWrite events for {CAPTURE_WINDOW:?}..."
    );

    // Subscribe BEFORE generating any activity so we don't miss any.
    let mut rx = sub.bus.subscribe(&[EventKind::FileWrite]);

    // A UNIQUE probe file under the OS temp dir — pid-suffixed so concurrent
    // or repeat runs never collide.
    let pid = std::process::id();
    let probe = std::env::temp_dir().join(format!("torda-filewrite-etw-probe-{pid}.tmp"));
    let probe_name = probe
        .file_name()
        .and_then(|n| n.to_str())
        .expect("probe path has a file name")
        .to_lowercase();
    println!("probe file: {}", probe.display());

    // Open (Create id 12 -> cached FileObject->path), then repeatedly
    // WriteFile a sizeable, known payload (Write id 16 -> IOSize > 0).
    match std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&probe)
    {
        Ok(mut f) => {
            for _ in 0..NUM_PROBE_WRITES {
                if let Err(e) = f.write_all(&PROBE_PAYLOAD) {
                    eprintln!("warning: probe write_all failed: {e}");
                }
                let _ = f.flush();
                std::thread::sleep(Duration::from_millis(150));
            }
            drop(f);
        }
        Err(e) => {
            eprintln!(
                "FAILURE: could not open probe file {}: {e}",
                probe.display()
            );
            std::process::exit(1);
        }
    }

    // Collect for a bounded window. `recv()` is wrapped in a timeout so a quiet
    // bus can never hang the loop; the outer deadline caps total time.
    let mut write_events: Vec<SubstrateEvent> = Vec::new();
    let deadline = tokio::time::Instant::now() + CAPTURE_WINDOW;

    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(RECV_TIMEOUT, rx.recv()).await {
            Ok(Ok(ev)) => {
                if ev.kind == EventKind::FileWrite {
                    let ev_pid = ev.fields.get("pid").cloned().unwrap_or_default();
                    let path = ev.fields.get("path").and_then(|v| v.as_str()).unwrap_or("");
                    let op = ev.fields.get("op").and_then(|v| v.as_str()).unwrap_or("");
                    let bytes = ev.fields.get("bytes").and_then(|v| v.as_u64());
                    println!("pid={ev_pid} path={path} op={op} bytes={bytes:?}");
                    write_events.push(ev);
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

    // Best-effort cleanup of the probe file; do this before the asserts so a
    // failed assert still leaves no litter behind.
    let _ = std::fs::remove_file(&probe);

    // 4) Self-assert the CRITICAL thing: at least one FileWrite whose `path`
    // ENDS WITH our probe's NAME AND whose `bytes` field is present and > 0.
    // Deliberately NOT "any FileWrite matching the path" — a write-intent
    // FileWrite (from the Create event's disposition decode alone, no `bytes`
    // key at all) would satisfy a path-only match vacuously, without ever
    // exercising the Write-event-16 parse or the FileObject->path
    // correlation cache that this demo exists to prove.
    let byte_level_matched: Vec<&SubstrateEvent> = write_events
        .iter()
        .filter(|ev| {
            let path_matches = ev
                .fields
                .get("path")
                .and_then(|v| v.as_str())
                .map(|p| p.to_lowercase().ends_with(&probe_name))
                .unwrap_or(false);
            let bytes_positive = ev
                .fields
                .get("bytes")
                .and_then(|v| v.as_u64())
                .map(|n| n > 0)
                .unwrap_or(false);
            path_matches && bytes_positive
        })
        .collect();

    if write_events.is_empty() {
        eprintln!(
            "\nFAILURE: ETW session opened but ZERO FileWrite events were parsed.\n\
             Most likely a Kernel-File event-id/property mismatch (see\n\
             crates/substrate/src/etw.rs handle_file_record: EVENT_ID_FILE_WRITE\n\
             and the try_parse(\"FileObject\")/try_parse(\"IOSize\") field names)."
        );
        std::process::exit(1);
    }
    if byte_level_matched.is_empty() {
        eprintln!(
            "\nFAILURE: captured {} FileWrite event(s) matching path suffix \"{probe_name}\"\n\
             but NONE had a `bytes` field > 0. This means we saw only write-INTENT FileWrite(s)\n\
             (from the Create event's disposition decode) but never a byte-level Write (id 16)\n\
             whose FileObject correctly resolved via the FileNameCache correlation. Check\n\
             handle_file_write / FileNameCache / EVENT_ID_FILE_WRITE in\n\
             crates/substrate/src/etw.rs — either the Write event 16 isn't being parsed, IOSize\n\
             isn't decoding, or the FileObject->path correlation cache isn't resolving the path\n\
             (in which case handle_file_write's \"DROPPED (no pathless write)\" policy would\n\
             silently drop the write entirely instead of matching here).",
            write_events.len()
        );
        std::process::exit(1);
    }

    // 5) Success summary. Sample matched event shows the resolved path + bytes.
    let sample = byte_level_matched[0];
    println!(
        "\nOK: captured {} FileWrite event(s); {} byte-level (bytes>0) matched probe \"{}\" —\n\
         real ETW Kernel-File Write (id 16) + FileObject->path correlation cache is live.\n\
         sample: pid={} path={} bytes={}",
        write_events.len(),
        byte_level_matched.len(),
        probe_name,
        sample.fields.get("pid").cloned().unwrap_or_default(),
        sample
            .fields
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
        sample
            .fields
            .get("bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
    );

    // Drop the substrate -> EtwBus Drop stops the session + joins the consumer.
    drop(sub);
}
