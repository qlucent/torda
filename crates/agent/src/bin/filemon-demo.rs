//! P3i-1 Task 3 LIVE file-detection proof (behind the `windows-etw` /
//! `linux-ebpf` features) — proves the REAL `torda_mod_filemon::FileMonModule`
//! detects real file writes on the real substrate, on BOTH backends.
//!
//! PURPOSE: Task 1 (`c2b6c89`) built the pure `FilePolicy`/`assess` ruleset;
//! Task 2 (`65c4674`) built `FileMonModule` (subscribes `FileOpen`/`FileWrite`
//! on the bus -> filter first -> assess -> emit OCSF File System Activity
//! (1001)). Neither proved the module detects a REAL file write flowing
//! through a REAL substrate backend. This binary wires the exact module the
//! agent registers onto the real bus (mirrors
//! `crates/agent/src/bin/netmon-ebpf-demo.rs`'s pattern of running a real
//! module + a capturing emitter against the real substrate, not just reading
//! the raw bus).
//!
//! # Why the probes live under the OS temp dir but contain rule substrings
//! `FileMonModule`'s ruleset only flags a PATH match against a rule substring
//! (e.g. `\windows\system32\`, `/etc/`) — it does no content inspection. This
//! demo must never actually write into a real system directory (that would be
//! unsafe and likely require privileges of its own, defeating the "no
//! root/admin needed to build this demo" scope). The fix: plant probe files
//! inside a per-run temp directory whose PATH TEXT happens to contain the
//! watched rule substring (e.g. `<temp>/torda-filemon-probe-<pid>/etc/passwd`).
//! The module only ever inspects the path string — it never resolves it
//! against the filesystem — so a path that merely *contains* `/etc/` triggers
//! the exact same `write_to_sensitive_config` rule a real `/etc/passwd` write
//! would, with zero risk to the host.
//!
//! # Why a CUSTOM policy is required (not `FilePolicy::default()`)
//! The shipped default policy's `ignore` list includes temp-dir substrings
//! (`\appdata\local\temp\`, `/tmp/`, `\temp\`) specifically to suppress temp
//! noise (see `torda_mod_filemon`'s module doc). Since every probe here
//! necessarily lives under `std::env::temp_dir()`, the default policy would
//! silently DROP both probes before `assess` ever runs. This demo instead
//! builds a `FilePolicy::new(watch, ignore)` whose `ignore` list contains ONLY
//! the `torda-ignored` marker (no temp-dir entries), so the probes survive the
//! prefilter and reach the real ruleset.
//!
//! # The three probes
//! - **Watched probe** (OS-specific — path separators differ between
//!   backends): proves a real planted sensitive/system write is detected at
//!   HIGH severity with the expected rule.
//!     - Windows (ETW): `<probe_root>\Windows\System32\evil.sys` — contains
//!       `\windows\system32\` -> rule `write_to_system_dir`.
//!     - Linux (eBPF): `<probe_root>/etc/passwd` — contains `/etc/` -> rule
//!       `write_to_sensitive_config`.
//! - **Ignored probe**: the SAME rule-matching tail placed under a
//!   `torda-ignored` directory (so it WOULD be watched on path alone), proving
//!   `ignore` beats `watch` through the REAL module end-to-end (not just in a
//!   unit test). A write here must produce ZERO envelopes.
//!
//! # Honest about which path this is on (mirrors `netmon-ebpf-demo.rs`)
//!   * Stub bus (`bus_label` neither `"ebpf"` nor `"etw"` — no privileges, or
//!     the elevated feature is off): there is no real OS file activity to
//!     detect on, so the demo prints instructions for BOTH elevated paths and
//!     exits 0. It does NOT assert or fake a detection. THIS is the path a
//!     default (non-elevated) build/run verifies.
//!   * ROOT in WSL with `--features linux-ebpf`, or ADMINISTRATOR on Windows
//!     with `--features windows-etw`: the real event bus started. The demo
//!     wires a REAL `FileMonModule::with_policy(custom_policy)` onto the real
//!     substrate + a capturing emitter, `init()`s and `start()`s it BEFORE any
//!     probe write, generates the writes, waits a bounded capture window, then
//!     self-asserts both properties above. Each assert is a distinct, loud
//!     `eprintln!` + non-zero exit on failure — never hidden.
//!
//! Every wait is bounded (deadline-polled capture window; no unbounded
//! join/recv). The probe root is removed (`remove_dir_all`, best-effort)
//! before the asserts run, so a failed assert still leaves no litter.
//! Dropping the substrate tears the live backend down (Drop stops + joins).
//!
//! DEMO-ONLY: no library was edited. Only the public `FileMonModule` +
//! `FilePolicy` + `ModuleCtx` + `Substrate` API is used.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use torda_core::{
    Module, ModuleCtx, OcsfEmitter, ResourceBudget, ResourceGovernor, ResourceSampler,
    ResourceUsage,
};
use torda_mod_filemon::{FileMonModule, FilePolicy, SEV_HIGH};
use torda_ocsf::OcsfEnvelope;

/// Total wall-clock window to wait for the capturing emitter to accumulate
/// records on the elevated path.
const CAPTURE_WINDOW: Duration = Duration::from_secs(3);
/// Poll interval while waiting for the capturing emitter to fill up.
const POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Number of deterministic writes to each probe file.
const NUM_PROBE_WRITES: usize = 3;
/// Marker directory name proving `ignore` beats `watch` through the real module.
const IGNORED_MARKER: &str = "torda-ignored";

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

    // 2) Stub path (no privileges / feature off): be honest, instruct, exit 0.
    if sub.bus_label != "ebpf" && sub.bus_label != "etw" {
        println!(
            "\nNo live event bus active (running on the '{}' bus) — no real file events to \
             detect on.\n\
             To see REAL file-write DETECTION (the real FileMonModule flagging a planted \
             sensitive write), build then run one of:\n\
             \x20   Linux/eBPF as ROOT in WSL:\n\
             \x20       CARGO_TARGET_DIR=$HOME/torda-ebpf-target cargo run -p torda \\\n\
             \x20           --features linux-ebpf --bin filemon-demo\n\
             \x20   Windows/ETW as ADMINISTRATOR:\n\
             \x20       cargo run -p torda --features windows-etw --bin filemon-demo",
            sub.bus_label
        );
        // Nothing to assert: there are no real OS events on the stub bus.
        return;
    }

    // 3) Live path (ROOT/ADMINISTRATOR): run the REAL FileMonModule against
    // the real bus and prove real file-write detection.
    println!(
        "live event bus ({}) — wiring the real FileMonModule onto the real bus and capturing \
         real file-write detections for up to {CAPTURE_WINDOW:?}...",
        sub.bus_label
    );

    // OS-appropriate probe paths + policy entries: path separators differ
    // (ETW yields NT-device backslash paths, eBPF yields POSIX paths).
    let probe_root =
        std::env::temp_dir().join(format!("torda-filemon-probe-{}", std::process::id()));
    let (watch_entry, watched_rel, expected_rule): (&str, &str, &str) = if cfg!(windows) {
        (
            "\\windows\\system32\\",
            "Windows\\System32\\evil.sys",
            "write_to_system_dir",
        )
    } else {
        ("/etc/", "etc/passwd", "write_to_sensitive_config")
    };
    let watched_probe = probe_root.join(watched_rel);
    let ignored_probe = probe_root.join(IGNORED_MARKER).join(watched_rel);

    println!("watched probe: {}", watched_probe.display());
    println!("ignored probe: {}", ignored_probe.display());

    // Create parent dirs for both probes BEFORE any write.
    std::fs::create_dir_all(watched_probe.parent().expect("watched probe has a parent"))
        .expect("create watched probe parent dir");
    std::fs::create_dir_all(ignored_probe.parent().expect("ignored probe has a parent"))
        .expect("create ignored probe parent dir");

    // CUSTOM policy: watch matches our rule substring; ignore contains ONLY
    // the torda-ignored marker (both separator forms) — NOT temp-dir entries,
    // since `FilePolicy::default()` would drop both probes as temp noise.
    let custom_policy = FilePolicy::new(
        vec![watch_entry.to_string()],
        vec![
            "/torda-ignored/".to_string(),
            "\\torda-ignored\\".to_string(),
        ],
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

    // The SAME real module the agent registers, but with our custom policy.
    // init() + start() BEFORE generating any file activity.
    let mut filemon = FileMonModule::with_policy(custom_policy);
    filemon.init(ctx).await.expect("filemon init");
    filemon
        .start()
        .await
        .expect("filemon start (subscribes before we write)");

    // 4) Generate activity: write BOTH probes a few times.
    for _ in 0..NUM_PROBE_WRITES {
        let _ = std::fs::write(&watched_probe, b"torda-filemon-watched-probe");
        let _ = std::fs::write(&ignored_probe, b"torda-filemon-ignored-probe");
        std::thread::sleep(Duration::from_millis(150));
    }

    // 5) Bounded capture window: poll the capturing emitter's Vec.
    let watched_name = watched_probe
        .file_name()
        .and_then(|n| n.to_str())
        .expect("watched probe has a file name")
        .to_lowercase();
    let deadline = tokio::time::Instant::now() + CAPTURE_WINDOW;
    while tokio::time::Instant::now() < deadline {
        let flagged_seen = records.lock().unwrap().iter().any(|env| {
            env.data["file"]["path"]
                .as_str()
                .map(|p| p.to_lowercase().contains(&watched_name))
                .unwrap_or(false)
                && env.severity_id == SEV_HIGH
        });
        if flagged_seen {
            break;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    filemon.stop().await.expect("filemon clean shutdown");

    // 6) Clean up the whole probe root BEFORE the asserts (best-effort) so a
    // failed assert still leaves no litter.
    let _ = std::fs::remove_dir_all(&probe_root);

    // 7) Inspect the captured OCSF envelopes.
    let emitted = records.lock().unwrap().clone();
    let mut watched_flagged = false;
    let mut ignored_leaked = false;

    for env in emitted.iter() {
        let path = env.data["file"]["path"].as_str().unwrap_or("");
        let op = env.data["file"]["op"].as_str().unwrap_or("");
        let rules: Vec<&str> = env.data["detections"]
            .as_array()
            .map(|a| a.iter().filter_map(|d| d["rule"].as_str()).collect())
            .unwrap_or_default();
        println!(
            "severity_id={} path={path} op={op} detections={:?}",
            env.severity_id, rules
        );

        if path.to_lowercase().contains(&watched_name)
            && env.severity_id == SEV_HIGH
            && rules.contains(&expected_rule)
        {
            watched_flagged = true;
        }
        if path.to_lowercase().contains(IGNORED_MARKER) {
            ignored_leaked = true;
        }
    }

    // 8) Self-assert BOTH — each a distinct loud failure.
    if !watched_flagged {
        eprintln!(
            "\nFAILURE: no captured envelope matched the WATCHED probe (\"{watched_name}\") with \
             severity_id=={SEV_HIGH} (SEV_HIGH) and detections containing \"{expected_rule}\".\n\
             Captured {} envelope(s) total (see the printed list above). Expected the planted \
             write to {} to flow through the real event bus into FileMonModule, survive the \
             custom policy's `considers()` prefilter, and be flagged {expected_rule} by `assess`. \
             Check the write-event capture in crates/substrate/src/{} and FileMonModule's \
             subscribe/assess path in crates/modules/filemon/src/lib.rs.",
            emitted.len(),
            watched_probe.display(),
            if cfg!(windows) { "etw.rs" } else { "ebpf.rs" }
        );
        std::process::exit(1);
    }
    if ignored_leaked {
        eprintln!(
            "\nFAILURE: at least one captured envelope's path contained the IGNORED marker \
             (\"{IGNORED_MARKER}\") — the real FileMonModule emitted a record for a path that \
             should have been dropped by the custom policy's `ignore` list. `ignore` must beat \
             `watch` even when watch would otherwise match (see FilePolicy::considers in \
             crates/modules/filemon/src/lib.rs)."
        );
        std::process::exit(1);
    }

    // 9) Success summary.
    println!(
        "\nOK: captured {} File System Activity envelope(s); the planted write to \"{}\" \
         (containing \"{watch_entry}\") flagged {expected_rule} at HIGH severity, and the \
         torda-ignored probe produced ZERO envelopes — real {} file-write detection is live, and \
         ignore correctly beat watch through the real module.",
        emitted.len(),
        watched_probe.display(),
        sub.bus_label
    );

    // Drop the substrate -> live backend Drop stops collection + joins.
    drop(sub);
}
