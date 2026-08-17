//! Task 2 (p3g4-file-process-correlation) LIVE cross-sensor FILE correlation
//! proof — the file analog of `corr-ebpf-demo.rs`. It proves a REAL
//! `CORRELATED_ACTIVITY` (class 9002) attack-chain detection flows through the
//! REAL `CorrModule`'s FILE join (`suspicious_process_suspicious_file_write`,
//! `CORRELATED_FILE_RULE` in `crates/modules/corr/src/lib.rs`) over the real
//! substrate event bus (either the Linux eBPF bus or the Windows ETW bus — this
//! demo works on EITHER live backend, unlike `corr-ebpf-demo.rs` which is
//! Linux/eBPF-only, because both a suspicious exec and a write-intent
//! file-write are observable on both substrates).
//!
//! # The attack chain: `curl` is BOTH halves at once
//! `corr-ebpf-demo.rs` generates its chain with two DIFFERENT curl behaviors
//! (an exec + a separate `connect(2)`). Here ONE curl invocation supplies both
//! halves of the FILE rule for the SAME pid:
//! ```text
//! curl -s -o <PROBE_PATH> file://<LOCAL_SOURCE>
//! ```
//! * The exec of `curl` itself is the LOLBin signal — `torda_mod_procmon::assess`
//!   flags `curl` (see `LOLBINS` in `crates/modules/procmon/src/lib.rs`).
//! * `curl -o <PROBE_PATH>` copies bytes from a small local source file this
//!   demo writes first, referenced by a `file://` URL. curl opens `<PROBE_PATH>`
//!   for writing (`O_WRONLY|O_CREAT|O_TRUNC`) as soon as the first source bytes
//!   arrive — which for a local `file://` source is immediate and OFFLINE, so
//!   the write-intent `FileWrite` fires deterministically with no network
//!   dependency.
//!
//!   (An earlier version dialed a non-routable HTTP URL instead. curl opens its
//!   `-o` output file LAZILY — only once body bytes actually arrive — so a
//!   timed-out connection wrote NOTHING and the file rule never fired, even
//!   though the connect syscall still correlated. The live checkpoint caught
//!   this; a local `file://` source removes the network dependency entirely.)
//!
//! Same curl pid for both signals -> `CorrModule` joins the exec verdict and
//! the write verdict by pid and emits ONE `CORRELATED_ACTIVITY` record whose
//! top-level `detections` carries `suspicious_process_suspicious_file_write`.
//!
//! # The probe path MUST pass `FilePolicy::default().considers()`
//! `CorrModule` gates every `FileWrite` through the DEFAULT `FilePolicy`
//! (`crates/modules/filemon/src/lib.rs`) before it ever reaches the join or
//! `torda_mod_filemon::assess`. The default policy WATCHES system/sensitive
//! substrings (e.g. `/etc/`, `\windows\system32\`) and IGNORES temp dirs
//! (`/tmp/`, `\appdata\local\temp\`, `\temp\`) and caches/logs — ignore always
//! wins over watch. So the probe path is built to:
//!   * embed a WATCH substring as a literal path COMPONENT, and
//!   * live under the user's HOME directory (never a temp dir, never the real
//!     system directory it names).
//!
//! Concretely (`cfg!(windows)` picks the OS-appropriate form):
//!   * **Linux:** `<HOME>/torda-corr-probe-<demo-pid>/etc/probe.tmp` — the
//!     literal `/etc/` component makes `considers()` watch it, and
//!     `torda_mod_filemon::assess` fires `write_to_sensitive_config` on it.
//!     `<HOME>/...` is never under `/tmp/`, so nothing ignores it.
//!   * **Windows:** `<USERPROFILE>\torda-corr-probe-<demo-pid>\Windows\System32\probe.tmp`
//!     — the literal `\Windows\System32\` component is the watch substring
//!     (`write_to_system_dir`); it lives under the user's profile directory,
//!     never under `\Temp\`/`\AppData\Local\Temp\`, and never touches the
//!     REAL `C:\Windows\System32`.
//!
//! These are just probe subdirectories named `etc` / `Windows\System32` under
//! the demo-runner's own HOME — nothing here ever reads or writes a real
//! system path. `curl -o` does NOT create parent directories itself, so this
//! binary `create_dir_all`s the probe's parent directory before spawning curl,
//! and best-effort removes the whole `torda-corr-probe-<demo-pid>` directory when
//! done.
//!
//! # Honest about which path this is on (mirrors `corr-ebpf-demo.rs`)
//!   * NON-privileged (or both features off, e.g. default Windows/Linux):
//!     `Substrate::for_this_platform()` fell back to the stub bus
//!     (`bus_label` is neither `"ebpf"` nor `"etw"`). There is no real OS
//!     activity to correlate, so the demo prints a clear "run elevated"
//!     instruction for `--bin corr-file-demo` and exits 0. It does NOT assert
//!     or fake a detection. THIS is the path a non-elevated default run
//!     verifies.
//!   * ROOT in WSL with `--features linux-ebpf`, or ADMINISTRATOR with
//!     `--features windows-etw`: the real bus started. The demo wires the
//!     REAL `CorrModule` (the exact module the agent registers) onto the real
//!     substrate with a capturing emitter, `init()`s and `start()`s it (so it
//!     subscribes BEFORE any curl spawns), generates the attack chain via
//!     several bounded curl invocations, waits a bounded window, then
//!     self-asserts.
//!
//! Every wait on this path is bounded: `curl --max-time 1` bounds each spawn;
//! the capture window is a deadline-bounded poll loop; no helper thread is
//! spawned/joined unboundedly anywhere in this file. Dropping the substrate
//! tears the live collection down (the real bus's `Drop` stops + joins).
//!
//! DEMO-ONLY: no library was edited — it uses only the public `CorrModule` +
//! `ModuleCtx` + `Substrate` + `FilePolicy::default()`'s documented contract.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use torda_core::{
    Module, ModuleCtx, OcsfEmitter, ResourceBudget, ResourceGovernor, ResourceSampler,
    ResourceUsage,
};
use torda_ocsf::OcsfEnvelope;

/// Total wall-clock window to wait for the capturing emitter to accumulate
/// records on the live path.
const CAPTURE_WINDOW: Duration = Duration::from_secs(5);
/// Poll interval while waiting for the capturing emitter to fill up.
const POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Number of curl attempts. A few repeats make the live proof robust to any
/// single dropped/lagged event, mirroring `corr-ebpf-demo.rs`'s pacing.
const NUM_CURL_ATTEMPTS: usize = 5;
/// Small pause between curl spawns so each attempt's exec+write pair has a
/// clear window to be drained before the next attempt starts.
const INTER_ATTEMPT_SLEEP: Duration = Duration::from_millis(200);
/// The bytes the demo writes into a small local source file that `curl` then
/// copies into the probe path via a `file://` URL. Any non-empty content works;
/// curl opening its `-o` output to receive these bytes is the write-intent
/// `FileWrite` this demo correlates.
const SOURCE_PAYLOAD: &[u8] = b"torda-corr-probe demo write payload\n";
/// The correlated FILE rule this demo proves — the file analog of
/// `suspicious_process_suspicious_connection`.
const CORRELATED_FILE_RULE: &str = "suspicious_process_suspicious_file_write";

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

/// Builds the OS-appropriate probe directory root, the probe file path, and
/// the lowercase path TAIL used to match a (possibly NT-device-prefixed, on
/// ETW) reported path back to this probe. All three are namespaced by this
/// process's own pid so concurrent runs never collide.
fn probe_paths() -> (String, String, String) {
    let demo_pid = std::process::id();
    if cfg!(windows) {
        let home = std::env::var("USERPROFILE").unwrap_or_else(|_| r"C:\Users\Default".into());
        let root = format!(r"{home}\torda-corr-probe-{demo_pid}");
        let path = format!(r"{root}\Windows\System32\probe.tmp");
        let tail = format!(r"torda-corr-probe-{demo_pid}\windows\system32\probe.tmp");
        (root, path, tail)
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
        let root = format!("{home}/torda-corr-probe-{demo_pid}");
        let path = format!("{root}/etc/probe.tmp");
        let tail = format!("torda-corr-probe-{demo_pid}/etc/probe.tmp");
        (root, path, tail)
    }
}

/// Builds a `file://` URL curl can read for a local absolute path. On Unix the
/// path already starts with `/` (→ `file:///abs/path`); on Windows it starts
/// with a drive letter and uses backslashes, which are converted to forward
/// slashes (→ `file:///C:/abs/path`). curl accepts both forms.
fn file_url_for(src_path: &str) -> String {
    let fwd = src_path.replace('\\', "/");
    if fwd.starts_with('/') {
        format!("file://{fwd}")
    } else {
        format!("file:///{fwd}")
    }
}

#[tokio::main]
async fn main() {
    // 1) Build the shared substrate for THIS host and report the live bus.
    let sub = torda_substrate::Substrate::for_this_platform();
    println!("event bus: {}", sub.bus_label);

    // 2) Stub path (NON-privileged / both features off / unsupported OS): be
    // honest, instruct, exit 0. No real OS events exist to correlate here.
    if sub.bus_label != "ebpf" && sub.bus_label != "etw" {
        println!(
            "\nNo live event bus active (running on the '{}' bus) — no real process/file \
             events to correlate.\n\
             To see REAL cross-sensor FILE correlation (the real CorrModule joining a curl exec \
             to its own `-o` file-write), build then run ELEVATED:\n\
             \x20   Linux (ROOT in WSL):\n\
             \x20     CARGO_TARGET_DIR=$HOME/torda-ebpf-target cargo run -p torda \\\n\
             \x20         --features linux-ebpf --bin corr-file-demo\n\
             \x20     (or: wsl -u root)\n\
             \x20   Windows (ADMINISTRATOR):\n\
             \x20     cargo run -p torda --features windows-etw --bin corr-file-demo\n\
             (loading eBPF requires root/CAP_BPF; the ETW session requires Administrator.)",
            sub.bus_label
        );
        // Nothing to assert: there are no real OS events on the stub bus.
        return;
    }

    // 3) Live path (ROOT / ADMINISTRATOR): run the REAL CorrModule against the
    // real bus and prove real process<->file-write correlation.
    println!(
        "'{}' event bus live — wiring the real CorrModule onto the real bus and capturing real \
         correlated attack-chain detections for up to {CAPTURE_WINDOW:?}...",
        sub.bus_label
    );

    let (probe_root, probe_path, probe_tail) = probe_paths();
    let probe_parent = Path::new(&probe_path)
        .parent()
        .expect("probe path has a parent")
        .to_path_buf();
    std::fs::create_dir_all(&probe_parent).unwrap_or_else(|e| {
        panic!("failed to create probe parent dir {probe_parent:?}: {e}");
    });
    println!(
        "probe path: {probe_path} (a probe subdir under HOME — never the real system directory \
         it names)"
    );

    // curl copies from this small local source via a file:// URL so the -o write
    // is deterministic and OFFLINE (see the header note on curl's lazy -o open —
    // a non-routable HTTP source wrote nothing). The source sits under the same
    // probe root, so the best-effort remove_dir_all cleans it up too.
    let src_path = Path::new(&probe_root).join("src.txt");
    std::fs::write(&src_path, SOURCE_PAYLOAD).unwrap_or_else(|e| {
        panic!("failed to write probe source {src_path:?}: {e}");
    });
    let src_url = file_url_for(&src_path.to_string_lossy());

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

    // The SAME real module the agent registers. It subscribes to
    // ProcessExec + ProcessExit + NetConnect + FileWrite on the real bus
    // BEFORE we generate any activity, so no event is missed.
    let mut corr = torda_mod_corr::CorrModule::new();
    corr.init(ctx).await.expect("corr init");
    corr.start()
        .await
        .expect("corr start (subscribes before we spawn curl)");

    // 3a) Generate the attack chain: spawn curl several times, each copying the
    // local file:// source into the SAME probe path via `-o`. Each spawn execs
    // the LOLBin `curl` (procmon flags it) and `-o` opens the probe path for
    // writing to receive the source bytes (filemon's default policy watches it
    // — see the header). The file:// source is local and immediate, so the
    // write fires deterministically with no network dependency. `--max-time 5`
    // is a belt-and-braces bound (a local copy returns at once); the curl
    // result is ignored.
    println!(
        "spawning curl x{NUM_CURL_ATTEMPTS}, each copying {src_url} -> {probe_path} via -o \
         (offline file:// source; curl execs as the LOLBin and opens the probe path for write)"
    );
    for i in 0..NUM_CURL_ATTEMPTS {
        let _ = std::process::Command::new("curl")
            .args(["--max-time", "5", "-s", "-o", &probe_path, &src_url])
            .status();
        println!("  curl attempt {} done", i + 1);
        std::thread::sleep(INTER_ATTEMPT_SLEEP);
    }

    // Collect for a bounded window: poll the capturing emitter's Vec rather
    // than a raw rx, since the module itself is draining the bus.
    let probe_tail_lower = probe_tail.to_ascii_lowercase();
    let matches_probe = |env: &OcsfEnvelope| -> bool {
        let path_lower = env.data["file"]["path"]
            .as_str()
            .unwrap_or("")
            .to_ascii_lowercase();
        let has_rule = env.data["detections"]
            .as_array()
            .map(|a| a.iter().any(|d| d["rule"] == CORRELATED_FILE_RULE))
            .unwrap_or(false);
        has_rule && path_lower.ends_with(&probe_tail_lower)
    };

    let deadline = tokio::time::Instant::now() + CAPTURE_WINDOW;
    while tokio::time::Instant::now() < deadline {
        let seen = records.lock().unwrap().iter().any(matches_probe);
        if seen {
            break;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    corr.stop().await.expect("corr clean shutdown");

    // 4) Inspect the captured OCSF envelopes.
    let emitted = records.lock().unwrap().clone();
    let mut captured = 0usize;
    let mut file_correlated_attributed = 0usize;

    for env in emitted.iter() {
        captured += 1;
        let pid = &env.data["process"]["pid"];
        let image = env.data["process"]["image"].as_str().unwrap_or("?");
        let attributed = env.data["process"]["attributed"].as_bool().unwrap_or(false);
        let path = env.data["file"]["path"].as_str().unwrap_or("?");
        let rules: Vec<&str> = env.data["detections"]
            .as_array()
            .map(|a| a.iter().filter_map(|d| d["rule"].as_str()).collect())
            .unwrap_or_default();
        let is_probe_match = matches_probe(env);
        if is_probe_match && attributed {
            file_correlated_attributed += 1;
        }
        println!(
            "pid={pid} image={image} path={path} attributed={attributed} severity_id={} \
             detections={rules:?} probe_match={is_probe_match}",
            env.severity_id
        );
    }

    // 5) Self-assert the CRITICAL thing this demo exists to prove: the real
    // FILE join fired, attributing the write to the curl exec — NOT merely
    // "some 9002 was captured" (a connection-rule 9002 from the same curl's
    // `connect(2)` would satisfy that vacuously). Require >= 1 captured
    // record whose path corresponds to the probe, whose top-level detections
    // carry the FILE rule, AND that is attributed to the process that wrote
    // it (curl).
    if file_correlated_attributed < 1 {
        eprintln!(
            "\nFAILURE: no attributed `{CORRELATED_FILE_RULE}` record was captured for the probe \
             path.\n\
             Captured {captured} Correlated Activity record(s) total, but none carried the FILE \
             rule attributed to the probe write. Check:\n\
             \x20 - `torda_mod_procmon::assess(\"curl\")` still flags curl as a lolbin \
             (crates/modules/procmon/src/lib.rs)\n\
             \x20 - `FilePolicy::default().considers(\"{probe_path}\")` still returns true \
             (crates/modules/filemon/src/lib.rs) — it must contain a WATCH substring and no \
             IGNORE substring\n\
             \x20 - CorrModule's file join / grace-buffer re-attribution \
             (crates/modules/corr/src/lib.rs, handle_file_write / handle_exec)\n\
             \x20 - the substrate's FileWrite classification for a `-o`/O_CREAT|O_TRUNC open \
             (crates/substrate/src/ebpf.rs or crates/substrate/src/etw.rs)"
        );
        let _ = std::fs::remove_dir_all(&probe_root);
        drop(sub);
        std::process::exit(1);
    }

    // 6) Success summary.
    println!(
        "\nOK: captured {captured} Correlated Activity record(s); {file_correlated_attributed} \
         attributed `{CORRELATED_FILE_RULE}` record(s) matched the probe path — real \
         process<->file-write correlation (curl as LOLBin + writer via -o) is live."
    );

    // Best-effort cleanup of the whole probe directory tree.
    let _ = std::fs::remove_dir_all(&probe_root);

    // Drop the substrate -> the live bus's Drop stops collection + joins.
    drop(sub);
}
