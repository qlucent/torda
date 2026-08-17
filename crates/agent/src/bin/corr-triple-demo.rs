//! Task 2 (p3g5-triple-chain-correlation) LIVE proof of the TRIPLE chain — the
//! dropper-then-C2 attack chain — flowing through the REAL `CorrModule` over the
//! real substrate event bus. It is the sibling of `corr-file-demo.rs` (which
//! proves the two-signal FILE join) and `corr-ebpf-demo.rs` (the two-signal
//! CONNECT join): here ONE curl pid supplies BOTH a suspicious CONNECT and a
//! suspicious FILE-WRITE, so the REAL module's `CORRELATED_CHAIN_RULE`
//! (`suspicious_process_wrote_file_and_connected`, a class-9002 record — see
//! `emit_correlated_chain` in `crates/modules/corr/src/lib.rs`) fires. Like
//! `corr-file-demo.rs` it works on EITHER live backend (Linux eBPF ROOT or
//! Windows ETW ADMINISTRATOR) because both a suspicious connect and a
//! write-intent file-write are observable on both substrates.
//!
//! # The attack-chain staging: ONE curl pid does BOTH halves
//! The triple needs ONE pid to make a suspicious CONNECT and a suspicious
//! FILE-WRITE within the module's `CHAIN_WINDOW`. This demo stages that with a
//! LOCAL loopback responder + a single curl invocation:
//!
//! ```text
//! curl --max-time 5 -s -o <PROBE_PATH> http://127.0.0.1:4444/
//! ```
//!
//! * A bounded local HTTP responder (a `std::net::TcpListener` bound to
//!   `127.0.0.1:4444`) is spun up in ONE helper thread BEFORE the curl loop. For
//!   each connection it reads/ignores the request and writes a minimal valid HTTP
//!   response with a small body, then drops the stream. Port **4444** is a netmon
//!   `SUSPICIOUS_PORT` (Metasploit's default LPORT — see `SUSPICIOUS_PORTS` in
//!   `crates/modules/netmon/src/lib.rs`), which `torda_mod_netmon::assess` flags
//!   `"suspicious_port"` (MEDIUM) on the PORT ALONE, regardless of the loopback
//!   IP. That is the **suspicious CONNECT** half.
//! * curl's exec is the LOLBin signal — `torda_mod_procmon::assess` flags `curl`
//!   (see `LOLBINS` in `crates/modules/procmon/src/lib.rs`), so the process half
//!   of BOTH component rules is suspicious.
//! * The responder returns a body, so curl opens `-o <PROBE_PATH>` for writing
//!   (`O_WRONLY|O_CREAT|O_TRUNC`) once the body bytes arrive and writes them —
//!   the **suspicious FILE-WRITE** half. The probe path is a watched path (see
//!   below), so filemon considers it and `torda_mod_filemon::assess` flags it.
//!
//! The SAME curl pid produced both suspicious signals, so the REAL `CorrModule`
//! fires `CORRELATED_RULE` (connect), `CORRELATED_FILE_RULE` (write), AND — the
//! point of this demo — joins those two attributed component verdicts into the
//! TRIPLE `CORRELATED_CHAIN_RULE`. A local loopback responder makes the connect
//! offline and deterministic, and its body makes the `-o` write deterministic
//! (an earlier file demo learned that curl opens its `-o` output LAZILY, only
//! once body bytes arrive — a non-responding source writes nothing).
//!
//! # The probe path MUST pass `FilePolicy::default().considers()`
//! `CorrModule` gates every `FileWrite` through the DEFAULT `FilePolicy`
//! (`crates/modules/filemon/src/lib.rs`) before it reaches the join. The default
//! policy WATCHES system/sensitive substrings (`/etc/`, `\windows\system32\`) and
//! IGNORES temp dirs — ignore wins over watch. So the probe path embeds a WATCH
//! substring as a literal path COMPONENT and lives UNDER the user's HOME (never a
//! temp dir, never the real system directory it names):
//!   * **Linux:** `<HOME>/torda-corr-triple-probe-<pid>/etc/probe.tmp` — the literal
//!     `/etc/` component makes `considers()` watch it; `<HOME>/...` is never under
//!     `/tmp/`.
//!   * **Windows:** `<USERPROFILE>\torda-corr-triple-probe-<pid>\Windows\System32\probe.tmp`
//!     — the literal `\Windows\System32\` component is the watch substring; it
//!     lives under the user's profile, never under `\Temp\`, and never touches the
//!     REAL `C:\Windows\System32`.
//!
//! These are just probe subdirs named `etc` / `Windows\System32` under the
//! demo-runner's own HOME — nothing here reads or writes a real system path.
//! `curl -o` does NOT create parent directories, so this binary `create_dir_all`s
//! the probe parent before spawning curl and best-effort removes the whole
//! `torda-corr-triple-probe-<pid>` directory when done.
//!
//! # Honest about which path this is on (mirrors `corr-file-demo.rs`)
//!   * NON-privileged (or both features off): `Substrate::for_this_platform()`
//!     fell back to the stub bus (`bus_label` is neither `"ebpf"` nor `"etw"`).
//!     There is no real OS activity to correlate, so the demo prints a clear "run
//!     elevated" instruction for `--bin corr-triple-demo` and exits 0. It does NOT
//!     assert or fake a detection. THIS is the path a non-elevated default run
//!     verifies.
//!   * ROOT in WSL with `--features linux-ebpf`, or ADMINISTRATOR with
//!     `--features windows-etw`: the real bus started. The demo starts the bounded
//!     responder, wires the REAL `CorrModule` + a capturing emitter, `init()`s and
//!     `start()`s it (so it subscribes BEFORE any curl spawns), generates the
//!     chain via several bounded curl invocations, waits a bounded window, then
//!     self-asserts the TRIPLE specifically.
//!
//! Every wait is bounded: the responder uses non-blocking accept + read/write
//! timeouts + a hard deadline and is JOINED (bounded) at the end; each `curl
//! --max-time 5` spawn is bounded; the capture window is a deadline-bounded poll
//! loop; dropping the substrate tears live collection down (the real bus's `Drop`
//! stops + joins). The responder binds loopback-only and is DEMO-ONLY.
//!
//! DEMO-ONLY: no library was edited — it uses only the public `CorrModule` +
//! `ModuleCtx` + `Substrate` + `FilePolicy::default()`'s documented contract and
//! a `std::net::TcpListener` (no new dependency).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use torda_core::{
    Module, ModuleCtx, OcsfEmitter, ResourceBudget, ResourceGovernor, ResourceSampler,
    ResourceUsage,
};
use torda_ocsf::OcsfEnvelope;

/// Total wall-clock window to wait for the capturing emitter to accumulate the
/// triple record on the live path.
const CAPTURE_WINDOW: Duration = Duration::from_secs(5);
/// Poll interval while waiting for the capturing emitter to fill up.
const POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Number of curl attempts. A few repeats make the live proof robust to any
/// single dropped/lagged event, mirroring `corr-file-demo.rs`'s pacing.
const NUM_CURL_ATTEMPTS: usize = 5;
/// Small pause between curl spawns so each attempt's connect+write pair has a
/// clear window to be drained before the next attempt starts.
const INTER_ATTEMPT_SLEEP: Duration = Duration::from_millis(200);
/// The suspicious C2 port the responder listens on and curl dials. It is a
/// netmon `SUSPICIOUS_PORT` (flagged by port alone, regardless of the loopback
/// IP), which is what makes the connect half suspicious.
const RESPONDER_PORT: u16 = 4444;
/// The loopback address:port the responder binds and curl connects to.
const RESPONDER_ADDR: &str = "127.0.0.1:4444";
/// A minimal valid HTTP response the responder writes for each connection; the
/// 20-byte body is what curl writes into the `-o` probe path (the suspicious
/// file-write half). `Connection: close` lets curl finish promptly.
const HTTP_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\nua-corr-triple-probe";
/// Hard deadline for the responder thread: it serves `NUM_CURL_ATTEMPTS`
/// connections then exits early, but this bound guarantees it can never hang
/// (and the end-of-run join is therefore always bounded) even if fewer curls
/// connect than expected. Generous enough to cover the whole curl loop +
/// capture window worst case.
const RESPONDER_HARD_DEADLINE: Duration = Duration::from_secs(45);
/// Bounded accept/read/write timeouts inside the responder so no single
/// connection can wedge it.
const RESPONDER_IO_TIMEOUT: Duration = Duration::from_millis(500);
/// The TRIPLE chain rule this demo exists to prove.
const CORRELATED_CHAIN_RULE: &str = "suspicious_process_wrote_file_and_connected";

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

/// Builds the OS-appropriate probe directory root, the probe file path, and the
/// lowercase path TAIL used to match a (possibly NT-device-prefixed, on ETW)
/// reported path back to this probe. All three are namespaced by this process's
/// own pid so concurrent runs never collide.
fn probe_paths() -> (String, String, String) {
    let demo_pid = std::process::id();
    if cfg!(windows) {
        let home = std::env::var("USERPROFILE").unwrap_or_else(|_| r"C:\Users\Default".into());
        let root = format!(r"{home}\torda-corr-triple-probe-{demo_pid}");
        let path = format!(r"{root}\Windows\System32\probe.tmp");
        let tail = format!(r"torda-corr-triple-probe-{demo_pid}\windows\system32\probe.tmp");
        (root, path, tail)
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
        let root = format!("{home}/torda-corr-triple-probe-{demo_pid}");
        let path = format!("{root}/etc/probe.tmp");
        let tail = format!("torda-corr-triple-probe-{demo_pid}/etc/probe.tmp");
        (root, path, tail)
    }
}

/// The responder loop, running on its own thread: serve up to
/// `NUM_CURL_ATTEMPTS` loopback connections (each: read+ignore the request,
/// write `HTTP_RESPONSE`, drop the stream), then exit. Bounded on every axis —
/// non-blocking accept with a short poll sleep, per-connection read/write
/// timeouts, and a hard wall-clock deadline — so it can never hang and the
/// end-of-run join is always bounded. Takes ownership of a listener already
/// bound by the caller (so a bind failure is handled BEFORE the thread spawns).
fn run_responder(listener: TcpListener) {
    let deadline = Instant::now() + RESPONDER_HARD_DEADLINE;
    let mut served = 0usize;
    while served < NUM_CURL_ATTEMPTS && Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_read_timeout(Some(RESPONDER_IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(RESPONDER_IO_TIMEOUT));
                // Read and ignore the request bytes (bounded by the read timeout).
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(HTTP_RESPONSE);
                let _ = stream.flush();
                served += 1;
                drop(stream);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No pending connection yet; brief bounded sleep, then re-poll.
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break, // listener error → stop; the demo's deadlines still bound us.
        }
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
            "\nNo live event bus active (running on the '{}' bus) — no real process/file/network \
             events to correlate.\n\
             To see the REAL TRIPLE chain (the real CorrModule joining ONE curl's suspicious \
             connect to :4444 AND its `-o` write of a watched path into \
             `{CORRELATED_CHAIN_RULE}`), build then run ELEVATED:\n\
             \x20   Linux (ROOT in WSL):\n\
             \x20     CARGO_TARGET_DIR=$HOME/torda-ebpf-target cargo run -p torda \\\n\
             \x20         --features linux-ebpf --bin corr-triple-demo\n\
             \x20     (or: wsl -u root)\n\
             \x20   Windows (ADMINISTRATOR):\n\
             \x20     cargo run -p torda --features windows-etw --bin corr-triple-demo\n\
             (loading eBPF requires root/CAP_BPF; the ETW session requires Administrator.)",
            sub.bus_label
        );
        // Nothing to assert: there are no real OS events on the stub bus.
        return;
    }

    // 3) Live path (ROOT / ADMINISTRATOR): run the REAL CorrModule against the
    // real bus and prove the real TRIPLE chain (dropper-then-C2).
    println!(
        "'{}' event bus live — wiring the real CorrModule onto the real bus and capturing the \
         real TRIPLE chain for up to {CAPTURE_WINDOW:?}...",
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

    // Bind the loopback responder BEFORE spawning its thread so a bind failure
    // (e.g. port 4444 already in use) is handled here: clean up and exit 0
    // (an environment condition, not a detection failure — never panic/hang).
    let listener = match TcpListener::bind(RESPONDER_ADDR) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "could not bind the loopback responder on {RESPONDER_ADDR} ({e}) — port {RESPONDER_PORT} \
                 is likely already in use. Free it and re-run. Exiting 0 (no detection to assert)."
            );
            let _ = std::fs::remove_dir_all(&probe_root);
            drop(sub);
            return;
        }
    };
    // Non-blocking accept so the responder loop can honor its hard deadline.
    listener
        .set_nonblocking(true)
        .expect("set responder listener non-blocking");
    let responder = thread::spawn(move || run_responder(listener));
    println!("loopback responder listening on {RESPONDER_ADDR} (bounded; serves {NUM_CURL_ATTEMPTS} connections then exits)");

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

    // 3a) Generate the chain: spawn curl several times, each doing BOTH halves in
    // ONE invocation — CONNECT to the local suspicious-port responder AND `-o`
    // write the response body into the watched probe path. Each spawn execs the
    // LOLBin `curl` (procmon flags it), connects to 127.0.0.1:4444 (netmon flags
    // `suspicious_port`), and writes the probe path (filemon watches it). Same
    // curl pid for all three → corr fires the connect rule, the file rule, AND
    // the TRIPLE. `--max-time 5` bounds each spawn; the curl result is ignored.
    println!(
        "spawning curl x{NUM_CURL_ATTEMPTS}, each: connect http://{RESPONDER_ADDR}/ (suspicious \
         port {RESPONDER_PORT}) AND -o {probe_path} (write the response body to the watched probe)"
    );
    let url = format!("http://{RESPONDER_ADDR}/");
    for i in 0..NUM_CURL_ATTEMPTS {
        let _ = std::process::Command::new("curl")
            .args(["--max-time", "5", "-s", "-o", &probe_path, &url])
            .status();
        println!("  curl attempt {} done", i + 1);
        thread::sleep(INTER_ATTEMPT_SLEEP);
    }

    // Collect for a bounded window: poll the capturing emitter's Vec for the
    // TRIPLE specifically (not a mere connect- or file-rule 9002).
    let probe_tail_lower = probe_tail.to_ascii_lowercase();
    let is_triple_for_probe = |env: &OcsfEnvelope| -> bool {
        let has_chain_rule = env.data["detections"]
            .as_array()
            .map(|a| a.iter().any(|d| d["rule"] == CORRELATED_CHAIN_RULE))
            .unwrap_or(false);
        let attributed = env.data["process"]["attributed"].as_bool().unwrap_or(false);
        let path_lower = env.data["file"]["path"]
            .as_str()
            .unwrap_or("")
            .to_ascii_lowercase();
        let dport = env.data["connection"]["dport"].as_u64().unwrap_or(0);
        has_chain_rule
            && attributed
            && path_lower.ends_with(&probe_tail_lower)
            && dport == RESPONDER_PORT as u64
    };

    let deadline = tokio::time::Instant::now() + CAPTURE_WINDOW;
    while tokio::time::Instant::now() < deadline {
        let seen = records.lock().unwrap().iter().any(is_triple_for_probe);
        if seen {
            break;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    corr.stop().await.expect("corr clean shutdown");

    // The responder serves NUM_CURL_ATTEMPTS then exits (and has a hard
    // deadline), so this join is bounded — it has almost certainly already
    // finished by now.
    let _ = responder.join();

    // 4) Inspect the captured OCSF envelopes. Print EVERY class-9002 record for
    // diagnosis, and count the TRIPLE-for-probe matches.
    let emitted = records.lock().unwrap().clone();
    let mut nine_thousand_two = 0usize;
    let mut triple_matches = 0usize;

    for env in emitted.iter() {
        // Only Correlated Activity (9002) records carry these fields; others
        // (e.g. an asset/health record, unlikely here) are skipped from the dump.
        if env.class_uid != torda_ocsf::class::CORRELATED_ACTIVITY {
            continue;
        }
        nine_thousand_two += 1;
        let pid = &env.data["process"]["pid"];
        let image = env.data["process"]["image"].as_str().unwrap_or("?");
        let attributed = env.data["process"]["attributed"].as_bool().unwrap_or(false);
        let path = env.data["file"]["path"].as_str().unwrap_or("-");
        let dport = env.data["connection"]["dport"].as_u64().unwrap_or(0);
        let rules: Vec<&str> = env.data["detections"]
            .as_array()
            .map(|a| a.iter().filter_map(|d| d["rule"].as_str()).collect())
            .unwrap_or_default();
        let is_triple = is_triple_for_probe(env);
        if is_triple {
            triple_matches += 1;
        }
        println!(
            "pid={pid} image={image} path={path} dport={dport} attributed={attributed} \
             severity_id={} detections={rules:?} triple_match={is_triple}",
            env.severity_id
        );
    }

    // 5) Self-assert the CRITICAL thing this demo exists to prove: the TRIPLE
    // chain fired — a class-9002 record carrying `CORRELATED_CHAIN_RULE`,
    // attributed, for OUR probe path, to port 4444. A mere connection-rule or
    // file-rule 9002 does NOT satisfy this (that would be the two-signal demos,
    // not the triple).
    if triple_matches < 1 {
        eprintln!(
            "\nFAILURE: no attributed `{CORRELATED_CHAIN_RULE}` (TRIPLE) record was captured for \
             the probe path + port {RESPONDER_PORT}.\n\
             Captured {nine_thousand_two} Correlated Activity (9002) record(s) total, but none was \
             the attributed TRIPLE for our probe. Check:\n\
             \x20 - `torda_mod_procmon::assess(\"curl\")` still flags curl as a lolbin \
             (crates/modules/procmon/src/lib.rs)\n\
             \x20 - `torda_mod_netmon::assess(_, {RESPONDER_PORT})` still flags `suspicious_port` \
             (crates/modules/netmon/src/lib.rs) — port {RESPONDER_PORT} must stay in SUSPICIOUS_PORTS\n\
             \x20 - the loopback responder actually served the body (curl's `-o` write is lazy — no \
             body, no write); check the bind on {RESPONDER_ADDR} succeeded\n\
             \x20 - `FilePolicy::default().considers(\"{probe_path}\")` still returns true \
             (crates/modules/filemon/src/lib.rs) — a WATCH substring, no IGNORE substring\n\
             \x20 - CorrModule's chain join / CHAIN_WINDOW (crates/modules/corr/src/lib.rs, \
             record_connect_and_maybe_chain / record_file_and_maybe_chain / maybe_fire_chain) — \
             BOTH component rules must fire for the SAME pid within the window"
        );
        let _ = std::fs::remove_dir_all(&probe_root);
        drop(sub);
        std::process::exit(1);
    }

    // 6) Success summary.
    println!(
        "\nOK: captured {nine_thousand_two} Correlated Activity record(s); {triple_matches} \
         attributed `{CORRELATED_CHAIN_RULE}` (TRIPLE) record(s) matched the probe path + port \
         {RESPONDER_PORT} — the real dropper-then-C2 triple chain (one curl that connected to \
         :{RESPONDER_PORT} AND wrote a watched path) is live."
    );

    // Best-effort cleanup of the whole probe directory tree.
    let _ = std::fs::remove_dir_all(&probe_root);

    // Drop the substrate -> the live bus's Drop stops collection + joins.
    drop(sub);
}
