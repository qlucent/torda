//! P3g1 Task 3 LIVE eBPF cross-sensor correlation proof (behind the
//! `linux-ebpf` feature) — proves a REAL `CORRELATED_ACTIVITY` (class 9002)
//! attack-chain detection flows through the REAL `CorrModule` over the real
//! Linux eBPF `EventBus`.
//!
//! PURPOSE: `corr-demo.rs` (Task 2) proves the subscribe -> correlate -> emit
//! path against a synthetic `StubBus` sequence it publishes itself. This
//! binary mirrors `netmon-ebpf-demo.rs`'s pattern instead: it wires the SAME
//! real module (`torda_mod_corr::CorrModule`, the exact module the agent
//! registers) onto the REAL eBPF substrate + a capturing emitter, then
//! generates REAL OS activity — spawning `curl` against a non-routable
//! address — so that BOTH halves of the attack chain fire from the actual
//! kernel: a `ProcessExec` for the LOLBin `curl` (procmon::assess flags it)
//! and a `NetConnect` for `curl`'s `connect(2)` to a suspicious external port
//! (netmon::assess flags it). `CorrModule` joins the two by pid and emits a
//! `suspicious_process_suspicious_connection` correlated record — proving
//! real cross-sensor (process <-> network) correlation, not a mocked one.
//!
//! HONEST about which path it is on (mirrors `netmon-ebpf-demo.rs` /
//! `procmon-lifecycle-ebpf-demo.rs`):
//!   * NON-root (or feature off / non-Linux, e.g. default Windows):
//!     `Substrate::for_this_platform()` fell back to the stub bus
//!     (`bus_label != "ebpf"`). There are no real OS events to correlate, so
//!     the demo prints a clear "run as root" instruction and exits 0. It does
//!     NOT assert or fake a detection. THIS is the path a non-root (default
//!     Windows) run verifies.
//!   * ROOT with `--features linux-ebpf` (Linux, e.g. via `wsl -u root`): the
//!     real `EbpfBus` started (`bus_label == "ebpf"`). The demo wires a REAL
//!     `CorrModule` onto the real substrate + a capturing emitter, subscribes
//!     it to `ProcessExec`/`ProcessExit`/`NetConnect` BEFORE generating any
//!     traffic, then spawns `curl --max-time 1 -s http://203.0.113.1:4444/`
//!     SEVERAL times (see the cross-ring ordering note below). Each `curl`
//!     invocation execs (comm "curl", a LOLBin) and then attempts a
//!     `connect(2)` to 203.0.113.1:4444 (TEST-NET-3, RFC5737 — non-routable,
//!     so the connect fails/times out, but `sys_enter_connect` fires on
//!     syscall ENTRY regardless of outcome).
//!
//! CRITICAL — cross-ring ordering: process events (EVENTS ring) and network
//! events (NET_EVENTS ring) are drained by SEPARATE threads in the real eBPF
//! substrate, so for any ONE curl invocation the `NetConnect` could
//! occasionally reach `CorrModule` before the `ProcessExec` has populated the
//! pid -> process-context map (a race with no ordering guarantee across two
//! independent ring buffers/threads). Pre-fix, `CorrModule` attributed a
//! `NetConnect` only if the matching `ProcessExec` had ALREADY landed, so a
//! `NetConnect` that arrived first was immediately emitted attributed=false
//! and never revisited — on the live harness this correlated only 2 of the 5
//! curl attempts. `CorrModule` now buffers an unattributed `NetConnect` and
//! re-attributes it when its `ProcessExec` arrives within a short grace
//! window, so correlation is order-independent: it no longer matters which
//! ring drains first for a given pid. The self-assert reflects that fix: it
//! requires a strict MAJORITY of the curl attempts to correlate
//! (`>= NUM_CURL_ATTEMPTS - 1`, allowing exactly one straggler — e.g. a pid
//! evicted before its exec/connect pair completed, or a curl that failed to
//! exec at all), not merely >= 1 as before. A regression back to the old
//! immediate-attribution race would again cap correlation near 2/5 and fail
//! this assert.
//!
//! Every wait on this path is bounded: `curl --max-time 1` bounds each spawn
//! (and `Command::status()` itself only returns once the child exits, which
//! `--max-time` guarantees happens quickly even though the target is
//! non-routable); the capture window is a deadline-bounded poll loop exactly
//! like `netmon-ebpf-demo.rs`; no helper thread is spawned and joined
//! unboundedly anywhere in this file. Dropping the substrate tears the eBPF
//! collection down (`EbpfBus` `Drop` stops + joins).
//!
//! DEMO-ONLY: no library was edited — it uses only the public `CorrModule` +
//! `ModuleCtx` + `Substrate`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use torda_core::{
    Module, ModuleCtx, OcsfEmitter, ResourceBudget, ResourceGovernor, ResourceSampler,
    ResourceUsage,
};
use torda_ocsf::OcsfEnvelope;

/// Total wall-clock window to wait for the capturing emitter to accumulate
/// records on the root path.
const CAPTURE_WINDOW: Duration = Duration::from_secs(5);
/// Poll interval while waiting for the capturing emitter to fill up.
const POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Number of curl attempts. Spawning several (rather than one) makes the live
/// proof robust to the cross-ring (EVENTS vs NET_EVENTS) ordering race
/// described above — at least one attempt's exec is overwhelmingly likely to
/// land before its connect.
const NUM_CURL_ATTEMPTS: usize = 5;
/// Small pause between curl spawns so each attempt's exec+connect pair has a
/// clear window to be drained before the next attempt starts.
const INTER_ATTEMPT_SLEEP: Duration = Duration::from_millis(200);
/// TEST-NET-3 (RFC5737) — documented non-routable, so this address is safe to
/// dial from any host without reaching a real third party. netmon classifies
/// it as "external" (not private/loopback/link-local) on a suspicious port.
const SUSPICIOUS_URL: &str = "http://203.0.113.1:4444/";
const CORRELATED_RULE: &str = "suspicious_process_suspicious_connection";

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

    // 2) Stub path (NON-root / feature off / non-Linux): be honest, instruct, exit 0.
    if sub.bus_label != "ebpf" {
        println!(
            "\neBPF event bus not active (running on the '{}' bus) — no real process/network \
             events to correlate.\n\
             To see REAL Linux cross-sensor correlation (the real CorrModule joining a curl \
             exec to its suspicious connect), build then run as ROOT in WSL:\n\
             \x20   CARGO_TARGET_DIR=$HOME/torda-ebpf-target cargo run -p torda --features linux-ebpf \\\n\
             \x20       --bin corr-ebpf-demo\n\
             \x20   (or: wsl -u root)\n\
             (loading eBPF requires root/CAP_BPF.)",
            sub.bus_label
        );
        // Nothing to assert: there are no real OS events on the stub bus.
        return;
    }

    // 3) eBPF path (ROOT): run the REAL CorrModule against the real bus and
    // prove real process<->network correlation.
    println!(
        "eBPF collection live — wiring the real CorrModule onto the real bus and capturing \
         real correlated attack-chain detections for up to {CAPTURE_WINDOW:?}..."
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

    // The SAME real module the agent registers. It subscribes to
    // ProcessExec + ProcessExit + NetConnect on the real bus BEFORE we
    // generate any traffic, so no event is missed.
    let mut corr = torda_mod_corr::CorrModule::new();
    corr.init(ctx).await.expect("corr init");
    corr.start()
        .await
        .expect("corr start (subscribes before we spawn curl)");

    // 3a) Generate the attack chain: spawn curl several times. Each spawn
    // execs the LOLBin `curl` (procmon flags it) then attempts connect(2) to
    // a non-routable suspicious external port (netmon flags it on syscall
    // entry, independent of connect success). `--max-time 1` bounds each
    // spawn so a non-routable target can never hang this demo; the result is
    // deliberately ignored (failure/timeout is expected and irrelevant —
    // sys_enter_connect already fired).
    println!(
        "spawning curl x{NUM_CURL_ATTEMPTS} against {SUSPICIOUS_URL} (expected to fail/time out; \
         both the exec and the connect syscall still fire; see the cross-ring ordering note in \
         this file's header for why several attempts are used)"
    );
    for i in 0..NUM_CURL_ATTEMPTS {
        let _ = std::process::Command::new("curl")
            .args(["--max-time", "1", "-s", SUSPICIOUS_URL])
            .status();
        println!("  curl attempt {} done", i + 1);
        std::thread::sleep(INTER_ATTEMPT_SLEEP);
    }

    // Collect for a bounded window: poll the capturing emitter's Vec rather
    // than a raw rx, since the module itself is draining the bus.
    let deadline = tokio::time::Instant::now() + CAPTURE_WINDOW;
    while tokio::time::Instant::now() < deadline {
        let correlated_seen = records.lock().unwrap().iter().any(|env| {
            env.data["detections"]
                .as_array()
                .map(|a| a.iter().any(|d| d["rule"] == CORRELATED_RULE))
                .unwrap_or(false)
        });
        if correlated_seen {
            break;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    corr.stop().await.expect("corr clean shutdown");

    // 4) Inspect the captured OCSF envelopes.
    let emitted = records.lock().unwrap().clone();
    let mut captured = 0usize;
    let mut attributed = 0usize;
    let mut correlated = 0usize;

    for env in emitted.iter() {
        captured += 1;
        let pid = &env.data["process"]["pid"];
        let image = env.data["process"]["image"].as_str().unwrap_or("?");
        let is_attributed = env.data["process"]["attributed"].as_bool().unwrap_or(false);
        if is_attributed {
            attributed += 1;
        }
        let daddr = env.data["connection"]["daddr"].as_str().unwrap_or("?");
        let dport = env.data["connection"]["dport"].as_u64().unwrap_or(0);
        let rules: Vec<&str> = env.data["detections"]
            .as_array()
            .map(|a| a.iter().filter_map(|d| d["rule"].as_str()).collect())
            .unwrap_or_default();
        let has_correlated_rule = rules.contains(&CORRELATED_RULE);
        if has_correlated_rule {
            correlated += 1;
        }
        println!(
            "pid={pid} image={image} {daddr}:{dport} attributed={is_attributed} \
             severity_id={} detections={:?}",
            env.severity_id, rules
        );
    }

    // 5) Self-assert the CRITICAL thing: correlation is now order-independent
    // (Task 1 buffers an unattributed NetConnect and re-attributes it when its
    // ProcessExec arrives within the grace window), so a strict MAJORITY of
    // the curl attempts must correlate — allowing exactly one straggler (e.g.
    // a pid evicted before its pair completed, or a curl that failed to
    // exec). Pre-fix, the cross-ring drain-order race capped this at 2 of 5;
    // requiring >= NUM_CURL_ATTEMPTS - 1 here means a regression back to that
    // racy behavior fails loudly instead of passing on a lucky >= 1.
    const REQUIRED_CORRELATED: usize = NUM_CURL_ATTEMPTS - 1;
    if correlated < REQUIRED_CORRELATED {
        eprintln!(
            "\nFAILURE: too few correlated attack-chain records were captured.\n\
             Captured {captured} Correlated Activity record(s) total, {attributed} attributed to \
             a process, but only {correlated} of {NUM_CURL_ATTEMPTS} curl attempts carried the \
             `{CORRELATED_RULE}` rule (required >= {REQUIRED_CORRELATED}, i.e. a strict majority \
             allowing one straggler). Correlation is now order-independent (CorrModule buffers an \
             unattributed NetConnect and re-attributes it when its ProcessExec lands within the \
             grace window), so this should correlate (essentially) every attempt, not the pre-fix \
             2/5 racy baseline. Check the process/net probes in crates/substrate/src/ebpf.rs and \
             CorrModule's buffer/re-attribution path in crates/modules/corr/src/lib.rs."
        );
        std::process::exit(1);
    }

    // 6) Success summary.
    println!(
        "\nOK: captured {captured} Correlated Activity; {correlated} of {NUM_CURL_ATTEMPTS} \
         attack-chain correlated ({CORRELATED_RULE}) — real eBPF process<->network correlation is \
         live and order-independent (>= {REQUIRED_CORRELATED} required, pre-fix baseline was 2/5)"
    );

    // Drop the substrate -> EbpfBus Drop stops collection + joins.
    drop(sub);
}
