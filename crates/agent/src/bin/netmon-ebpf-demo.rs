//! P3f-1 Task 3 LIVE eBPF network-detection proof (behind the `linux-ebpf`
//! feature) — proves REAL `NetConnect` events flow through the REAL
//! `NetMonModule` into OCSF Network Activity detections over the real Linux
//! eBPF EventBus.
//!
//! PURPOSE: `net-demo.rs` (Task 2) only proves the eBPF connect(2) probe
//! extracts `daddr`/`dport` correctly — it reads the raw bus directly and
//! never runs a module, so it cannot prove detection. This binary combines
//! that connection-generation pattern with `procmon-lifecycle-ebpf-demo.rs`'s
//! pattern of running the REAL module (this time `torda_mod_netmon::NetMonModule`,
//! the exact module the agent registers) against the real substrate + a
//! capturing emitter. The module subscribes to `NetConnect` on the real bus,
//! runs its pure `assess` ruleset per connection, and emits an OCSF Network
//! Activity envelope per connect — benign loopback traffic stays
//! Informational/no-detections, while a planted suspicious-port connection to
//! a public (TEST-NET-3) address is flagged `suspicious_port` +
//! `suspicious_port_to_external` at High severity.
//!
//! HONEST about which path it is on (mirrors `procmon-lifecycle-ebpf-demo.rs`
//! and `net-demo.rs`):
//!   * NON-root (or feature off / non-Linux, e.g. default Windows):
//!     `Substrate::for_this_platform()` fell back to the stub bus
//!     (`bus_label != "ebpf"`). There are no real OS events to detect on, so
//!     the demo prints a clear "run as root" instruction and exits 0. It does
//!     NOT assert or fake a detection. THIS is the path a non-root (default
//!     Windows) run verifies.
//!   * ROOT with `--features linux-ebpf` (Linux, e.g. via `wsl -u root`): the
//!     real `EbpfBus` started (`bus_label == "ebpf"`). The demo wires a REAL
//!     `NetMonModule` onto the real substrate + a capturing emitter,
//!     subscribes it to the bus BEFORE generating any connections, then:
//!       - binds a local `TcpListener` on an OS-assigned loopback port and
//!         connects to it a couple of times (benign, informational);
//!       - `connect_timeout`s a few times to `203.0.113.1:4444` (TEST-NET-3,
//!         RFC5737 — non-routable, so the connect fails/times out, but
//!         `sys_enter_connect` fires on syscall ENTRY regardless of outcome,
//!         so eBPF still captures `daddr=203.0.113.1 dport=4444`).
//!
//!     It then self-asserts at least one captured Network Activity envelope
//!     whose `daddr == "203.0.113.1"` AND `dport == 4444` AND whose
//!     `detections` carries a `suspicious_port` rule hit — proving the
//!     planted suspicious-external connect was captured over the REAL eBPF
//!     bus AND flagged by the REAL module's ruleset. Zero such events => a
//!     loud non-zero failure (never hidden).
//!
//! Every wait is bounded by a timeout so NEITHER path can hang: the loopback
//! connects target our own already-bound listener (no accept-thread is even
//! needed — a connect to a listening socket completes via the kernel backlog
//! without a userspace `accept()`), and the suspicious-external connect uses
//! `connect_timeout` with a short duration so a non-routable address can never
//! block. The capture window itself is a deadline-bounded poll loop, exactly
//! like `procmon-lifecycle-ebpf-demo.rs`. Dropping the substrate tears the
//! eBPF collection down (`EbpfBus` `Drop` stops + joins).
//!
//! DEMO-ONLY: no library was edited — it uses only the public `NetMonModule` +
//! `ModuleCtx` + `Substrate`.

use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use torda_core::{
    Module, ModuleCtx, OcsfEmitter, ResourceBudget, ResourceGovernor, ResourceSampler,
    ResourceUsage,
};
use torda_ocsf::OcsfEnvelope;

/// Total wall-clock window to wait for the capturing emitter to accumulate
/// records on the root path.
const CAPTURE_WINDOW: Duration = Duration::from_secs(3);
/// Poll interval while waiting for the capturing emitter to fill up.
const POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Number of deterministic benign loopback connections to generate.
const NUM_LOOPBACK_CONNECTS: usize = 2;
/// Number of deterministic suspicious-external connect attempts to generate.
const NUM_SUSPICIOUS_CONNECTS: usize = 3;
/// TEST-NET-3 (RFC5737) — documented non-routable, so this address is safe to
/// dial from any host without reaching a real third party; netmon classifies
/// it as "external" (not private/loopback/link-local).
const SUSPICIOUS_ADDR: &str = "203.0.113.1:4444";
const SUSPICIOUS_DADDR: &str = "203.0.113.1";
const SUSPICIOUS_DPORT: u64 = 4444;
/// Small bound so a non-routable destination can never block the demo.
const CONNECT_TIMEOUT: Duration = Duration::from_millis(50);

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
            "\neBPF event bus not active (running on the '{}' bus) — no real network events to \
             detect on.\n\
             To see REAL Linux network-connect DETECTION (the real NetMonModule flagging a\n\
             planted suspicious-external connect), build then run as ROOT in WSL:\n\
             \x20   CARGO_TARGET_DIR=$HOME/torda-ebpf-target cargo run -p torda --features linux-ebpf \\\n\
             \x20       --bin netmon-ebpf-demo\n\
             \x20   (or: wsl -u root)\n\
             (loading eBPF requires root/CAP_BPF.)",
            sub.bus_label
        );
        // Nothing to assert: there are no real OS events on the stub bus.
        return;
    }

    // 3) eBPF path (ROOT): run the REAL NetMonModule against the real bus and
    // prove real network-connect detection.
    println!(
        "eBPF collection live — wiring the real NetMonModule onto the real bus and capturing \
         real NetConnect-derived detections for up to {CAPTURE_WINDOW:?}..."
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

    // The SAME real module the agent registers. Subscribe BEFORE generating
    // connections so we don't miss any of them.
    let mut netmon = torda_mod_netmon::NetMonModule::new();
    netmon.init(ctx).await.expect("netmon init");
    netmon
        .start()
        .await
        .expect("netmon start (subscribes before we connect)");

    // 3a) Benign loopback: bind an OS-assigned port and connect to it a
    // couple of times. A connect to an already-listening socket completes via
    // the kernel backlog without a userspace `accept()`, so no accept thread
    // is needed at all here — avoiding the net-demo unbounded-accept hang
    // entirely.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0 failed");
    let loopback_port = listener.local_addr().expect("local_addr failed").port();
    println!("benign: listening on 127.0.0.1:{loopback_port}");
    for _ in 0..NUM_LOOPBACK_CONNECTS {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", loopback_port)) {
            drop(stream);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // Keep the listener alive for the whole demo so nothing resets in-flight
    // connections; it is dropped at the end of `main` (bounded lifetime).
    drop(listener);

    // 3b) Suspicious external: connect_timeout a few times to a TEST-NET-3
    // (RFC5737, non-routable) address on a known C2/backdoor port. The
    // connect will FAIL/time out — we deliberately ignore the result — but
    // `sys_enter_connect` fires on syscall ENTRY regardless, so eBPF still
    // captures `daddr=203.0.113.1 dport=4444`.
    let suspicious_target: std::net::SocketAddr =
        SUSPICIOUS_ADDR.parse().expect("valid socket addr literal");
    println!("suspicious: connect_timeout x{NUM_SUSPICIOUS_CONNECTS} to {SUSPICIOUS_ADDR} (expected to fail/time out; syscall still fires)");
    for _ in 0..NUM_SUSPICIOUS_CONNECTS {
        let _ = TcpStream::connect_timeout(&suspicious_target, CONNECT_TIMEOUT);
    }

    // Collect for a bounded window: poll the capturing emitter's Vec rather
    // than a raw rx, since the module itself is draining the bus.
    let deadline = tokio::time::Instant::now() + CAPTURE_WINDOW;
    while tokio::time::Instant::now() < deadline {
        let flagged_seen = records.lock().unwrap().iter().any(|env| {
            env.data["connection"]["daddr"] == SUSPICIOUS_DADDR
                && env.data["connection"]["dport"] == SUSPICIOUS_DPORT
        });
        if flagged_seen {
            break;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    netmon.stop().await.expect("netmon clean shutdown");

    // 4) Inspect the captured OCSF envelopes.
    let emitted = records.lock().unwrap().clone();
    let mut captured = 0usize;
    let mut flagged = 0usize;
    let mut suspicious_external_flagged = false;

    for env in emitted.iter() {
        // Only Network Activity records derived from NetConnect carry this shape.
        if env.data["activity"] != "connect" {
            continue;
        }
        captured += 1;
        let daddr = env.data["connection"]["daddr"].as_str().unwrap_or("?");
        let dport = env.data["connection"]["dport"].as_u64().unwrap_or(0);
        let rules: Vec<&str> = env.data["detections"]
            .as_array()
            .map(|a| a.iter().filter_map(|d| d["rule"].as_str()).collect())
            .unwrap_or_default();
        if !rules.is_empty() {
            flagged += 1;
        }
        if daddr == SUSPICIOUS_DADDR
            && dport == SUSPICIOUS_DPORT
            && rules.contains(&"suspicious_port")
        {
            suspicious_external_flagged = true;
        }
        println!(
            "daddr={daddr} dport={dport} severity_id={} detections={:?}",
            env.severity_id, rules
        );
    }

    // 5) Self-assert the CRITICAL thing: the planted suspicious-external
    // connect was captured over the REAL eBPF bus AND flagged by the REAL
    // module's ruleset. Missing => loud non-zero failure, never hidden.
    if !suspicious_external_flagged {
        eprintln!(
            "\nFAILURE: the planted suspicious-external connect was not captured+flagged.\n\
             Captured {captured} Network Activity record(s) total, {flagged} flagged with at \
             least one detection, but NONE matched daddr==\"{SUSPICIOUS_DADDR}\" AND \
             dport=={SUSPICIOUS_DPORT} with a `suspicious_port` rule hit. Expected the \
             connect_timeout attempts to {SUSPICIOUS_ADDR} to fire sys_enter_connect (syscall \
             entry, independent of connect success), flow through the real eBPF bus into \
             NetMonModule, and be flagged suspicious_port(_to_external) by `assess`. Check the \
             connect probe in crates/substrate/src/ebpf.rs and NetMonModule's subscribe/assess \
             path."
        );
        std::process::exit(1);
    }

    // 6) Success summary.
    println!(
        "\nOK: captured {captured} Network Activity; {flagged} flagged; the planted \
         203.0.113.1:4444 connect flagged suspicious_port(_to_external) — real eBPF network \
         detection is live"
    );

    // Drop the substrate -> EbpfBus Drop stops collection + joins.
    drop(sub);
}
