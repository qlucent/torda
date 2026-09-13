//! eBPF runtime library-load proof demo (behind the `linux-ebpf` feature) — the
//! reachability-telemetry counterpart to `file-ebpf-demo.rs`.
//!
//! PURPOSE: prove the FULL agent path for runtime-reachability telemetry — the
//! real `EbpfBus` captures live `openat(2)` of shared libraries, the real
//! `torda-mod-libload` `LibLoadModule` filters those to library loads, dedups,
//! and emits OCSF **Runtime Module Load (9003)** records with the loaded
//! library's path. This is what the backend later joins against the SBOM to
//! confirm a vulnerable package's code was actually loaded, not just installed.
//!
//! HONEST about which path it is on:
//!   * NON-root (or feature off / non-Linux): the substrate fell back to the
//!     stub bus (`bus_label != "ebpf"`). No real OS events exist there, so the
//!     demo prints a "run as root in WSL" instruction and exits 0 — it never
//!     asserts or fakes success. (This is the path the Windows host runs.)
//!   * ROOT with `--features linux-ebpf`: the real `EbpfBus` started. The demo
//!     wires the REAL `LibLoadModule` to it with a capturing emitter, then
//!     spawns a dynamically-linked child (`cat`) a few times so the loader
//!     `openat`s its shared-library dependencies (libc, etc.). It collects the
//!     module's emitted 9003 records for a bounded window and self-asserts at
//!     least one whose `module.path` is a real shared library — proving the
//!     capture→filter→emit chain, not merely that the probe attached.
//!
//! Every wait is bounded; neither path can hang. DEMO-ONLY: no library edited.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use torda_core::{
    Module, ModuleCtx, OcsfEmitter, ResourceBudget, ResourceGovernor, ResourceSampler,
    ResourceUsage,
};
use torda_ocsf::OcsfEnvelope;

const CAPTURE_WINDOW: Duration = Duration::from_secs(3);
const NUM_TRIGGERS: usize = 4;

/// Collects the module's emitted OCSF records for inspection.
#[derive(Default)]
struct CapturingEmitter {
    emitted: Mutex<Vec<OcsfEnvelope>>,
}
impl OcsfEmitter for CapturingEmitter {
    fn emit(&self, rec: OcsfEnvelope) {
        self.emitted.lock().unwrap().push(rec);
    }
}

/// Zero-cost resource sampler for the demo governor.
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
            "\neBPF event bus not active (running on the '{}' bus).\n\
             To see REAL runtime library-load (9003) telemetry, build+run as ROOT in WSL:\n\
             \x20   CARGO_TARGET_DIR=$HOME/torda-ebpf-target cargo run -p torda --features linux-ebpf --bin libload-ebpf-demo\n\
             (loading eBPF requires root/CAP_BPF; use e.g. `wsl -u root`.)",
            sub.bus_label
        );
        return;
    }

    // 3) eBPF path (ROOT): wire the REAL LibLoadModule to the live bus.
    println!(
        "eBPF collection live — running the real LibLoadModule and capturing 9003 observations for {CAPTURE_WINDOW:?}..."
    );

    let cap = Arc::new(CapturingEmitter::default());
    let ctx = ModuleCtx {
        bus: sub.bus.clone(),
        // Only device() is read from the snapshot; a stub snapshot gives a real host/os.
        snapshot: torda_substrate::StubSnapshot::new(),
        emitter: cap.clone(),
        governor: Arc::new(ResourceGovernor::new(
            ResourceBudget::default(),
            Box::new(ZeroSampler),
        )),
        tenant_id: "demo".to_string(),
        product: "torda".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };

    let mut module = torda_mod_libload::LibLoadModule::new();
    module.init(ctx).await.expect("libload init");
    module.start().await.expect("libload start");

    // Trigger library loads: spawn a dynamically-linked child a few times so the
    // loader openat()s its .so dependencies (libc, etc.), which the eBPF probe
    // captures and the module turns into 9003 observations.
    for _ in 0..NUM_TRIGGERS {
        let _ = std::process::Command::new("cat")
            .arg("/proc/version")
            .output();
        std::thread::sleep(Duration::from_millis(200));
    }

    // Let the module's task drain the bus for the rest of the window.
    tokio::time::sleep(CAPTURE_WINDOW).await;

    // Stop the module (ends its task, drops its bus handle) before tearing down.
    module.stop().await.expect("libload stop");

    let observations = cap.emitted.lock().unwrap().clone();
    let libs: Vec<&OcsfEnvelope> = observations
        .iter()
        .filter(|e| e.class_uid == torda_ocsf::class::RUNTIME_MODULE_LOAD)
        .collect();

    for e in &libs {
        println!(
            "9003 module load: path={} pid={} image={}",
            e.data["module"]["path"].as_str().unwrap_or(""),
            e.data["pid"]
                .as_i64()
                .map(|v| v.to_string())
                .unwrap_or_default(),
            e.data["image"].as_str().unwrap_or(""),
        );
    }

    // 4) Self-assert: at least one real shared-library load was observed and
    // emitted as 9003. The module only emits for .so/.dll paths, so any 9003 is
    // a genuine library-load observation.
    if libs.is_empty() {
        eprintln!(
            "\nFAILURE: eBPF collection was live but the LibLoadModule emitted ZERO Runtime\n\
             Module Load (9003) records. A dynamically-linked child was spawned, so its\n\
             library openat()s should have been captured — check the FileOpen decode in\n\
             crates/substrate/src/ebpf.rs (map_file_record) and the module's is_shared_library\n\
             filter in crates/modules/libload/src/lib.rs."
        );
        drop(sub);
        std::process::exit(1);
    }

    println!(
        "\nOK: LibLoadModule emitted {} runtime library-load observation(s) from real eBPF\n\
         FileOpen events — the reachability telemetry chain (capture -> filter -> 9003) is live.",
        libs.len()
    );

    // Drop the substrate -> EbpfBus Drop stops collection + joins.
    drop(sub);
}
