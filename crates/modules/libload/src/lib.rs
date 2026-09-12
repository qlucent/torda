//! Library-load observer (pure core) — runtime-reachability telemetry.
//!
//! A shared library being loaded shows up on the substrate bus as an
//! `EventKind::FileOpen` (a read-open of the `.so`/`.dll`). `torda-mod-libload`
//! is the consumer that turns those specific opens into a small, deduplicated
//! stream of OCSF **Runtime Module Load** (9003) observations — the raw
//! telemetry the backend joins against the SBOM to confirm that a vulnerable
//! package's code was *actually loaded at runtime*, not merely installed.
//!
//! Deliberately distinct from the neighbouring file modules:
//! - `torda-mod-filemon` judges file *events* against a suspicious-path ruleset
//!   and emits **only when a rule fires**. It never reports a benign library
//!   open — exactly the events reachability needs.
//! - `torda-mod-corr` consumes `FileOpen` only to build attack-chains; it never
//!   re-emits a standalone file record.
//!
//! So this is a new, purpose-built observer. It is pure telemetry: **no rules,
//! no verdict, severity stays Informational.** The reachability *logic* (the
//! join to a package and the effect on a finding's score) lives server-side in
//! the FSL engine, never here.
//!
//! It reads only the shared bus and emits; it never touches the OS and never
//! opens a probe of its own.
//!
//! # Volume control: dedup by path
//! The live substrate emits hundreds of file events per second, and a busy host
//! loads the same handful of libraries constantly. Reachability only cares
//! *whether* a library was ever loaded, so this module emits **one** observation
//! per distinct library path for the life of the run and drops the rest. That
//! keeps the signal bounded (≈ the number of distinct libraries) without a
//! ruleset.
//!
//! # Honest limits (v0)
//! - **Substring/basename matching, not path canonicalization** — a `.so`/`.dll`
//!   basename is the whole test; it shares the un-canonicalized-path caveats of
//!   `torda-mod-filemon`.
//! - **Load ≈ open.** A `FileOpen` of a library is treated as a load. A process
//!   that opens a `.so` without mapping it (rare) would be over-counted; under
//!   upgrade-only reachability that only risks a false *confirmation*, which is
//!   why the backend still requires the library to belong to the flagged
//!   package before it upgrades anything.

use std::collections::HashSet;

/// True if `path`'s final component names a shared library — Linux `*.so` /
/// `*.so.<ver>` or Windows `*.dll` (case-insensitive).
fn is_shared_library(path: &str) -> bool {
    let base = path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase();
    base.ends_with(".so") || base.contains(".so.") || base.ends_with(".dll")
}

/// Handle one bus event: if it is a `FileOpen` of a shared library not seen
/// before, emit one Runtime Module Load (9003) observation. Every other event
/// (wrong kind, non-library path, missing path, or a repeat) is dropped without
/// emitting. `seen` carries the dedup state across the task's lifetime.
fn handle_event(
    ev: &torda_core::SubstrateEvent,
    seen: &mut HashSet<String>,
    meta: &torda_ocsf::Metadata,
    device: &torda_ocsf::Device,
    emitter: &dyn torda_core::OcsfEmitter,
) {
    // A library load is a read-open; FileWrite and everything else are not ours.
    if ev.kind != torda_core::EventKind::FileOpen {
        return;
    }
    let path = match ev.fields.get("path").and_then(serde_json::Value::as_str) {
        Some(s) => s,
        None => return,
    };
    if !is_shared_library(path) {
        return;
    }
    // Dedup: one observation per distinct library path for the run.
    if !seen.insert(path.to_string()) {
        return;
    }

    let pid = ev.fields.get("pid").and_then(serde_json::Value::as_u64);
    let image = ev.fields.get("image").and_then(serde_json::Value::as_str);

    let env = torda_ocsf::OcsfEnvelope::new(
        torda_ocsf::class::RUNTIME_MODULE_LOAD,
        "Runtime Module Load",
        meta.clone(),
        device.clone(),
        serde_json::json!({
            "module": { "path": path },
            "pid": pid,
            "image": image,
        }),
    );
    // Pure telemetry — severity stays Informational (OcsfEnvelope::new default 1).
    emitter.emit(env);
}

// ---------------- Module ----------------

/// Subscribes to `FileOpen` and emits one OCSF Runtime Module Load (9003)
/// observation per distinct shared-library path loaded at runtime.
pub struct LibLoadModule {
    ctx: Option<torda_core::ModuleCtx>,
    /// Signals the background task to stop; `true` == please exit.
    stop_tx: Option<tokio::sync::watch::Sender<bool>>,
    /// Handle to the bus-reading task, awaited (bounded) on `stop`.
    task: Option<tokio::task::JoinHandle<()>>,
}

impl LibLoadModule {
    pub fn new() -> Self {
        Self {
            ctx: None,
            stop_tx: None,
            task: None,
        }
    }
}

impl Default for LibLoadModule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl torda_core::Module for LibLoadModule {
    fn id(&self) -> torda_core::ModuleId {
        "libload".to_string()
    }

    async fn init(&mut self, ctx: torda_core::ModuleCtx) -> anyhow::Result<()> {
        self.ctx = Some(ctx);
        Ok(())
    }

    async fn start(&mut self) -> anyhow::Result<()> {
        let ctx = self
            .ctx
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("libload: init before start"))?;

        // Subscribe BEFORE spawning; capture only what the task needs so it owns
        // no ModuleCtx reference and stays 'static.
        let mut rx = ctx.bus.subscribe(&[torda_core::EventKind::FileOpen]);
        let meta = ctx.meta();
        let device = ctx.snapshot.device();
        let emitter = ctx.emitter.clone();

        let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            let mut seen: HashSet<String> = HashSet::new();
            loop {
                tokio::select! {
                    _ = stop_rx.changed() => {
                        if *stop_rx.borrow() {
                            break;
                        }
                    }
                    r = rx.recv() => match r {
                        Ok(ev) => handle_event(&ev, &mut seen, &meta, &device, emitter.as_ref()),
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    },
                }
            }
        });

        self.stop_tx = Some(stop_tx);
        self.task = Some(task);
        Ok(())
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(true);
        }
        if let Some(task) = self.task.take() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), task).await;
        }
        Ok(())
    }

    fn health(&self) -> torda_core::ModuleHealth {
        torda_core::ModuleHealth {
            ok: self.ctx.is_some(),
            detail: "library-load observer ready".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use torda_core::{
        EventBus, EventKind, Module, OcsfEmitter, ResourceBudget, ResourceGovernor,
        ResourceSampler, ResourceUsage, SubstrateEvent,
    };

    #[derive(Default)]
    struct CapturingEmitter {
        emitted: Mutex<Vec<torda_ocsf::OcsfEnvelope>>,
    }
    impl OcsfEmitter for CapturingEmitter {
        fn emit(&self, rec: torda_ocsf::OcsfEnvelope) {
            self.emitted.lock().unwrap().push(rec);
        }
    }

    fn meta() -> torda_ocsf::Metadata {
        torda_ocsf::Metadata {
            product: "torda".into(),
            version: "0".into(),
            tenant_id: "t".into(),
        }
    }
    fn device() -> torda_ocsf::Device {
        torda_ocsf::Device {
            hostname: "host-A".into(),
            os: "Linux".into(),
            os_version: "1".into(),
        }
    }

    fn open_event(path: &str) -> SubstrateEvent {
        SubstrateEvent {
            kind: EventKind::FileOpen,
            ts: 1000,
            fields: serde_json::json!({ "pid": 1234, "image": "curl", "path": path, "op": "open" }),
        }
    }

    fn drain(cap: &CapturingEmitter) -> Vec<torda_ocsf::OcsfEnvelope> {
        cap.emitted.lock().unwrap().clone()
    }

    #[test]
    fn library_open_emits_one_9003_with_module_path() {
        let cap = CapturingEmitter::default();
        let mut seen = HashSet::new();
        handle_event(
            &open_event("/usr/lib/x86_64-linux-gnu/libssl.so.3"),
            &mut seen,
            &meta(),
            &device(),
            &cap,
        );
        let out = drain(&cap);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].class_uid, torda_ocsf::class::RUNTIME_MODULE_LOAD);
        assert_eq!(out[0].class_name, "Runtime Module Load");
        assert_eq!(out[0].severity_id, 1, "telemetry, not a detection");
        assert_eq!(
            out[0].data["module"]["path"],
            "/usr/lib/x86_64-linux-gnu/libssl.so.3"
        );
        assert_eq!(out[0].data["pid"], 1234);
        assert_eq!(out[0].data["image"], "curl");
        assert_eq!(out[0].device.hostname, "host-A");
    }

    #[test]
    fn non_library_open_emits_nothing() {
        let cap = CapturingEmitter::default();
        let mut seen = HashSet::new();
        handle_event(
            &open_event("/etc/passwd"),
            &mut seen,
            &meta(),
            &device(),
            &cap,
        );
        handle_event(
            &open_event("/usr/bin/curl"),
            &mut seen,
            &meta(),
            &device(),
            &cap,
        );
        assert!(drain(&cap).is_empty());
    }

    #[test]
    fn file_write_of_a_library_is_ignored() {
        let cap = CapturingEmitter::default();
        let mut seen = HashSet::new();
        let mut ev = open_event("/usr/lib/libssl.so.3");
        ev.kind = EventKind::FileWrite;
        handle_event(&ev, &mut seen, &meta(), &device(), &cap);
        assert!(
            drain(&cap).is_empty(),
            "only reads (FileOpen) are library loads"
        );
    }

    #[test]
    fn repeated_load_of_same_library_dedups_to_one() {
        let cap = CapturingEmitter::default();
        let mut seen = HashSet::new();
        for _ in 0..5 {
            handle_event(
                &open_event("/usr/lib/libssl.so.3"),
                &mut seen,
                &meta(),
                &device(),
                &cap,
            );
        }
        assert_eq!(drain(&cap).len(), 1, "one observation per distinct library");
    }

    #[test]
    fn distinct_libraries_each_emit_once() {
        let cap = CapturingEmitter::default();
        let mut seen = HashSet::new();
        handle_event(
            &open_event("/usr/lib/libssl.so.3"),
            &mut seen,
            &meta(),
            &device(),
            &cap,
        );
        handle_event(
            &open_event("/usr/lib/libcrypto.so.3"),
            &mut seen,
            &meta(),
            &device(),
            &cap,
        );
        assert_eq!(drain(&cap).len(), 2);
    }

    #[test]
    fn malformed_event_without_path_is_skipped() {
        let cap = CapturingEmitter::default();
        let mut seen = HashSet::new();
        let ev = SubstrateEvent {
            kind: EventKind::FileOpen,
            ts: 1,
            fields: serde_json::json!({ "pid": 1 }),
        };
        handle_event(&ev, &mut seen, &meta(), &device(), &cap);
        assert!(drain(&cap).is_empty());
    }

    // --- wiring: subscribe -> publish -> emit through the real Module lifecycle ---

    struct TestSampler;
    impl ResourceSampler for TestSampler {
        fn sample(&self) -> ResourceUsage {
            ResourceUsage::ZERO
        }
    }

    #[tokio::test]
    async fn module_emits_9003_for_a_published_library_open() {
        let bus = torda_substrate::StubBus::new();
        let snapshot = torda_substrate::StubSnapshot::with_provider(Box::new(
            torda_substrate::packages::EmptyProvider,
        ));
        let cap = Arc::new(CapturingEmitter::default());
        let ctx = torda_core::ModuleCtx {
            bus: bus.clone(),
            snapshot,
            emitter: cap.clone(),
            governor: Arc::new(ResourceGovernor::new(
                ResourceBudget::default(),
                Box::new(TestSampler),
            )),
            tenant_id: "t".into(),
            product: "torda".into(),
            version: "0".into(),
        };

        let mut m = LibLoadModule::new();
        m.init(ctx).await.unwrap();
        m.start().await.unwrap();

        // Publish a couple of library opens plus noise, then let the task run.
        bus.publish(open_event("/usr/lib/x86_64-linux-gnu/libssl.so.3"));
        bus.publish(open_event("/etc/passwd"));
        bus.publish(open_event("/usr/lib/x86_64-linux-gnu/libssl.so.3")); // dup

        for _ in 0..100 {
            if !cap.emitted.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        m.stop().await.unwrap();

        let out = drain(&cap);
        assert_eq!(
            out.len(),
            1,
            "one 9003 for the library open (dup + non-lib dropped)"
        );
        assert_eq!(out[0].class_uid, torda_ocsf::class::RUNTIME_MODULE_LOAD);
    }
}
