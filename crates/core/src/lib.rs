//! Core runtime contracts. Deterministic; no LLM, no network in hot paths.
//! Every capability is a `Module` consuming the shared substrate.

mod resource;
pub use resource::*;

use async_trait::async_trait;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant};
use torda_ocsf::OcsfEnvelope;

pub type ModuleId = String;

// ---------------- Substrate: event bus ----------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventKind {
    ProcessExec,
    ProcessExit,
    FileOpen,
    FileWrite,
    NetConnect,
    AuthEvent,
}

#[derive(Clone, Debug)]
pub struct SubstrateEvent {
    pub kind: EventKind,
    pub ts: i64,
    pub fields: serde_json::Value,
}

/// One probe set publishes here; many modules subscribe. No module
/// is allowed to open kernel probes directly — this is the only door.
pub trait EventBus: Send + Sync {
    fn publish(&self, ev: SubstrateEvent);
    fn subscribe(&self, kinds: &[EventKind]) -> tokio::sync::broadcast::Receiver<SubstrateEvent>;
}

// ---------------- Substrate: state snapshot ----------------

#[derive(Clone, Debug)]
pub struct Rows(pub Vec<serde_json::Value>);

/// osquery-style current-state tables. Asset/Vuln/Config read this;
/// they never query the OS directly. (Predicate pushdown is a TODO.)
pub trait SnapshotProvider: Send + Sync {
    fn query(&self, table: &str) -> anyhow::Result<Rows>;
    fn device(&self) -> torda_ocsf::Device;
}

// ---------------- Output ----------------

pub trait OcsfEmitter: Send + Sync {
    fn emit(&self, rec: OcsfEnvelope);
}

// ---------------- Module contract ----------------

#[derive(Clone)]
pub struct ModuleCtx {
    pub bus: Arc<dyn EventBus>,
    pub snapshot: Arc<dyn SnapshotProvider>,
    pub emitter: Arc<dyn OcsfEmitter>,
    pub governor: Arc<ResourceGovernor>,
    pub tenant_id: String,
    pub product: String,
    pub version: String,
}

impl ModuleCtx {
    pub fn meta(&self) -> torda_ocsf::Metadata {
        torda_ocsf::Metadata {
            product: self.product.clone(),
            version: self.version.clone(),
            tenant_id: self.tenant_id.clone(),
        }
    }
}

pub struct ModuleHealth {
    pub ok: bool,
    pub detail: String,
}

#[async_trait]
pub trait Module: Send + Sync {
    fn id(&self) -> ModuleId;
    fn config_schema(&self) -> serde_json::Value {
        serde_json::json!({})
    }
    async fn init(&mut self, ctx: ModuleCtx) -> anyhow::Result<()>;
    async fn start(&mut self) -> anyhow::Result<()>;
    async fn stop(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
    fn health(&self) -> ModuleHealth;

    /// Re-collect current state and emit ONLY what changed since the last
    /// collection. Snapshot modules (asset/health/vuln/compliance/drift/fim)
    /// override this so a daemon re-evaluates the world on an interval —
    /// crucially FIM/drift, whose whole purpose is detecting change AFTER
    /// startup. Event-driven modules (procmon/netmon/filemon/corr/libload) stream
    /// continuously and keep the default no-op. The [`ModuleManager`] scheduler
    /// calls this on [`refresh_interval`](Self::refresh_interval).
    async fn refresh(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    /// How often [`refresh`](Self::refresh) should run. `None` (the default) means
    /// NEVER — one-shot at start, today's behavior — which every event module and
    /// any snapshot module configured `off` returns. A snapshot module returns its
    /// effective interval (its sensible built-in default, or a config override
    /// applied via [`set_refresh_interval`](Self::set_refresh_interval)).
    fn refresh_interval(&self) -> Option<Duration> {
        None
    }

    /// Override the periodic-refresh interval from config (`Some(0s)` / `off` →
    /// `None`, restoring one-shot behavior). Default no-op: event modules ignore
    /// it. Called by [`ModuleManager::apply_refresh_overrides`] BEFORE `start`.
    fn set_refresh_interval(&mut self, _interval: Option<Duration>) {}
}

/// A per-module gate that emits an OCSF envelope ONLY when the payload changed
/// since the last emit through it — so a periodic [`Module::refresh`] does not
/// re-emit an identical finding set every interval. It hashes the emitted `data`;
/// the FIRST emit always fires (nothing to compare against), and a subsequent one
/// fires only when the hash differs. The diff is at the emit-payload granularity:
/// a snapshot module re-emits its whole record set exactly when something in it
/// changed.
#[derive(Default)]
pub struct ChangeGate {
    last: Option<u64>,
}

impl ChangeGate {
    pub fn new() -> Self {
        Self::default()
    }

    /// Emit `data` as `class_uid`/`class_name` (with `ctx`'s meta + device) via
    /// the ctx emitter IFF it differs from the last payload emitted through this
    /// gate. Returns `true` when it emitted.
    pub fn emit_if_changed(
        &mut self,
        ctx: &ModuleCtx,
        class_uid: u32,
        class_name: &str,
        data: serde_json::Value,
    ) -> bool {
        let h = stable_hash(&data);
        if self.last == Some(h) {
            return false;
        }
        self.last = Some(h);
        ctx.emitter.emit(OcsfEnvelope::new(
            class_uid,
            class_name,
            ctx.meta(),
            ctx.snapshot.device(),
            data,
        ));
        true
    }
}

/// Stable content hash of an OCSF `data` payload, used by [`ChangeGate`] to decide
/// whether a refresh changed anything. Hashes the serialized JSON: snapshot
/// modules build their payload deterministically (same field order each run), so
/// an unchanged world serializes identically and hashes equal.
fn stable_hash(data: &serde_json::Value) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    serde_json::to_string(data)
        .unwrap_or_default()
        .hash(&mut hasher);
    hasher.finish()
}

// ---------------- Severity scale ----------------

/// Canonical OCSF `severity_id` values, defined ONCE here and shared by every module.
/// (OCSF severity_id: 1 = Informational, 2 = Low, 3 = Medium, 4 = High.) `u8` to match
/// `torda_ocsf::OcsfEnvelope::severity_id` and the existing `> SEV_INFORMATIONAL` comparisons.
pub mod severity {
    pub const SEV_INFORMATIONAL: u8 = 1;
    pub const SEV_LOW: u8 = 2;
    pub const SEV_MEDIUM: u8 = 3;
    pub const SEV_HIGH: u8 = 4;
}

// ---------------- Module manager ----------------

pub struct ModuleManager {
    ctx: ModuleCtx,
    modules: Vec<Box<dyn Module>>,
}

impl ModuleManager {
    pub fn new(ctx: ModuleCtx) -> Self {
        Self {
            ctx,
            modules: Vec::new(),
        }
    }

    /// Per-tenant policy decides which modules get registered.
    pub fn register(&mut self, m: Box<dyn Module>) {
        self.modules.push(m);
    }

    pub async fn init_all(&mut self) -> anyhow::Result<()> {
        for m in self.modules.iter_mut() {
            m.init(self.ctx.clone()).await?;
        }
        Ok(())
    }

    pub async fn start_all(&mut self) -> anyhow::Result<()> {
        for m in self.modules.iter_mut() {
            m.start().await?;
        }
        Ok(())
    }

    pub async fn stop_all(&mut self) -> anyhow::Result<()> {
        for m in self.modules.iter_mut() {
            m.stop().await?;
        }
        Ok(())
    }

    pub fn health(&self) -> Vec<(ModuleId, ModuleHealth)> {
        self.modules.iter().map(|m| (m.id(), m.health())).collect()
    }

    /// Apply per-module refresh-interval overrides (module id → seconds; `0` =
    /// off/one-shot) from config, BEFORE `start_all`. A module whose id is absent
    /// from the map keeps its built-in default interval; event modules ignore the
    /// override (default no-op setter). An unknown id in the map is ignored.
    pub fn apply_refresh_overrides(&mut self, overrides: &std::collections::HashMap<String, u64>) {
        for m in self.modules.iter_mut() {
            if let Some(&secs) = overrides.get(&m.id()) {
                let interval = (secs > 0).then(|| Duration::from_secs(secs));
                m.set_refresh_interval(interval);
            }
        }
    }

    /// Drive periodic [`Module::refresh`] for every module that declares a
    /// [`refresh_interval`](Module::refresh_interval), each on its own cadence,
    /// FOREVER — the caller (the daemon) races this against its shutdown signal and
    /// drops the future to stop. With NO module scheduled it idles (never returns
    /// on its own, so it can never end a `select!` prematurely). A single
    /// `refresh` erroring is logged and never aborts the loop or the others.
    ///
    /// Sequential by construction (one `&mut self`): snapshot refreshes are
    /// periodic and cheap, so a single scheduler thread is simpler and avoids the
    /// shared-mutable-state a per-module task would need.
    pub async fn run_periodic(&mut self) {
        // (module index, interval, next-due instant) for each schedulable module.
        let mut schedule: Vec<(usize, Duration, Instant)> = self
            .modules
            .iter()
            .enumerate()
            .filter_map(|(i, m)| m.refresh_interval().map(|iv| (i, iv, Instant::now() + iv)))
            .collect();

        if schedule.is_empty() {
            // Nothing to refresh — idle until the daemon's shutdown cancels us.
            std::future::pending::<()>().await;
            return;
        }

        loop {
            // The soonest-due entry.
            let idx = (0..schedule.len())
                .min_by_key(|&k| schedule[k].2)
                .expect("schedule is non-empty");
            let (mod_i, interval, due) = schedule[idx];
            let now = Instant::now();
            if due > now {
                tokio::time::sleep(due - now).await;
            }
            if let Err(e) = self.modules[mod_i].refresh().await {
                eprintln!("module {} refresh failed: {e}", self.modules[mod_i].id());
            }
            // Reschedule from NOW (drift-free relative to completion, and a slow
            // refresh can never build a backlog of overdue ticks).
            schedule[idx].2 = Instant::now() + interval;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// Pin the canonical OCSF severity scale so it can't drift silently —
    /// every module (procmon, netmon, corr) re-exports/imports these values.
    #[test]
    fn severity_scale_is_pinned() {
        assert_eq!(severity::SEV_INFORMATIONAL, 1);
        assert_eq!(severity::SEV_LOW, 2);
        assert_eq!(severity::SEV_MEDIUM, 3);
        assert_eq!(severity::SEV_HIGH, 4);
    }

    // ---- minimal substrate fakes for the refresh-framework tests ----

    #[derive(Default)]
    struct CapturingEmitter {
        emitted: Mutex<Vec<OcsfEnvelope>>,
    }
    impl OcsfEmitter for CapturingEmitter {
        fn emit(&self, rec: OcsfEnvelope) {
            self.emitted.lock().unwrap().push(rec);
        }
    }
    struct FakeBus;
    impl EventBus for FakeBus {
        fn publish(&self, _ev: SubstrateEvent) {}
        fn subscribe(&self, _k: &[EventKind]) -> tokio::sync::broadcast::Receiver<SubstrateEvent> {
            tokio::sync::broadcast::channel(1).1
        }
    }
    struct FakeSnapshot;
    impl SnapshotProvider for FakeSnapshot {
        fn query(&self, table: &str) -> anyhow::Result<Rows> {
            anyhow::bail!("no table {table}")
        }
        fn device(&self) -> torda_ocsf::Device {
            torda_ocsf::Device {
                hostname: "h".into(),
                os: "T".into(),
                os_version: "1".into(),
            }
        }
    }
    struct ZeroSampler;
    impl ResourceSampler for ZeroSampler {
        fn sample(&self) -> ResourceUsage {
            ResourceUsage::ZERO
        }
    }
    fn fake_ctx(emitter: Arc<CapturingEmitter>) -> ModuleCtx {
        ModuleCtx {
            bus: Arc::new(FakeBus),
            snapshot: Arc::new(FakeSnapshot),
            emitter,
            governor: Arc::new(ResourceGovernor::new(
                ResourceBudget::default(),
                Box::new(ZeroSampler),
            )),
            tenant_id: "t".into(),
            product: "torda".into(),
            version: "0".into(),
        }
    }

    /// The gate emits the FIRST payload, suppresses an identical repeat, and emits
    /// again when the payload changes.
    #[test]
    fn change_gate_emits_only_on_change() {
        let emitter = Arc::new(CapturingEmitter::default());
        let ctx = fake_ctx(emitter.clone());
        let mut gate = ChangeGate::new();

        assert!(gate.emit_if_changed(&ctx, 1, "X", serde_json::json!({"a":1})));
        assert!(!gate.emit_if_changed(&ctx, 1, "X", serde_json::json!({"a":1})));
        assert!(gate.emit_if_changed(&ctx, 1, "X", serde_json::json!({"a":2})));
        assert_eq!(emitter.emitted.lock().unwrap().len(), 2);
    }

    /// A test module that counts `refresh` calls and reports a configurable
    /// interval, to exercise the manager scheduler + override plumbing.
    struct CountingModule {
        interval: Option<Duration>,
        refreshes: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl Module for CountingModule {
        fn id(&self) -> ModuleId {
            "counter".into()
        }
        async fn init(&mut self, _ctx: ModuleCtx) -> anyhow::Result<()> {
            Ok(())
        }
        async fn start(&mut self) -> anyhow::Result<()> {
            Ok(())
        }
        async fn refresh(&mut self) -> anyhow::Result<()> {
            self.refreshes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn refresh_interval(&self) -> Option<Duration> {
            self.interval
        }
        fn set_refresh_interval(&mut self, interval: Option<Duration>) {
            self.interval = interval;
        }
        fn health(&self) -> ModuleHealth {
            ModuleHealth {
                ok: true,
                detail: String::new(),
            }
        }
    }

    /// A config override of `0` turns a module's interval OFF; a non-zero value
    /// sets it; an absent id leaves the built-in default untouched.
    #[test]
    fn apply_refresh_overrides_maps_zero_to_off() {
        let emitter = Arc::new(CapturingEmitter::default());
        let mut mgr = ModuleManager::new(fake_ctx(emitter));
        mgr.register(Box::new(CountingModule {
            interval: Some(Duration::from_secs(300)),
            refreshes: Arc::new(AtomicUsize::new(0)),
        }));
        let mut overrides = HashMap::new();
        overrides.insert("counter".to_string(), 0u64);
        mgr.apply_refresh_overrides(&overrides);
        assert_eq!(mgr.modules[0].refresh_interval(), None, "0 → off");

        overrides.insert("counter".to_string(), 42u64);
        mgr.apply_refresh_overrides(&overrides);
        assert_eq!(
            mgr.modules[0].refresh_interval(),
            Some(Duration::from_secs(42))
        );
    }

    /// `run_periodic` drives `refresh` on the interval. Under paused time the
    /// scheduler is deterministic: advancing ~3 intervals yields ~3 refreshes, and
    /// the loop never returns on its own (the timer arm ends the select).
    #[tokio::test(start_paused = true)]
    async fn run_periodic_drives_refresh_on_interval() {
        let refreshes = Arc::new(AtomicUsize::new(0));
        let emitter = Arc::new(CapturingEmitter::default());
        let mut mgr = ModuleManager::new(fake_ctx(emitter));
        mgr.register(Box::new(CountingModule {
            interval: Some(Duration::from_millis(100)),
            refreshes: refreshes.clone(),
        }));

        tokio::select! {
            _ = mgr.run_periodic() => unreachable!("run_periodic never returns on its own"),
            _ = tokio::time::sleep(Duration::from_millis(350)) => {}
        }
        // Ticks at t=100/200/300ms → 3 refreshes before the 350ms arm fires.
        assert_eq!(refreshes.load(Ordering::SeqCst), 3);
    }

    /// With NO schedulable module, `run_periodic` idles (never returns), so it can
    /// never end a `select!` prematurely — the timer arm always wins.
    #[tokio::test(start_paused = true)]
    async fn run_periodic_idles_when_nothing_scheduled() {
        let emitter = Arc::new(CapturingEmitter::default());
        let mut mgr = ModuleManager::new(fake_ctx(emitter));
        mgr.register(Box::new(CountingModule {
            interval: None,
            refreshes: Arc::new(AtomicUsize::new(0)),
        }));
        tokio::select! {
            _ = mgr.run_periodic() => unreachable!("must idle, not return"),
            _ = tokio::time::sleep(Duration::from_secs(10)) => {}
        }
    }
}
