//! Network-discovery module. Reads the shared snapshot's `network_hosts` table —
//! hosts the substrate found via an active network sweep (IP, responding
//! protocol, and open ports where probed) — and reports them as an OCSF Network
//! Host Inventory (`9005`) record. Thin by design: all sweeping/probing lives in
//! the substrate (the only door); this module just reads and emits.
//!
//! Refresh-capable: like FIM, its value is detecting change AFTER startup, so it
//! re-evaluates on an interval and a [`ChangeGate`] suppresses re-emitting an
//! unchanged host set — a re-emit means a host appeared, vanished, or its
//! open-port set changed.
//!
//! Discovery only (open-source, in the agent). Scoring these into posture findings
//! — e.g. "an unmanaged host with an open admin port" — is the backend's job (the
//! paid platform).
use async_trait::async_trait;
use std::time::Duration;
use torda_core::{ChangeGate, Module, ModuleCtx, ModuleHealth, ModuleId};
use torda_ocsf::class;

/// Default refresh cadence in a daemon: 1 hour. The local network's host set
/// changes rarely, so a light interval catches drift without churn. `[refresh]
/// netdiscovery = <secs>` overrides; `0` = off/one-shot.
const DEFAULT_NETDISCOVERY_INTERVAL: Duration = Duration::from_secs(3600);

/// Reads the `network_hosts` snapshot table and emits one Network Host Inventory
/// (`9005`) record — at startup and, in a daemon, on each refresh where the host
/// set CHANGED (gated so an unchanged snapshot does not re-emit).
pub struct NetDiscoveryModule {
    ctx: Option<ModuleCtx>,
    gate: ChangeGate,
    interval: Option<Duration>,
}

impl Default for NetDiscoveryModule {
    fn default() -> Self {
        Self {
            ctx: None,
            gate: ChangeGate::new(),
            interval: Some(DEFAULT_NETDISCOVERY_INTERVAL),
        }
    }
}

impl NetDiscoveryModule {
    pub fn new() -> Self {
        Self::default()
    }

    /// Query the `network_hosts` table and emit the inventory, gated so an
    /// unchanged set doesn't re-emit on a periodic refresh. Shared by `start` and
    /// `refresh`. Stays SILENT when no hosts are present (avoid empty-inventory
    /// spam).
    fn collect_and_emit(&mut self) {
        let ctx = self.ctx.clone().expect("init before start/refresh");
        let hosts = ctx
            .snapshot
            .query("network_hosts")
            .map(|r| r.0)
            .unwrap_or_default();
        if hosts.is_empty() {
            return;
        }
        let data = serde_json::json!({
            "host_count": hosts.len(),
            "hosts": hosts,
        });
        self.gate.emit_if_changed(
            &ctx,
            class::NETWORK_HOST_INVENTORY,
            "Network Host Inventory",
            data,
        );
    }
}

#[async_trait]
impl Module for NetDiscoveryModule {
    fn id(&self) -> ModuleId {
        "netdiscovery".to_string()
    }

    async fn init(&mut self, ctx: ModuleCtx) -> anyhow::Result<()> {
        self.ctx = Some(ctx);
        Ok(())
    }

    async fn start(&mut self) -> anyhow::Result<()> {
        self.collect_and_emit();
        Ok(())
    }

    async fn refresh(&mut self) -> anyhow::Result<()> {
        self.collect_and_emit();
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
            ok: self.ctx.is_some(),
            detail: "net discovery ready".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use torda_core::{
        EventBus, EventKind, OcsfEmitter, ResourceBudget, ResourceGovernor, ResourceSampler,
        ResourceUsage, Rows, SnapshotProvider, SubstrateEvent,
    };
    use torda_ocsf::OcsfEnvelope;

    /// A snapshot whose `network_hosts` table can be mutated mid-run.
    struct MutableSnapshot {
        rows: Arc<Mutex<Vec<serde_json::Value>>>,
    }
    impl SnapshotProvider for MutableSnapshot {
        fn query(&self, table: &str) -> anyhow::Result<Rows> {
            match table {
                "network_hosts" => Ok(Rows(self.rows.lock().unwrap().clone())),
                other => anyhow::bail!("no table {other}"),
            }
        }
        fn device(&self) -> torda_ocsf::Device {
            torda_ocsf::Device {
                hostname: "host-1".into(),
                os: "Test".into(),
                os_version: "1".into(),
            }
        }
    }
    #[derive(Default)]
    struct CapturingEmitter {
        emitted: Mutex<Vec<OcsfEnvelope>>,
    }
    impl OcsfEmitter for CapturingEmitter {
        fn emit(&self, rec: OcsfEnvelope) {
            self.emitted.lock().unwrap().push(rec);
        }
    }
    struct FakeBus {
        tx: tokio::sync::broadcast::Sender<SubstrateEvent>,
    }
    impl EventBus for FakeBus {
        fn publish(&self, ev: SubstrateEvent) {
            let _ = self.tx.send(ev);
        }
        fn subscribe(&self, _k: &[EventKind]) -> tokio::sync::broadcast::Receiver<SubstrateEvent> {
            self.tx.subscribe()
        }
    }
    struct TestSampler;
    impl ResourceSampler for TestSampler {
        fn sample(&self) -> ResourceUsage {
            ResourceUsage::ZERO
        }
    }

    fn host(ip: &str, port: u16, proto: &str) -> serde_json::Value {
        serde_json::json!({
            "ip": ip,
            "open_ports": [{"port": port, "proto": proto}],
        })
    }

    fn ctx_with(
        rows: Arc<Mutex<Vec<serde_json::Value>>>,
        emitter: Arc<CapturingEmitter>,
    ) -> ModuleCtx {
        let (tx, _rx) = tokio::sync::broadcast::channel(16);
        ModuleCtx {
            bus: Arc::new(FakeBus { tx }),
            snapshot: Arc::new(MutableSnapshot { rows }),
            emitter,
            governor: Arc::new(ResourceGovernor::new(
                ResourceBudget::default(),
                Box::new(TestSampler),
            )),
            tenant_id: "t".into(),
            product: "torda".into(),
            version: "0".into(),
        }
    }

    #[tokio::test]
    async fn emits_network_inventory() {
        let rows = Arc::new(Mutex::new(vec![
            host("10.0.0.5", 5432, "tcp"),
            host("10.0.0.6", 22, "tcp"),
        ]));
        let em = Arc::new(CapturingEmitter::default());
        let mut m = NetDiscoveryModule::new();
        m.init(ctx_with(rows, em.clone())).await.unwrap();
        m.start().await.unwrap();

        let out = em.emitted.lock().unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].class_uid, class::NETWORK_HOST_INVENTORY);
        assert_eq!(out[0].data["host_count"], 2);
        assert_eq!(out[0].data["hosts"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn silent_when_no_hosts() {
        let em = Arc::new(CapturingEmitter::default());
        let mut m = NetDiscoveryModule::new();
        m.init(ctx_with(Arc::new(Mutex::new(vec![])), em.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();
        assert!(em.emitted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn refresh_emits_only_on_drift() {
        let rows = Arc::new(Mutex::new(vec![host("10.0.0.5", 5432, "tcp")]));
        let em = Arc::new(CapturingEmitter::default());
        let mut m = NetDiscoveryModule::new();
        m.init(ctx_with(rows.clone(), em.clone())).await.unwrap();

        m.start().await.unwrap();
        assert_eq!(em.emitted.lock().unwrap().len(), 1, "startup emits once");

        // No change → gate suppresses.
        m.refresh().await.unwrap();
        assert_eq!(
            em.emitted.lock().unwrap().len(),
            1,
            "unchanged → no re-emit"
        );

        // A host's open ports change (drift) → refresh emits.
        rows.lock().unwrap()[0] = host("10.0.0.5", 8080, "tcp");
        m.refresh().await.unwrap();
        assert_eq!(em.emitted.lock().unwrap().len(), 2, "drift → re-emit");
    }

    #[test]
    fn refresh_interval_defaults_and_is_configurable_off() {
        let mut m = NetDiscoveryModule::new();
        assert_eq!(m.refresh_interval(), Some(DEFAULT_NETDISCOVERY_INTERVAL));
        m.set_refresh_interval(None);
        assert_eq!(m.refresh_interval(), None);
        m.set_refresh_interval(Some(Duration::from_secs(30)));
        assert_eq!(m.refresh_interval(), Some(Duration::from_secs(30)));
    }
}
