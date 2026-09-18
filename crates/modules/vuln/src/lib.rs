//! Vulnerability module. Reads the shared package snapshot and emits an OCSF
//! Software Inventory (SBOM) record. Detection only — CVE matching and scoring
//! happen server-side (the agent never carries a CVE database). It reads the
//! snapshot; it never touches the OS.

use async_trait::async_trait;
use std::time::Duration;
use torda_core::{ChangeGate, Module, ModuleCtx, ModuleHealth, ModuleId};
use torda_ocsf::class;

/// Default SBOM refresh cadence in a daemon: hourly (installed packages change
/// slowly). Config `[refresh] vuln = <secs>` overrides; `0` = off/one-shot.
const DEFAULT_VULN_INTERVAL: Duration = Duration::from_secs(3600);

/// Shapes package snapshot rows into an OCSF Software Inventory (SBOM) payload.
/// Pure — the components pass through as-is (`{name, version, source}`); the
/// server's findings engine matches them against CVE feeds in a later slice.
pub fn build_sbom_data(packages: &[serde_json::Value]) -> serde_json::Value {
    serde_json::json!({
        "sbom": {
            "format": "torda-native",
            "components": packages,
            "component_count": packages.len(),
        }
    })
}

/// Emits an OCSF Software Inventory (SBOM) record from the package snapshot.
pub struct VulnModule {
    ctx: Option<ModuleCtx>,
    gate: ChangeGate,
    interval: Option<Duration>,
}

impl Default for VulnModule {
    fn default() -> Self {
        Self {
            ctx: None,
            gate: ChangeGate::new(),
            interval: Some(DEFAULT_VULN_INTERVAL),
        }
    }
}

impl VulnModule {
    pub fn new() -> Self {
        Self::default()
    }

    /// Read the current package set and emit the SBOM, gated so an unchanged
    /// package set does not re-emit on a periodic refresh. Shared by `start` and
    /// `refresh`.
    fn collect_and_emit(&mut self) -> anyhow::Result<()> {
        let ctx = self.ctx.clone().expect("init before start/refresh");
        let packages = ctx.snapshot.query("packages")?;
        let data = build_sbom_data(&packages.0);
        self.gate.emit_if_changed(
            &ctx,
            class::SOFTWARE_INVENTORY_INFO,
            "Software Inventory Info",
            data,
        );
        Ok(())
    }
}

#[async_trait]
impl Module for VulnModule {
    fn id(&self) -> ModuleId {
        "vuln".to_string()
    }

    async fn init(&mut self, ctx: ModuleCtx) -> anyhow::Result<()> {
        self.ctx = Some(ctx);
        Ok(())
    }

    async fn start(&mut self) -> anyhow::Result<()> {
        self.collect_and_emit()
    }

    async fn refresh(&mut self) -> anyhow::Result<()> {
        self.collect_and_emit()
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
            detail: "sbom emitter ready".to_string(),
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

    #[test]
    fn build_sbom_data_wraps_components_with_count() {
        let pkgs = vec![
            serde_json::json!({"name":"openssl","version":"3.0.2","source":"dpkg"}),
            serde_json::json!({"name":"glibc","version":"2.39","source":"dpkg"}),
        ];
        let data = build_sbom_data(&pkgs);
        assert_eq!(data["sbom"]["format"], "torda-native");
        assert_eq!(data["sbom"]["component_count"], 2);
        assert_eq!(data["sbom"]["components"][0]["name"], "openssl");
        assert_eq!(data["sbom"]["components"][1]["version"], "2.39");
    }

    #[test]
    fn build_sbom_data_empty_is_zero_count() {
        let data = build_sbom_data(&[]);
        assert_eq!(data["sbom"]["component_count"], 0);
        assert!(data["sbom"]["components"].as_array().unwrap().is_empty());
    }

    struct FakeSnapshot;
    impl SnapshotProvider for FakeSnapshot {
        fn query(&self, table: &str) -> anyhow::Result<Rows> {
            match table {
                "packages" => Ok(Rows(vec![
                    serde_json::json!({"name":"openssl","version":"3.0.2","source":"dpkg"}),
                    serde_json::json!({"name":"curl","version":"8.5.0","source":"dpkg"}),
                ])),
                other => anyhow::bail!("unexpected table {other}"),
            }
        }
        fn device(&self) -> torda_ocsf::Device {
            torda_ocsf::Device {
                hostname: "test-host".into(),
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

    fn test_ctx(emitter: Arc<CapturingEmitter>) -> ModuleCtx {
        let (tx, _rx) = tokio::sync::broadcast::channel(16);
        ModuleCtx {
            bus: Arc::new(FakeBus { tx }),
            snapshot: Arc::new(FakeSnapshot),
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
    async fn emits_one_sbom_envelope_that_round_trips() {
        let emitter = Arc::new(CapturingEmitter::default());
        let mut m = VulnModule::new();
        m.init(test_ctx(emitter.clone())).await.unwrap();
        m.start().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(emitted.len(), 1, "exactly one SBOM record");
        let env = &emitted[0];
        assert_eq!(env.class_uid, torda_ocsf::class::SOFTWARE_INVENTORY_INFO);
        assert_eq!(env.class_name, "Software Inventory Info");
        assert_eq!(env.device.hostname, "test-host");
        assert_eq!(env.data["sbom"]["component_count"], 2);
        assert_eq!(env.data["sbom"]["components"][0]["name"], "openssl");

        // Round-trips through OcsfEnvelope (serialize -> deserialize).
        let json = serde_json::to_string(env).unwrap();
        let back: OcsfEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back.class_uid, torda_ocsf::class::SOFTWARE_INVENTORY_INFO);
        assert_eq!(back.data["sbom"]["component_count"], 2);
    }
}
