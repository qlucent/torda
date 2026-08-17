//! Config drift module. Evaluates an org baseline against the shared snapshot
//! service and emits an OCSF Device Config State record (one entry per baseline
//! rule, drifted or not, with expected vs actual). Detection only — the server
//! recomputes the canonical score from the baseline weight. Reads the snapshot;
//! never the OS.
use async_trait::async_trait;
use std::collections::HashSet;
use torda_compliance::control::Snapshot;
use torda_compliance::drift::{builtin_baseline, detect_drift, to_drift_records};
use torda_core::{Module, ModuleCtx, ModuleHealth, ModuleId};
use torda_ocsf::{class, OcsfEnvelope};

/// Evaluates the config baseline over the snapshot and emits one OCSF Device
/// Config State record for the whole run.
#[derive(Default)]
pub struct DriftModule {
    ctx: Option<ModuleCtx>,
}

impl DriftModule {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Module for DriftModule {
    fn id(&self) -> ModuleId {
        "drift".to_string()
    }

    async fn init(&mut self, ctx: ModuleCtx) -> anyhow::Result<()> {
        self.ctx = Some(ctx);
        Ok(())
    }

    async fn start(&mut self) -> anyhow::Result<()> {
        let ctx = self.ctx.as_ref().expect("init before start");
        let baseline = builtin_baseline();

        // Build the snapshot from the tables the baseline needs; a table the
        // provider lacks is omitted, so its entries skip (not reported as drift).
        let mut snap = Snapshot::default();
        let mut seen = HashSet::new();
        for e in &baseline {
            if seen.insert(e.table.clone()) {
                if let Ok(rows) = ctx.snapshot.query(&e.table) {
                    snap.0.insert(e.table.clone(), rows.0);
                }
            }
        }

        let records = to_drift_records(&detect_drift(&baseline, &snap));
        let data = serde_json::json!({ "drift": { "records": records } });
        ctx.emitter.emit(OcsfEnvelope::new(
            class::DEVICE_CONFIG_STATE,
            "Device Config State",
            ctx.meta(),
            ctx.snapshot.device(),
            data,
        ));
        Ok(())
    }

    fn health(&self) -> ModuleHealth {
        ModuleHealth {
            ok: self.ctx.is_some(),
            detail: "drift evaluator ready".to_string(),
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

    struct FakeSnapshot;
    impl SnapshotProvider for FakeSnapshot {
        fn query(&self, table: &str) -> anyhow::Result<Rows> {
            match table {
                "packages" => Ok(Rows(vec![
                    serde_json::json!({"name":"openssl","version":"3.0.2","source":"dpkg"}),
                    serde_json::json!({"name":"telnet","version":"0.17","source":"dpkg"}),
                ])),
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
    async fn emits_device_config_state_with_openssl_and_telnet_drift() {
        let emitter = Arc::new(CapturingEmitter::default());
        let mut m = DriftModule::new();
        m.init(test_ctx(emitter.clone())).await.unwrap();
        m.start().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(emitted.len(), 1);
        let env = &emitted[0];
        assert_eq!(env.class_uid, class::DEVICE_CONFIG_STATE);
        assert_eq!(env.class_name, "Device Config State");
        let records = env.data["drift"]["records"].as_array().unwrap();
        let openssl = records
            .iter()
            .find(|r| r["entry_id"] == "openssl-pinned")
            .unwrap();
        assert_eq!(openssl["drifted"], true);
        assert_eq!(openssl["expected"], "3.0.14");
        assert_eq!(openssl["actual"], "3.0.2");
        let telnet = records
            .iter()
            .find(|r| r["entry_id"] == "telnet-absent")
            .unwrap();
        assert_eq!(telnet["drifted"], true);
        assert_eq!(telnet["actual"], "present");
    }
}
