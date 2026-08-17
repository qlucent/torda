//! File integrity module. Evaluates an org watchlist against the shared snapshot
//! service's `files` table and emits an OCSF File Integrity Finding record (one
//! entry per watched file, violated or not, with expected vs actual digest).
//! Detection only — the server recomputes the canonical score from the watch
//! weight. Reads the snapshot; never a file.
use async_trait::async_trait;
use torda_compliance::control::Snapshot;
use torda_compliance::fim::{builtin_watchlist, check_integrity, to_fim_records};
use torda_core::{Module, ModuleCtx, ModuleHealth, ModuleId};
use torda_ocsf::{class, OcsfEnvelope};

/// Evaluates the file-integrity watchlist over the snapshot `files` table and
/// emits one OCSF File Integrity Finding record for the whole run.
#[derive(Default)]
pub struct FimModule {
    ctx: Option<ModuleCtx>,
}

impl FimModule {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Module for FimModule {
    fn id(&self) -> ModuleId {
        "fim".to_string()
    }

    async fn init(&mut self, ctx: ModuleCtx) -> anyhow::Result<()> {
        self.ctx = Some(ctx);
        Ok(())
    }

    async fn start(&mut self) -> anyhow::Result<()> {
        let ctx = self.ctx.as_ref().expect("init before start");

        // Build a snapshot holding just the files table; if the provider lacks it,
        // the table is omitted and every watch entry skips (FIM not collected).
        let mut snap = Snapshot::default();
        if let Ok(rows) = ctx.snapshot.query("files") {
            snap.0.insert("files".to_string(), rows.0);
        }

        let records = to_fim_records(&check_integrity(&builtin_watchlist(), &snap));
        let data = serde_json::json!({ "fim": { "records": records } });
        ctx.emitter.emit(OcsfEnvelope::new(
            class::FILE_INTEGRITY_FINDING,
            "File Integrity Finding",
            ctx.meta(),
            ctx.snapshot.device(),
            data,
        ));
        Ok(())
    }

    fn health(&self) -> ModuleHealth {
        ModuleHealth {
            ok: self.ctx.is_some(),
            detail: "file integrity evaluator ready".to_string(),
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
                // passwd digest differs from the builtin watchlist -> violation.
                "files" => Ok(Rows(vec![serde_json::json!({
                    "path":"/etc/passwd",
                    "sha256":"9999999999999999999999999999999999999999999999999999999999999999",
                    "exists":true
                })])),
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
    async fn emits_file_integrity_finding_with_passwd_violation() {
        let emitter = Arc::new(CapturingEmitter::default());
        let mut m = FimModule::new();
        m.init(test_ctx(emitter.clone())).await.unwrap();
        m.start().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(emitted.len(), 1);
        let env = &emitted[0];
        assert_eq!(env.class_uid, class::FILE_INTEGRITY_FINDING);
        assert_eq!(env.class_name, "File Integrity Finding");
        let records = env.data["fim"]["records"].as_array().unwrap();
        let passwd = records
            .iter()
            .find(|r| r["entry_id"] == "fim-passwd")
            .unwrap();
        assert_eq!(passwd["violated"], true);
        assert_eq!(
            passwd["actual_sha256"],
            "9999999999999999999999999999999999999999999999999999999999999999"
        );
        // sshd_config path is not in the fake files table -> also a violation (missing).
        let sshd = records
            .iter()
            .find(|r| r["entry_id"] == "fim-sshd-config")
            .unwrap();
        assert_eq!(sshd["violated"], true);
        assert_eq!(sshd["actual_sha256"], serde_json::Value::Null);
    }
}
