//! File integrity module. Evaluates an org watchlist against the shared snapshot
//! service's `files` table and emits an OCSF File Integrity Finding record (one
//! entry per watched file, violated or not, with expected vs actual digest).
//! Detection only — the server recomputes the canonical score from the watch
//! weight. Reads the snapshot; never a file.
use async_trait::async_trait;
use std::time::Duration;
use torda_compliance::control::Snapshot;
use torda_compliance::fim::{builtin_watchlist, check_integrity, to_fim_records};
use torda_core::{ChangeGate, Module, ModuleCtx, ModuleHealth, ModuleId};
use torda_ocsf::class;

/// Default FIM refresh cadence in a daemon: 5 minutes. FIM's whole purpose is
/// detecting change AFTER startup, so it re-evaluates the `files` table on this
/// interval (config `[refresh] fim = <secs>` overrides; `0` = off/one-shot).
const DEFAULT_FIM_INTERVAL: Duration = Duration::from_secs(300);

/// Evaluates the file-integrity watchlist over the snapshot `files` table and
/// emits one OCSF File Integrity Finding record — at startup and, in a daemon, on
/// each refresh when a watched file's digest CHANGED (gated so an unchanged
/// snapshot does not re-emit).
pub struct FimModule {
    ctx: Option<ModuleCtx>,
    gate: ChangeGate,
    interval: Option<Duration>,
}

impl Default for FimModule {
    fn default() -> Self {
        Self {
            ctx: None,
            gate: ChangeGate::new(),
            interval: Some(DEFAULT_FIM_INTERVAL),
        }
    }
}

impl FimModule {
    pub fn new() -> Self {
        Self::default()
    }

    /// Evaluate the watchlist over the current `files` table and emit the finding
    /// set, gated so an unchanged snapshot (identical digests) does not re-emit on
    /// a periodic refresh. Shared by `start` (first, always-emits) and `refresh`.
    fn collect_and_emit(&mut self) {
        let ctx = self.ctx.clone().expect("init before start/refresh");

        // Build a snapshot holding just the files table; if the provider lacks it,
        // the table is omitted and every watch entry skips (FIM not collected).
        let mut snap = Snapshot::default();
        if let Ok(rows) = ctx.snapshot.query("files") {
            snap.0.insert("files".to_string(), rows.0);
        }

        let records = to_fim_records(&check_integrity(&builtin_watchlist(), &snap));
        let data = serde_json::json!({ "fim": { "records": records } });
        self.gate.emit_if_changed(
            &ctx,
            class::FILE_INTEGRITY_FINDING,
            "File Integrity Finding",
            data,
        );
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
    use torda_ocsf::OcsfEnvelope;

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

    /// A snapshot whose `/etc/passwd` digest can be mutated mid-run, to simulate a
    /// watched file changing AFTER the agent started.
    struct MutableSnapshot {
        passwd_digest: Arc<Mutex<String>>,
    }
    impl SnapshotProvider for MutableSnapshot {
        fn query(&self, table: &str) -> anyhow::Result<Rows> {
            match table {
                "files" => Ok(Rows(vec![serde_json::json!({
                    "path":"/etc/passwd",
                    "sha256": *self.passwd_digest.lock().unwrap(),
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

    /// P0-3 acceptance: FIM emits when a watched file changes AFTER startup, and
    /// the change-gate suppresses re-emitting an UNCHANGED snapshot on refresh.
    #[tokio::test]
    async fn refresh_emits_only_when_a_watched_file_changes_after_startup() {
        let emitter = Arc::new(CapturingEmitter::default());
        let digest = Arc::new(Mutex::new("a".repeat(64)));
        let (tx, _rx) = tokio::sync::broadcast::channel(16);
        let ctx = ModuleCtx {
            bus: Arc::new(FakeBus { tx }),
            snapshot: Arc::new(MutableSnapshot {
                passwd_digest: digest.clone(),
            }),
            emitter: emitter.clone(),
            governor: Arc::new(ResourceGovernor::new(
                ResourceBudget::default(),
                Box::new(TestSampler),
            )),
            tenant_id: "t".into(),
            product: "torda".into(),
            version: "0".into(),
        };

        let mut m = FimModule::new();
        m.init(ctx).await.unwrap();

        // Startup: always emits the initial finding set.
        m.start().await.unwrap();
        assert_eq!(
            emitter.emitted.lock().unwrap().len(),
            1,
            "startup emits once"
        );

        // Refresh with NO change → gate suppresses the duplicate.
        m.refresh().await.unwrap();
        assert_eq!(
            emitter.emitted.lock().unwrap().len(),
            1,
            "unchanged snapshot must not re-emit"
        );

        // A watched file changes AFTER startup → refresh emits the new finding set.
        *digest.lock().unwrap() = "b".repeat(64);
        m.refresh().await.unwrap();
        assert_eq!(
            emitter.emitted.lock().unwrap().len(),
            2,
            "a post-startup change must emit"
        );

        // The newest record reflects the changed digest.
        let emitted = emitter.emitted.lock().unwrap();
        let records = emitted[1].data["fim"]["records"].as_array().unwrap();
        let passwd = records
            .iter()
            .find(|r| r["entry_id"] == "fim-passwd")
            .unwrap();
        assert_eq!(passwd["actual_sha256"], "b".repeat(64));
    }

    /// A snapshot module carries a sensible default refresh interval, and config
    /// (via `set_refresh_interval`) can turn it OFF (`None`) for one-shot behavior.
    #[test]
    fn refresh_interval_defaults_on_and_is_configurable_off() {
        let mut m = FimModule::new();
        assert_eq!(m.refresh_interval(), Some(DEFAULT_FIM_INTERVAL));
        m.set_refresh_interval(None);
        assert_eq!(m.refresh_interval(), None);
        m.set_refresh_interval(Some(Duration::from_secs(30)));
        assert_eq!(m.refresh_interval(), Some(Duration::from_secs(30)));
    }
}
