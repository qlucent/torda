//! AI model-integrity module. Reads the shared snapshot's `ai_models` table — AI
//! model weight files the substrate discovered (format, a code-execution risk flag
//! for pickle-family formats, size, mtime, and a change-detection fingerprint) —
//! and reports them as an OCSF AI Inventory Info (`9004`) record of kind
//! `ai_model_inventory`. Thin by design: all discovery/hashing lives in the
//! substrate (the only door); this module reads and emits.
//!
//! Refresh-capable: like FIM, its value is detecting change AFTER startup, so it
//! re-evaluates on an interval and a [`ChangeGate`] suppresses re-emitting an
//! unchanged model set — a re-emit means a model file appeared, vanished, or its
//! fingerprint changed (integrity drift / tamper).
//!
//! Discovery only (open-source, in the agent). Scoring these into posture findings
//! — "an untrusted pickle model on a crown-jewel host", or "a model's hash drifted
//! from its known-good digest" — is the backend's job (the paid platform).
use async_trait::async_trait;
use std::time::Duration;
use torda_core::{ChangeGate, Module, ModuleCtx, ModuleHealth, ModuleId};
use torda_ocsf::class;

/// Default refresh cadence in a daemon: 1 hour. Model files change rarely (a pull
/// or an update), so a light interval catches drift without churn. `[refresh]
/// aimodel = <secs>` overrides; `0` = off/one-shot.
const DEFAULT_AIMODEL_INTERVAL: Duration = Duration::from_secs(3600);

/// Reads the `ai_models` snapshot table and emits one AI Inventory Info (`9004`,
/// kind `ai_model_inventory`) record — at startup and, in a daemon, on each refresh
/// where the model set CHANGED (gated so an unchanged snapshot does not re-emit).
pub struct AiModelModule {
    ctx: Option<ModuleCtx>,
    gate: ChangeGate,
    interval: Option<Duration>,
}

impl Default for AiModelModule {
    fn default() -> Self {
        Self {
            ctx: None,
            gate: ChangeGate::new(),
            interval: Some(DEFAULT_AIMODEL_INTERVAL),
        }
    }
}

impl AiModelModule {
    pub fn new() -> Self {
        Self::default()
    }

    /// Query the `ai_models` table and emit the inventory, gated so an unchanged
    /// set doesn't re-emit on a periodic refresh. Shared by `start` and `refresh`.
    /// Stays SILENT when no model files are present (avoid empty-inventory spam).
    fn collect_and_emit(&mut self) {
        let ctx = self.ctx.clone().expect("init before start/refresh");
        let models = ctx
            .snapshot
            .query("ai_models")
            .map(|r| r.0)
            .unwrap_or_default();
        if models.is_empty() {
            return;
        }
        let risky_count = models
            .iter()
            .filter(|m| m["risky"] == serde_json::Value::Bool(true))
            .count();
        let data = serde_json::json!({
            "kind": "ai_model_inventory",
            "models": models,
            "count": models.len(),
            "risky_count": risky_count,
        });
        self.gate
            .emit_if_changed(&ctx, class::AI_INVENTORY_INFO, "AI Inventory Info", data);
    }
}

#[async_trait]
impl Module for AiModelModule {
    fn id(&self) -> ModuleId {
        "aimodel".to_string()
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
            detail: "ai model integrity ready".to_string(),
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

    /// A snapshot whose `ai_models` table can be mutated mid-run.
    struct MutableSnapshot {
        rows: Arc<Mutex<Vec<serde_json::Value>>>,
    }
    impl SnapshotProvider for MutableSnapshot {
        fn query(&self, table: &str) -> anyhow::Result<Rows> {
            match table {
                "ai_models" => Ok(Rows(self.rows.lock().unwrap().clone())),
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

    fn model(path: &str, format: &str, risky: bool, fp: &str) -> serde_json::Value {
        serde_json::json!({
            "path": path, "format": format, "risky": risky,
            "size": 10, "mtime": 1, "fingerprint": fp
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
    async fn emits_inventory_with_risky_count() {
        let rows = Arc::new(Mutex::new(vec![
            model("/m/llama.gguf", "gguf", false, "aaa"),
            model("/m/pytorch_model.bin", "pytorch-bin", true, "bbb"),
        ]));
        let em = Arc::new(CapturingEmitter::default());
        let mut m = AiModelModule::new();
        m.init(ctx_with(rows, em.clone())).await.unwrap();
        m.start().await.unwrap();

        let out = em.emitted.lock().unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].class_uid, class::AI_INVENTORY_INFO);
        assert_eq!(out[0].data["kind"], "ai_model_inventory");
        assert_eq!(out[0].data["count"], 2);
        assert_eq!(out[0].data["risky_count"], 1, "the .bin pickle model");
    }

    #[tokio::test]
    async fn silent_when_no_models() {
        let em = Arc::new(CapturingEmitter::default());
        let mut m = AiModelModule::new();
        m.init(ctx_with(Arc::new(Mutex::new(vec![])), em.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();
        assert!(em.emitted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn refresh_emits_only_on_drift() {
        let rows = Arc::new(Mutex::new(vec![model(
            "/m/model.safetensors",
            "safetensors",
            false,
            "fp-1",
        )]));
        let em = Arc::new(CapturingEmitter::default());
        let mut m = AiModelModule::new();
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

        // A model's fingerprint changes (tamper/update) → refresh emits.
        rows.lock().unwrap()[0] = model("/m/model.safetensors", "safetensors", false, "fp-2");
        m.refresh().await.unwrap();
        assert_eq!(em.emitted.lock().unwrap().len(), 2, "drift → re-emit");
    }

    #[test]
    fn refresh_interval_defaults_on_and_is_configurable_off() {
        let mut m = AiModelModule::new();
        assert_eq!(m.refresh_interval(), Some(DEFAULT_AIMODEL_INTERVAL));
        m.set_refresh_interval(None);
        assert_eq!(m.refresh_interval(), None);
        m.set_refresh_interval(Some(Duration::from_secs(30)));
        assert_eq!(m.refresh_interval(), Some(Duration::from_secs(30)));
    }
}
