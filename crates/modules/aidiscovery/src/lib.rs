//! AI-discovery module. Reads the shared snapshot's `ai_runtimes` table — local
//! AI servers (Ollama, LM Studio, llama.cpp, …) the substrate discovered and
//! probed (runtime, exposure, and, where available, version + loaded models) —
//! and reports them as an OCSF AI Inventory Info (`9004`) record. Thin by design:
//! all discovery/probing lives in the substrate (the only door); this module just
//! reads and emits.
//!
//! Discovery only (open-source, in the agent). Scoring these into posture findings
//! — e.g. "an unauthenticated Ollama is exposed on a crown-jewel host" — is the
//! backend's job (the paid platform).
use async_trait::async_trait;
use serde_json::json;
use torda_core::{Module, ModuleCtx, ModuleHealth, ModuleId};
use torda_ocsf::{class, OcsfEnvelope};

#[derive(Default)]
pub struct AiDiscoveryModule {
    ctx: Option<ModuleCtx>,
}

impl AiDiscoveryModule {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Module for AiDiscoveryModule {
    fn id(&self) -> ModuleId {
        "aidiscovery".to_string()
    }

    async fn init(&mut self, ctx: ModuleCtx) -> anyhow::Result<()> {
        self.ctx = Some(ctx);
        Ok(())
    }

    async fn start(&mut self) -> anyhow::Result<()> {
        let ctx = self.ctx.as_ref().expect("init before start");
        let servers = ctx.snapshot.query("ai_runtimes")?.0;
        // Nothing to report → stay silent (avoid empty-inventory spam).
        if servers.is_empty() {
            return Ok(());
        }
        let exposed = servers
            .iter()
            .filter(|s| s["exposed"] == json!(true))
            .count();
        let data = json!({
            "ai_servers": servers,
            "count": servers.len(),
            "exposed_count": exposed,
        });
        ctx.emitter.emit(OcsfEnvelope::new(
            class::AI_INVENTORY_INFO,
            "AI Inventory Info",
            ctx.meta(),
            ctx.snapshot.device(),
            data,
        ));
        Ok(())
    }

    fn health(&self) -> ModuleHealth {
        ModuleHealth {
            ok: self.ctx.is_some(),
            detail: "ai discovery ready".to_string(),
        }
    }
}
