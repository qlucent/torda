//! Core runtime contracts. Deterministic; no LLM, no network in hot paths.
//! Every capability is a `Module` consuming the shared substrate.

mod resource;
pub use resource::*;

use async_trait::async_trait;
use std::sync::Arc;
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
}

#[cfg(test)]
mod tests {
    use super::severity;

    /// Pin the canonical OCSF severity scale so it can't drift silently —
    /// every module (procmon, netmon, corr) re-exports/imports these values.
    #[test]
    fn severity_scale_is_pinned() {
        assert_eq!(severity::SEV_INFORMATIONAL, 1);
        assert_eq!(severity::SEV_LOW, 2);
        assert_eq!(severity::SEV_MEDIUM, 3);
        assert_eq!(severity::SEV_HIGH, 4);
    }
}
