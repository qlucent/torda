//! Asset inventory module. Reads the shared snapshot service and emits an
//! OCSF Inventory Info record. Note: it never touches the OS directly.
use async_trait::async_trait;
use std::time::Duration;
use torda_core::{ChangeGate, Module, ModuleCtx, ModuleHealth, ModuleId};
use torda_ocsf::class;

/// Default asset-inventory refresh cadence in a daemon: hourly (inventory drifts
/// slowly). Config `[refresh] asset = <secs>` overrides; `0` = off/one-shot.
const DEFAULT_ASSET_INTERVAL: Duration = Duration::from_secs(3600);

pub struct AssetModule {
    ctx: Option<ModuleCtx>,
    gate: ChangeGate,
    interval: Option<Duration>,
}

impl Default for AssetModule {
    fn default() -> Self {
        Self {
            ctx: None,
            gate: ChangeGate::new(),
            interval: Some(DEFAULT_ASSET_INTERVAL),
        }
    }
}

impl AssetModule {
    pub fn new() -> Self {
        Self::default()
    }

    /// Read the current inventory and emit it, gated so an unchanged inventory
    /// does not re-emit on a periodic refresh. Shared by `start` and `refresh`.
    fn collect_and_emit(&mut self) -> anyhow::Result<()> {
        let ctx = self.ctx.clone().expect("init before start/refresh");
        let os = ctx.snapshot.query("os_version")?;
        let packages = ctx.snapshot.query("packages")?;
        let data = serde_json::json!({
            "os": os.0,
            "packages": packages.0,
            "package_count": packages.0.len(),
        });
        self.gate
            .emit_if_changed(&ctx, class::INVENTORY_INFO, "Inventory Info", data);
        Ok(())
    }
}

#[async_trait]
impl Module for AssetModule {
    fn id(&self) -> ModuleId {
        "asset".to_string()
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
            detail: "asset inventory ready".to_string(),
        }
    }
}
