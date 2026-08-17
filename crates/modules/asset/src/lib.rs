//! Asset inventory module. Reads the shared snapshot service and emits an
//! OCSF Inventory Info record. Note: it never touches the OS directly.
use async_trait::async_trait;
use torda_core::{Module, ModuleCtx, ModuleHealth, ModuleId};
use torda_ocsf::{class, OcsfEnvelope};

#[derive(Default)]
pub struct AssetModule {
    ctx: Option<ModuleCtx>,
}

impl AssetModule {
    pub fn new() -> Self {
        Self::default()
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
        let ctx = self.ctx.as_ref().expect("init before start");
        let os = ctx.snapshot.query("os_version")?;
        let packages = ctx.snapshot.query("packages")?;

        let data = serde_json::json!({
            "os": os.0,
            "packages": packages.0,
            "package_count": packages.0.len(),
        });

        ctx.emitter.emit(OcsfEnvelope::new(
            class::INVENTORY_INFO,
            "Inventory Info",
            ctx.meta(),
            ctx.snapshot.device(),
            data,
        ));
        Ok(())
    }

    fn health(&self) -> ModuleHealth {
        ModuleHealth {
            ok: self.ctx.is_some(),
            detail: "asset inventory ready".to_string(),
        }
    }
}
