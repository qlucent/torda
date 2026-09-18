//! Agent self-health module. Emits a heartbeat OCSF record.
use async_trait::async_trait;
use std::time::{Duration, Instant};
use torda_core::{
    ChangeGate, Module, ModuleCtx, ModuleHealth, ModuleId, ResourceBudget, ResourceUsage,
};
use torda_ocsf::class;

/// Default health-heartbeat cadence in a daemon: 60s. Unlike the other snapshot
/// modules this is a LIVENESS beat — its payload (uptime/resource usage) changes
/// every tick, so it re-emits each interval by design. Config `[refresh] health =
/// <secs>` overrides; `0` = off (a single startup heartbeat).
const DEFAULT_HEALTH_INTERVAL: Duration = Duration::from_secs(60);

pub struct HealthModule {
    ctx: Option<ModuleCtx>,
    started: Instant,
    gate: ChangeGate,
    interval: Option<Duration>,
}

impl HealthModule {
    pub fn new() -> Self {
        Self {
            ctx: None,
            started: Instant::now(),
            gate: ChangeGate::new(),
            interval: Some(DEFAULT_HEALTH_INTERVAL),
        }
    }

    /// Emit a heartbeat with current uptime + resource usage. Gated for API
    /// uniformity, though the changing uptime means it emits every refresh (a
    /// liveness beat, by design). Shared by `start` and `refresh`.
    fn collect_and_emit(&mut self) {
        let ctx = self.ctx.clone().expect("init before start/refresh");
        let usage = ctx.governor.last_usage();
        let data = serde_json::json!({
            "status": "ok",
            "uptime_ms": self.started.elapsed().as_millis() as u64,
            "resource": resource_data(&usage, ctx.governor.budget()),
        });
        self.gate
            .emit_if_changed(&ctx, class::AGENT_HEALTH, "Agent Health", data);
    }
}

impl Default for HealthModule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Module for HealthModule {
    fn id(&self) -> ModuleId {
        "health".to_string()
    }

    async fn init(&mut self, ctx: ModuleCtx) -> anyhow::Result<()> {
        self.ctx = Some(ctx);
        self.started = Instant::now();
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
            ok: true,
            detail: "heartbeat ok".to_string(),
        }
    }
}

/// Shapes a usage sample + budget into the OCSF `resource` payload, so an
/// operator can verify the agent stayed within its budget.
fn resource_data(usage: &ResourceUsage, budget: ResourceBudget) -> serde_json::Value {
    let cpu_used = pct_of(usage.cpu_pct, budget.cpu_pct);
    let mem_used = pct_of(usage.mem_pct, budget.mem_pct);
    serde_json::json!({
        "cpu_pct": usage.cpu_pct,
        "rss_bytes": usage.rss_bytes,
        "mem_pct": usage.mem_pct,
        "budget": { "cpu_pct": budget.cpu_pct, "mem_pct": budget.mem_pct },
        "budget_used": { "cpu": cpu_used, "mem": mem_used },
        "over_budget": cpu_used > 100.0 || mem_used > 100.0,
    })
}

/// Percent of budget consumed. Zero budget returns `f32::MAX` as a large-but-finite
/// sentinel (JSON-safe; `f32::INFINITY` would serialize as `null` under serde_json).
fn pct_of(used: f32, budget: f32) -> f32 {
    if budget <= 0.0 {
        f32::MAX
    } else {
        used / budget * 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use torda_core::{ResourceBudget, ResourceUsage};

    #[test]
    fn resource_data_reports_budget_usage() {
        let usage = ResourceUsage {
            cpu_pct: 2.5,
            rss_bytes: 1_048_576,
            mem_pct: 2.0,
        };
        let budget = ResourceBudget::default(); // 5% / 5%
        let v = resource_data(&usage, budget);

        assert_eq!(v["cpu_pct"], 2.5);
        assert_eq!(v["rss_bytes"], 1_048_576u64);
        assert_eq!(v["budget"]["cpu_pct"], 5.0);
        // 2.5% used of a 5% budget => 50% of budget.
        assert_eq!(v["budget_used"]["cpu"], 50.0);
        assert_eq!(v["budget_used"]["mem"], 40.0);
        assert_eq!(v["over_budget"], false);
    }

    #[test]
    fn resource_data_flags_over_budget() {
        let usage = ResourceUsage {
            cpu_pct: 8.0,
            rss_bytes: 10,
            mem_pct: 1.0,
        };
        let v = resource_data(&usage, ResourceBudget::default());
        assert_eq!(v["over_budget"], true); // 8% > 5% CPU budget
        assert_eq!(v["budget_used"]["cpu"], 160.0);
    }
}
