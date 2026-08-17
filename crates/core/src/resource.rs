//! Resource governance: a user-configurable ceiling on the agent's own CPU/RAM
//! usage, enforced cooperatively (self-meter -> throttle). Hard kernel
//! enforcement (cgroup-v2 / Job Objects) lands in P3; this is the
//! cross-platform cooperative tier and the inner loop under hard limits.

use std::sync::Mutex;

/// User-configurable resource ceiling. The agent must never exceed it.
/// Defaults: 5% of total CPU capacity, 5% of total system RAM.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ResourceBudget {
    /// Share of total CPU capacity, 0..100.
    pub cpu_pct: f32,
    /// Share of total system RAM, 0..100.
    pub mem_pct: f32,
}

impl Default for ResourceBudget {
    fn default() -> Self {
        Self {
            cpu_pct: 5.0,
            mem_pct: 5.0,
        }
    }
}

impl ResourceBudget {
    /// Reads optional overrides from the environment, falling back to 5%/5%.
    /// `TORDA_CPU_BUDGET_PCT` / `TORDA_MEM_BUDGET_PCT` accept a float in (0, 100].
    pub fn from_env() -> Self {
        let d = Self::default();
        Self {
            cpu_pct: std::env::var("TORDA_CPU_BUDGET_PCT")
                .ok()
                .as_deref()
                .and_then(parse_pct)
                .unwrap_or(d.cpu_pct),
            mem_pct: std::env::var("TORDA_MEM_BUDGET_PCT")
                .ok()
                .as_deref()
                .and_then(parse_pct)
                .unwrap_or(d.mem_pct),
        }
    }
}

/// Parses a percent string in the half-open range (0, 100]. Pure — unit-tested.
fn parse_pct(raw: &str) -> Option<f32> {
    raw.trim()
        .parse::<f32>()
        .ok()
        .filter(|v| *v > 0.0 && *v <= 100.0)
}

/// A point-in-time measurement of the agent's OWN resource usage.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ResourceUsage {
    /// Agent CPU as a percent of total capacity, 0..100.
    pub cpu_pct: f32,
    /// Resident set size in bytes.
    pub rss_bytes: u64,
    /// RSS as a percent of total system RAM, 0..100.
    pub mem_pct: f32,
}

impl ResourceUsage {
    pub const ZERO: ResourceUsage = ResourceUsage {
        cpu_pct: 0.0,
        rss_bytes: 0,
        mem_pct: 0.0,
    };
}

/// Platform shim that samples the agent's own usage. One impl per OS lives in
/// the agent crate; the governor depends only on this trait so its logic stays
/// pure and unit-testable.
pub trait ResourceSampler: Send + Sync {
    fn sample(&self) -> ResourceUsage;
}

/// What the scheduler should do given current usage vs budget.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ThrottleDecision {
    /// Under budget — run normally.
    Run,
    /// Over budget by `over_factor` (> 1.0). The scheduler sheds low-priority
    /// work proportionally and always protects the health heartbeat.
    Throttle { over_factor: f32 },
}

/// Always-on cooperative governor: holds the budget + a sampler, caches the last
/// sample, and answers "are we over budget?". Pure logic over an injected sampler.
pub struct ResourceGovernor {
    budget: ResourceBudget,
    sampler: Box<dyn ResourceSampler>,
    last: Mutex<ResourceUsage>,
}

impl ResourceGovernor {
    pub fn new(budget: ResourceBudget, sampler: Box<dyn ResourceSampler>) -> Self {
        Self {
            budget,
            sampler,
            last: Mutex::new(ResourceUsage::ZERO),
        }
    }

    pub fn budget(&self) -> ResourceBudget {
        self.budget
    }

    /// Samples current usage, caches it, and returns it.
    pub fn poll(&self) -> ResourceUsage {
        let u = self.sampler.sample();
        *self.last.lock().expect("governor lock poisoned") = u;
        u
    }

    /// The most recent sampled usage (`ZERO` before the first poll).
    pub fn last_usage(&self) -> ResourceUsage {
        *self.last.lock().expect("governor lock poisoned")
    }

    /// Pure decision: throttle when either dimension exceeds budget; `over_factor`
    /// is the worst overage ratio across CPU and memory.
    pub fn decide(&self, usage: &ResourceUsage) -> ThrottleDecision {
        let over = ratio(usage.cpu_pct, self.budget.cpu_pct)
            .max(ratio(usage.mem_pct, self.budget.mem_pct));
        if over > 1.0 {
            ThrottleDecision::Throttle { over_factor: over }
        } else {
            ThrottleDecision::Run
        }
    }

    /// Convenience: poll then decide.
    pub fn check(&self) -> ThrottleDecision {
        let u = self.poll();
        self.decide(&u)
    }
}

/// Usage-over-budget ratio. A non-positive budget means "no headroom" → infinite.
fn ratio(used: f32, budget: f32) -> f32 {
    if budget <= 0.0 {
        f32::INFINITY
    } else {
        used / budget
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_defaults_to_five_percent() {
        let b = ResourceBudget::default();
        assert_eq!(b.cpu_pct, 5.0);
        assert_eq!(b.mem_pct, 5.0);
    }

    #[test]
    fn parse_pct_accepts_valid_rejects_invalid() {
        assert_eq!(parse_pct("10"), Some(10.0));
        assert_eq!(parse_pct(" 7.5 "), Some(7.5));
        assert_eq!(parse_pct("100"), Some(100.0));
        assert_eq!(parse_pct("0"), None); // must be > 0
        assert_eq!(parse_pct("150"), None); // must be <= 100
        assert_eq!(parse_pct("abc"), None);
        assert_eq!(parse_pct(""), None);
    }

    #[test]
    fn usage_zero_is_all_zero() {
        assert_eq!(ResourceUsage::ZERO.cpu_pct, 0.0);
        assert_eq!(ResourceUsage::ZERO.rss_bytes, 0);
        assert_eq!(ResourceUsage::ZERO.mem_pct, 0.0);
    }

    struct FakeSampler(ResourceUsage);
    impl ResourceSampler for FakeSampler {
        fn sample(&self) -> ResourceUsage {
            self.0
        }
    }

    fn governor_with(usage: ResourceUsage) -> ResourceGovernor {
        ResourceGovernor::new(ResourceBudget::default(), Box::new(FakeSampler(usage)))
    }

    #[test]
    fn under_budget_runs() {
        let g = governor_with(ResourceUsage {
            cpu_pct: 2.0,
            rss_bytes: 1,
            mem_pct: 1.0,
        });
        assert_eq!(g.decide(&g.poll()), ThrottleDecision::Run);
    }

    #[test]
    fn at_budget_runs() {
        // Exactly at the ceiling is not "over" — over is strict (> 1.0).
        let g = governor_with(ResourceUsage {
            cpu_pct: 5.0,
            rss_bytes: 1,
            mem_pct: 5.0,
        });
        assert_eq!(g.decide(&g.poll()), ThrottleDecision::Run);
    }

    #[test]
    fn cpu_over_budget_throttles_with_factor() {
        let g = governor_with(ResourceUsage {
            cpu_pct: 10.0,
            rss_bytes: 1,
            mem_pct: 1.0,
        });
        match g.decide(&g.poll()) {
            ThrottleDecision::Throttle { over_factor } => assert!((over_factor - 2.0).abs() < 1e-6),
            other => panic!("expected throttle, got {other:?}"),
        }
    }

    #[test]
    fn mem_over_budget_throttles() {
        let g = governor_with(ResourceUsage {
            cpu_pct: 1.0,
            rss_bytes: 1,
            mem_pct: 7.5,
        });
        match g.decide(&g.poll()) {
            ThrottleDecision::Throttle { over_factor } => assert!((over_factor - 1.5).abs() < 1e-6),
            other => panic!("expected throttle, got {other:?}"),
        }
    }

    #[test]
    fn over_factor_is_worst_dimension() {
        // CPU 2x over, mem 3x over -> factor is the max (3.0).
        let g = governor_with(ResourceUsage {
            cpu_pct: 10.0,
            rss_bytes: 1,
            mem_pct: 15.0,
        });
        match g.decide(&g.poll()) {
            ThrottleDecision::Throttle { over_factor } => assert!((over_factor - 3.0).abs() < 1e-6),
            other => panic!("expected throttle, got {other:?}"),
        }
    }

    #[test]
    fn poll_caches_last_usage() {
        let u = ResourceUsage {
            cpu_pct: 3.0,
            rss_bytes: 42,
            mem_pct: 2.0,
        };
        let g = governor_with(u);
        assert_eq!(g.last_usage(), ResourceUsage::ZERO); // before first poll
        assert_eq!(g.poll(), u);
        assert_eq!(g.last_usage(), u); // cached after poll
    }
}
