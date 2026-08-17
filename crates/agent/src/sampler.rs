//! Concrete `ResourceSampler` for the agent's own process, backed by `sysinfo`.
//! Lives in the agent crate so `torda-core` stays dependency-light; the governor
//! depends only on the `ResourceSampler` trait.
use std::sync::Mutex;
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, Pid, ProcessRefreshKind, RefreshKind, System};
use torda_core::{ResourceSampler, ResourceUsage};

pub struct SysinfoSampler {
    sys: Mutex<System>,
    pid: Pid,
    ncpu: f32,
    total_mem: u64,
}

impl SysinfoSampler {
    pub fn new() -> Self {
        let refresh = RefreshKind::new()
            .with_memory(MemoryRefreshKind::everything())
            .with_cpu(CpuRefreshKind::everything());
        let mut sys = System::new_with_specifics(refresh);
        sys.refresh_specifics(refresh);
        let pid = sysinfo::get_current_pid().expect("current pid available");
        let ncpu = sys.cpus().len().max(1) as f32;
        let total_mem = sys.total_memory().max(1);
        Self {
            sys: Mutex::new(sys),
            pid,
            ncpu,
            total_mem,
        }
    }
}

impl ResourceSampler for SysinfoSampler {
    fn sample(&self) -> ResourceUsage {
        let mut sys = self.sys.lock().expect("sampler lock poisoned");
        sys.refresh_process_specifics(self.pid, ProcessRefreshKind::new().with_cpu().with_memory());
        let (cpu_pct, rss_bytes) = match sys.process(self.pid) {
            // sysinfo reports CPU as percent of a single core; divide by core
            // count to express it as a share of total capacity.
            Some(p) => (p.cpu_usage() / self.ncpu, p.memory()),
            None => (0.0_f32, 0_u64),
        };
        let mem_pct = (rss_bytes as f32 / self.total_mem as f32) * 100.0;
        ResourceUsage {
            cpu_pct,
            rss_bytes,
            mem_pct,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_is_finite_and_nonnegative() {
        let s = SysinfoSampler::new();
        let u = s.sample();
        assert!(
            u.cpu_pct.is_finite() && u.cpu_pct >= 0.0,
            "cpu_pct = {}",
            u.cpu_pct
        );
        assert!(
            u.mem_pct.is_finite() && u.mem_pct >= 0.0,
            "mem_pct = {}",
            u.mem_pct
        );
        // This process occupies some memory.
        assert!(u.rss_bytes > 0, "rss should be > 0");
    }
}
