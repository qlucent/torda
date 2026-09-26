//! TCP-connect network sweep engine for the shared substrate.
//!
//! Discovers live hosts/ports by attempting short-timeout TCP connects across
//! a set of CIDRs — the same substrate-owns-the-socket pattern as `ai.rs`'s
//! runtime probing. Modules never sweep themselves; they read the resulting
//! `network_hosts` snapshot table (wired in a later task). The real
//! `TcpSweepProvider` is feature-gated behind `active-sweep` so the default
//! build never touches the network; `EmptySweepProvider` is the no-op stub.

#[cfg(feature = "active-sweep")]
use std::net::{SocketAddr, TcpStream};
#[cfg(feature = "active-sweep")]
use std::time::Duration;

/// A sweep target: CIDRs to expand, ports to probe, and a soft rate cap.
#[derive(Clone, Default)]
pub struct SweepConfig {
    pub cidrs: Vec<String>,
    pub ports: Vec<u16>,
    pub rate_pps: u32,
}

/// One host found with at least one open port.
#[derive(Clone, Debug, PartialEq)]
pub struct HostResult {
    pub ip: String,
    pub open_ports: Vec<u16>,
}

/// Supplies the sweep results for this cycle.
pub trait NetworkSweepProvider: Send + Sync {
    fn sweep(&self) -> Vec<HostResult>;
}

/// No sweep — the default/no-op provider (sweeping is opt-in and feature-gated).
pub struct EmptySweepProvider;
impl NetworkSweepProvider for EmptySweepProvider {
    fn sweep(&self) -> Vec<HostResult> {
        Vec::new()
    }
}

/// Expands `a.b.c.d/prefix` into every address in the range. Refuses (returns
/// empty) rather than enumerating more than `max_hosts` addresses, and returns
/// empty on any malformed input. Pure, no panic.
pub fn expand_cidr(cidr: &str, max_hosts: usize) -> Vec<std::net::Ipv4Addr> {
    let Some((addr, prefix)) = cidr.split_once('/') else {
        return Vec::new();
    };
    let Ok(base): Result<std::net::Ipv4Addr, _> = addr.parse() else {
        return Vec::new();
    };
    let Ok(prefix): Result<u32, _> = prefix.parse() else {
        return Vec::new();
    };
    if prefix > 32 {
        return Vec::new();
    }
    let host_count: u64 = 1u64 << (32 - prefix);
    if host_count > max_hosts as u64 {
        return Vec::new();
    }
    // Mask off the host bits to get the network address. `host_count as u32`
    // wraps to 0 when prefix == 0 (2^32 doesn't fit u32), which yields mask 0
    // and network 0 — correct, though unreachable in practice since max_hosts
    // (far below 2^32) already refused above.
    let network = u32::from(base) & !((host_count as u32).wrapping_sub(1));
    (0..host_count)
        .map(|i| std::net::Ipv4Addr::from(network.wrapping_add(i as u32)))
        .collect()
}

/// Max addresses a single CIDR may expand to — refuses anything larger.
#[cfg(feature = "active-sweep")]
const MAX_HOSTS: usize = 65536;
#[cfg(feature = "active-sweep")]
const CONNECT_TIMEOUT: Duration = Duration::from_millis(300);

/// Real TCP-connect sweep: for each configured CIDR × port, attempts a short
/// connect and records which ports answered. Fail-soft — a connect error just
/// means the port is closed, never a panic.
#[cfg(feature = "active-sweep")]
pub struct TcpSweepProvider {
    cfg: SweepConfig,
}

#[cfg(feature = "active-sweep")]
impl TcpSweepProvider {
    pub fn new(cfg: SweepConfig) -> Self {
        Self { cfg }
    }
}

#[cfg(feature = "active-sweep")]
impl NetworkSweepProvider for TcpSweepProvider {
    fn sweep(&self) -> Vec<HostResult> {
        let mut results = Vec::new();
        for cidr in &self.cfg.cidrs {
            for ip in expand_cidr(cidr, MAX_HOSTS) {
                let mut open_ports = Vec::new();
                for &port in &self.cfg.ports {
                    let sa = SocketAddr::new(ip.into(), port);
                    if TcpStream::connect_timeout(&sa, CONNECT_TIMEOUT).is_ok() {
                        open_ports.push(port);
                    }
                    if self.cfg.rate_pps > 0 {
                        // ponytail: naive per-connect sleep rate limiter; token
                        // bucket if throughput matters.
                        std::thread::sleep(Duration::from_millis(1000 / self.cfg.rate_pps as u64));
                    }
                }
                if !open_ports.is_empty() {
                    results.push(HostResult {
                        ip: ip.to_string(),
                        open_ports,
                    });
                }
            }
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "active-sweep")]
    use std::net::TcpListener;

    #[test]
    fn expand_cidr_enumerates_hosts() {
        let hosts = expand_cidr("192.168.1.0/30", 65536);
        // /30 → 4 addrs; usable-host convention: include all 4 for a connect sweep
        assert_eq!(hosts.len(), 4);
        assert!(hosts.contains(&"192.168.1.1".parse().unwrap()));
    }
    #[test]
    fn expand_cidr_caps_oversize_range() {
        // a /8 exceeds max_hosts → returns empty (refused), never enumerates 16M
        assert!(expand_cidr("10.0.0.0/8", 65536).is_empty());
    }
    #[test]
    fn expand_cidr_bad_input_is_empty() {
        assert!(expand_cidr("not-a-cidr", 65536).is_empty());
        assert!(expand_cidr("10.0.0.0/33", 65536).is_empty());
    }
    #[test]
    fn empty_provider_returns_nothing() {
        assert!(EmptySweepProvider.sweep().is_empty());
    }

    #[cfg(feature = "active-sweep")]
    #[test]
    fn tcp_sweep_finds_a_local_open_port() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let cfg = SweepConfig {
            cidrs: vec!["127.0.0.1/32".into()],
            ports: vec![port],
            rate_pps: 1000,
        };
        let hosts = TcpSweepProvider::new(cfg).sweep();
        let me = hosts
            .iter()
            .find(|h| h.ip == "127.0.0.1")
            .expect("loopback found");
        assert!(me.open_ports.contains(&port));
    }
}
