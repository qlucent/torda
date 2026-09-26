# Network Discovery SP2 — `netdiscovery` Agent Module — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The agent-side (collector) half of agentless network discovery — a substrate sweep that TCP-connect-probes operator-configured CIDRs to find live hosts + open ports, and a thin `netdiscovery` module that emits them as OCSF **class 9005 "Network Host Inventory"** (the contract the torda-cloud backend already ingests, SP1/PR #50).

**Architecture:** Follows the agent's substrate-is-the-only-door model: the SWEEP lives in the substrate (a `network_hosts` snapshot table populated at construction by a `NetworkSweepProvider`); the `netdiscovery` MODULE is thin — reads `snapshot.query("network_hosts")` and emits class-9005 (mirrors `aidiscovery`). Config-driven, opt-in, TCP-connect-only, rate-capped, configured-CIDR-only.

**Tech Stack:** Rust (async-trait, tokio runtime, `std::net::TcpStream::connect_timeout` for the probe — matches `crates/substrate/src/ai.rs`), serde_json. **No new dependency** (ICMP/raw-socket deferred).

**Spec:** `torda-cloud` repo `docs/superpowers/specs/2026-09-25-agentless-network-discovery-design.md` (whole-system, 3 sub-projects). This plan is **SP2**. The locked wire contract (class 9005) and the SP1 backend (`net_assets::extract`/`classify`) already shipped; this must emit that shape.

## Coordinator rulings (refine the SP2 sketch to the agent repo's reality — recorded so they're explicit)

- **TCP-connect only for v1; ICMP deferred.** The repo has no ICMP/raw-socket dependency and CI runs unprivileged. Liveness = "at least one probed port accepted a TCP connection." TCP-connect matches the existing `ai.rs` precedent and adds **no dependency**. ICMP ping (needs `socket2`/a ping crate + privilege) is a follow-up.
- **Sweep once at substrate construction** (like `ai_runtimes`), NOT a background re-sweep loop. Keeps the synchronous immutable `query(&self)` contract intact — no interior mutability, no background task. Periodic re-sweep is a follow-up (would add a `Mutex` table + a sweeper task).
- **Opt-in `active-sweep` Cargo feature + empty-CIDRs = no-op.** This is the agent's first non-loopback network call; make it a deliberate opt-in. With the feature off OR no CIDRs configured, the sweep provider is `EmptySweepProvider` (returns `[]`), the table is empty, and the module stays silent (like `aidiscovery` when there's nothing to report). This is a NEW feature-gate precedent (existing snapshot tables aren't gated) — intentional, for safety.
- **New `[netdiscovery]` config section** in `AgentConfig` (`cidrs`, `ports`, `rate_pps`); threaded via a new `Substrate::for_this_platform_with_sweep(SweepConfig)` constructor (the existing `for_this_platform()` stays, delegating with an empty config, so its call sites/tests are unchanged).
- **v1 HostResult fields = `ip` + `open_ports`** (what TCP-connect yields). The class-9005 `data.hosts[]` shape carries mac/cert_subjects/ttl/snmp/hostname too, but v1 emits those as `null`/absent — the SP1 backend `classify()` degrades to the open-port fingerprint tier, which is exactly designed for this. Reverse-DNS hostname, MAC/ARP, banners, certs, SNMP are follow-ups.

## Global Constraints

- Run `cargo` from the repo root `D:\Torda\torda-public`. Gates before every commit: `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, `cargo test --workspace` — all green. Also build the feature: `cargo build -p torda-substrate --features active-sweep`.
- **No new runtime dependency.** Use `std::net::TcpStream::connect_timeout` (as `ai.rs` does). serde_json/async-trait/tokio already present.
- **Safety (non-negotiable, from the spec):** sweep ONLY the operator-configured CIDRs; TCP-connect only (no raw/SYN/ICMP); hard rate cap; read-only; empty/absent config = no-op. Cap CIDR expansion size (refuse/skip a CIDR wider than a configured max, default /16 = 65536 hosts) to prevent a footgun.
- The agent's `crates/ocsf` conformance test `emitted_classes_are_stock_or_labeled_extensions` MUST list any new 9000-block class or `cargo test` fails.
- CI legs (`.github/workflows/ci.yml`): `stub` (ubuntu/windows/macos fmt+clippy+build+test), `linux-ebpf`, `windows-etw`, `supply-chain` (cargo-deny). Tests run UNPRIVILEGED — any real-sweep test must target only `127.0.0.1` (bind a `TcpListener` on `127.0.0.1:0` in-test) or assert the no-op path; NEVER sweep a live network in CI.
- Branch: `feat/netdiscovery` (created). This is the `qlucent/torda` agent repo — branch→PR→**user merges**. Commit footer on every commit:
  `Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>` / `Claude-Session: https://claude.ai/code/session_019se5tFub9ydymgLV9XwdHs`.

---

### Task 1: OCSF class 9005 constant

**Files:**
- Modify: `crates/ocsf/src/lib.rs` (add the const + the conformance-test list entry)

**Interfaces:**
- Produces: `pub const NETWORK_HOST_INVENTORY: u32 = 9005;` in the `class` module.

- [ ] **Step 1: Add the const** after `AI_INVENTORY_INFO` (lib.rs:19):
```rust
pub const NETWORK_HOST_INVENTORY: u32 = 9005; // custom extension: hosts discovered by an active network sweep (agentless network inventory)
```
- [ ] **Step 2: Add it to the conformance-test list** — in `emitted_classes_are_stock_or_labeled_extensions` (lib.rs:155-160), add `class::NETWORK_HOST_INVENTORY,` to the `for ext in [ ... ]` array (the test asserts each is in `9001..=9999`).
- [ ] **Step 3: Run** `cargo test -p torda-ocsf` → PASS.
- [ ] **Step 4: Commit** — `feat(ocsf): class 9005 Network Host Inventory`.

---

### Task 2: Substrate sweep engine (`network_hosts.rs`)

**Files:**
- Create: `crates/substrate/src/network_hosts.rs`
- Modify: `crates/substrate/Cargo.toml` (add `active-sweep` feature)

**Interfaces:**
- Produces: `pub struct SweepConfig { pub cidrs: Vec<String>, pub ports: Vec<u16>, pub rate_pps: u32 }` (Clone, Default — Default = empty cidrs/ports, rate_pps 0); `pub struct HostResult { pub ip: String, pub open_ports: Vec<u16> }` (Clone, Debug); `pub trait NetworkSweepProvider: Send + Sync { fn sweep(&self) -> Vec<HostResult>; }`; `pub struct EmptySweepProvider;` (impl returns `vec![]`); `pub fn expand_cidr(cidr: &str, max_hosts: usize) -> Vec<std::net::Ipv4Addr>` (pure); and (behind `#[cfg(feature = "active-sweep")]`) `pub struct TcpSweepProvider { cfg: SweepConfig }` + impl.

- [ ] **Step 1: Write the failing tests** (in `network_hosts.rs`):
```rust
#[cfg(test)]
mod tests {
    use super::*;
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
        let cfg = SweepConfig { cidrs: vec!["127.0.0.1/32".into()], ports: vec![port], rate_pps: 1000 };
        let hosts = TcpSweepProvider::new(cfg).sweep();
        let me = hosts.iter().find(|h| h.ip == "127.0.0.1").expect("loopback found");
        assert!(me.open_ports.contains(&port));
    }
}
```
- [ ] **Step 2: Run** `cargo test -p torda-substrate network_hosts` (and with `--features active-sweep`) → FAIL.
- [ ] **Step 3: Implement.**
  - `expand_cidr(cidr, max_hosts)`: parse `a.b.c.d/prefix` (split on `/`, parse `Ipv4Addr` + prefix 0..=32); compute host count `1u64 << (32 - prefix)`; if `> max_hosts` return `vec![]` (refuse oversize); else enumerate all addresses in range (u32 start..=end → Ipv4Addr). Bad input → `vec![]`. Pure, no panic.
  - `NetworkSweepProvider` trait + `EmptySweepProvider` (returns `vec![]`).
  - `TcpSweepProvider` (feature-gated): `new(SweepConfig)`; `sweep()` = for each CIDR → `expand_cidr(cidr, MAX_HOSTS=65536)`; for each ip × each configured port, `std::net::TcpStream::connect_timeout(&SocketAddr, CONNECT_TIMEOUT=~300ms)` (mirror `ai.rs`'s `PROBE_TIMEOUT`); collect open ports per ip; a host with ≥1 open port → `HostResult{ip, open_ports}`. Rate-cap: sleep to keep connects/sec under `rate_pps` (a simple per-connect `thread::sleep(1000/rate_pps ms)` when `rate_pps>0`; `ponytail:` comment noting a naive rate limiter, upgrade to a token bucket if throughput matters). Fail-soft: a connect error = port closed, never a panic.
  - `crates/substrate/Cargo.toml`: add `[features] active-sweep = []` (declare the feature; no new dep).
- [ ] **Step 4: Run** both test modes → PASS. `cargo fmt` + `cargo clippy --all-targets -- -D warnings` (also `--features active-sweep`).
- [ ] **Step 5: Commit** — `feat(substrate): TCP-connect network sweep engine (feature active-sweep)`.

---

### Task 3: Wire `network_hosts` into StubSnapshot + Substrate

**Files:**
- Modify: `crates/substrate/src/lib.rs` (`pub mod network_hosts;`, `StubSnapshot` field + `query` arm + constructor, `Substrate::for_this_platform_with_sweep`)

**Interfaces:**
- Consumes: `network_hosts::{HostResult, SweepConfig, NetworkSweepProvider, EmptySweepProvider}` (T2), and (feature-gated) `TcpSweepProvider`.
- Produces: `snapshot.query("network_hosts")` returns class-9005-`data.hosts[]`-shaped rows; `Substrate::for_this_platform_with_sweep(SweepConfig)`.

- [ ] **Step 1: Failing test** (in substrate/lib.rs tests): construct a `StubSnapshot` with a fake `NetworkSweepProvider` returning one `HostResult{ip:"10.0.0.5", open_ports:vec![5432]}`; assert `query("network_hosts")?.0` has one row with `row["ip"]=="10.0.0.5"` and `row["open_ports"]` an array containing `{port:5432, proto:"tcp"}`. (Mirror how existing tests build StubSnapshot with providers.)
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.**
  - `pub mod network_hosts;`.
  - `StubSnapshot`: add `network_hosts: Vec<network_hosts::HostResult>` field; populate it in the provider-threaded constructor (`with_all_providers`, mirror how `ai_runtimes`/`ai_models` are threaded — accept a `&dyn NetworkSweepProvider` and call `.sweep()` once).
  - `query()` add a `"network_hosts"` arm mapping each `HostResult` to the class-9005 host shape:
    ```rust
    "network_hosts" => self.network_hosts.iter().map(|h| serde_json::json!({
        "ip": h.ip,
        "hostname": serde_json::Value::Null,
        "mac": serde_json::Value::Null,
        "responded_via": "tcp",
        "ttl": serde_json::Value::Null,
        "open_ports": h.open_ports.iter().map(|p| serde_json::json!({"port": p, "proto": "tcp", "service": serde_json::Value::Null, "banner": serde_json::Value::Null})).collect::<Vec<_>>(),
        "cert_subjects": [],
        "snmp_sysdescr": serde_json::Value::Null,
        "os_guess": serde_json::Value::Null,
        "last_seen": serde_json::Value::Null,
    })).collect(),
    ```
  - `Substrate::for_this_platform_with_sweep(sweep: network_hosts::SweepConfig)`: build the sweep provider — if `sweep.cidrs` is empty OR the `active-sweep` feature is off, use `EmptySweepProvider`; else (feature on + cidrs present) use `TcpSweepProvider::new(sweep)` (gate the `TcpSweepProvider` construction behind `#[cfg(feature="active-sweep")]`, falling back to `EmptySweepProvider` otherwise). Keep the existing `for_this_platform()` — redefine it as `Self::for_this_platform_with_sweep(SweepConfig::default())` so all current call sites/tests compile unchanged.
- [ ] **Step 4: Run** `cargo test --workspace` (and `-p torda-substrate --features active-sweep`) → PASS. fmt + clippy.
- [ ] **Step 5: Commit** — `feat(substrate): network_hosts snapshot table + sweep-config constructor`.

---

### Task 4: The `netdiscovery` module

**Files:**
- Create: `crates/modules/netdiscovery/` (Cargo.toml + src/lib.rs)
- Modify: root `Cargo.toml` (add the workspace member if members are listed explicitly)

**Interfaces:**
- Consumes: `torda_core::{Module, ModuleCtx, ModuleHealth, ModuleId, ChangeGate/snapshot-module helper}`, `torda_ocsf::{class::NETWORK_HOST_INVENTORY, OcsfEnvelope}`, `snapshot.query("network_hosts")`.
- Produces: `pub struct NetDiscoveryModule` with `pub fn new() -> Self`, impl `Module` (id `"netdiscovery"`).

- [ ] **Step 1: Write failing tests** (mirror `crates/modules/aimodel/src/lib.rs` tests — `MutableSnapshot` returning `"network_hosts"` rows + `CapturingEmitter`):
  - `emits_network_inventory`: snapshot `network_hosts` has 2 host rows → `start()` emits ONE class-9005 envelope with `data.host_count == 2` and `data.hosts` length 2, each host carrying `ip`+`open_ports`.
  - `silent_when_no_hosts`: empty `network_hosts` → no emit (mirror aidiscovery's `if empty return`).
  - `refresh_emits_only_on_drift` (if mirroring the ChangeGate pattern): re-`refresh()` with unchanged rows → no re-emit; mutate rows → re-emit.
  - `refresh_interval_defaults_and_is_configurable_off`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement `netdiscovery/src/lib.rs`** — mirror `aidiscovery` (thin read+emit) plus `aimodel`'s refresh/ChangeGate + interval:
  - `start()`: `let hosts = ctx.snapshot.query("network_hosts")?.0; if hosts.is_empty() { return Ok(()) }`; `let data = json!({ "host_count": hosts.len(), "hosts": hosts });`; `ctx.emitter.emit(OcsfEnvelope::new(class::NETWORK_HOST_INVENTORY, "Network Host Inventory", ctx.meta(), ctx.snapshot.device(), data));`. Use the ChangeGate so `refresh()` re-emits only on drift (copy aimodel's pattern verbatim, swapping the table name + class).
  - `Cargo.toml`: package `torda-mod-netdiscovery` (match the naming of `torda-mod-aidiscovery`), deps on `torda-core`/`torda-ocsf`/`async-trait`/`serde_json`/`tokio` per the sibling module.
  - Add to the workspace members list in root `Cargo.toml` if members are explicit.
- [ ] **Step 4: Run** `cargo test -p torda-mod-netdiscovery` + `cargo test --workspace` → PASS. fmt + clippy.
- [ ] **Step 5: Commit** — `feat(netdiscovery): thin module emitting OCSF class 9005 from network_hosts`.

---

### Task 5: Agent config `[netdiscovery]` + main.rs wiring

**Files:**
- Modify: `crates/agent/src/lib.rs` (`AgentConfig` + a `NetDiscoveryConfig` section), `crates/agent/src/main.rs` (build substrate with sweep config; register the module)

**Interfaces:**
- Consumes: `AgentConfig` (lib.rs:134-153), the module registration block (main.rs:302-349), `Substrate::for_this_platform_with_sweep` (T3), `network_hosts::SweepConfig` (T2), `NetDiscoveryModule` (T4).

- [ ] **Step 1: Failing test** (in agent/src/lib.rs config tests, mirror the existing AgentConfig TOML parse tests): a TOML with
  ```toml
  [netdiscovery]
  cidrs = ["10.0.0.0/24"]
  ports = [22, 443, 5432]
  rate_pps = 500
  ```
  parses into `AgentConfig.netdiscovery` = `Some(NetDiscoveryConfig{ cidrs, ports, rate_pps })`; and a config with NO `[netdiscovery]` → `None` (the no-op default).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.**
  - `crates/agent/src/lib.rs`: `#[derive(Debug, Clone, Deserialize, Default)] pub struct NetDiscoveryConfig { #[serde(default)] pub cidrs: Vec<String>, #[serde(default)] pub ports: Vec<u16>, #[serde(default)] pub rate_pps: u32 }`; add `#[serde(default)] pub netdiscovery: Option<NetDiscoveryConfig>` to `AgentConfig`. Provide a small mapper `NetDiscoveryConfig -> network_hosts::SweepConfig` (or build it in main).
  - `crates/agent/src/main.rs`: build the `SweepConfig` from `config.netdiscovery` (absent → default empty → no-op), pass it to `Substrate::for_this_platform_with_sweep(sweep_cfg)` where the substrate is constructed; register the module: `mgr.register(Box::new(torda_mod_netdiscovery::NetDiscoveryModule::new()));` beside the other `mgr.register(...)` calls. (Registering it is harmless when the table is empty — the module stays silent.)
  - Default ports when `[netdiscovery]` present but `ports` empty: a top-N default set (22,80,443,3389,3306,5432,161,23,8080,8443,445,139,25,53,1433,27017,6379,9100,623,1900) — put this default in the config→SweepConfig mapper.
- [ ] **Step 4: Run** `cargo test --workspace` → PASS; `cargo build` (default) and `cargo build -p torda-agent --features ...` if the agent forwards the `active-sweep` feature (wire an `active-sweep` feature on the agent crate that enables `torda-substrate/active-sweep`, so a build opts in). fmt + clippy.
- [ ] **Step 5: Commit** — `feat(agent): [netdiscovery] config + wire sweep substrate + register module`.

---

### Task 6: Ship

- [ ] Push `feat/netdiscovery`, open PR (base `main`) on `qlucent/torda`, poll CI legs (`stub` ubuntu/windows/macos, `linux-ebpf`, `windows-etw`, `supply-chain` cargo-deny). No new dep → supply-chain trivial. Also verify a `--features active-sweep` build is green (add to the PR description that the sweep is opt-in via that feature + `[netdiscovery]` config).
- [ ] PR body: this is SP2 of agentless network discovery; emits OCSF class 9005 to the SP1 backend (torda-cloud PR #50). Safety recap: configured-CIDR-only, TCP-connect, rate-capped, read-only, opt-in feature, empty-config no-op. SP3 (collector role/enrollment) follows.
- [ ] Hold for user merge; fix any CI leg on-branch.

## Self-Review

- **Spec coverage (SP2 scope):** class 9005 (T1), sweep engine incl. safety caps (T2), substrate table + config constructor (T3), thin emitting module (T4), agent config + wiring (T5), ship (T6). SP3 out of scope.
- **Placeholders:** none — sweep engine, table mapping, module, config all have concrete code + tests.
- **Type consistency:** `SweepConfig`/`HostResult`/`NetworkSweepProvider` defined T2, consumed T3; `network_hosts` table shape (T3) matches class-9005 `data.hosts[]` the SP1 backend `net_assets::extract` reads; `NETWORK_HOST_INVENTORY` (T1) emitted by the module (T4); `NetDiscoveryConfig`→`SweepConfig` (T5).
- **Contract check:** the emitted `data.hosts[]` (ip + open_ports[{port,proto}], other fields null) is exactly what SP1's `classify()` consumes via its open-port fingerprint tier — verified against the SP1 spec.
