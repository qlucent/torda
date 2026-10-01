# Agent Real Shell Executor (opt-in) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the Torda agent actually run `Shell` remediation payloads on its host — OFF by default, opt-in via config — behind the existing gated execution Bridge.

**Architecture:** The agent already has the complete, gated execution state machine (`Bridge` canary/rollout/rollback, `Executor`/`Verifier` traits, signature→replay→role→state gates) exercised today only against a no-op `DryRunExecutor`. This plan adds a real `Executor`/`Verifier` for `Method::Shell` plus an opt-in `ControlConfig.apply` config, and selects it at the one wiring point. No gate, state-machine, or protocol change.

**Tech Stack:** Rust (`torda` agent crate at `crates/agent`, Apache-2.0), `std::process` only (no new deps; the control thread is a plain `std` thread, not tokio).

**Spec:** this is the public-agent slice (SP-D1) of a larger real-apply design; this plan is self-contained and public-safe. (The cross-repo orchestration that will later drive this executor is out of scope here.)

## Global Constraints
- Public repo `qlucent/torda` (`D:/Torda/torda-public`), Apache-2.0. Agent package is `torda` at `crates/agent`.
- **Real execution is OFF by default.** Absent config or `enabled=false` ⇒ the existing `DryRunExecutor`/`DryRunVerifier` (unchanged). This is the single most important invariant.
- Only `Method::Shell` is supported in this slice. Any other method, or a method not in `allowed_methods`, ⇒ `Err` with no process spawned.
- Bounded execution: per-exec timeout (`exec_timeout_secs`, default 300) and a captured-output cap (`max_output_bytes`, default 65536) that only prevents pipe-deadlock/OOM. **Error summaries are short and secret-free — never echo the payload or captured output content** (only an exit/timeout/spawn category).
- No new crate dependencies. Must build and test on Linux, macOS, and Windows (the public CI legs). Use `cfg!(windows)` to pick the shell.
- No changes to `server/remediation`, `server/control-plane`, or the gate/state machine. Only `crates/agent`.
- Gates (from `torda-public` root): `cargo fmt --all --check`; `cargo clippy --all-targets --locked -- -D warnings`; `cargo test --locked`. Keep `cargo-deny` clean (add no deps). Branch off `main`.
- Commit messages end with:
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` / `Claude-Session: https://claude.ai/code/session_019se5tFub9ydymgLV9XwdHs`.

## Review Focus
- **Default-off safety:** absent/`enabled=false` config must still select `DryRunExecutor` — a real apply must never happen without explicit opt-in. → Task 3 test `select_executor_defaults_to_dry_run`.
- **Disallowed/non-Shell method never spawns:** a non-Shell method, or Shell absent from `allowed_methods`, must return `Err` before any process starts. → Task 2 test `disallowed_method_does_not_execute`.
- **Timeout actually kills:** a payload that runs longer than `exec_timeout_secs` must be killed and reported as a timeout (not hang, not false success). → Task 2 test `apply_times_out_and_is_killed`.
- **Non-zero exit is a failure:** a payload exiting non-zero must be `Err`, never a silent `Ok`. → Task 2 test `nonzero_exit_is_error`.
- **Output is bounded and never leaked:** large output must not OOM or appear in the error string; the error carries only an exit/timeout category. → Task 2 test `large_output_is_bounded_and_not_leaked`.

---

### Task 1: `ApplyConfig` + `ControlConfig.apply`

**Files:**
- Modify: `crates/agent/src/lib.rs` (add `ApplyConfig` near `ControlConfig` ~line 212; add the `apply` field to `ControlConfig`; import `Method`)
- Test: inline `#[cfg(test)]` in `crates/agent/src/lib.rs`

**Interfaces:**
- Produces: `pub struct ApplyConfig { pub enabled: bool, pub allowed_methods: Vec<Method>, pub exec_timeout_secs: u64, pub max_output_bytes: usize }` (derives `Debug, Clone, PartialEq, Eq, Serialize, Deserialize`); `ControlConfig.apply: Option<ApplyConfig>`.

- [ ] **Step 1: Write the failing config test** (inline in `lib.rs` tests):

```rust
#[test]
fn apply_config_absent_is_none_and_present_fills_defaults() {
    // absent -> None
    let toml_no = r#"
control_addr = "127.0.0.1:0"
tenant_id = "t"
trust_dir = "trust"
agent_key_file = "k"
[control.cert]
"#;
    // NOTE: match the real ControlConfig shape; the point is `apply` omitted => None.
    // present + partial -> defaults fill
    let cfg: ApplyConfig = toml::from_str("enabled = true\nallowed_methods = [\"Shell\"]\n").unwrap();
    assert!(cfg.enabled);
    assert_eq!(cfg.allowed_methods, vec![Method::Shell]);
    assert_eq!(cfg.exec_timeout_secs, 300);
    assert_eq!(cfg.max_output_bytes, 65536);
    let def: ApplyConfig = toml::from_str("").unwrap();
    assert!(!def.enabled);
    assert!(def.allowed_methods.is_empty());
    let _ = toml_no;
}
```

- [ ] **Step 2: Run to verify it fails** — `cargo test -p torda --locked apply_config_absent` → FAIL (`ApplyConfig` undefined).

- [ ] **Step 3: Implement the config** in `lib.rs`. Add `Method` to the `torda_remediation` import line used for `RemediationAction`. Add:

```rust
/// Opt-in real-apply configuration. ABSENT or `enabled=false` keeps the agent on the
/// safe dry-run executor. `allowed_methods` is an allow-list; a method not listed is
/// refused before any process is spawned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allowed_methods: Vec<Method>,
    #[serde(default = "default_exec_timeout_secs")]
    pub exec_timeout_secs: u64,
    #[serde(default = "default_max_output_bytes")]
    pub max_output_bytes: usize,
}
fn default_exec_timeout_secs() -> u64 { 300 }
fn default_max_output_bytes() -> usize { 65536 }
```
and add to `ControlConfig` (after `roles`):
```rust
    /// Opt-in real-apply config. Absent (the default) keeps the dry-run executor.
    #[serde(default)]
    pub apply: Option<ApplyConfig>,
```

- [ ] **Step 4: Run to verify it passes** — `cargo test -p torda --locked apply_config_absent` → PASS. (If the `toml_no` whole-ControlConfig parse is awkward, keep the focused `ApplyConfig` parse assertions — they prove defaults + None-by-omission via `#[serde(default)]`.)

- [ ] **Step 5: fmt + clippy + commit**

```bash
cargo fmt --all --check && cargo clippy --all-targets --locked -- -D warnings
git add crates/agent/src/lib.rs
git commit -m "feat(agent): opt-in ApplyConfig on ControlConfig (default off)"
```

---

### Task 2: `RealExecutor` + `RealVerifier` (Shell)

**Files:**
- Create: `crates/agent/src/apply.rs`
- Modify: `crates/agent/src/lib.rs` (add `mod apply;` and re-export `pub use apply::{RealExecutor, RealVerifier};`)
- Test: inline `#[cfg(test)]` in `crates/agent/src/apply.rs`

**Interfaces:**
- Consumes: `ApplyConfig` (Task 1); `torda_remediation::bridge::{Executor, Verifier, VerifyOutcome}`; `torda_remediation::action::{RemediationAction, Method}` (match the exact import paths `DryRunExecutor` uses in `lib.rs`).
- Produces: `pub struct RealExecutor { cfg: ApplyConfig }` with `pub fn new(cfg: ApplyConfig) -> Self`, `impl Executor`; `pub struct RealVerifier` (unit), `impl Verifier`. (No `applied` field — the Bridge tracks applied targets itself and passes them to `verify`; an unread field would trip `-D warnings`.)

- [ ] **Step 1: Write failing tests** in `apply.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ApplyConfig;
    use torda_remediation::action::{AssetSelector, CanarySpec, Method, RemediationAction, VerifySpec};
    use torda_remediation::bridge::{Executor, Verifier, VerifyOutcome};

    fn action(method: Method, payload: &str, rollback: Option<&str>, targets: &[&str]) -> RemediationAction {
        RemediationAction {
            id: "a".into(), name: "n".into(), method, payload: payload.into(),
            targets: AssetSelector { asset_ids: targets.iter().map(|s| s.to_string()).collect() },
            requires_approval: true, dry_run_supported: true,
            rollback: rollback.map(|s| s.to_string()),
            verify: VerifySpec { finding_ids: vec![] },
            canary: CanarySpec { cohort_size: 1, failure_threshold: 0.0 },
        }
    }
    fn cfg(timeout: u64) -> ApplyConfig {
        ApplyConfig { enabled: true, allowed_methods: vec![Method::Shell], exec_timeout_secs: timeout, max_output_bytes: 1024 }
    }
    // portable no-op success; `exit 0`/`cmd /C` both succeed on empty-ish commands
    const OK: &str = "exit 0";
    const FAIL: &str = "exit 7";

    #[test]
    fn apply_success_and_nonzero_exit_is_error() {
        let mut ex = RealExecutor::new(cfg(30));
        ex.apply(&action(Method::Shell, OK, None, &["h1"]), "h1").unwrap();
        assert!(ex.apply(&action(Method::Shell, FAIL, None, &["h1"]), "h1").is_err());
    }

    #[test]
    fn disallowed_method_does_not_execute() {
        let mut ex = RealExecutor::new(cfg(30));
        // non-Shell method
        assert!(ex.apply(&action(Method::Ansible, OK, None, &["h1"]), "h1").is_err());
        // Shell not in allow-list
        let mut ex2 = RealExecutor::new(ApplyConfig { allowed_methods: vec![], ..cfg(30) });
        assert!(ex2.apply(&action(Method::Shell, OK, None, &["h1"]), "h1").is_err());
    }

    #[test]
    fn apply_times_out_and_is_killed() {
        let mut ex = RealExecutor::new(cfg(1)); // 1s timeout
        let sleep = if cfg!(windows) { "ping -n 6 127.0.0.1 > NUL" } else { "sleep 5" };
        let start = std::time::Instant::now();
        let r = ex.apply(&action(Method::Shell, sleep, None, &["h1"]), "h1");
        assert!(r.is_err());
        assert!(start.elapsed() < std::time::Duration::from_secs(4), "must kill ~at timeout");
    }

    #[test]
    fn large_output_is_bounded_and_not_leaked() {
        let mut ex = RealExecutor::new(ApplyConfig { max_output_bytes: 64, ..cfg(30) });
        let big = if cfg!(windows) { "echo SECRETSECRETSECRET & exit 3" } else { "echo SECRETSECRETSECRET; exit 3" };
        let err = ex.apply(&action(Method::Shell, big, None, &["h1"]), "h1").unwrap_err().to_string();
        assert!(!err.contains("SECRET"), "error must not leak output");
    }

    #[test]
    fn rollback_runs_when_present_and_noops_when_absent() {
        let mut ex = RealExecutor::new(cfg(30));
        ex.rollback(&action(Method::Shell, OK, None, &["h1"]), "h1").unwrap(); // None -> Ok
        assert!(ex.rollback(&action(Method::Shell, OK, Some(FAIL), &["h1"]), "h1").is_err()); // runs, fails
    }

    #[test]
    fn verifier_fixed_only_when_all_targets_applied() {
        let v = RealVerifier;
        let a = action(Method::Shell, OK, None, &["h1", "h2"]);
        assert_eq!(v.verify(&a, &["h1".into(), "h2".into()]), VerifyOutcome::Fixed);
        assert_eq!(v.verify(&a, &["h1".into()]), VerifyOutcome::NotFixed);
        assert_eq!(v.verify(&a, &[]), VerifyOutcome::NotFixed);
    }
}
```

- [ ] **Step 2: Run to verify they fail** — `cargo test -p torda --locked apply::` → FAIL (module/types undefined).

- [ ] **Step 3: Implement `apply.rs`:**

```rust
//! Opt-in REAL remediation executor (Shell only). Selected only when
//! `ControlConfig.apply.enabled` is set; the default stays the dry-run no-op.
use crate::ApplyConfig;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use torda_remediation::action::{Method, RemediationAction};
use torda_remediation::bridge::{Executor, Verifier, VerifyOutcome};

#[derive(Debug)]
pub struct RealExecutor {
    cfg: ApplyConfig,
}
impl RealExecutor {
    pub fn new(cfg: ApplyConfig) -> Self {
        Self { cfg }
    }
    fn permitted(&self, action: &RemediationAction) -> anyhow::Result<()> {
        // SP-D1 supports Shell only, and only if the operator allow-listed it.
        if action.method != Method::Shell || !self.cfg.allowed_methods.contains(&action.method) {
            anyhow::bail!("method not permitted");
        }
        Ok(())
    }
    fn run(&self, payload: &str) -> anyhow::Result<()> {
        run_bounded(
            payload,
            Duration::from_secs(self.cfg.exec_timeout_secs),
            self.cfg.max_output_bytes,
        )
        .map_err(|cat| anyhow::anyhow!("{cat}")) // cat is a short, secret-free category
    }
}

impl Executor for RealExecutor {
    fn preview(&self, action: &RemediationAction) -> String {
        // No payload echo (payloads may carry secrets); just a method + scope summary.
        format!("[apply:{:?}] {} target(s)", action.method, action.targets.asset_ids.len())
    }
    fn apply(&mut self, action: &RemediationAction, _target: &str) -> anyhow::Result<()> {
        self.permitted(action)?;
        self.run(&action.payload)
    }
    fn rollback(&mut self, action: &RemediationAction, _target: &str) -> anyhow::Result<()> {
        self.permitted(action)?;
        match &action.rollback {
            Some(p) => self.run(p),
            None => Ok(()),
        }
    }
}

#[derive(Debug, Default)]
pub struct RealVerifier;
impl Verifier for RealVerifier {
    fn verify(&self, action: &RemediationAction, applied: &[String]) -> VerifyOutcome {
        let targets = &action.targets.asset_ids;
        if !targets.is_empty() && targets.iter().all(|t| applied.iter().any(|a| a == t)) {
            VerifyOutcome::Fixed
        } else {
            VerifyOutcome::NotFixed
        }
    }
}

/// Run `payload` under the platform shell, bounded by `timeout`, draining stdout/stderr to
/// at most `max_bytes` (to avoid a full-pipe deadlock / unbounded memory). Returns a SHORT,
/// SECRET-FREE category on failure; the captured output is intentionally NOT returned.
fn run_bounded(payload: &str, timeout: Duration, max_bytes: usize) -> Result<(), String> {
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.arg("/C").arg(payload);
        c
    } else {
        let mut c = Command::new("sh");
        c.arg("-c").arg(payload);
        c
    };
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|_| "spawn failed".to_string())?;
    // Drain pipes in threads so a chatty child can't block on a full pipe; cap the read.
    let cap = max_bytes as u64;
    let mut out = child.stdout.take().expect("piped");
    let mut err = child.stderr.take().expect("piped");
    let ot = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out.by_ref().take(cap + 1).read_to_end(&mut b);
        // keep reading-to-drain past the cap without storing, so the child can finish/exit
        let _ = std::io::copy(&mut out, &mut std::io::sink());
    });
    let et = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = err.by_ref().take(cap + 1).read_to_end(&mut b);
        let _ = std::io::copy(&mut err, &mut std::io::sink());
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let _ = ot.join();
    let _ = et.join();
    match status {
        Some(s) if s.success() => Ok(()),
        Some(s) => Err(format!("exit {}", s.code().map_or_else(|| "signal".to_string(), |c| c.to_string()))),
        None => Err("timed out".to_string()),
    }
}
```
Then in `lib.rs`: add `mod apply;` and `pub use apply::{RealExecutor, RealVerifier};` near the other declarations.

- [ ] **Step 4: Run tests to verify they pass** — `cargo test -p torda --locked apply::` → PASS on this platform. (If a portable payload differs on Windows CI, keep the `cfg!(windows)` branches shown.)

- [ ] **Step 5: fmt + clippy + commit**

```bash
cargo fmt --all --check && cargo clippy --all-targets --locked -- -D warnings
git add crates/agent/src/apply.rs crates/agent/src/lib.rs
git commit -m "feat(agent): real Shell executor + verifier (bounded, secret-free)"
```

---

### Task 3: Wire opt-in selection into the control loop

**Files:**
- Modify: `crates/agent/src/lib.rs` (`spawn_control_service` passes `cfg.apply.clone()`; `control_accept_loop` takes an `apply: Option<ApplyConfig>` param and selects the executor per connection via a new `select_executor` helper)
- Test: inline `#[cfg(test)]` in `crates/agent/src/lib.rs`

**Interfaces:**
- Consumes: `ApplyConfig` (Task 1), `RealExecutor`/`RealVerifier` (Task 2), existing `DryRunExecutor`/`DryRunVerifier`, `Executor`/`Verifier` traits.
- Produces: `fn select_executor(apply: &Option<ApplyConfig>) -> (Box<dyn Executor>, Box<dyn Verifier>)`.

- [ ] **Step 1: Write the failing selection test** (inline in `lib.rs` tests):

```rust
#[test]
fn select_executor_defaults_to_dry_run() {
    use torda_remediation::action::{AssetSelector, CanarySpec, Method, RemediationAction, VerifySpec};
    let action = RemediationAction {
        id: "a".into(), name: "n".into(), method: Method::Shell, payload: "exit 0".into(),
        targets: AssetSelector { asset_ids: vec!["h1".into()] },
        requires_approval: true, dry_run_supported: true, rollback: None,
        verify: VerifySpec { finding_ids: vec![] },
        canary: CanarySpec { cohort_size: 1, failure_threshold: 0.0 },
    };
    // None and disabled => dry-run (preview starts with "[dry-run]")
    assert!(select_executor(&None).0.preview(&action).starts_with("[dry-run]"));
    let off = ApplyConfig { enabled: false, allowed_methods: vec![Method::Shell], exec_timeout_secs: 300, max_output_bytes: 65536 };
    assert!(select_executor(&Some(off)).0.preview(&action).starts_with("[dry-run]"));
    // enabled => real (preview starts with "[apply:")
    let on = ApplyConfig { enabled: true, allowed_methods: vec![Method::Shell], exec_timeout_secs: 300, max_output_bytes: 65536 };
    assert!(select_executor(&Some(on)).0.preview(&action).starts_with("[apply:"));
}
```

- [ ] **Step 2: Run to verify it fails** — `cargo test -p torda --locked select_executor_defaults` → FAIL (`select_executor` undefined).

- [ ] **Step 3: Implement selection + thread the config.** Add the helper in `lib.rs`:

```rust
/// Choose the control-channel executor/verifier. Real execution is opt-in: only an
/// `apply` config with `enabled = true` selects `RealExecutor`; every other case
/// (absent config, or `enabled = false`) keeps the safe dry-run no-op.
fn select_executor(apply: &Option<ApplyConfig>) -> (Box<dyn Executor>, Box<dyn Verifier>) {
    match apply {
        Some(a) if a.enabled => (Box::new(RealExecutor::new(a.clone())), Box::new(RealVerifier)),
        _ => (Box::new(DryRunExecutor::new()), Box::new(DryRunVerifier)),
    }
}
```
Change `control_accept_loop`'s signature to add `apply: Option<ApplyConfig>` (last param) and, inside the accept loop, replace the hard-coded boxes (~lines 519-525) with:
```rust
                let (executor, verifier) = select_executor(&apply);
                let handler = AgentControlHandler::new(&verifier_store, &policy, &signer);
                let mut agent_loop =
                    AgentControlLoop::with_session(handler, &session, 0, executor, verifier);
```
(Keep the existing name for the `ReloadableVerifier` arg — shown here as `verifier_store` — distinct from the per-connection `Box<dyn Verifier>`; if the existing param is named `verifier`, rename the local `Box<dyn Verifier>` to `result_verifier` and pass it as the 5th arg to avoid shadowing. Pick names that compile cleanly; do not change `AgentControlHandler::new`'s signature.)
Update the one call site in `spawn_control_service` that spawns `control_accept_loop` to pass `cfg.apply.clone()` as the new argument. Ensure `Executor`/`Verifier` are in scope in `lib.rs` (import from `torda_remediation::bridge` if not already).

- [ ] **Step 4: Run tests** — `cargo test -p torda --locked` (the selection test + the whole crate) → PASS. Confirm the dry-run default path is unchanged.

- [ ] **Step 5: fmt + clippy + commit**

```bash
cargo fmt --all --check && cargo clippy --all-targets --locked -- -D warnings
git add crates/agent/src/lib.rs
git commit -m "feat(agent): select real executor only when apply.enabled (default dry-run)"
```

---

### Task 4: Full-slice gates + docs

**Files:**
- Modify: `crates/agent` docs/README or config example if one documents `[control]` (add an `[control.apply]` example noting default-off + Shell-only + bounded); if none exists, add a short doc comment block — do not invent a new doc file.

- [ ] **Step 1: Document the opt-in** where `[control]` config is described (search `crates/agent` for existing config docs/examples). Add an example:
```toml
# [control.apply]        # OMIT this whole section to keep the safe dry-run default.
# enabled = true          # real execution; OFF unless explicitly set
# allowed_methods = ["Shell"]
# exec_timeout_secs = 300
# max_output_bytes = 65536
```
with a one-line note: real apply runs the operator's payload on this host as the agent's user; keep the agent least-privileged.

- [ ] **Step 2: Full gates** (from `torda-public` root): `cargo fmt --all --check`; `cargo clippy --all-targets --locked -- -D warnings`; `cargo test --locked`. Record outputs.

- [ ] **Step 3: Commit docs** (if changed):
```bash
git add -A
git commit -m "docs(agent): document opt-in [control.apply] (default off)"
```

- [ ] **Step 4:** Hand off to in-window Codex review (`codex review --base main -c model_reasoning_effort="medium"` from `torda-public`), fix findings, then push + open the PR (CI incl. Linux/macOS/Windows + eBPF/ETW/cargo-deny) → user merges.
