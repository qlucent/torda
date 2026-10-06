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
    /// Scoped-targets gate: this agent executes ONLY against the single asset it
    /// represents (`cfg.host_id`). The Bridge calls `apply`/`rollback` once per
    /// selected asset; running the payload for a target that is not this host would
    /// mutate the local host while auditing success for some other asset id. Fail
    /// closed (no process spawned) if `host_id` is unset or the target is not us.
    fn host_targeted(&self, target: &str) -> anyhow::Result<()> {
        if self.cfg.host_id.is_empty() || target != self.cfg.host_id {
            anyhow::bail!("target not permitted for this host");
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
        format!(
            "[apply:{:?}] {} target(s)",
            action.method,
            action.targets.asset_ids.len()
        )
    }
    fn apply(&mut self, action: &RemediationAction, target: &str) -> anyhow::Result<()> {
        self.permitted(action)?;
        self.host_targeted(target)?;
        self.run(&action.payload)
    }
    fn rollback(&mut self, action: &RemediationAction, target: &str) -> anyhow::Result<()> {
        self.permitted(action)?;
        self.host_targeted(target)?;
        match &action.rollback {
            Some(p) => self.run(p),
            None => Ok(()),
        }
    }
}

#[derive(Debug, Default)]
pub struct RealVerifier;
impl Verifier for RealVerifier {
    fn verify(&self, _action: &RemediationAction, applied: &[String]) -> VerifyOutcome {
        // Stage-aware: the Bridge applies a cohort/stage (canary = a SUBSET of the
        // action's targets) and passes only the targets whose `apply` returned Ok.
        // The agent cannot re-check findings here, so a non-empty applied set is the
        // honest success signal for whatever stage was applied; requiring ALL action
        // targets would fail every partial-cohort canary and strand the rollout.
        if applied.is_empty() {
            VerifyOutcome::NotFixed
        } else {
            VerifyOutcome::Fixed
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
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // UNIX: make the child its own process-group leader (pgid == child pid) so that on
    // timeout we can signal the WHOLE group — the shell plus any grandchildren it
    // spawned — not just `sh`. `process_group` is stable since Rust 1.64.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let mut child = cmd.spawn().map_err(|_| "spawn failed".to_string())?;
    // Drain pipes in threads so a chatty child can't block on a full pipe; cap the read.
    let cap = max_bytes as u64;
    let mut out = child.stdout.take().expect("piped");
    let mut err = child.stderr.take().expect("piped");
    // Spawned detached (not joined): their only job is to drain the pipes so the child
    // can't block on a full buffer. Captured bytes are discarded (never returned — that's
    // how the error stays secret-free), so nothing here needs their completion. Killing
    // `cmd`/`sh` on a timeout does not kill any grandchild it spawned (e.g. `ping`), which
    // can keep a pipe open well past the kill; joining would then block OUR timeout on
    // that orphan's lifetime instead of the configured deadline.
    std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out.by_ref().take(cap + 1).read_to_end(&mut b);
        // keep reading-to-drain past the cap without storing, so the child can finish/exit
        let _ = std::io::copy(&mut out, &mut std::io::sink());
    });
    std::thread::spawn(move || {
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
                    kill_tree(&mut child);
                    break None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => {
                kill_tree(&mut child);
                break None;
            }
        }
    };
    match status {
        Some(s) if s.success() => Ok(()),
        Some(s) => Err(format!(
            "exit {}",
            s.code()
                .map_or_else(|| "signal".to_string(), |c| c.to_string())
        )),
        None => Err("timed out".to_string()),
    }
}

/// Terminate the child's ENTIRE process tree, then reap the child. Killing only
/// `cmd`/`sh` would leave any grandchild (e.g. a backgrounded subprocess) alive to
/// keep mutating the host after we report a timeout. Best-effort and secret-free.
#[cfg(unix)]
fn kill_tree(child: &mut std::process::Child) {
    // A NEGATIVE pid targets the process GROUP; the child leads its own group
    // (set via `process_group(0)` at spawn), so this reaches the shell + descendants.
    let _ = Command::new("kill")
        .arg("-KILL")
        .arg(format!("-{}", child.id()))
        .status();
    // Native fallback: if `kill` is missing/fails, still terminate the direct child so
    // the timeout is ALWAYS enforced — `wait()` must never block forever on the shell.
    let _ = child.kill();
    let _ = child.wait();
}

/// Windows variant: `taskkill /T` terminates the child and its whole tree.
#[cfg(windows)]
fn kill_tree(child: &mut std::process::Child) {
    let _ = Command::new("taskkill")
        .args(["/F", "/T", "/PID", &child.id().to_string()])
        .output();
    // Native fallback: if `taskkill` is missing/fails, still terminate the direct child
    // so the timeout is ALWAYS enforced — `wait()` must never block forever.
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ApplyConfig;
    use torda_remediation::action::{
        AssetSelector, CanarySpec, Method, RemediationAction, VerifySpec,
    };
    use torda_remediation::bridge::{Executor, Verifier, VerifyOutcome};

    fn action(
        method: Method,
        payload: &str,
        rollback: Option<&str>,
        targets: &[&str],
    ) -> RemediationAction {
        RemediationAction {
            id: "a".into(),
            name: "n".into(),
            method,
            payload: payload.into(),
            targets: AssetSelector {
                asset_ids: targets.iter().map(|s| s.to_string()).collect(),
            },
            requires_approval: true,
            dry_run_supported: true,
            rollback: rollback.map(|s| s.to_string()),
            verify: VerifySpec {
                finding_ids: vec![],
            },
            canary: CanarySpec {
                cohort_size: 1,
                failure_threshold: 0.0,
            },
        }
    }
    fn cfg(timeout: u64) -> ApplyConfig {
        ApplyConfig {
            enabled: true,
            allowed_methods: vec![Method::Shell],
            exec_timeout_secs: timeout,
            max_output_bytes: 1024,
            host_id: "h1".into(),
        }
    }
    // portable no-op success; `exit 0`/`cmd /C` both succeed on empty-ish commands
    const OK: &str = "exit 0";
    const FAIL: &str = "exit 7";

    #[test]
    fn apply_success_and_nonzero_exit_is_error() {
        let mut ex = RealExecutor::new(cfg(30));
        ex.apply(&action(Method::Shell, OK, None, &["h1"]), "h1")
            .unwrap();
        assert!(ex
            .apply(&action(Method::Shell, FAIL, None, &["h1"]), "h1")
            .is_err());
    }

    #[test]
    fn disallowed_method_does_not_execute() {
        let mut ex = RealExecutor::new(cfg(30));
        // non-Shell method
        assert!(ex
            .apply(&action(Method::Ansible, OK, None, &["h1"]), "h1")
            .is_err());
        // Shell not in allow-list
        let mut ex2 = RealExecutor::new(ApplyConfig {
            allowed_methods: vec![],
            ..cfg(30)
        });
        assert!(ex2
            .apply(&action(Method::Shell, OK, None, &["h1"]), "h1")
            .is_err());
    }

    #[test]
    fn apply_times_out_and_is_killed() {
        let mut ex = RealExecutor::new(cfg(1)); // 1s timeout
        let sleep = if cfg!(windows) {
            "ping -n 6 127.0.0.1 > NUL"
        } else {
            "sleep 5"
        };
        let start = std::time::Instant::now();
        let r = ex.apply(&action(Method::Shell, sleep, None, &["h1"]), "h1");
        assert!(r.is_err());
        assert!(
            start.elapsed() < std::time::Duration::from_secs(4),
            "must kill ~at timeout"
        );
    }

    #[test]
    fn large_output_is_bounded_and_not_leaked() {
        let mut ex = RealExecutor::new(ApplyConfig {
            max_output_bytes: 64,
            ..cfg(30)
        });
        let big = if cfg!(windows) {
            "echo SECRETSECRETSECRET & exit 3"
        } else {
            "echo SECRETSECRETSECRET; exit 3"
        };
        let err = ex
            .apply(&action(Method::Shell, big, None, &["h1"]), "h1")
            .unwrap_err()
            .to_string();
        assert!(!err.contains("SECRET"), "error must not leak output");
    }

    #[test]
    fn rollback_runs_when_present_and_noops_when_absent() {
        let mut ex = RealExecutor::new(cfg(30));
        ex.rollback(&action(Method::Shell, OK, None, &["h1"]), "h1")
            .unwrap(); // None -> Ok
        assert!(ex
            .rollback(&action(Method::Shell, OK, Some(FAIL), &["h1"]), "h1")
            .is_err()); // runs, fails
    }

    // #3: stage-aware verify — a non-empty applied set (even a canary SUBSET of the
    // action's larger target list) is Fixed; only an empty applied set is NotFixed.
    #[test]
    fn verifier_fixed_when_applied_nonempty_including_canary_subset() {
        let v = RealVerifier;
        let a = action(Method::Shell, OK, None, &["h1", "h2", "h3"]);
        // canary cohort: a strict, non-empty subset must verify Fixed (else rollout
        // is never reached) — this was the P2 regression.
        assert_eq!(v.verify(&a, &["h1".into()]), VerifyOutcome::Fixed);
        assert_eq!(
            v.verify(&a, &["h1".into(), "h2".into()]),
            VerifyOutcome::Fixed
        );
        // nothing applied => NotFixed.
        assert_eq!(v.verify(&a, &[]), VerifyOutcome::NotFixed);
    }

    // #2: scoped-targets — only the asset this agent represents (host_id) may run the
    // payload. A mismatched target (or an unset host_id) fails closed with NOTHING run.
    #[test]
    fn apply_rejects_target_that_is_not_this_host() {
        // host_id is "h1" (from cfg). FAIL would surface as "exit 7" if it ran; the
        // scope check must short-circuit to "target not permitted" with no spawn.
        let mut ex = RealExecutor::new(cfg(30));
        let e = ex
            .apply(&action(Method::Shell, FAIL, None, &["other"]), "other")
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("target not permitted"),
            "scope error, not exec: {e}"
        );
        let e = ex
            .rollback(&action(Method::Shell, OK, Some(FAIL), &["other"]), "other")
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("target not permitted"),
            "rollback scoped too: {e}"
        );
        // Matching target runs for real (OK succeeds).
        ex.apply(&action(Method::Shell, OK, None, &["h1"]), "h1")
            .unwrap();
    }

    #[test]
    fn empty_host_id_fails_closed_even_when_enabled() {
        let mut ex = RealExecutor::new(ApplyConfig {
            host_id: String::new(),
            ..cfg(30)
        });
        // Even an empty target must not match an empty host_id.
        let e = ex
            .apply(&action(Method::Shell, OK, None, &[""]), "")
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("target not permitted"),
            "unset host_id must refuse: {e}"
        );
    }

    // #1: timeout kills the whole tree. The payload backgrounds a long-lived
    // grandchild AND keeps the shell busy so the shell itself times out; on timeout we
    // signal the group/tree (not just the shell). Cross-platform we can't portably
    // assert the grandchild is dead, so this asserts the tree-kill timeout path runs:
    // Err is returned promptly and we do NOT hang on a surviving grandchild's pipe.
    #[test]
    fn timeout_tree_kill_path_returns_promptly_with_backgrounded_child() {
        let mut ex = RealExecutor::new(cfg(1)); // 1s timeout
        let payload = if cfg!(windows) {
            "start /b ping -n 30 127.0.0.1 >NUL & ping -n 30 127.0.0.1 >NUL"
        } else {
            "sleep 30 & sleep 30"
        };
        let start = std::time::Instant::now();
        let r = ex.apply(&action(Method::Shell, payload, None, &["h1"]), "h1");
        assert!(r.is_err(), "a timed-out payload is an error");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(4),
            "tree-kill timeout path must not hang on a surviving grandchild"
        );
    }
}
