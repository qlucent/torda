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
        format!(
            "[apply:{:?}] {} target(s)",
            action.method,
            action.targets.asset_ids.len()
        )
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
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
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

    #[test]
    fn verifier_fixed_only_when_all_targets_applied() {
        let v = RealVerifier;
        let a = action(Method::Shell, OK, None, &["h1", "h2"]);
        assert_eq!(
            v.verify(&a, &["h1".into(), "h2".into()]),
            VerifyOutcome::Fixed
        );
        assert_eq!(v.verify(&a, &["h1".into()]), VerifyOutcome::NotFixed);
        assert_eq!(v.verify(&a, &[]), VerifyOutcome::NotFixed);
    }
}
