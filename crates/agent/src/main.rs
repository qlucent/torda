//! P1 agent: wires the shared substrate + enabled modules and runs one
//! collection cycle, emitting OCSF to stdout (NDJSON). The emitter is the
//! seam where the mTLS transport + WAL buffer plug in at P1.
//!
//! P3c: the collection cycle is UNCHANGED and always runs. Additionally, if a
//! config is supplied (via `--config <path>` or `$TORDA_AGENT_CONFIG`) AND that
//! config has `control_enabled = true`, the agent ALSO stands up the mutual-TLS
//! remediation control service on its own dedicated std::thread (off the tokio
//! reactor) and keeps the process alive to serve the channel until a shutdown
//! signal (ctrl-c) or an optional `$TORDA_RUN_SECS` bound. With no config — or with
//! `control_enabled = false` — the binary behaves EXACTLY as before: one cycle,
//! OCSF to stdout, exit 0. Control is strictly OPT-IN.
//!
//! MA-1b: the config (now TOML, `torda::AgentConfig`) is loaded exactly ONCE
//! at startup and drives THREE concerns — daemon mode, output sink, and control —
//! with CLI-flag/env values taking precedence: **flag > env > config > default**.
//! `resolve_daemon_mode`/`resolve_output` are the small, unit-testable resolvers;
//! `discover_daemon_mode`/`emit::discover_output` remain the flag/env-only layer they
//! consult. Backward compat is load-bearing: with no `--config` and no daemon/output
//! flags, the agent runs the classic one-shot-to-stdout path, byte-identical.
mod emit;
mod sampler;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use emit::FileEmitter;
use sampler::SysinfoSampler;
use torda::{load_config, spawn_control_service, AgentConfig, ControlConfig, OutputConfig};
use torda_core::{
    ModuleCtx, ModuleManager, OcsfEmitter, ResourceBudget, ResourceGovernor, ThrottleDecision,
};
use torda_ocsf::OcsfEnvelope;

/// Writes each OCSF record as one NDJSON line. Swap for the buffered,
/// WAL-backed, mTLS transport sink in P1 — no module changes required.
struct StdoutEmitter;
impl OcsfEmitter for StdoutEmitter {
    fn emit(&self, rec: OcsfEnvelope) {
        match serde_json::to_string(&rec) {
            Ok(line) => println!("{line}"),
            Err(e) => eprintln!("emit serialize error: {e}"),
        }
    }
}

/// The FLAG/ENV layer for daemon mode: whether `--daemon`/`$TORDA_DAEMON` was explicitly
/// present, and its value if so (`$TORDA_DAEMON` is truthy for `"1"`/`"true"`,
/// case-insensitive). `None` means NEITHER was present — the presence-aware signal
/// `resolve_daemon_mode`'s config-fallback precedence needs: a config's `[agent].daemon`
/// should only be consulted when this layer is silent, not when it explicitly says
/// `false`. Mirrors `discover_config_path`'s flag-then-env precedence pattern.
fn daemon_flag_env_from(
    args: impl Iterator<Item = String>,
    env: impl Fn(&str) -> Option<String>,
) -> Option<bool> {
    for arg in args {
        if arg == "--daemon" {
            return Some(true);
        }
    }
    env("TORDA_DAEMON").map(|v| {
        let v = v.trim().to_ascii_lowercase();
        v == "1" || v == "true"
    })
}

/// Resolve the EFFECTIVE daemon mode: `--daemon`/`$TORDA_DAEMON` (if present) wins
/// outright; otherwise fall back to the config's `[agent].daemon`; otherwise `false`.
/// Precedence: **flag > env > config > default**. Unit-testable: takes the argument
/// iterator, env lookup, and the config's daemon value as plain inputs.
fn resolve_daemon_mode(
    args: impl Iterator<Item = String>,
    env: impl Fn(&str) -> Option<String>,
    config_daemon: bool,
) -> bool {
    daemon_flag_env_from(args, env).unwrap_or(config_daemon)
}

/// Resolve the EFFECTIVE output sink: `--output`/`$TORDA_OUTPUT` (+ `--rotate-mb`/
/// `$TORDA_ROTATE_MB`), if present, wins outright; otherwise fall back to the config's
/// `[output]` section; otherwise `None` (stdout). Precedence: **flag > env > config >
/// default**.
///
/// `flag_env` is the ALREADY-RESOLVED flag/env layer (`emit::discover_output()`'s
/// output) so this function stays a pure, unit-testable resolver with no direct env
/// access of its own.
///
/// Returns `Ok(Some((path, rotate_bytes)))` for a file sink, `Ok(None)` for stdout, or
/// `Err(message)` if the config's `[output]` section is unusable (`sink = "file"` with
/// no `path`, or an unrecognized `sink` value) — the caller fails closed on `Err`,
/// exactly like an unopenable file sink from a flag: a clear fatal error, never a
/// silent stdout fallback and never a panic.
fn resolve_output(
    flag_env: Option<(PathBuf, u64)>,
    config_output: Option<&OutputConfig>,
) -> Result<Option<(PathBuf, u64)>, String> {
    if let Some(pair) = flag_env {
        return Ok(Some(pair));
    }
    match config_output {
        None => Ok(None),
        Some(out) => match out.sink.as_str() {
            "file" => {
                let path = out
                    .path
                    .clone()
                    .ok_or_else(|| "[output] sink = \"file\" requires a path".to_string())?;
                let rotate_mb = out.rotate_mb.unwrap_or(emit::DEFAULT_ROTATE_MB);
                Ok(Some((path, rotate_mb.saturating_mul(1024 * 1024))))
            }
            "stdout" => Ok(None),
            other => Err(format!(
                "[output] has unknown sink \"{other}\" (expected \"stdout\" or \"file\")"
            )),
        },
    }
}

/// Discover an optional config path, OPT-IN and backward-compatible: `--config <path>`
/// (or `--config=<path>`) on the command line takes precedence, else `$TORDA_AGENT_CONFIG`.
/// `None` means no config was requested — the agent runs exactly as it did at P2a
/// (collection only, no control). Absence is NOT an error; a config is never required.
fn discover_config_path() -> Option<PathBuf> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if let Some(inline) = arg.strip_prefix("--config=") {
            return Some(PathBuf::from(inline));
        }
        if arg == "--config" {
            // The following arg (if any) is the path. A bare `--config` with no value
            // falls through to the env var / None so we never index past the end.
            if let Some(path) = args.next() {
                return Some(PathBuf::from(path));
            }
        }
    }
    std::env::var_os("TORDA_AGENT_CONFIG").map(PathBuf::from)
}

/// Load the config ONCE (if a path was requested), FAIL-CLOSED: a requested-but-unloadable
/// config prints the error to stderr and exits non-zero — never a silent downgrade to the
/// unconfigured path — BEFORE any collection side effects. `None` (no `--config`/
/// `$TORDA_AGENT_CONFIG`) means no config was requested; the agent runs with all defaults,
/// overridable only by CLI flags/env, exactly as before this config existed.
///
/// MA-1b: this SINGLE loaded config now drives all three concerns — daemon, output, and
/// control — each via its own precedence resolver (flag > env > config > default). Loading
/// it once here (instead of once per concern) is the fix for the double-load Task 1 left.
fn load_agent_config(path: Option<&Path>) -> Option<AgentConfig> {
    let path = path?;
    match load_config(path) {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            eprintln!("fatal: cannot load agent config {}: {e}", path.display());
            std::process::exit(1);
        }
    }
}

/// Resolve the effective control section from the ALREADY-LOADED config: `None` if no
/// config was requested (old behavior), or if the config's `[control]` section is absent /
/// `enabled = false` (prints the same diagnostic as before); `Some(control)` if present and
/// enabled. The config's own fail-closed load happens once, in `load_agent_config`, before
/// this is ever called — this function never fails.
fn effective_control(path: Option<&Path>, config: Option<&AgentConfig>) -> Option<ControlConfig> {
    let path = path?;
    match config.and_then(|cfg| cfg.control.clone()) {
        Some(control) if control.enabled => Some(control),
        _ => {
            eprintln!(
                "control disabled in config {} (no [control] section, or enabled = false) — collection only",
                path.display()
            );
            None
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Config discovery + load happen FIRST, ONCE, so a bad requested config fails closed
    // before any collection side effects. `None` => no config requested at all; every
    // concern below falls back to CLI flags/env and then defaults.
    let config_path = discover_config_path();
    let config = load_agent_config(config_path.as_deref());

    // Effective control: `None` if no config was requested, or the config's [control] is
    // absent/disabled; `Some` if present and enabled. (Old behavior, now off the single load.)
    let control_cfg = effective_control(config_path.as_deref(), config.as_ref());
    // Effective daemon mode: `--daemon`/`$TORDA_DAEMON` (if present) wins outright; otherwise
    // the config's `[agent].daemon`; otherwise `false` — today's one-shot path, unchanged
    // when neither a flag/env nor a config was supplied.
    let daemon_mode = resolve_daemon_mode(
        std::env::args().skip(1),
        |k| std::env::var(k).ok(),
        config.as_ref().map(|cfg| cfg.agent.daemon).unwrap_or(false),
    );

    match &control_cfg {
        Some(_) => eprintln!(
            "torda P3c — shared substrate + modules + mTLS control channel (ENABLED)"
        ),
        None => eprintln!(
            "torda P2a — shared substrate + asset + health + vuln + compliance + drift + fim + procmon + netmon + filemon + corr (control disabled)"
        ),
    }

    // If control is enabled, stand up the mutual-TLS service NOW (before collection) on
    // its dedicated std::thread — off the tokio reactor — so it is listening while the
    // collection cycle runs. All fallible setup fails closed here via `?`/exit.
    let control_handle = match &control_cfg {
        Some(cfg) => {
            let handle = spawn_control_service(cfg)
                .map_err(|e| anyhow::anyhow!("failed to start control service: {e}"))?;
            eprintln!(
                "control channel listening on {} (mTLS)",
                handle.local_addr()
            );
            Some(handle)
        }
        None => None,
    };

    // Obtain the EventBus + SnapshotProvider from the unified per-OS factory. The
    // snapshot is real (real hostname/OS + real host package inventory, e.g. the
    // Windows registry uninstall keys); the event bus is still the stub until a
    // real kernel-event backend feature is on. Modules depend only on the traits,
    // so this swap changes no collection behavior.
    let substrate = torda_substrate::Substrate::for_this_platform();
    let bus_label = substrate.bus_label;
    let bus = substrate.bus;
    let snapshot = substrate.snapshot;
    eprintln!(
        "substrate: {} (real snapshot; {bus_label} event bus)",
        std::env::consts::OS
    );
    // Output selection: `--output <path>`/`--output=<path>`/`$TORDA_OUTPUT` (+
    // `--rotate-mb`/`$TORDA_ROTATE_MB`), if present, wins outright; otherwise the config's
    // `[output]` section; otherwise today's default, byte-identical stdout path. Exactly
    // one active sink this slice — no tee (see the plan doc).
    let emitter: Arc<dyn OcsfEmitter> = match resolve_output(
        emit::discover_output(),
        config.as_ref().and_then(|cfg| cfg.output.as_ref()),
    ) {
        Ok(Some((path, rotate_bytes))) => {
            match FileEmitter::new(&path, rotate_bytes, emit::DEFAULT_MAX_ROLLS) {
                Ok(fe) => {
                    eprintln!(
                        "output: file sink at {} (rotate at {rotate_bytes} bytes, max {} rolls)",
                        path.display(),
                        emit::DEFAULT_MAX_ROLLS
                    );
                    Arc::new(fe)
                }
                Err(e) => {
                    // Fail closed: an operator who explicitly asked for a file
                    // sink that can't be opened must not silently fall back to
                    // stdout — mirrors the config fail-closed pattern above.
                    eprintln!("fatal: cannot open output file {}: {e}", path.display());
                    std::process::exit(1);
                }
            }
        }
        Ok(None) => Arc::new(StdoutEmitter),
        Err(msg) => {
            // Fail closed on an underspecified/invalid config [output] section too — never
            // a silent fallback to stdout, never a panic.
            eprintln!("fatal: invalid [output] configuration: {msg}");
            std::process::exit(1);
        }
    };

    let budget = ResourceBudget::from_env();
    let governor = Arc::new(ResourceGovernor::new(
        budget,
        Box::new(SysinfoSampler::new()),
    ));
    // Warm up CPU metering before any module emits: sysinfo derives process CPU%
    // from the delta between two refreshes, so a single sample reads 0. Take two
    // samples spaced by sysinfo's minimum interval so the first Agent Health record
    // carries a real cpu_pct, not a structural zero.
    governor.poll();
    tokio::time::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL).await;
    governor.poll();
    eprintln!(
        "resource budget: {:.1}% CPU, {:.1}% RAM",
        budget.cpu_pct, budget.mem_pct
    );

    let ctx = ModuleCtx {
        bus,
        snapshot,
        emitter,
        governor: governor.clone(),
        tenant_id: "tenant-dev".to_string(),
        product: "torda".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };

    let mut mgr = ModuleManager::new(ctx);

    // Per-tenant policy would decide this set. P2a enables asset + health + vuln + compliance + drift + fim + procmon.
    mgr.register(Box::new(torda_mod_asset::AssetModule::new()));
    mgr.register(Box::new(torda_mod_health::HealthModule::new()));
    mgr.register(Box::new(torda_mod_vuln::VulnModule::new()));
    mgr.register(Box::new(torda_mod_compliance::ComplianceModule::new()));
    mgr.register(Box::new(torda_mod_drift::DriftModule::new()));
    mgr.register(Box::new(torda_mod_fim::FimModule::new()));
    // procmon CONSUMES the shared event bus (ProcessExec). On the default StubBus no
    // events are published, so it subscribes and emits NOTHING — a behavior-preserving
    // no-op until a real event backend (windows-etw / linux-ebpf) feeds the bus.
    mgr.register(Box::new(torda_mod_procmon::ProcMonModule::new()));
    // netmon CONSUMES the shared event bus (NetConnect); on the default StubBus no
    // events → a behavior-preserving no-op until a real backend feeds the bus.
    mgr.register(Box::new(torda_mod_netmon::NetMonModule::new()));
    // filemon CONSUMES the shared event bus (FileOpen/FileWrite), prefiltered by
    // FilePolicy before assessment; on the default StubBus no events → a
    // behavior-preserving no-op until a real backend feeds the bus.
    mgr.register(Box::new(torda_mod_filemon::FileMonModule::new()));
    // libload CONSUMES the shared event bus (FileOpen), emitting one Runtime
    // Module Load (9003) observation per distinct shared library loaded — the
    // runtime-reachability telemetry the backend joins against the SBOM. On the
    // default StubBus no events → a behavior-preserving no-op until a real
    // backend feeds the bus.
    mgr.register(Box::new(torda_mod_libload::LibLoadModule::new()));
    // corr CONSUMES ProcessExec+NetConnect and correlates them by pid; on the
    // default StubBus no events → a behavior-preserving no-op.
    mgr.register(Box::new(torda_mod_corr::CorrModule::new()));

    mgr.init_all().await?;
    mgr.start_all().await?;

    if daemon_mode {
        // Daemon mode: the event-driven modules (procmon/netmon/filemon/corr)
        // are already running as continuous background subscription tasks
        // from `start_all()` — they stream to the sink for as long as the
        // process stays up. So "run continuously" simply means: don't
        // `stop_all()` yet. Keep the process alive (governor polling
        // cooperatively the whole time) until the shared shutdown signal
        // fires, THEN stop everything cleanly. Composes with control: both
        // stream/serve until the SAME signal.
        eprintln!("daemon mode — streaming until shutdown (ctrl-c / TORDA_RUN_SECS)");

        // Cooperative governor: periodically sample and warn on over-budget,
        // for the DURATION of the daemon run (not just a handful of ticks).
        // Aborted (bounded, no hang) once the shutdown signal fires below.
        let gov = governor.clone();
        let poller = tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_millis(250));
            loop {
                tick.tick().await;
                if let ThrottleDecision::Throttle { over_factor } = gov.check() {
                    eprintln!(
                        "over resource budget by {over_factor:.2}x — throttling low-priority work"
                    );
                }
            }
        });

        // Reuse the SAME shutdown wait as the control-only path: ctrl-c /
        // SIGINT, or the deterministic `$TORDA_RUN_SECS` bound — so a daemon run
        // (with or without control) never hangs.
        wait_for_shutdown().await;
        poller.abort();
        let _ = poller.await; // expected Cancelled error from abort() — not a failure

        // Let any in-flight async emits flush before reporting health / stopping.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        for (id, h) in mgr.health() {
            eprintln!("module {id}: ok={} ({})", h.ok, h.detail);
        }

        mgr.stop_all().await?;
        eprintln!("torda daemon stopped");

        // If control was also enabled, shut it down on the same signal.
        if let Some(handle) = control_handle {
            eprintln!("shutting down control channel…");
            handle.shutdown(); // signals the accept thread and joins it (bounded, no hang)
            eprintln!("control channel stopped");
        }
    } else {
        // Non-daemon path: BYTE-IDENTICAL to before daemon mode existed —
        // one bounded collection cycle, then (only if control is enabled)
        // keep serving control until shutdown. No behavior change here.

        // Cooperative governor: periodically sample and warn on over-budget. The
        // scheduler in later P1 slices consults `check()` to shed low-priority work.
        let gov = governor.clone();
        let poller = tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_millis(250));
            for _ in 0..4 {
                tick.tick().await;
                if let ThrottleDecision::Throttle { over_factor } = gov.check() {
                    eprintln!(
                        "over resource budget by {over_factor:.2}x — throttling low-priority work"
                    );
                }
            }
        });
        let _ = poller.await;

        // Let async emits flush. P1 replaces this with the scheduler/event loop.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        for (id, h) in mgr.health() {
            eprintln!("module {id}: ok={} ({})", h.ok, h.detail);
        }

        mgr.stop_all().await?;
        eprintln!("torda P1 cycle complete");

        // If control is enabled, KEEP THE PROCESS ALIVE to serve the mTLS channel. The
        // control service is on its own std::thread; here we simply park the tokio task until
        // a shutdown signal, then stop the service cleanly. When control is disabled this
        // block is skipped entirely and we exit immediately — identical to P2a.
        if let Some(handle) = control_handle {
            wait_for_shutdown().await;
            eprintln!("shutting down control channel…");
            handle.shutdown(); // signals the accept thread and joins it (bounded, no hang)
            eprintln!("control channel stopped");
        }
    }

    Ok(())
}

/// Block until it's time to stop serving the control channel: either a ctrl-c / SIGINT,
/// or — if `$TORDA_RUN_SECS` is set to a value > 0 — after that many seconds (a deterministic,
/// testable bound so an enabled run never hangs CI). `TORDA_RUN_SECS=0` (or unset/invalid)
/// means "run until ctrl-c".
async fn wait_for_shutdown() {
    let run_secs = std::env::var("TORDA_RUN_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&s| s > 0);

    match run_secs {
        Some(secs) => {
            eprintln!("serving control channel for {secs}s (TORDA_RUN_SECS), then shutting down");
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(secs)) => {}
                r = tokio::signal::ctrl_c() => {
                    if r.is_ok() {
                        eprintln!("received ctrl-c");
                    }
                }
            }
        }
        None => {
            eprintln!("serving control channel until ctrl-c");
            if tokio::signal::ctrl_c().await.is_ok() {
                eprintln!("received ctrl-c");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_mode_flag_is_detected() {
        let args = vec!["--daemon".to_string()];
        assert_eq!(daemon_flag_env_from(args.into_iter(), |_| None), Some(true));
    }

    #[test]
    fn daemon_mode_env_truthy_values_are_detected() {
        for v in ["1", "true", "TRUE", " true ", "True"] {
            let v = v.to_string();
            assert_eq!(
                daemon_flag_env_from(std::iter::empty(), |k| if k == "TORDA_DAEMON" {
                    Some(v.clone())
                } else {
                    None
                }),
                Some(true),
                "TORDA_DAEMON={v:?} should be truthy"
            );
        }
    }

    #[test]
    fn daemon_mode_env_falsy_or_unset_is_not_daemon() {
        assert_eq!(
            daemon_flag_env_from(std::iter::empty(), |_| None),
            None,
            "no flag, no env => neither layer present"
        );
        for v in ["0", "false", "no", "", "garbage"] {
            let v = v.to_string();
            assert_eq!(
                daemon_flag_env_from(std::iter::empty(), |k| if k == "TORDA_DAEMON" {
                    Some(v.clone())
                } else {
                    None
                }),
                Some(false),
                "TORDA_DAEMON={v:?} should be present but NOT truthy"
            );
        }
    }

    #[test]
    fn daemon_mode_flag_takes_precedence_and_ignores_other_args() {
        let args = vec![
            "--config".to_string(),
            "path".to_string(),
            "--daemon".to_string(),
        ];
        assert_eq!(daemon_flag_env_from(args.into_iter(), |_| None), Some(true));
    }

    // --- MA-1b: flag > env > config > default precedence resolvers ---

    #[test]
    fn resolve_daemon_mode_falls_back_to_config_when_flag_and_env_absent() {
        assert!(
            resolve_daemon_mode(std::iter::empty(), |_| None, true),
            "no flag/env -> config's daemon=true wins"
        );
        assert!(
            !resolve_daemon_mode(std::iter::empty(), |_| None, false),
            "no flag/env -> config's daemon=false wins"
        );
    }

    #[test]
    fn resolve_daemon_mode_default_false_when_nothing_set() {
        assert!(!resolve_daemon_mode(std::iter::empty(), |_| None, false));
    }

    #[test]
    fn resolve_daemon_mode_flag_overrides_config_false() {
        let args = vec!["--daemon".to_string()];
        assert!(
            resolve_daemon_mode(args.into_iter(), |_| None, false),
            "--daemon wins even when the config says daemon=false"
        );
    }

    #[test]
    fn resolve_daemon_mode_env_overrides_config() {
        assert!(
            resolve_daemon_mode(
                std::iter::empty(),
                |k| if k == "TORDA_DAEMON" {
                    Some("true".to_string())
                } else {
                    None
                },
                false
            ),
            "TORDA_DAEMON=true wins even when the config says daemon=false"
        );
        assert!(
            !resolve_daemon_mode(
                std::iter::empty(),
                |k| if k == "TORDA_DAEMON" {
                    Some("false".to_string())
                } else {
                    None
                },
                true
            ),
            "TORDA_DAEMON=false wins even when the config says daemon=true"
        );
    }

    #[test]
    fn resolve_output_flag_env_overrides_config() {
        let flag_env = Some((PathBuf::from("/flag/out.ndjson"), 10 * 1024 * 1024));
        let config_output = OutputConfig {
            sink: "file".to_string(),
            path: Some(PathBuf::from("/config/out.ndjson")),
            rotate_mb: Some(64),
        };
        let got = resolve_output(flag_env.clone(), Some(&config_output)).expect("resolves");
        assert_eq!(
            got, flag_env,
            "the flag/env sink wins over the config's [output]"
        );
    }

    #[test]
    fn resolve_output_uses_config_file_sink_when_flag_env_absent() {
        let config_output = OutputConfig {
            sink: "file".to_string(),
            path: Some(PathBuf::from("/config/out.ndjson")),
            rotate_mb: Some(10),
        };
        let got = resolve_output(None, Some(&config_output)).expect("resolves");
        assert_eq!(
            got,
            Some((PathBuf::from("/config/out.ndjson"), 10 * 1024 * 1024))
        );
    }

    #[test]
    fn resolve_output_config_file_sink_defaults_rotate_mb_when_absent() {
        let config_output = OutputConfig {
            sink: "file".to_string(),
            path: Some(PathBuf::from("/config/out.ndjson")),
            rotate_mb: None,
        };
        let got = resolve_output(None, Some(&config_output)).expect("resolves");
        assert_eq!(
            got,
            Some((
                PathBuf::from("/config/out.ndjson"),
                emit::DEFAULT_ROTATE_MB * 1024 * 1024
            ))
        );
    }

    #[test]
    fn resolve_output_config_stdout_sink_is_none() {
        let config_output = OutputConfig {
            sink: "stdout".to_string(),
            path: None,
            rotate_mb: None,
        };
        assert_eq!(
            resolve_output(None, Some(&config_output)).expect("resolves"),
            None
        );
    }

    #[test]
    fn resolve_output_absent_flag_env_and_config_is_none() {
        assert_eq!(resolve_output(None, None).expect("resolves"), None);
    }

    #[test]
    fn resolve_output_config_file_sink_missing_path_is_fatal_error() {
        let config_output = OutputConfig {
            sink: "file".to_string(),
            path: None,
            rotate_mb: None,
        };
        let err = resolve_output(None, Some(&config_output)).expect_err(
            "sink=\"file\" with no path must be a fatal Err, not a panic or a stdout fallback",
        );
        assert!(
            err.contains("path"),
            "error should mention the missing path: {err}"
        );
    }

    #[test]
    fn resolve_output_config_unknown_sink_is_fatal_error() {
        let config_output = OutputConfig {
            sink: "syslog".to_string(),
            path: None,
            rotate_mb: None,
        };
        let err = resolve_output(None, Some(&config_output))
            .expect_err("an unrecognized sink value must be a fatal Err, never a silent fallback");
        assert!(
            err.contains("syslog"),
            "error should name the offending sink: {err}"
        );
    }

    #[test]
    fn effective_control_none_when_no_config_requested() {
        assert!(effective_control(None, None).is_none());
    }

    #[test]
    fn effective_control_none_when_config_has_no_control_section() {
        let path = PathBuf::from("agent.toml");
        let cfg = AgentConfig::default();
        assert!(effective_control(Some(&path), Some(&cfg)).is_none());
    }
}
