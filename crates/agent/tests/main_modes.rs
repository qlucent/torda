//! Proves the `torda` BINARY's two run modes by spawning the compiled agent as a
//! child process (via `$CARGO_BIN_EXE_torda`) and inspecting its real stdout/stderr:
//!
//!  * `disabled_mode_runs_one_cycle_and_exits` — with NO config (no `--config`, no env), the
//!    binary runs the classic P2a collection cycle: OCSF NDJSON on stdout, module health on
//!    stderr, exit 0. Control is OPT-IN, so absence of a config keeps the old behavior.
//!  * `enabled_mode_listens_emits_and_shuts_down` — with a generated test config (real test
//!    PKI + ed25519 trust dir) supplied via `--config` and a bounded `TORDA_RUN_SECS=1`, the
//!    binary ALSO stands up the mTLS control channel (prints "control channel listening"),
//!    STILL emits OCSF, and exits 0 after the bounded run — no hang.
//!
//! Both children are guarded by a watchdog so a regression can never wedge CI.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use torda_control_plane::CommandSigner;
use torda_transport_tls::{generate_test_pki, write_pki_to_pem};

use torda::{AgentConfig, CertPaths, ControlConfig, RoleEntry};

const OPERATOR_SEED: [u8; 32] = [7u8; 32];
const AGENT_SEED: [u8; 32] = [42u8; 32];

fn unique_temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "torda-main-modes-{tag}-{}-{}",
        std::process::id(),
        nanos
    ));
    fs::create_dir_all(&dir).expect("create unique temp dir");
    dir
}

/// Write a full control config (test PKI + ed25519 trust dir + agent key) to `dir` and
/// return the path of the TOML config file. The `[control]` section has `enabled = true`.
fn write_enabled_config(dir: &Path) -> PathBuf {
    let pki = generate_test_pki();
    let pki_paths = write_pki_to_pem(&pki, dir).expect("write test PKI to PEM");

    let trust_dir = dir.join("trust");
    fs::create_dir_all(&trust_dir).unwrap();
    let operator_pub = hex::encode(
        CommandSigner::from_seed("operator", OPERATOR_SEED)
            .verifying_key()
            .to_bytes(),
    );
    fs::write(trust_dir.join("operator.pub"), format!("{operator_pub}\n")).unwrap();

    let agent_key_file = dir.join("agent-1.key");
    fs::write(&agent_key_file, format!("{}\n", hex::encode(AGENT_SEED))).unwrap();

    let cfg = AgentConfig {
        agent: Default::default(),
        output: None,
        control: Some(ControlConfig {
            control_addr: "127.0.0.1:0".to_string(),
            tenant_id: "tenant-test".to_string(),
            cert: CertPaths {
                ca_paths: vec![pki_paths.ca.clone()],
                cert_chain: pki_paths.server_chain.clone(),
                key: pki_paths.server_key.clone(),
                crl_paths: vec![],
            },
            trust_dir,
            agent_key_file,
            roles: vec![RoleEntry {
                actor: "operator".into(),
                role: "operator".into(),
            }],
            enabled: true,
        }),
    };

    let cfg_path = dir.join("agent.toml");
    fs::write(&cfg_path, toml::to_string(&cfg).unwrap()).unwrap();
    cfg_path
}

/// Run the compiled agent binary to completion under a watchdog, returning
/// `(exit_ok, stdout, stderr)`. Panics if the child does not exit within `deadline`.
fn run_agent(args: &[&str], env: &[(&str, &str)], deadline: Duration) -> (bool, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_torda"));
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn torda binary");

    // Drain stdout+stderr on their own threads so a large emission (e.g. a full
    // real-package SBOM on a CI runner with hundreds of packages) can't fill the
    // OS pipe buffer and wedge the child on a blocked write while we wait for it
    // to exit. The reader threads end when the child closes its pipes (exit/kill).
    let mut out_pipe = child.stdout.take().expect("child stdout piped");
    let mut err_pipe = child.stderr.take().expect("child stderr piped");
    let out_reader = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = out_pipe.read_to_string(&mut s);
        s
    });
    let err_reader = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = err_pipe.read_to_string(&mut s);
        s
    });

    // Watchdog: if the child overruns the deadline, kill it so the test fails fast
    // instead of hanging CI.
    let start = std::time::Instant::now();
    let status = loop {
        match child.try_wait().expect("try_wait on child") {
            Some(status) => break status,
            None => {
                if start.elapsed() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("agent child did not exit within {deadline:?} — it hung");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    };

    let stdout = out_reader.join().expect("join stdout reader");
    let stderr = err_reader.join().expect("join stderr reader");
    (status.success(), stdout, stderr)
}

#[test]
fn disabled_mode_runs_one_cycle_and_exits() {
    let (ok, stdout, stderr) = run_agent(&[], &[], Duration::from_secs(30));

    assert!(ok, "disabled-mode agent exits 0");
    assert!(
        stdout.contains("\"class_uid\""),
        "disabled mode still emits OCSF NDJSON on stdout; got: {stdout}"
    );
    assert!(
        stderr.contains("control disabled"),
        "disabled mode reports control disabled; stderr: {stderr}"
    );
    assert!(
        !stderr.contains("control channel listening"),
        "disabled mode must NOT start the control channel; stderr: {stderr}"
    );
    assert!(
        stderr.contains("torda P1 cycle complete"),
        "disabled mode completes the collection cycle; stderr: {stderr}"
    );
}

#[test]
fn enabled_mode_listens_emits_and_shuts_down() {
    let dir = unique_temp_dir("enabled");
    let cfg_path = write_enabled_config(&dir);

    // TORDA_RUN_SECS=1 bounds the keep-alive so the enabled run exits ~1s later, no hang.
    let (ok, stdout, stderr) = run_agent(
        &["--config", cfg_path.to_str().unwrap()],
        &[("TORDA_RUN_SECS", "1")],
        Duration::from_secs(30),
    );

    assert!(
        ok,
        "enabled-mode agent exits 0 after the bounded run; stderr: {stderr}"
    );
    assert!(
        stderr.contains("control channel listening on 127.0.0.1:"),
        "enabled mode prints the bound control listen address; stderr: {stderr}"
    );
    assert!(
        stdout.contains("\"class_uid\""),
        "enabled mode STILL emits OCSF NDJSON on stdout; got: {stdout}"
    );
    assert!(
        stderr.contains("control channel stopped"),
        "enabled mode shuts the control channel down cleanly; stderr: {stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}
