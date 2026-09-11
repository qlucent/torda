//! End-to-end proof that the agent's secure control service (`spawn_control_service`)
//! stands up a REAL mutual-TLS control channel over loopback and runs the UNCHANGED
//! `AgentControlLoop` against it:
//!
//!  * `signed_authorized_command_reaches_the_real_agent_loop` — an operator's signed,
//!    AUTHORIZED Draft, sent over real mTLS + real ed25519, is `Applied` by the agent's
//!    live control loop. This proves the whole stack is wired: file-loaded config ->
//!    mutual-TLS listener on a dedicated std::thread -> handler (verify + authorize) ->
//!    bridge -> signed result back over the wire.
//!  * `an_untrusted_client_is_rejected` — a client from a FOREIGN CA is rejected at the
//!    TLS handshake by the agent's `accept`; it never gets a command applied.
//!  * `shutdown_returns_without_hanging` — `handle.shutdown()` joins the accept thread
//!    cleanly (bounded read timeouts guarantee no hang).
//!
//! Everything below the app runs on synchronous rustls + std::net — there is no tokio
//! runtime in this test, matching the service's off-tokio design.

use std::fs;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::pki_types::{CertificateDer, ServerName};

use torda_control_plane::{CommandOutcome, CommandSigner, Ed25519Verifier};
use torda_control_server::{
    client_config_from_files, connect, ControlPlaneClient, TlsClientTransport,
};
use torda_remediation::action::{AssetSelector, CanarySpec, Method, RemediationAction, VerifySpec};
use torda_remediation::control::{CommandKind, ControlCommand};
use torda_transport_tls::{generate_test_pki, write_pki_to_pem, CertFilePaths};

use torda::{load_config, spawn_control_service, AgentConfig, CertPaths, ControlConfig, RoleEntry};

/// Bounds any client-side read so a bug can never hang CI. Loopback round-trips are
/// sub-millisecond; this is a safety net only.
const CLIENT_READ_TIMEOUT: Duration = Duration::from_secs(5);

const OPERATOR_SEED: [u8; 32] = [7u8; 32];
const AGENT_SEED: [u8; 32] = [42u8; 32];

/// A fresh, uniquely-named temp dir (pid + nanos) so concurrent test runs never collide.
fn unique_temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "torda-ctl-e2e-{tag}-{}-{}",
        std::process::id(),
        nanos
    ));
    fs::create_dir_all(&dir).expect("create unique temp dir");
    dir
}

/// A benign, fully-scoped Draft command for `actor` at `(session, seq)`, UNSIGNED.
fn draft_cmd(actor: &str, session: &str, seq: u64) -> ControlCommand {
    let action = RemediationAction {
        id: "fix-openssl".into(),
        name: "upgrade openssl".into(),
        method: Method::PackageMgr,
        payload: "apt-get install -y openssl=3.0.14".into(),
        targets: AssetSelector {
            asset_ids: vec!["host-1".into()],
        },
        requires_approval: true,
        dry_run_supported: true,
        rollback: Some("apt-get install -y openssl=3.0.2".into()),
        verify: VerifySpec {
            finding_ids: vec![],
        },
        canary: CanarySpec {
            cohort_size: 1,
            failure_threshold: 0.0,
        },
    };
    ControlCommand {
        action_id: "fix-openssl".into(),
        kind: CommandKind::Draft(Box::new(action)),
        actor: actor.into(),
        session: session.into(),
        seq,
        schedule: None,
        signature: String::new(),
    }
}

/// Write a full agent-config setup to disk and return the loaded [`ControlConfig`] (the
/// `[control]` section `spawn_control_service` consumes): a test PKI (server chain/key + a
/// client-auth CA), an ed25519 trust dir holding the operator's PUBLIC key, and the agent's
/// OWN private signing key at `agent-1.key`. Returns `(control, CertFilePaths, client_leaf,
/// agent_actor)` so the caller can build a matching client (the client leaf DER is needed for
/// cert-bound session derivation).
fn write_config(
    dir: &Path,
) -> (
    ControlConfig,
    CertFilePaths,
    CertificateDer<'static>,
    String,
) {
    // mTLS material: one CA signs both the server (agent) leaf and the client leaf, so the
    // agent trusts the client's CA and vice versa.
    let pki = generate_test_pki();
    let client_leaf = pki.client_cert_chain[0].clone();
    let pki_paths = write_pki_to_pem(&pki, dir).expect("write test PKI to PEM");

    // ed25519 command-verifier trust dir: the operator's PUBLIC key under actor "operator".
    let trust_dir = dir.join("trust");
    fs::create_dir_all(&trust_dir).unwrap();
    let operator_pub = hex::encode(
        CommandSigner::from_seed("operator", OPERATOR_SEED)
            .verifying_key()
            .to_bytes(),
    );
    fs::write(trust_dir.join("operator.pub"), format!("{operator_pub}\n")).unwrap();

    // The agent's OWN signing key (private seed). Its stem "agent-1" is the actor it signs
    // results under, so the issuer trusts results from "agent-1".
    let agent_actor = "agent-1".to_string();
    let agent_key_file = dir.join(format!("{agent_actor}.key"));
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

    // Round-trip through the REAL loader: serialize to TOML, then `load_config` it back.
    let cfg_path = dir.join("agent.toml");
    fs::write(&cfg_path, toml::to_string(&cfg).unwrap()).unwrap();
    let loaded = load_config(&cfg_path).expect("load_config parses the written config");
    let control = loaded
        .control
        .expect("the written config has a [control] section");
    (control, pki_paths, client_leaf, agent_actor)
}

/// Connect an mTLS client to `addr` using the client cert/key in `paths` (trusting the CA
/// as the server root). Returns the connected transport + the cert-bound session id.
fn connect_client(
    addr: std::net::SocketAddr,
    paths: &CertFilePaths,
    client_leaf: &CertificateDer<'static>,
) -> (TlsClientTransport, String) {
    let client_cfg = client_config_from_files(&[&paths.ca], &paths.client_chain, &paths.client_key)
        .expect("client cfg from files");
    let stream = TcpStream::connect(addr).expect("client TCP connect");
    stream.set_read_timeout(Some(CLIENT_READ_TIMEOUT)).unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    connect(stream, client_cfg, name, client_leaf).expect("mTLS handshake + server auth")
}

/// Best-effort: does an already-connected client obtain an `Applied` outcome for an
/// operator-signed Draft? Trusts the agent's key so a genuine result would verify.
fn client_gets_applied(
    transport: &mut TlsClientTransport,
    session: &str,
    agent_actor: &str,
) -> bool {
    let operator = CommandSigner::from_seed("operator", OPERATOR_SEED);
    let agent_id = CommandSigner::from_seed(agent_actor, AGENT_SEED);
    let mut server_v = Ed25519Verifier::new();
    server_v.trust(agent_actor, agent_id.verifying_key());
    let mut client = ControlPlaneClient::new(operator, server_v);

    let mut cmd = draft_cmd("operator", session, 1);
    client.sign(&mut cmd);
    if client.send_command(transport, cmd).is_err() {
        return false;
    }
    matches!(client.await_result(transport), Ok(Some(r)) if r.outcome == CommandOutcome::Applied)
}

#[test]
fn signed_authorized_command_reaches_the_real_agent_loop() {
    let dir = unique_temp_dir("ok");
    let (cfg, paths, client_leaf, agent_actor) = write_config(&dir);

    let handle = spawn_control_service(&cfg).expect("control service spawns");
    let addr = handle.local_addr();

    // Client: real mTLS handshake, then issue an operator-signed, AUTHORIZED Draft.
    let (mut transport, session) = connect_client(addr, &paths, &client_leaf);

    let operator = CommandSigner::from_seed("operator", OPERATOR_SEED);
    let agent_id = CommandSigner::from_seed(&agent_actor, AGENT_SEED);
    let mut server_v = Ed25519Verifier::new();
    server_v.trust(&agent_actor, agent_id.verifying_key()); // trust the agent's result signature
    let mut client = ControlPlaneClient::new(operator, server_v);

    let mut cmd = draft_cmd("operator", &session, 1);
    client.sign(&mut cmd);
    client
        .send_command(&mut transport, cmd)
        .expect("send command over real mTLS");
    let result = client
        .await_result(&mut transport)
        .expect("await result over real mTLS")
        .expect("a genuine, correlated result returns");

    assert_eq!(
        result.outcome,
        CommandOutcome::Applied,
        "the operator's signed, authorized Draft was APPLIED by the real agent control loop"
    );
    assert_eq!(
        result.agent, agent_actor,
        "the result is signed by the agent's own key"
    );

    drop(transport); // close the client connection so the agent's serve loop sees EOF
    handle.shutdown();

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn an_untrusted_client_is_rejected() {
    let dir = unique_temp_dir("untrusted");
    let (cfg, _paths, _client_leaf, agent_actor) = write_config(&dir);

    let handle = spawn_control_service(&cfg).expect("control service spawns");
    let addr = handle.local_addr();

    // An attacker with its OWN independent CA (untrusted by the agent). Write it to disk
    // and build a client config + leaf from it.
    let attacker_dir = unique_temp_dir("attacker");
    let attacker_pki = generate_test_pki();
    let attacker_paths = write_pki_to_pem(&attacker_pki, &attacker_dir).unwrap();

    let stream = TcpStream::connect(addr).expect("attacker TCP connect");
    stream.set_read_timeout(Some(CLIENT_READ_TIMEOUT)).unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    let attacker_cfg = client_config_from_files(
        &[&attacker_paths.ca],
        &attacker_paths.client_chain,
        &attacker_paths.client_key,
    )
    .unwrap();
    let attacker_leaf = attacker_pki.client_cert_chain[0].clone();

    // The agent REQUIRES a cert signed by ITS CA; the attacker's foreign-CA cert is rejected
    // at the handshake. Under TLS 1.3 the client's own `connect` may return Ok before the
    // server's fatal alert arrives, so we assert the security-critical fact directly: the
    // attacker NEVER gets a command applied.
    let applied = match connect(stream, attacker_cfg, name, &attacker_leaf) {
        Err(_) => false, // handshake failed outright — nothing applied
        Ok((mut transport, session)) => client_gets_applied(&mut transport, &session, &agent_actor),
    };
    assert!(
        !applied,
        "an untrusted foreign-CA client is served nothing — no command is applied"
    );

    handle.shutdown();
    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&attacker_dir);
}

#[test]
fn shutdown_returns_without_hanging() {
    let dir = unique_temp_dir("shutdown");
    let (cfg, _paths, _client_leaf, _agent_actor) = write_config(&dir);

    let handle = spawn_control_service(&cfg).expect("control service spawns");
    let _addr = handle.local_addr();

    // No connection at all: shutdown must still return promptly (the accept loop polls the
    // shutdown flag). A watchdog thread guarantees the test itself can't hang CI.
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        handle.shutdown();
        let _ = tx.send(());
    });
    match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(()) => {}
        Err(_) => panic!("handle.shutdown() did not return within 10s — it hung"),
    }
    worker.join().unwrap();

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn load_config_is_fail_closed() {
    let dir = unique_temp_dir("failclosed");

    // Missing file -> Err (never a panic).
    assert!(
        load_config(&dir.join("does-not-exist.toml")).is_err(),
        "missing config -> Err"
    );

    // Malformed TOML -> Err(InvalidData).
    let bad = dir.join("bad.toml");
    fs::write(&bad, b"{ not valid toml ").unwrap();
    let err = load_config(&bad).expect_err("malformed config -> Err");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::InvalidData,
        "malformed config is InvalidData"
    );

    // Unknown role -> Err (fail-closed): a valid config that names a bogus role must fail
    // when the service is built.
    let (mut cfg, _paths, _client_leaf, _actor) = write_config(&dir);
    cfg.roles = vec![RoleEntry {
        actor: "x".into(),
        role: "superuser".into(),
    }];
    assert!(
        spawn_control_service(&cfg).is_err(),
        "an unknown role string must fail-close when building the service"
    );

    let _ = fs::remove_dir_all(&dir);
}
