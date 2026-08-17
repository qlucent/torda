//! Integration proof that mTLS configs **loaded from ops-provisioned FILES** (PEM or DER)
//! drive the UNCHANGED P3b control loop/client over a real loopback handshake — and that
//! file loading did not weaken mutual authentication.
//!
//! Mirrors `mtls_channel.rs`: each round-trip test stands up a `TcpListener` on an
//! ephemeral port, runs the agent side (`accept` + an `AgentControlLoop`) on its own
//! thread, and drives the issuer side (`connect` + a `ControlPlaneClient`) from the test
//! thread. The ONLY difference is where the configs come from — files, via
//! `server_config_from_files` / `client_config_from_files` — proving the loading path is a
//! drop-in for the in-memory `server_config` / `client_config`.
//!
//! Windows note: an intermittent `LNK1104` on the FIRST build is an AV/lock flake — re-run.
//! Each test uses its OWN uniquely-named temp dir under `std::env::temp_dir()`, cleaned up
//! on drop, so tests never collide on disk and leave nothing behind.

use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::pki_types::ServerName;
use rustls::ServerConfig;

use torda_control_plane::{
    AgentControlHandler, AgentControlLoop, CommandOutcome, CommandResult, CommandSigner,
    ControlPlaneClient, Ed25519Verifier,
};
use torda_remediation::action::{
    ActionState, AssetSelector, CanarySpec, Method, RemediationAction, VerifySpec,
};
use torda_remediation::audit::VecAuditSink;
use torda_remediation::bridge::{Bridge, Executor, Verifier, VerifyOutcome};
use torda_remediation::control::{CommandKind, ControlCommand, Role, RolePolicy, SystemClock};
use torda_transport::Transport;
use torda_transport_tls::{
    accept, client_config_from_files, connect, generate_test_pki, server_config_from_files,
    write_pki_to_der, write_pki_to_pem, CertFilePaths, MAX_CERT_FILE_BYTES,
};

const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// A self-cleaning unique temp directory (`torda-certs-<pid>-<nanos>-<n>`), removed on drop so
/// no test hardcodes or shares a path on disk.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "torda-certs-{}-{}-{}",
            std::process::id(),
            nanos,
            n
        ));
        fs::create_dir_all(&dir).expect("create unique temp dir");
        TempDir(dir)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A benign, fully-scoped Draft command for `actor` at `(session, seq)`, UNSIGNED.
fn draft_cmd(actor: &str, session: &str, seq: u64) -> ControlCommand {
    let action = RemediationAction {
        id: "a".into(),
        name: "n".into(),
        method: Method::Shell,
        payload: "echo hi".into(),
        targets: AssetSelector {
            asset_ids: vec!["h1".into()],
        },
        requires_approval: true,
        dry_run_supported: true,
        rollback: None,
        verify: VerifySpec {
            finding_ids: vec![],
        },
        canary: CanarySpec {
            cohort_size: 1,
            failure_threshold: 0.0,
        },
    };
    ControlCommand {
        action_id: "a".into(),
        kind: CommandKind::Draft(Box::new(action)),
        actor: actor.into(),
        session: session.into(),
        seq,
        schedule: None,
        signature: String::new(),
    }
}

struct NoopExec;
impl Executor for NoopExec {
    fn preview(&self, _a: &RemediationAction) -> String {
        String::new()
    }
    fn apply(&mut self, _a: &RemediationAction, _t: &str) -> anyhow::Result<()> {
        Ok(())
    }
    fn rollback(&mut self, _a: &RemediationAction, _t: &str) -> anyhow::Result<()> {
        Ok(())
    }
}
struct FixedVerifier;
impl Verifier for FixedVerifier {
    fn verify(&self, _a: &RemediationAction, _t: &[String]) -> VerifyOutcome {
        VerifyOutcome::Fixed
    }
}

/// Agent side: accept ONE mTLS connection, build the UNCHANGED P3b loop on the cert-derived
/// session, `serve_one` command, and report `(session, served, state)`.
fn run_agent_once(
    listener: TcpListener,
    cfg: Arc<ServerConfig>,
) -> (String, bool, Option<ActionState>) {
    let (stream, _) = listener.accept().expect("agent accepts the TCP connection");
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .expect("set agent read timeout");
    let (mut transport, session) = accept(stream, cfg).expect("mTLS handshake + client auth");

    let operator = CommandSigner::from_seed("operator", [7u8; 32]);
    let agent = CommandSigner::from_seed("agent-1", [42u8; 32]);
    let mut verifier = Ed25519Verifier::new();
    verifier.trust(&operator.actor, operator.verifying_key());
    let mut policy = RolePolicy::new();
    policy.assign("operator", Role::Operator);
    let handler = AgentControlHandler::new(&verifier, &policy, &agent);
    let mut agent_loop = AgentControlLoop::with_session(
        handler,
        &session,
        0,
        Box::new(NoopExec),
        Box::new(FixedVerifier),
    );
    let mut bridge = Bridge::new(VecAuditSink::default());

    let served = agent_loop
        .serve_one(&mut transport, &mut bridge, &SystemClock)
        .expect("serve one frame");
    (session, served, bridge.state("a"))
}

/// Issuer side: sign + send an authorized Draft on `session` seq=1 and await its result.
fn issue_draft<T: Transport>(transport: &mut T, session: &str) -> Option<CommandResult> {
    let operator = CommandSigner::from_seed("operator", [7u8; 32]);
    let agent = CommandSigner::from_seed("agent-1", [42u8; 32]);
    let mut server_v = Ed25519Verifier::new();
    server_v.trust(&agent.actor, agent.verifying_key());
    let mut client = ControlPlaneClient::new(operator, server_v);

    let mut cmd = draft_cmd("operator", session, 1);
    client.sign(&mut cmd);
    client
        .send_command(transport, cmd)
        .expect("send command over mTLS");
    client
        .await_result(transport)
        .expect("await result over mTLS")
}

/// Run one full authorized round-trip using the given already-built file-loaded configs,
/// asserting the UNCHANGED loop applies the draft. `client_leaf` is the client's own leaf
/// (for the session-id derivation, same as `mtls_channel.rs`).
fn assert_round_trip(
    server_cfg: Arc<ServerConfig>,
    client_cfg: Arc<rustls::ClientConfig>,
    client_leaf: rustls::pki_types::CertificateDer<'static>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind control listener");
    let port = listener.local_addr().unwrap().port();

    let agent = thread::spawn(move || run_agent_once(listener, server_cfg));

    let stream = TcpStream::connect(("127.0.0.1", port)).expect("client TCP connect");
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .expect("set client read timeout");
    let name = ServerName::try_from("localhost").expect("valid server name");
    let (mut transport, client_session) =
        connect(stream, client_cfg, name, &client_leaf).expect("mTLS handshake + server auth");

    let result = issue_draft(&mut transport, &client_session).expect("a genuine Applied result");
    assert_eq!(
        result.outcome,
        CommandOutcome::Applied,
        "the authorized draft applied over file-loaded mTLS"
    );

    let (agent_session, served, state) = agent.join().expect("agent thread joins");
    assert!(
        served,
        "the agent loop served exactly one command frame off the TLS socket"
    );
    assert_eq!(
        agent_session, client_session,
        "both ends derived the SAME session id from the client cert"
    );
    assert_eq!(
        state,
        Some(ActionState::Drafted),
        "the gated draft advanced the agent's bridge"
    );
}

#[test]
fn pem_file_loaded_configs_drive_a_real_mtls_round_trip() {
    let pki = generate_test_pki();
    let client_leaf = pki.client_cert_chain[0].clone();
    let dir = TempDir::new();
    let CertFilePaths {
        ca,
        server_chain,
        server_key,
        client_chain,
        client_key,
    } = write_pki_to_pem(&pki, dir.path()).expect("write PEM PKI");

    let server_cfg =
        server_config_from_files(&[&ca], &server_chain, &server_key).expect("server cfg from PEM");
    let client_cfg =
        client_config_from_files(&[&ca], &client_chain, &client_key).expect("client cfg from PEM");

    assert_round_trip(server_cfg, client_cfg, client_leaf);
}

#[test]
fn der_file_loaded_configs_also_work() {
    let pki = generate_test_pki();
    let client_leaf = pki.client_cert_chain[0].clone();
    let dir = TempDir::new();
    let CertFilePaths {
        ca,
        server_chain,
        server_key,
        client_chain,
        client_key,
    } = write_pki_to_der(&pki, dir.path()).expect("write DER PKI");

    // .der files carry no PEM armor — the loaders auto-detect DER from content.
    let server_cfg =
        server_config_from_files(&[&ca], &server_chain, &server_key).expect("server cfg from DER");
    let client_cfg =
        client_config_from_files(&[&ca], &client_chain, &client_key).expect("client cfg from DER");

    assert_round_trip(server_cfg, client_cfg, client_leaf);
}

#[test]
fn an_untrusted_client_is_still_rejected_with_file_loaded_configs() {
    // The server trusts CA #1 (loaded from files); an attacker presents a client cert from
    // an INDEPENDENT CA #2 (also loaded from files). Mutual auth must still reject it at the
    // handshake — file loading did not weaken it.
    let server_pki = generate_test_pki();
    let attacker_pki = generate_test_pki();
    let server_dir = TempDir::new();
    let attacker_dir = TempDir::new();
    let s = write_pki_to_pem(&server_pki, server_dir.path()).expect("write server PKI");
    let a = write_pki_to_pem(&attacker_pki, attacker_dir.path()).expect("write attacker PKI");
    let attacker_leaf = attacker_pki.client_cert_chain[0].clone();

    let server_cfg =
        server_config_from_files(&[&s.ca], &s.server_chain, &s.server_key).expect("server cfg");
    let attacker_cfg =
        client_config_from_files(&[&a.ca], &a.client_chain, &a.client_key).expect("attacker cfg");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let port = listener.local_addr().unwrap().port();

    let agent = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("agent accepts TCP");
        stream.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
        accept(stream, server_cfg).is_err()
    });

    let stream = TcpStream::connect(("127.0.0.1", port)).expect("client TCP connect");
    stream.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    let connect_result = connect(stream, attacker_cfg, name, &attacker_leaf);

    let agent_rejected = agent.join().expect("agent thread joins");
    assert!(
        agent_rejected,
        "the server rejects the untrusted client AT the handshake even with file-loaded configs"
    );
    assert!(
        connect_result.is_err(),
        "the client also fails (untrusted server cert) — no frame exchanged"
    );
}

#[test]
fn two_ca_root_store_accepts_a_client_from_either_ca() {
    // Rotation-overlap foundation: a server whose ca_paths lists BOTH CA files trusts a
    // client chaining to CA #1 AND (separately) a client chaining to CA #2.
    let pki1 = generate_test_pki();
    let pki2 = generate_test_pki();
    let dir1 = TempDir::new();
    let dir2 = TempDir::new();
    let p1 = write_pki_to_pem(&pki1, dir1.path()).expect("write CA#1 PKI");
    let p2 = write_pki_to_pem(&pki2, dir2.path()).expect("write CA#2 PKI");

    // Each client trusts its OWN CA's server; the SERVER trusts BOTH CAs. The server also
    // needs a leaf a client can verify, so we run two separate servers (one per CA's leaf),
    // each configured with the SAME two-CA client-trust list — proving the multi-CA store
    // admits clients from either CA.
    for (client_pki, client_paths, server_paths) in [(&pki1, &p1, &p1), (&pki2, &p2, &p2)] {
        let client_leaf = client_pki.client_cert_chain[0].clone();
        let server_cfg = server_config_from_files(
            &[&p1.ca, &p2.ca], // BOTH CAs trusted for client auth
            &server_paths.server_chain,
            &server_paths.server_key,
        )
        .expect("two-CA server cfg");
        let client_cfg = client_config_from_files(
            &[&client_paths.ca],
            &client_paths.client_chain,
            &client_paths.client_key,
        )
        .expect("client cfg");
        assert_round_trip(server_cfg, client_cfg, client_leaf);
    }
}

#[test]
fn malformed_or_missing_or_oversized_cert_files_error_without_panic() {
    let pki = generate_test_pki();
    let dir = TempDir::new();
    let good = write_pki_to_pem(&pki, dir.path()).expect("write good PKI");

    // (a) missing path
    let missing = dir.path().join("does-not-exist.pem");
    assert!(
        server_config_from_files(&[&missing], &good.server_chain, &good.server_key).is_err(),
        "a missing CA file is an Err, not a panic"
    );

    // (b) garbage bytes as a CA file
    let garbage = dir.path().join("garbage.pem");
    fs::write(&garbage, b"this is not a certificate at all").unwrap();
    assert!(
        server_config_from_files(&[&garbage], &good.server_chain, &good.server_key).is_err(),
        "a garbage CA file is an Err"
    );

    // (c) empty file
    let empty = dir.path().join("empty.pem");
    fs::write(&empty, b"").unwrap();
    assert!(
        server_config_from_files(&[&empty], &good.server_chain, &good.server_key).is_err(),
        "an empty CA file is fail-closed (no silent empty chain)"
    );

    // (d) an empty PEM: armor but no certificate body -> zero certs -> Err
    let empty_pem = dir.path().join("empty-armor.pem");
    fs::write(
        &empty_pem,
        b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    assert!(
        server_config_from_files(&[&empty_pem], &good.server_chain, &good.server_key).is_err(),
        "an empty-body PEM yields zero certs -> Err, never a silent empty chain"
    );

    // (e) an oversized (> MAX_CERT_FILE_BYTES) file is rejected by the size cap
    let big = dir.path().join("big.pem");
    fs::write(&big, vec![b'a'; (MAX_CERT_FILE_BYTES + 1) as usize]).unwrap();
    assert!(
        server_config_from_files(&[&big], &good.server_chain, &good.server_key).is_err(),
        "a file exceeding the size cap is an Err, not an OOM/panic"
    );

    // (f) a malformed KEY file is likewise fail-closed (routed through the good CA).
    let bad_key = dir.path().join("bad-key.pem");
    fs::write(
        &bad_key,
        b"-----BEGIN PRIVATE KEY-----\nnonsense\n-----END PRIVATE KEY-----\n",
    )
    .unwrap();
    assert!(
        server_config_from_files(&[&good.ca], &good.server_chain, &bad_key).is_err(),
        "a malformed private key is an Err"
    );
}
