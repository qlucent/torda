//! Integration proof that the **UNCHANGED** P3b-6 control loop/client run over a real
//! mutual-TLS socket on loopback.
//!
//! Each test stands up a `TcpListener` on an ephemeral port (`127.0.0.1:0`), runs the
//! agent side (`torda_transport_tls::accept` + an `AgentControlLoop`) on its own thread, and
//! drives the issuer side (`torda_transport_tls::connect` + a `ControlPlaneClient`) from the
//! test thread. The loop/client/bridge types are byte-for-byte the P3b-6 types — the
//! `Transport` seam is all that changed underneath them.
//!
//! Windows note: an intermittent `LNK1104` (linker cannot open file, AV/lock flake) can
//! fail the FIRST build of this crate — simply re-run `cargo test -p torda-transport-tls`.
//! Ephemeral ports avoid bind collisions; read timeouts bound any misbehaving socket so a
//! failed handshake can never hang the suite; threads are joined.

use std::io::ErrorKind;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::ServerConfig;

use torda_control_plane::{
    AgentControlHandler, AgentControlLoop, CommandOutcome, CommandResult, CommandSigner,
    Ed25519Verifier,
};
use torda_control_server::{connect, ControlPlaneClient};
use torda_remediation::action::{
    ActionState, AssetSelector, CanarySpec, Method, RemediationAction, VerifySpec,
};
use torda_remediation::audit::VecAuditSink;
use torda_remediation::bridge::{Bridge, Executor, Verifier, VerifyOutcome};
use torda_remediation::control::{CommandKind, ControlCommand, Role, RolePolicy, SystemClock};
use torda_transport::Transport;
use torda_transport_tls::{accept, client_config, generate_test_pki, server_config};

/// Generous read timeout: the loopback round-trip completes in milliseconds; this only
/// exists so a misbehaving/aborted handshake can never hang the test suite.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

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

/// A no-op orchestrator executor: the mTLS vectors only exercise a lifecycle Draft, so
/// the held executor is never consulted (these tests send no execution command).
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
/// A stub re-score verifier (unused by these lifecycle-only vectors).
struct FixedVerifier;
impl Verifier for FixedVerifier {
    fn verify(&self, _a: &RemediationAction, _t: &[String]) -> VerifyOutcome {
        VerifyOutcome::Fixed
    }
}

/// Agent side: accept ONE mTLS connection off `listener`, build the UNCHANGED P3b-6 loop
/// on the TLS-exported session, `serve_one` command, and report `(session, served, state)`.
fn run_agent_once(
    listener: TcpListener,
    cfg: Arc<ServerConfig>,
) -> (String, bool, Option<ActionState>) {
    let (stream, _) = listener.accept().expect("agent accepts the TCP connection");
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .expect("set agent read timeout");
    // Handshake completes here (mutual auth); an untrusted client would fail before this returns.
    let (mut transport, session) = accept(stream, cfg).expect("mTLS handshake + client auth");

    // The loop/handler/bridge are the SAME types as P3b-6 — no edits.
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
    server_v.trust(&agent.actor, agent.verifying_key()); // trust the agent's result signature
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

#[test]
fn mtls_round_trip_drives_the_unchanged_loop() {
    let pki = generate_test_pki();
    let server_cfg = server_config(&pki);
    let client_cfg = client_config(&pki);
    let client_leaf = pki.client_cert_chain[0].clone();

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
        "the authorized draft applied over real mTLS"
    );

    let (agent_session, served, state) = agent.join().expect("agent thread joins");
    assert!(
        served,
        "the agent loop served exactly one command frame off the TLS socket"
    );
    assert_eq!(
        agent_session, client_session,
        "both ends independently derived the SAME TLS-exported session id"
    );
    assert_eq!(
        state,
        Some(ActionState::Drafted),
        "the gated draft advanced the agent's bridge"
    );
}

#[test]
fn an_untrusted_client_is_rejected_at_the_handshake() {
    // The server trusts CA #1; the attacker presents a client cert from an INDEPENDENT
    // CA #2 (and, symmetrically, would reject the server's CA-#1 cert). The rejection is
    // at the TLS handshake — no application/control frame is ever processed.
    let server_pki = generate_test_pki();
    let attacker_pki = generate_test_pki();
    let server_cfg = server_config(&server_pki);
    let attacker_cfg = client_config(&attacker_pki);
    let attacker_leaf = attacker_pki.client_cert_chain[0].clone();

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let port = listener.local_addr().unwrap().port();

    // The agent thread must NOT reach a loop: accept() returns Err at the handshake.
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
        "the server rejects the untrusted client AT the TLS handshake"
    );
    assert!(
        connect_result.is_err(),
        "the client also fails the handshake (untrusted server cert) — no frame exchanged"
    );
}

#[test]
fn reconnect_with_same_cert_rejects_old_signed_command_and_accepts_current_session() {
    let pki = generate_test_pki();
    let server_cfg = server_config(&pki);
    let client_cfg = client_config(&pki);
    let client_leaf = pki.client_cert_chain[0].clone();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind control listener");
    let port = listener.local_addr().unwrap().port();

    let agent = thread::spawn(move || {
        let mut sessions = Vec::new();
        let mut second_results = Vec::new();
        for connection in 0..2 {
            let (stream, _) = listener.accept().expect("accept connection");
            stream.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
            let (mut transport, session) = accept(stream, server_cfg.clone()).expect("mTLS accept");
            sessions.push(session.clone());

            let operator = CommandSigner::from_seed("operator", [7u8; 32]);
            let agent_signer = CommandSigner::from_seed("agent-1", [42u8; 32]);
            let mut verifier = Ed25519Verifier::new();
            verifier.trust(&operator.actor, operator.verifying_key());
            let mut policy = RolePolicy::new();
            policy.assign("operator", Role::Operator);
            let handler = AgentControlHandler::new(&verifier, &policy, &agent_signer);
            let mut loop_ = AgentControlLoop::with_session(
                handler,
                &session,
                0,
                Box::new(NoopExec),
                Box::new(FixedVerifier),
            );
            let mut bridge = Bridge::new(VecAuditSink::default());
            let count = if connection == 0 { 1 } else { 2 };
            for _ in 0..count {
                assert!(loop_
                    .serve_one(&mut transport, &mut bridge, &SystemClock)
                    .unwrap());
                second_results.push(bridge.state("a"));
            }
        }
        (sessions, second_results)
    });

    let connect_once = |cfg: Arc<rustls::ClientConfig>| {
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("client TCP connect");
        stream.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
        let name = ServerName::try_from("localhost").unwrap();
        connect(stream, cfg, name, &client_leaf).expect("mTLS connect")
    };
    let operator = CommandSigner::from_seed("operator", [7u8; 32]);
    let agent_signer = CommandSigner::from_seed("agent-1", [42u8; 32]);
    let mut result_verifier = Ed25519Verifier::new();
    result_verifier.trust(&agent_signer.actor, agent_signer.verifying_key());
    let mut client = ControlPlaneClient::new(operator, result_verifier);

    let (mut first, old_session) = connect_once(client_cfg.clone());
    let mut old_command = draft_cmd("operator", &old_session, 1);
    client.sign(&mut old_command);
    let old_command_for_replay: ControlCommand =
        serde_json::from_slice(&serde_json::to_vec(&old_command).unwrap()).unwrap();
    client.send_command(&mut first, old_command).unwrap();
    assert_eq!(
        client.await_result(&mut first).unwrap().unwrap().outcome,
        CommandOutcome::Applied
    );
    drop(first);

    let (mut second, current_session) = connect_once(client_cfg);
    assert_eq!(old_session.len(), 64, "full 32-byte exporter is encoded");
    assert!(old_session.chars().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(
        old_session, current_session,
        "same certificate must get a fresh session"
    );

    client
        .send_command(&mut second, old_command_for_replay)
        .unwrap();
    assert_eq!(
        client.await_result(&mut second).unwrap().unwrap().outcome,
        CommandOutcome::Rejected,
        "old signed command must be rejected on a new TLS connection"
    );
    let mut current_command = draft_cmd("operator", &current_session, 1);
    client.sign(&mut current_command);
    client.send_command(&mut second, current_command).unwrap();
    assert_eq!(
        client.await_result(&mut second).unwrap().unwrap().outcome,
        CommandOutcome::Applied,
        "a correctly signed command for the current session is accepted"
    );

    let (agent_sessions, states) = agent.join().expect("agent joins");
    assert_eq!(agent_sessions, vec![old_session, current_session]);
    assert_eq!(
        states,
        vec![Some(ActionState::Drafted), None, Some(ActionState::Drafted)]
    );
}
#[test]
fn control_and_telemetry_use_physically_distinct_ports() {
    // Realizes the physical control/telemetry separation P3b-4..6 only modeled: control
    // and telemetry are DISTINCT listeners on DISTINCT ephemeral ports. The control
    // round-trip touches ONLY the control port; the telemetry listener accepts nothing.
    let pki = generate_test_pki();
    let server_cfg = server_config(&pki);
    let client_cfg = client_config(&pki);
    let client_leaf = pki.client_cert_chain[0].clone();

    let control_listener = TcpListener::bind("127.0.0.1:0").expect("bind control listener");
    let control_port = control_listener.local_addr().unwrap().port();
    let telemetry_listener = TcpListener::bind("127.0.0.1:0").expect("bind telemetry listener");
    let telemetry_port = telemetry_listener.local_addr().unwrap().port();
    assert_ne!(
        control_port, telemetry_port,
        "control and telemetry are physically distinct ports"
    );
    // Non-blocking so we can assert "no connection arrived" without hanging.
    telemetry_listener
        .set_nonblocking(true)
        .expect("telemetry listener non-blocking");

    let agent = thread::spawn(move || run_agent_once(control_listener, server_cfg));

    let stream =
        TcpStream::connect(("127.0.0.1", control_port)).expect("client connects to CONTROL port");
    stream.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    let (mut transport, session) =
        connect(stream, client_cfg, name, &client_leaf).expect("mTLS handshake on control port");

    let result = issue_draft(&mut transport, &session).expect("Applied result on control port");
    assert_eq!(result.outcome, CommandOutcome::Applied);

    let (_s, served, state) = agent.join().expect("agent joins");
    assert!(served);
    assert_eq!(state, Some(ActionState::Drafted));

    // The telemetry listener received NO connection: its non-blocking accept would-block.
    match telemetry_listener.accept() {
        Err(e) if e.kind() == ErrorKind::WouldBlock => {}
        other => panic!(
            "telemetry listener must have accepted NO control connection, got: {:?}",
            other.map(|_| "a connection")
        ),
    }
}

#[test]
fn accept_rejects_missing_peer_certificate_even_if_config_allows_it() {
    let pki = generate_test_pki();
    let cfg = Arc::new(
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(pki.server_cert_chain.clone(), pki.server_key.clone_key())
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let agent = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
        match accept(stream, cfg) {
            Err(err) => assert_eq!(err.kind(), ErrorKind::PermissionDenied),
            Ok(_) => panic!("control transport must require a client certificate"),
        }
    });
    let stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
    let _client = connect(
        stream,
        client_config(&pki),
        ServerName::try_from("localhost").unwrap(),
        &pki.client_cert_chain[0],
    );
    agent.join().unwrap();
}
