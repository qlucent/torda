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
    accept, client_config, connect, generate_test_pki, server_config, session_from_cert,
};

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
/// on the cert-derived session, `serve_one` command, and report `(session, served, state)`.
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
        "both ends independently derived the SAME session id from the client cert"
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
fn session_is_bound_to_the_peer_cert() {
    let pki_a = generate_test_pki();
    let pki_b = generate_test_pki();

    let session_a = session_from_cert(pki_a.client_cert_chain[0].as_ref());
    let session_b = session_from_cert(pki_b.client_cert_chain[0].as_ref());

    assert!(!session_a.is_empty(), "the derived session id is non-empty");
    assert_eq!(session_a.len(), 16, "session id is 16 hex chars");
    assert_ne!(
        session_a, session_b,
        "a DIFFERENT client cert yields a DIFFERENT session id"
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
