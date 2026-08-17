//! Integration proof that certificate **REVOCATION (CRL)** and **CA ROTATION** are enforced
//! at the real mutual-TLS handshake — before any application frame is exchanged — driving the
//! UNCHANGED P3b control loop/client over a loopback socket.
//!
//! Mirrors `cert_files.rs`: each round-trip stands up a `TcpListener` on an ephemeral port,
//! runs the agent side (`accept` + an `AgentControlLoop`) on its own thread, and drives the
//! issuer side (`connect` + a `ControlPlaneClient`) from the test thread. The rejection tests
//! assert the SERVER rejects the peer AT the handshake (`accept` -> `Err`, so `serve_one` never
//! runs and the remediation bridge is never touched) and that the peer is served nothing (no
//! command is ever `Applied`). See `assert_peer_rejected_by_server` for why the client's own
//! `connect` may return `Ok` under TLS 1.3 when it is the SERVER refusing the client cert.
//!
//! Windows note: an intermittent `LNK1104` on the FIRST build is an AV/lock flake — re-run.
//! Each test uses its OWN uniquely-named temp dir under `std::env::temp_dir()`, cleaned on drop.

use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ServerConfig};

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
    accept, client_config_from_files, connect, generate_revocation_test_pki, generate_test_pki,
    load_crls, load_crls_from_files, server_config_from_files, server_config_from_files_with_crl,
    write_pki_to_pem, CertFilePaths,
};

const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// A self-cleaning unique temp directory, removed on drop so no test shares a path on disk.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("torda-crl-{}-{}-{}", std::process::id(), nanos, n));
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

/// A full authorized round-trip: the UNCHANGED loop must apply the draft over the given configs.
fn assert_round_trip(
    server_cfg: Arc<ServerConfig>,
    client_cfg: Arc<ClientConfig>,
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
        "the authorized draft applied over mTLS"
    );

    let (agent_session, served, state) = agent.join().expect("agent thread joins");
    assert!(
        served,
        "the agent loop served exactly one command frame off the TLS socket"
    );
    assert_eq!(
        agent_session, client_session,
        "both ends derived the SAME session id"
    );
    assert_eq!(
        state,
        Some(ActionState::Drafted),
        "the gated draft advanced the agent's bridge"
    );
}

/// Best-effort attempt by an already-connected client to get a command APPLIED. Returns
/// `false` iff the peer never obtains an `Applied` outcome (any transport error, EOF, or a
/// non-`Applied` result all count as "not applied"). Used to prove a server-rejected peer is
/// served nothing even if its own `connect` optimistically returned `Ok`.
fn client_gets_applied<T: Transport>(transport: &mut T, session: &str) -> bool {
    let operator = CommandSigner::from_seed("operator", [7u8; 32]);
    let agent = CommandSigner::from_seed("agent-1", [42u8; 32]);
    let mut server_v = Ed25519Verifier::new();
    server_v.trust(&agent.actor, agent.verifying_key());
    let mut client = ControlPlaneClient::new(operator, server_v);

    let mut cmd = draft_cmd("operator", session, 1);
    client.sign(&mut cmd);
    if client.send_command(transport, cmd).is_err() {
        return false;
    }
    matches!(client.await_result(transport), Ok(Some(r)) if r.outcome == CommandOutcome::Applied)
}

/// Assert a peer is REJECTED by the SERVER at the TLS handshake: `accept` (agent) returns
/// `Err`, so the loop's `serve_one`/bridge is never reached, AND the client is served nothing
/// (it never gets an `Applied` outcome).
///
/// ## Why not "both sides Err at connect"
///
/// In these scenarios the client *trusts* the server cert (same/old CA) — the ONLY reason for
/// rejection is the server refusing the client's revoked/retired certificate. Under TLS 1.3
/// the client finishes its handshake flight (sending its Certificate + Finished) and `connect`
/// can return `Ok` *before* the server's fatal alert arrives; the failure then surfaces on the
/// first frame exchange. We therefore assert the security-critical facts directly: the SERVER
/// rejected at the handshake (bridge untouched) and NO command was ever applied. (The
/// untrusted-*server* case, where the client also rejects, is covered in `cert_files.rs`.)
fn assert_peer_rejected_by_server(
    server_cfg: Arc<ServerConfig>,
    client_cfg: Arc<ClientConfig>,
    client_leaf: rustls::pki_types::CertificateDer<'static>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let port = listener.local_addr().unwrap().port();

    // The agent thread must NOT reach a loop: `accept` returns Err AT the handshake, so the
    // remediation bridge is never constructed/touched.
    let agent = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("agent accepts TCP");
        stream.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
        accept(stream, server_cfg).is_err()
    });

    let stream = TcpStream::connect(("127.0.0.1", port)).expect("client TCP connect");
    stream.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    let applied = match connect(stream, client_cfg, name, &client_leaf) {
        Err(_) => false, // client handshake failed outright — nothing applied
        Ok((mut transport, session)) => client_gets_applied(&mut transport, &session),
    };

    let agent_rejected = agent.join().expect("agent thread joins");
    assert!(
        agent_rejected,
        "the server rejects the peer AT the handshake (accept -> Err)"
    );
    assert!(
        !applied,
        "a server-rejected peer is served nothing — no command is ever applied"
    );
}

/// Write CRL DER bytes to `dir/name.der`, returning the path (loaders auto-detect DER).
fn write_crl_der(dir: &Path, name: &str, der: &[u8]) -> PathBuf {
    let p = dir.join(format!("{name}.der"));
    fs::write(&p, der).expect("write CRL DER");
    p
}

#[test]
fn a_revoked_client_certificate_is_rejected_at_the_handshake() {
    let rpki = generate_revocation_test_pki();
    let dir = TempDir::new();
    // pki_revoked's CLIENT leaf is the one named in the CRL.
    let CertFilePaths {
        ca,
        server_chain,
        server_key,
        client_chain,
        client_key,
    } = write_pki_to_pem(&rpki.pki_revoked, dir.path()).expect("write revoked PKI");
    let crl = write_crl_der(dir.path(), "revoke", rpki.crl_der.as_ref());
    let revoked_leaf = rpki.pki_revoked.client_cert_chain[0].clone();

    // The server enforces the CRL; the revoked client presents a serial listed in it.
    let server_cfg = server_config_from_files_with_crl(&[&ca], &server_chain, &server_key, &[&crl])
        .expect("CRL-enforcing server cfg");
    let client_cfg =
        client_config_from_files(&[&ca], &client_chain, &client_key).expect("revoked client cfg");

    // Rejected AT the handshake, on both ends — the loop/bridge is never reached.
    assert_peer_rejected_by_server(server_cfg, client_cfg, revoked_leaf);
}

#[test]
fn a_non_revoked_client_from_the_same_ca_still_connects() {
    let rpki = generate_revocation_test_pki();
    let dir = TempDir::new();
    // pki_good shares the SAME CA + server leaf, but its client serial is NOT in the CRL.
    let CertFilePaths {
        ca,
        server_chain,
        server_key,
        client_chain,
        client_key,
    } = write_pki_to_pem(&rpki.pki_good, dir.path()).expect("write good PKI");
    let crl = write_crl_der(dir.path(), "revoke", rpki.crl_der.as_ref());
    let good_leaf = rpki.pki_good.client_cert_chain[0].clone();

    // The SAME CRL config is in force, yet a non-revoked client of the same CA round-trips.
    let server_cfg = server_config_from_files_with_crl(&[&ca], &server_chain, &server_key, &[&crl])
        .expect("CRL-enforcing server cfg");
    let client_cfg =
        client_config_from_files(&[&ca], &client_chain, &client_key).expect("good client cfg");

    assert_round_trip(server_cfg, client_cfg, good_leaf);
}

#[test]
fn ca_rotation_overlap_then_retire() {
    // Two INDEPENDENT CAs, each with its own server + client leaf.
    let old = generate_test_pki();
    let new = generate_test_pki();
    let dir_old = TempDir::new();
    let dir_new = TempDir::new();
    let p_old = write_pki_to_pem(&old, dir_old.path()).expect("write CA_old PKI");
    let p_new = write_pki_to_pem(&new, dir_new.path()).expect("write CA_new PKI");
    let old_leaf = old.client_cert_chain[0].clone();
    let new_leaf = new.client_cert_chain[0].clone();

    // ---- OVERLAP: server trusts BOTH CAs. A CA_old client AND a CA_new client both connect.
    // (A client only trusts its OWN CA's server cert, so each sub-case runs a server presenting
    // that client's-CA server leaf, but ALWAYS with the two-CA client-auth trust list.)
    {
        let server_cfg = server_config_from_files(
            &[&p_old.ca, &p_new.ca],
            &p_old.server_chain,
            &p_old.server_key,
        )
        .expect("overlap server cfg (old leaf)");
        let client_cfg =
            client_config_from_files(&[&p_old.ca], &p_old.client_chain, &p_old.client_key)
                .expect("CA_old client cfg");
        assert_round_trip(server_cfg, client_cfg, old_leaf.clone());
    }
    {
        let server_cfg = server_config_from_files(
            &[&p_old.ca, &p_new.ca],
            &p_new.server_chain,
            &p_new.server_key,
        )
        .expect("overlap server cfg (new leaf)");
        let client_cfg =
            client_config_from_files(&[&p_new.ca], &p_new.client_chain, &p_new.client_key)
                .expect("CA_new client cfg");
        assert_round_trip(server_cfg, client_cfg, new_leaf.clone());
    }

    // ---- RETIRE: server trusts ONLY CA_new. The CA_new client still connects...
    {
        let server_cfg =
            server_config_from_files(&[&p_new.ca], &p_new.server_chain, &p_new.server_key)
                .expect("retired server cfg (new only)");
        let client_cfg =
            client_config_from_files(&[&p_new.ca], &p_new.client_chain, &p_new.client_key)
                .expect("CA_new client cfg");
        assert_round_trip(server_cfg, client_cfg, new_leaf);
    }
    // ...but the CA_old client is now REJECTED at the handshake. The server presents the OLD
    // server leaf (so the old client's SERVER-auth succeeds and the failure is isolated to the
    // server no longer trusting CA_old for CLIENT auth), while trusting ONLY CA_new.
    {
        let server_cfg =
            server_config_from_files(&[&p_new.ca], &p_old.server_chain, &p_old.server_key)
                .expect("retired server cfg (old leaf, trusts new only)");
        let client_cfg =
            client_config_from_files(&[&p_old.ca], &p_old.client_chain, &p_old.client_key)
                .expect("CA_old client cfg");
        assert_peer_rejected_by_server(server_cfg, client_cfg, old_leaf);
    }
}

#[test]
fn a_malformed_crl_is_rejected_not_panicked() {
    // (a) empty bytes -> fail-closed (an empty CRL set would silently disable revocation).
    assert!(load_crls(b"").is_err(), "empty CRL bytes are fail-closed");

    // (b) a malformed PEM CRL (armor present, garbage body) -> Err, no panic.
    assert!(
        load_crls(b"-----BEGIN X509 CRL-----\nnot valid base64 @@@\n-----END X509 CRL-----\n")
            .is_err(),
        "a malformed PEM CRL body is an Err"
    );

    // (c) an empty-body PEM CRL -> zero CRLs -> Err (never a silent empty set).
    assert!(
        load_crls(b"-----BEGIN X509 CRL-----\n-----END X509 CRL-----\n").is_err(),
        "an empty-body PEM CRL yields zero CRLs -> Err"
    );

    // (d) a genuinely-parseable CRL round-trips through load_crls (positive control).
    let rpki = generate_revocation_test_pki();
    assert!(
        load_crls(rpki.crl_der.as_ref()).is_ok(),
        "a real DER CRL loads"
    );

    // (e) at the config level: a structurally-garbage DER CRL is caught by the verifier
    // builder's own CRL parse and surfaces as Err (not a panic). Routed through a good CA +
    // server leaf so ONLY the CRL is at fault.
    let dir = TempDir::new();
    let good = write_pki_to_pem(&rpki.pki_good, dir.path()).expect("write good PKI");
    let garbage_crl = write_crl_der(dir.path(), "garbage", b"this is not a DER CRL at all");
    assert!(
        server_config_from_files_with_crl(
            &[&good.ca],
            &good.server_chain,
            &good.server_key,
            &[&garbage_crl]
        )
        .is_err(),
        "a structurally-malformed CRL is rejected by the verifier builder, not panicked"
    );

    // (f) an empty CRL FILE is fail-closed through the file loader too.
    let empty = dir.path().join("empty.crl");
    fs::write(&empty, b"").unwrap();
    assert!(
        load_crls_from_files(&[&empty]).is_err(),
        "an empty CRL file is fail-closed"
    );
}
