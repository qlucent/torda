//! Live functional demo of the P3b-7 **real mutual-TLS control channel**. It stands
//! up an actual mTLS socket on loopback — a CONTROL listener and a physically separate
//! TELEMETRY listener, each on its own ephemeral port — and drives the UNCHANGED P3b-6
//! `AgentControlLoop` <-> `ControlPlaneClient` command→result round-trip across it, with
//! real X.509 peer-certificate authentication (mutual auth; the client cert is REQUIRED).
//!
//! Four observable checkpoints:
//!   [1] a genuine command travels over real mTLS, the agent applies it, and the signed
//!       result comes back — both ends independently derive the SAME cert-bound session id.
//!   [2] an untrusted client (its own foreign CA) is rejected AT the TLS handshake — no
//!       control frame is ever processed.
//!   [3] the telemetry port is a physically distinct endpoint that carried zero control
//!       frames.
//!   [4] certificate management end to end: mTLS configs loaded from ops-provisioned FILES,
//!       a CRL-REVOKED client rejected at the handshake, and CA ROTATION (trust old+new during
//!       overlap, then retire old — the old-CA client is rejected, the new-CA client connects).
//!   [5] config HOT-RELOAD on a RUNNING agent (P3b-12): a single `ReloadableServerConfig` whose
//!       client-auth CA file is rewritten + `reload()`ed LIVE rejects the now-untrusted client on
//!       its NEXT connection with NO restart, while a bad reload (corrupt file) is a fail-safe
//!       no-op that keeps the last-good config serving a still-valid client.
//!
//! This is DEMO-ONLY: the control loop, the client, and the transport are byte-for-byte the
//! P3b-6 types — only the `Transport` seam underneath them is now a real TLS socket. Nothing
//! in any library changed. Certificates/keys/CRLs load from ops-provisioned files (checkpoint
//! [4] writes a throwaway test PKI to a temp dir to exercise that exact path).
//!
//! Windows note: an intermittent `LNK1104` (linker cannot open output file — AV/lock flake)
//! can fail the FIRST build; simply re-run. Ephemeral `:0` ports avoid bind collisions; read
//! timeouts bound any misbehaving socket so a failed handshake can never hang; threads join.

use std::fs;
use std::io::ErrorKind;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ServerConfig};

use torda_control_plane::{
    AgentControlHandler, AgentControlLoop, CommandOutcome, CommandSigner, Ed25519Verifier,
};
use torda_control_server::{client_config_from_files, connect, ControlPlaneClient};
use torda_remediation::action::{
    ActionState, AssetSelector, CanarySpec, Method, RemediationAction, VerifySpec,
};
use torda_remediation::audit::VecAuditSink;
use torda_remediation::bridge::{Bridge, Executor, Verifier, VerifyOutcome};
use torda_remediation::control::{CommandKind, ControlCommand, Role, RolePolicy, SystemClock};
use torda_transport_tls::{
    accept, client_config, generate_revocation_test_pki, generate_test_pki, server_config,
    server_config_from_files, server_config_from_files_with_crl, write_pki_to_pem, CertFilePaths,
    CertFileSpec, ReloadableServerConfig,
};

/// Generous read timeout: the loopback round-trip completes in milliseconds; this only exists
/// so a misbehaving or aborted handshake can never hang the demo.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// A benign, fully-scoped Draft command for `actor` at `(session, seq)`, UNSIGNED.
fn draft_cmd(actor: &str, session: &str, seq: u64) -> ControlCommand {
    let action = RemediationAction {
        id: "fix-openssl".into(),
        name: "upgrade openssl to 3.0.14".into(),
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

/// A no-op orchestrator executor: this demo drives only a lifecycle Draft over mTLS, so
/// the held executor is never consulted (no execution command is sent).
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
/// A stub re-score verifier (unused by this lifecycle-only demo).
struct FixedVerifier;
impl Verifier for FixedVerifier {
    fn verify(&self, _a: &RemediationAction, _t: &[String]) -> VerifyOutcome {
        VerifyOutcome::Fixed
    }
}

/// Agent side: accept ONE mTLS connection off `listener`, build the UNCHANGED P3b-6 loop on
/// the cert-derived session, `serve_one` command, and report `(session, served, state)`. The
/// mTLS handshake (mutual auth) completes inside `accept`; an untrusted client fails there.
fn run_agent_once(
    listener: TcpListener,
    cfg: Arc<ServerConfig>,
) -> (String, bool, Option<ActionState>) {
    let (stream, _) = listener.accept().expect("agent accepts the TCP connection");
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .expect("set agent read timeout");
    let (mut transport, session) = accept(stream, cfg).expect("mTLS handshake + client auth");

    // The loop / handler / bridge are the SAME types as P3b-6 — no edits.
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
    (session, served, bridge.state("fix-openssl"))
}

/// A fresh, uniquely-named temp directory under `std::env::temp_dir()` for checkpoint [4]'s
/// file-loaded PKI. Named with pid + nanos so concurrent runs never collide on disk.
fn unique_temp_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("torda-certdemo-{}-{}", std::process::id(), nanos));
    fs::create_dir_all(&dir).expect("create unique temp dir for the cert-management demo");
    dir
}

/// A full authorized round-trip over the given (file-loaded) configs: a server thread runs the
/// UNCHANGED P3b-6 loop, the client connects and gets its signed Draft `Applied`. Self-asserts
/// so any deviation exits non-zero. Mirrors checkpoint [1] and the `cert_files.rs` test.
fn round_trip(
    server_cfg: Arc<ServerConfig>,
    client_cfg: Arc<ClientConfig>,
    client_leaf: CertificateDer<'static>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind round-trip listener");
    let port = listener.local_addr().unwrap().port();

    let agent = thread::spawn(move || run_agent_once(listener, server_cfg));

    let stream = TcpStream::connect(("127.0.0.1", port)).expect("client TCP connect");
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .expect("set client read timeout");
    let name = ServerName::try_from("localhost").expect("valid server name");
    let (mut transport, client_session) =
        connect(stream, client_cfg, name, &client_leaf).expect("mTLS handshake + server auth");

    let operator = CommandSigner::from_seed("operator", [7u8; 32]);
    let agent_id = CommandSigner::from_seed("agent-1", [42u8; 32]);
    let mut server_v = Ed25519Verifier::new();
    server_v.trust(&agent_id.actor, agent_id.verifying_key());
    let mut client = ControlPlaneClient::new(operator, server_v);

    let mut cmd = draft_cmd("operator", &client_session, 1);
    client.sign(&mut cmd);
    client
        .send_command(&mut transport, cmd)
        .expect("send command over mTLS");
    let result = client
        .await_result(&mut transport)
        .expect("await result over mTLS")
        .expect("a genuine, correlated Applied result returns");
    assert_eq!(
        result.outcome,
        CommandOutcome::Applied,
        "the authorized draft applied over the file-loaded mTLS configs"
    );

    let (agent_session, served, state) = agent.join().expect("agent thread joins");
    assert!(
        served,
        "the agent loop served exactly one command frame off the TLS socket"
    );
    assert_eq!(
        agent_session, client_session,
        "both ends derived the SAME cert-bound session id"
    );
    assert_eq!(
        state,
        Some(ActionState::Drafted),
        "the gated draft advanced the agent's bridge"
    );
}

/// Best-effort attempt by an already-connected client to get a command APPLIED; `false` iff it
/// never obtains an `Applied` outcome (transport error, EOF, or a non-`Applied` result). Used to
/// prove a server-rejected peer is served nothing even if its own `connect` optimistically
/// returned `Ok` under TLS 1.3. Mirrors `cert_revocation.rs::client_gets_applied`.
fn client_gets_applied(
    transport: &mut torda_control_server::TlsClientTransport,
    session: &str,
) -> bool {
    let operator = CommandSigner::from_seed("operator", [7u8; 32]);
    let agent_id = CommandSigner::from_seed("agent-1", [42u8; 32]);
    let mut server_v = Ed25519Verifier::new();
    server_v.trust(&agent_id.actor, agent_id.verifying_key());
    let mut client = ControlPlaneClient::new(operator, server_v);

    let mut cmd = draft_cmd("operator", session, 1);
    client.sign(&mut cmd);
    if client.send_command(transport, cmd).is_err() {
        return false;
    }
    matches!(client.await_result(transport), Ok(Some(r)) if r.outcome == CommandOutcome::Applied)
}

/// Assert a peer is REJECTED by the SERVER at the TLS handshake: the agent's `accept` returns
/// `Err` (so the loop/bridge is never reached) AND the client is served nothing. The client may
/// *trust* the server cert here (same/old CA), so under TLS 1.3 its own `connect` can return
/// `Ok` before the server's fatal alert arrives — we therefore assert the security-critical
/// facts directly. Mirrors `cert_revocation.rs::assert_peer_rejected_by_server`.
fn peer_rejected_by_server(
    server_cfg: Arc<ServerConfig>,
    client_cfg: Arc<ClientConfig>,
    client_leaf: CertificateDer<'static>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind reject listener");
    let port = listener.local_addr().unwrap().port();

    // The agent thread must NOT reach a loop: `accept` returns Err AT the handshake.
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

    let agent_rejected = agent.join().expect("reject-attempt agent thread joins");
    assert!(
        agent_rejected,
        "the server rejects the peer AT the handshake (accept -> Err)"
    );
    assert!(
        !applied,
        "a server-rejected peer is served nothing — no command is ever applied"
    );
}

fn main() {
    // rustls' ring provider is installed explicitly per-config inside torda-transport-tls, so no
    // global install is needed here.
    println!("== Real mTLS control channel — live functional demo (P3b-7) ==\n");

    // ------------------------------------------------------------------------------------
    // [1] Real mTLS control channel (mutual peer-cert auth over loopback)
    // ------------------------------------------------------------------------------------
    println!("[1] Real mTLS control channel (mutual peer-cert auth over loopback)");
    let pki = generate_test_pki();
    let server_cfg = server_config(&pki);
    let client_cfg = client_config(&pki);
    let client_leaf = pki.client_cert_chain[0].clone();

    // Two physically distinct endpoints: a CONTROL listener and a separate TELEMETRY listener,
    // each on its own ephemeral loopback port.
    let control_listener = TcpListener::bind("127.0.0.1:0").expect("bind control listener");
    let control_port = control_listener.local_addr().unwrap().port();
    let telemetry_listener = TcpListener::bind("127.0.0.1:0").expect("bind telemetry listener");
    let telemetry_port = telemetry_listener.local_addr().unwrap().port();
    assert_ne!(
        control_port, telemetry_port,
        "control and telemetry are physically distinct ports"
    );
    // Non-blocking so [3] can assert "no connection arrived" without hanging.
    telemetry_listener
        .set_nonblocking(true)
        .expect("telemetry listener non-blocking");
    println!("    control endpoint : 127.0.0.1:{control_port}");
    println!("    telemetry endpoint: 127.0.0.1:{telemetry_port}  (distinct physical socket)");

    // Agent server thread: accepts one connection, runs the UNCHANGED loop, returns the
    // cert-derived session + served flag + bridge state via the thread join.
    let agent = thread::spawn(move || run_agent_once(control_listener, server_cfg));

    // Client (main thread): connect to the CONTROL port and complete the mTLS handshake.
    let stream = TcpStream::connect(("127.0.0.1", control_port)).expect("client TCP connect");
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .expect("set client read timeout");
    let name = ServerName::try_from("localhost").expect("valid server name for the server SAN");
    let (mut transport, client_session) =
        connect(stream, client_cfg, name, &client_leaf).expect("mTLS handshake + server auth");
    println!("    mTLS handshake complete — authenticated peer, session = {client_session}");

    // Issue an authorized, signed Draft (operator key the agent's verifier trusts) on the
    // cert-derived session at seq=1, and await the agent's signed result.
    let operator = CommandSigner::from_seed("operator", [7u8; 32]);
    let agent_id = CommandSigner::from_seed("agent-1", [42u8; 32]);
    let mut server_v = Ed25519Verifier::new();
    server_v.trust(&agent_id.actor, agent_id.verifying_key()); // trust the agent's result signature
    let mut client = ControlPlaneClient::new(operator, server_v);

    let mut cmd = draft_cmd("operator", &client_session, 1);
    client.sign(&mut cmd);
    client
        .send_command(&mut transport, cmd)
        .expect("send command over real mTLS");
    let result = client
        .await_result(&mut transport)
        .expect("await result over real mTLS")
        .expect("a genuine, correlated agent result returns over mTLS");
    println!(
        "    command sent over real mTLS -> agent applied -> result: {:?}",
        result.outcome
    );
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
        state,
        Some(ActionState::Drafted),
        "the gated draft advanced the agent's bridge"
    );
    assert_eq!(
        agent_session, client_session,
        "both ends independently derived the SAME cert-bound session id"
    );
    println!(
        "    session ids match on both ends (cert-derived): agent={agent_session} client={client_session}  \u{2713}\n"
    );

    // ------------------------------------------------------------------------------------
    // [2] An untrusted client is rejected at the TLS handshake
    // ------------------------------------------------------------------------------------
    println!("[2] An untrusted client is rejected at the TLS handshake");
    // The server trusts CA #1; the attacker presents a client cert from an INDEPENDENT CA #2
    // (and symmetrically rejects the server's CA-#1 cert). The rejection is AT the handshake —
    // no application/control frame is ever processed. A fresh listener + its own agent thread
    // (which EXPECTS `accept` to Err) keeps a failed handshake on one side from hanging the other.
    let server_pki = generate_test_pki();
    let attacker_pki = generate_test_pki(); // its own CA — untrusted by the server
    let server_cfg2 = server_config(&server_pki);
    let attacker_cfg = client_config(&attacker_pki);
    let attacker_leaf = attacker_pki.client_cert_chain[0].clone();

    let listener2 = TcpListener::bind("127.0.0.1:0").expect("bind untrusted-attempt listener");
    let port2 = listener2.local_addr().unwrap().port();

    // The agent thread must NOT reach a loop: `accept` returns Err at the handshake.
    let agent2 = thread::spawn(move || {
        let (stream, _) = listener2.accept().expect("agent accepts TCP");
        stream.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
        accept(stream, server_cfg2).is_err()
    });

    let stream2 = TcpStream::connect(("127.0.0.1", port2)).expect("attacker TCP connect");
    stream2.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
    let name2 = ServerName::try_from("localhost").unwrap();
    let connect_result = connect(stream2, attacker_cfg, name2, &attacker_leaf);

    let agent_rejected = agent2.join().expect("untrusted-attempt agent thread joins");
    assert!(
        agent_rejected,
        "the server rejects the untrusted client AT the TLS handshake"
    );
    assert!(
        connect_result.is_err(),
        "the client also fails the handshake (untrusted server cert) — no frame exchanged"
    );
    let err = connect_result.err().unwrap();
    println!("    untrusted client (foreign CA) -> handshake rejected: {err}  <- mTLS caught");
    println!("    no command was processed on the untrusted attempt  \u{2713}\n");

    // ------------------------------------------------------------------------------------
    // [3] Physical control/telemetry separation
    // ------------------------------------------------------------------------------------
    println!("[3] Physical control/telemetry separation");
    // The whole [1] round-trip touched ONLY the control port. The telemetry listener (set
    // non-blocking above) received NO connection: its accept would-block.
    match telemetry_listener.accept() {
        Err(e) if e.kind() == ErrorKind::WouldBlock => {}
        other => panic!(
            "telemetry listener must have accepted NO control connection, got: {:?}",
            other.map(|_| "a connection")
        ),
    }
    println!(
        "    telemetry port carried zero control frames — physically separate endpoint  \u{2713}\n"
    );

    // ------------------------------------------------------------------------------------
    // [4] Certificate management — file-loaded configs, CRL revocation, CA rotation
    // ------------------------------------------------------------------------------------
    println!("[4] Certificate management — file-loaded configs, CRL revocation, CA rotation");
    let cert_dir = unique_temp_dir();
    println!(
        "    provisioning throwaway test PKI under: {}",
        cert_dir.display()
    );

    // ---- [4.1] Configs loaded from FILES (PEM). Write a fresh test PKI to disk, build the
    // server/client configs straight from those PEM files, and run a real round-trip.
    let pki = generate_test_pki();
    let CertFilePaths {
        ca,
        server_chain,
        server_key,
        client_chain,
        client_key,
    } = write_pki_to_pem(&pki, &cert_dir).expect("write test PKI to PEM files");
    let file_server_cfg =
        server_config_from_files(&[&ca], &server_chain, &server_key).expect("server cfg from PEM");
    let file_client_cfg =
        client_config_from_files(&[&ca], &client_chain, &client_key).expect("client cfg from PEM");
    round_trip(
        file_server_cfg,
        file_client_cfg,
        pki.client_cert_chain[0].clone(),
    );
    println!("    mTLS configs loaded from PEM files; command verifies over the wire  \u{2713}");

    // ---- [4.2] CRL revocation. `generate_revocation_test_pki()` returns a RevocationTestPki:
    // `pki_revoked` (its client leaf's serial is named in the CRL) and `pki_good` (same CA +
    // server leaf, a DIFFERENT serial NOT in the CRL), plus `crl_der`. Write pki_revoked's CA +
    // server chain/key and the CRL to files, build a CRL-enforcing server cfg, and show the
    // revoked client rejected AT the handshake.
    let rpki = generate_revocation_test_pki();
    let rev_dir = unique_temp_dir();
    let rp = write_pki_to_pem(&rpki.pki_revoked, &rev_dir).expect("write revoked PKI to PEM");
    let crl_path = rev_dir.join("revoke.der");
    fs::write(&crl_path, rpki.crl_der.as_ref()).expect("write CRL DER to file");

    let crl_server_cfg = server_config_from_files_with_crl(
        &[&rp.ca],
        &rp.server_chain,
        &rp.server_key,
        &[&crl_path],
    )
    .expect("CRL-enforcing server cfg from files");
    let revoked_client_cfg = client_config_from_files(&[&rp.ca], &rp.client_chain, &rp.client_key)
        .expect("revoked client cfg from files");
    peer_rejected_by_server(
        crl_server_cfg,
        revoked_client_cfg,
        rpki.pki_revoked.client_cert_chain[0].clone(),
    );
    println!("    revoked client certificate -> rejected at the TLS handshake  <- CRL enforced");

    // Nice-to-have: the SAME CRL config admits a non-revoked client of the same CA. pki_good
    // shares the CA + server leaf, so we rebuild the CRL-enforcing server cfg over its files.
    let good_dir = unique_temp_dir();
    let gp = write_pki_to_pem(&rpki.pki_good, &good_dir).expect("write good PKI to PEM");
    let good_crl = good_dir.join("revoke.der");
    fs::write(&good_crl, rpki.crl_der.as_ref()).expect("write CRL DER to file");
    let good_server_cfg = server_config_from_files_with_crl(
        &[&gp.ca],
        &gp.server_chain,
        &gp.server_key,
        &[&good_crl],
    )
    .expect("CRL-enforcing server cfg (good)");
    let good_client_cfg = client_config_from_files(&[&gp.ca], &gp.client_chain, &gp.client_key)
        .expect("good client cfg from files");
    round_trip(
        good_server_cfg,
        good_client_cfg,
        rpki.pki_good.client_cert_chain[0].clone(),
    );
    println!(
        "    non-revoked client of the same CA -> still connects under the same CRL  \u{2713}"
    );

    // ---- [4.3] CA rotation (overlap -> retire). Two INDEPENDENT CAs, each with its own client.
    let old = generate_test_pki();
    let new = generate_test_pki();
    let old_dir = unique_temp_dir();
    let new_dir = unique_temp_dir();
    let po = write_pki_to_pem(&old, &old_dir).expect("write CA_old PKI");
    let pn = write_pki_to_pem(&new, &new_dir).expect("write CA_new PKI");
    let old_leaf = old.client_cert_chain[0].clone();
    let new_leaf = new.client_cert_chain[0].clone();

    // OVERLAP: server trusts BOTH CAs. A CA_old client AND a CA_new client both connect. (A
    // client only trusts its OWN CA's server leaf, so each sub-case presents that client's-CA
    // server leaf, always with the two-CA client-auth trust list.)
    {
        let s = server_config_from_files(&[&po.ca, &pn.ca], &po.server_chain, &po.server_key)
            .expect("overlap server cfg (old leaf)");
        let c = client_config_from_files(&[&po.ca], &po.client_chain, &po.client_key)
            .expect("CA_old client cfg");
        round_trip(s, c, old_leaf.clone());
    }
    {
        let s = server_config_from_files(&[&po.ca, &pn.ca], &pn.server_chain, &pn.server_key)
            .expect("overlap server cfg (new leaf)");
        let c = client_config_from_files(&[&pn.ca], &pn.client_chain, &pn.client_key)
            .expect("CA_new client cfg");
        round_trip(s, c, new_leaf.clone());
    }

    // RETIRE: server trusts ONLY CA_new. The CA_new client still connects...
    {
        let s = server_config_from_files(&[&pn.ca], &pn.server_chain, &pn.server_key)
            .expect("retired server cfg (new only)");
        let c = client_config_from_files(&[&pn.ca], &pn.client_chain, &pn.client_key)
            .expect("CA_new client cfg");
        round_trip(s, c, new_leaf.clone());
    }
    // ...but the CA_old client is now REJECTED. The server presents the OLD server leaf (so the
    // old client's SERVER-auth succeeds and the failure is isolated to the server no longer
    // trusting CA_old for CLIENT auth) while trusting ONLY CA_new.
    {
        let s = server_config_from_files(&[&pn.ca], &po.server_chain, &po.server_key)
            .expect("retired server cfg (old leaf, trusts new only)");
        let c = client_config_from_files(&[&po.ca], &po.client_chain, &po.client_key)
            .expect("CA_old client cfg");
        peer_rejected_by_server(s, c, old_leaf);
    }
    println!(
        "    CA rotation: overlap accepts old+new; after retiring old CA, old-CA client \
         rejected, new-CA client connects  <- rotated"
    );

    // Best-effort cleanup of the throwaway PKI temp dirs (a demo leaves nothing behind).
    for d in [&cert_dir, &rev_dir, &good_dir, &old_dir, &new_dir] {
        let _ = fs::remove_dir_all(d);
    }
    println!(
        "    mTLS certs/keys/CRLs load from ops-provisioned files (PEM or DER); a compromised \
         cert is revoked via CRL and rejected at the handshake; CA rotation trusts old+new \
         during overlap then retires the old — no flag day, mutual auth stays required."
    );
    println!("    (transport-layer twin of the P3b-10 signing-key rotation)  \u{2713}\n");

    // ------------------------------------------------------------------------------------
    // [5] Hot-reload — revoke/rotate certs on a running agent (no restart)
    // ------------------------------------------------------------------------------------
    println!("[5] Hot-reload — revoke/rotate certs on a running agent");
    // A SINGLE `ReloadableServerConfig` stands up ONCE; its client-auth CA file is then rewritten
    // and hot-reloaded LIVE, and the SAME running instance rejects the now-untrusted client on its
    // NEXT connection — no restart. (This demo uses CA rotation for the live-revocation step: it
    // exercises `ReloadableServerConfig` end to end with only `generate_test_pki`/`write_pki_to_pem`
    // — no rcgen, no new dependency. Rotating the client-auth CA revokes trust for every cert of the
    // retired CA. The `config_reload.rs` golden vectors cover the CRL-file variant.)
    let dir_server = unique_temp_dir();
    let dir_old = unique_temp_dir();
    let dir_new = unique_temp_dir();
    let dir_spec = unique_temp_dir();
    let pki_server = generate_test_pki(); // CONSTANT server identity both clients trust
    let pki_old = generate_test_pki(); // CA_old — the client we will revoke
    let pki_new = generate_test_pki(); // CA_new — a freshly-issued client
    let p_server = write_pki_to_pem(&pki_server, &dir_server).expect("write server PKI");
    let p_old = write_pki_to_pem(&pki_old, &dir_old).expect("write CA_old PKI");
    let p_new = write_pki_to_pem(&pki_new, &dir_new).expect("write CA_new PKI");

    // The ops-provisioned client-auth CA file — the ONLY thing we rotate. Start it as CA_old.
    let client_auth_ca = dir_spec.join("client-auth-ca.pem");
    fs::copy(&p_old.ca, &client_auth_ca).expect("seed client-auth CA with CA_old");
    let spec = CertFileSpec {
        // Client-auth trust root (rotated live). Server identity is the CONSTANT p_server leaf.
        ca_paths: vec![client_auth_ca.clone()],
        cert_chain: p_server.server_chain.clone(),
        key: p_server.server_key.clone(),
        crl_paths: vec![],
    };
    let reloadable =
        ReloadableServerConfig::from_files(spec).expect("initial (CA_old) reloadable config");

    // Both clients trust the CONSTANT server CA (so server-auth always passes); they differ only in
    // which client-CA signed their own leaf.
    let old_client_cfg =
        client_config_from_files(&[&p_server.ca], &p_old.client_chain, &p_old.client_key)
            .expect("CA_old client cfg");
    let new_client_cfg =
        client_config_from_files(&[&p_server.ca], &p_new.client_chain, &p_new.client_key)
            .expect("CA_new client cfg");
    let old_leaf = pki_old.client_cert_chain[0].clone();
    let new_leaf = pki_new.client_cert_chain[0].clone();

    // (1) BEFORE: the CA_old client connects over the running config.
    round_trip(
        reloadable.current(),
        old_client_cfg.clone(),
        old_leaf.clone(),
    );
    println!("    mTLS client connects  \u{2713}");

    // (2) REVOKE (live): rewrite the client-auth CA file to CA_new only, then hot-reload the SAME
    //     instance. The CA_old client's NEXT connection is rejected AT the handshake — no restart.
    fs::copy(&p_new.ca, &client_auth_ca).expect("rotate client-auth CA to CA_new");
    reloadable
        .reload()
        .expect("reload picks up the rotated CA (same instance, no restart)");
    peer_rejected_by_server(reloadable.current(), old_client_cfg, old_leaf);
    println!(
        "    certificate revoked via CA rotation + reloaded -> next connection rejected at the \
         handshake (no restart)  <- revoked live"
    );
    // ...while a freshly-issued CA_new client connects over the very same running config.
    round_trip(reloadable.current(), new_client_cfg, new_leaf);
    println!("    a freshly-issued cert connects over the same running config  \u{2713}");

    // (3) FAIL-SAFE — shown on a SEPARATE, fresh `ReloadableServerConfig` whose client is NEVER
    //     revoked, so a still-valid client is what proves the running config survives a bad reload.
    let dir_fs = unique_temp_dir();
    let pki_fs = generate_test_pki();
    let p_fs = write_pki_to_pem(&pki_fs, &dir_fs).expect("write fail-safe PKI");
    let spec_fs = CertFileSpec {
        ca_paths: vec![p_fs.ca.clone()],
        cert_chain: p_fs.server_chain.clone(),
        key: p_fs.server_key.clone(),
        crl_paths: vec![],
    };
    let reloadable_fs =
        ReloadableServerConfig::from_files(spec_fs).expect("initial fail-safe config");
    let fs_client_cfg = client_config_from_files(&[&p_fs.ca], &p_fs.client_chain, &p_fs.client_key)
        .expect("fail-safe client cfg");
    let fs_leaf = pki_fs.client_cert_chain[0].clone();
    // The still-valid client connects.
    round_trip(
        reloadable_fs.current(),
        fs_client_cfg.clone(),
        fs_leaf.clone(),
    );
    // Corrupt the server key file so the next rebuild fails; reload MUST return Err.
    fs::write(
        &p_fs.server_key,
        b"-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----\n",
    )
    .expect("corrupt the server key file");
    assert!(
        reloadable_fs.reload().is_err(),
        "a bad rebuild returns Err (fail-safe)"
    );
    // The SAME still-valid client STILL connects — the running config was never disarmed.
    round_trip(reloadable_fs.current(), fs_client_cfg, fs_leaf);
    println!(
        "    bad cert reload is a no-op -> agent keeps serving the running config  <- fail-safe"
    );

    for d in [&dir_server, &dir_old, &dir_new, &dir_spec, &dir_fs] {
        let _ = fs::remove_dir_all(d);
    }
    println!(
        "    certs reload from ops-provisioned files on a RUNNING agent; revocation/rotation takes \
         effect on the next connection with no restart; a bad reload is fail-safe (keeps the \
         current config).  \"Revoke immediately, no downtime.\"  \u{2713}\n"
    );

    println!(
        "== demo complete: a genuine command crossed a REAL mutual-TLS socket (cert-bound \
         session, both ends agree), the agent applied it and signed the result back, an \
         untrusted foreign-CA client was rejected at the handshake, control/telemetry stayed \
         on physically separate ports, and full certificate management (file-loaded configs, \
         CRL revocation, CA rotation) was enforced at the handshake, and CONFIG HOT-RELOAD on a \
         RUNNING agent revoked/rotated a cert LIVE — the retired-CA client rejected on its next \
         connection with NO restart, a bad reload fail-safe =="
    );
    println!(
        "note: this is the REAL mTLS carrier filling the P3b-6 transport seam — the \
         AgentControlLoop, the ControlPlaneClient, and every module are UNCHANGED. \
         Certificates, keys, and CRLs load from ops-provisioned files; compromised certs are \
         revoked via CRL and CA rotation runs old+new during overlap then retires the old."
    );
}
