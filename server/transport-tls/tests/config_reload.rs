//! Integration proof that [`torda_transport_tls::ReloadableServerConfig`] hot-reloads the
//! mutual-TLS server config **atomically** and **FAIL-SAFE** on a RUNNING agent — over real
//! loopback handshakes, driving the UNCHANGED P3b control loop/client, with NO restart.
//!
//! Mirrors `cert_revocation.rs`: each round-trip stands up a `TcpListener` on an ephemeral port,
//! runs the agent side (`accept` + an `AgentControlLoop`) on its own thread, and drives the
//! issuer side (`connect` + a `ControlPlaneClient`) from the test thread. The per-connection
//! `ServerConfig` handed to `accept` is a fresh `reloadable.current()` snapshot, exactly as a
//! real listener would take one per accept. `accept`/`connect`/`TlsTransport` are UNCHANGED.
//!
//! The four vectors prove: (1) publishing a CRL that revokes a client and calling `reload()`
//! rejects that SAME client on its NEXT connection though it connected before; (2) rotating the
//! client-auth CA file + `reload()` retires the old-CA client and admits the new-CA one; (3) a
//! failed reload (corrupt file) returns `Err` and keeps serving the last-good config (never
//! disarmed, never accept-any); (4) mutual auth is still REQUIRED after a reload — an
//! untrusted-CA client is still rejected. All on ONE `ReloadableServerConfig` instance, no
//! restart between the before/after connections.
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

use rustls::pki_types::{CertificateDer, ServerName};
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
    accept, client_config_from_files, connect, generate_test_pki, write_pki_to_pem, CertFilePaths,
    CertFileSpec, ReloadableServerConfig,
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
        let dir = std::env::temp_dir().join(format!(
            "torda-reload-{}-{}-{}",
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

// ---------------------------------------------------------------------------------------------
// Loopback harness — copied from cert_revocation.rs so the reload vectors drive the SAME
// UNCHANGED control loop/client over a real mTLS socket.
// ---------------------------------------------------------------------------------------------

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
/// Returns nothing; panics (fails the test) if the round-trip does not fully apply.
fn assert_round_trip(
    server_cfg: Arc<ServerConfig>,
    client_cfg: Arc<ClientConfig>,
    client_leaf: CertificateDer<'static>,
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
/// non-`Applied` result all count as "not applied").
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
/// `Err`, so the loop's `serve_one`/bridge is never reached, AND the client is served nothing.
/// See `cert_revocation.rs` for why the client's own `connect` may still return `Ok` under TLS
/// 1.3 when it is the SERVER refusing the client cert.
fn assert_peer_rejected_by_server(
    server_cfg: Arc<ServerConfig>,
    client_cfg: Arc<ClientConfig>,
    client_leaf: CertificateDer<'static>,
) {
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

// ---------------------------------------------------------------------------------------------
// rcgen minting for the live-revocation vector: one CA that can sign CRLs, a server leaf, a
// client leaf with an EXPLICIT serial, plus TWO CRLs signed by that CA — one revoking NOBODY
// (empty revoked list) and one revoking the client's serial. `generate_revocation_test_pki`
// only exposes ONE (revoking) CRL and hides the CA key, so we mint our own pair here.
// ---------------------------------------------------------------------------------------------

struct CrlReloadPki {
    ca_pem: String,
    server_chain_pem: String,
    server_key_pem: String,
    client_chain_pem: String,
    client_key_pem: String,
    client_leaf: CertificateDer<'static>,
    /// A valid CRL revoking NO certificate (empty revoked list) — the client is NOT revoked.
    crl_revoking_nobody_der: Vec<u8>,
    /// A valid CRL revoking the client's serial — the client IS revoked.
    crl_revoking_client_der: Vec<u8>,
}

fn mint_crl_reload_pki() -> CrlReloadPki {
    // A CA allowed to sign certs AND CRLs (rcgen/webpki require the CrlSign usage to sign/honour
    // a CRL against this trust anchor).
    let mut ca_params =
        rcgen::CertificateParams::new(Vec::new()).expect("CA params from empty SAN list");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    ca_params.distinguished_name.push(
        rcgen::DnType::CommonName,
        "torda-transport-tls reload test CA",
    );
    let ca_key = rcgen::KeyPair::generate().expect("generate CA key pair");
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA cert");

    // Server leaf (SAN localhost) signed by the CA.
    let server_params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("server params");
    let server_key = rcgen::KeyPair::generate().expect("generate server key");
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .expect("sign server leaf");

    // Client leaf with an EXPLICIT serial so a CRL can name it deterministically.
    let client_serial: u64 = 0x1234_5678;
    let mut client_params = rcgen::CertificateParams::new(vec!["torda-agent-client".to_string()])
        .expect("client params");
    client_params.serial_number = Some(rcgen::SerialNumber::from(client_serial));
    let client_key = rcgen::KeyPair::generate().expect("generate client key");
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .expect("sign client leaf");

    // Fixed, deterministic CRL validity window (past -> year 2100) so it never reads as expired.
    let this_update = rcgen::date_time_ymd(2023, 1, 1);
    let next_update = rcgen::date_time_ymd(2100, 1, 1);

    // (1) A CRL revoking NOBODY — an empty revoked list. A valid CRL under which the client is
    // NOT revoked, so revocation is enforced yet the client connects.
    let crl_nobody = rcgen::CertificateRevocationListParams {
        this_update,
        next_update,
        crl_number: rcgen::SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs: vec![],
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    }
    .signed_by(&ca_cert, &ca_key)
    .expect("sign empty CRL by the CA");

    // (2) A CRL revoking the client's serial (higher crl_number).
    let crl_client = rcgen::CertificateRevocationListParams {
        this_update,
        next_update,
        crl_number: rcgen::SerialNumber::from(2u64),
        issuing_distribution_point: None,
        revoked_certs: vec![rcgen::RevokedCertParams {
            serial_number: rcgen::SerialNumber::from(client_serial),
            revocation_time: this_update,
            reason_code: Some(rcgen::RevocationReason::KeyCompromise),
            invalidity_date: None,
        }],
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    }
    .signed_by(&ca_cert, &ca_key)
    .expect("sign revoking CRL by the CA");

    CrlReloadPki {
        ca_pem: ca_cert.pem(),
        server_chain_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        client_chain_pem: client_cert.pem(),
        client_key_pem: client_key.serialize_pem(),
        client_leaf: client_cert.der().clone(),
        crl_revoking_nobody_der: crl_nobody.der().to_vec(),
        crl_revoking_client_der: crl_client.der().to_vec(),
    }
}

/// Write `contents` to `dir/name`, returning the path.
fn write_file(dir: &Path, name: &str, contents: &[u8]) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, contents).expect("write file");
    p
}

// ---------------------------------------------------------------------------------------------
// The four golden vectors.
// ---------------------------------------------------------------------------------------------

/// (1) LIVE REVOCATION. A `ReloadableServerConfig` whose spec points at a CRL file that
/// initially revokes NOBODY: the client connects. Then the SAME CRL path is overwritten with a
/// CRL that revokes the client, `reload()` is called on the SAME instance, and the client's NEXT
/// connection (via the new `current()`) is REJECTED at the handshake — no restart.
#[test]
fn live_revocation_takes_effect_on_next_connection_after_reload() {
    let dir = TempDir::new();
    let pki = mint_crl_reload_pki();

    let ca = write_file(dir.path(), "ca.pem", pki.ca_pem.as_bytes());
    let server_chain = write_file(
        dir.path(),
        "server-chain.pem",
        pki.server_chain_pem.as_bytes(),
    );
    let server_key = write_file(dir.path(), "server-key.pem", pki.server_key_pem.as_bytes());
    let client_chain = write_file(
        dir.path(),
        "client-chain.pem",
        pki.client_chain_pem.as_bytes(),
    );
    let client_key = write_file(dir.path(), "client-key.pem", pki.client_key_pem.as_bytes());
    // The CRL path the spec enforces. Initially it revokes NOBODY.
    let crl = write_file(dir.path(), "revocations.der", &pki.crl_revoking_nobody_der);

    let spec = CertFileSpec {
        ca_paths: vec![ca],
        cert_chain: server_chain,
        key: server_key,
        crl_paths: vec![crl.clone()],
    };
    let reloadable =
        ReloadableServerConfig::from_files(spec).expect("initial CRL-enforcing config");

    // The client that we will later revoke.
    let client_cfg = client_config_from_files(
        &[reloadable.spec().ca_paths[0].as_path()],
        &client_chain,
        &client_key,
    )
    .expect("client cfg");

    // BEFORE reload: revocation is enforced but the client is not revoked — it connects.
    assert_round_trip(
        reloadable.current(),
        client_cfg.clone(),
        pki.client_leaf.clone(),
    );

    // Publish a CRL that revokes the client, at the SAME spec path, then hot-reload.
    fs::write(&crl, &pki.crl_revoking_client_der).expect("overwrite CRL with a revoking one");
    reloadable
        .reload()
        .expect("reload picks up the new CRL (same instance, no restart)");

    // AFTER reload: the SAME client's NEXT connection is rejected at the handshake.
    assert_peer_rejected_by_server(reloadable.current(), client_cfg, pki.client_leaf);
}

/// (2) LIVE CA ROTATION. The spec's single client-auth CA file initially holds CA_old; a
/// CA_old client connects. The file is overwritten with CA_new only, `reload()` is called on the
/// SAME instance, and the CA_old client is REJECTED while a CA_new client connects. Isolated to
/// CLIENT-CA trust: the server always presents a leaf signed by a SEPARATE, constant server CA
/// that BOTH clients trust, so server-auth always succeeds and the only variable is which
/// client-CA the server trusts.
#[test]
fn live_ca_rotation_rejects_old_ca_client_after_reload() {
    // Three independent CA+leaf sets: a constant SERVER identity, and old/new CLIENT CAs.
    let pki_server = generate_test_pki();
    let pki_old = generate_test_pki();
    let pki_new = generate_test_pki();

    let dir_server = TempDir::new();
    let dir_old = TempDir::new();
    let dir_new = TempDir::new();
    let dir_spec = TempDir::new();

    let p_server: CertFilePaths =
        write_pki_to_pem(&pki_server, dir_server.path()).expect("write server PKI");
    let p_old: CertFilePaths = write_pki_to_pem(&pki_old, dir_old.path()).expect("write old PKI");
    let p_new: CertFilePaths = write_pki_to_pem(&pki_new, dir_new.path()).expect("write new PKI");

    // The spec's client-auth CA file — the ONLY thing we rotate. Start with CA_old.
    let client_auth_ca = dir_spec.path().join("client-auth-ca.pem");
    fs::copy(&p_old.ca, &client_auth_ca).expect("seed client-auth CA with CA_old");

    let spec = CertFileSpec {
        // Client-auth trust root (rotated). Server identity is the CONSTANT p_server leaf.
        ca_paths: vec![client_auth_ca.clone()],
        cert_chain: p_server.server_chain.clone(),
        key: p_server.server_key.clone(),
        crl_paths: vec![],
    };
    let reloadable = ReloadableServerConfig::from_files(spec).expect("initial (CA_old) config");

    // Both clients trust the CONSTANT server CA (so server-auth always passes); they differ only
    // in which client-CA signed their own leaf.
    let old_client_cfg =
        client_config_from_files(&[&p_server.ca], &p_old.client_chain, &p_old.client_key)
            .expect("CA_old client cfg");
    let new_client_cfg =
        client_config_from_files(&[&p_server.ca], &p_new.client_chain, &p_new.client_key)
            .expect("CA_new client cfg");
    let old_leaf = pki_old.client_cert_chain[0].clone();
    let new_leaf = pki_new.client_cert_chain[0].clone();

    // BEFORE rotation: the CA_old client connects.
    assert_round_trip(
        reloadable.current(),
        old_client_cfg.clone(),
        old_leaf.clone(),
    );

    // Rotate the client-auth CA file to CA_new only, then hot-reload the SAME instance.
    fs::copy(&p_new.ca, &client_auth_ca).expect("rotate client-auth CA to CA_new");
    reloadable
        .reload()
        .expect("reload picks up CA_new (same instance, no restart)");

    // AFTER rotation: the CA_old client is rejected (server no longer trusts CA_old for client
    // auth) while the CA_new client connects.
    assert_peer_rejected_by_server(reloadable.current(), old_client_cfg, old_leaf);
    assert_round_trip(reloadable.current(), new_client_cfg, new_leaf);
}

/// (3) FAIL-SAFE. A client connects. Then a spec file is CORRUPTED and `reload()` returns `Err`.
/// The previously-valid client STILL connects via `current()` — the running config was neither
/// disarmed into accept-any nor broken; it keeps enforcing the last-good mutual-TLS policy.
#[test]
fn a_failed_reload_is_fail_safe_current_config_serves() {
    let dir = TempDir::new();
    let pki = generate_test_pki();
    let p = write_pki_to_pem(&pki, dir.path()).expect("write PKI");

    let spec = CertFileSpec {
        ca_paths: vec![p.ca.clone()],
        cert_chain: p.server_chain.clone(),
        key: p.server_key.clone(),
        crl_paths: vec![],
    };
    let reloadable = ReloadableServerConfig::from_files(spec).expect("initial good config");

    let client_cfg =
        client_config_from_files(&[&p.ca], &p.client_chain, &p.client_key).expect("client cfg");
    let leaf = pki.client_cert_chain[0].clone();

    // BEFORE: the client connects.
    assert_round_trip(reloadable.current(), client_cfg.clone(), leaf.clone());

    // Corrupt the server key file so the next rebuild fails.
    fs::write(
        &p.server_key,
        b"-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----\n",
    )
    .expect("corrupt the key file");
    assert!(
        reloadable.reload().is_err(),
        "a bad rebuild returns Err (fail-safe)"
    );

    // AFTER the failed reload: the SAME good config still serves the client — never disarmed.
    assert_round_trip(reloadable.current(), client_cfg, leaf);
}

/// (4) MUTUAL AUTH STILL REQUIRED AFTER RELOAD. After a successful reload from the same good
/// files, a client whose cert is signed by a DIFFERENT, untrusted CA is still rejected at the
/// handshake — no accept-any crept in via the reload path. (The untrusted client is given the
/// real server CA as its server-trust root so server-auth succeeds and the failure is isolated
/// to the server refusing the untrusted CLIENT cert.)
#[test]
fn mutual_auth_still_required_after_reload() {
    let dir = TempDir::new();
    let good = generate_test_pki();
    let attacker = generate_test_pki(); // an independent, untrusted CA + client leaf
    let p = write_pki_to_pem(&good, dir.path()).expect("write good PKI");
    let dir_att = TempDir::new();
    let p_att = write_pki_to_pem(&attacker, dir_att.path()).expect("write attacker PKI");

    let spec = CertFileSpec {
        ca_paths: vec![p.ca.clone()],
        cert_chain: p.server_chain.clone(),
        key: p.server_key.clone(),
        crl_paths: vec![],
    };
    let reloadable = ReloadableServerConfig::from_files(spec).expect("initial good config");

    // A successful reload from the SAME good files.
    reloadable
        .reload()
        .expect("reload from good files succeeds");

    // The attacker trusts the real server CA (server-auth passes) but presents an untrusted
    // client cert — the server must still reject it after the reload.
    let attacker_cfg = client_config_from_files(&[&p.ca], &p_att.client_chain, &p_att.client_key)
        .expect("attacker client cfg (trusts real server CA, presents untrusted client leaf)");
    let attacker_leaf = attacker.client_cert_chain[0].clone();

    assert_peer_rejected_by_server(reloadable.current(), attacker_cfg, attacker_leaf);
}
