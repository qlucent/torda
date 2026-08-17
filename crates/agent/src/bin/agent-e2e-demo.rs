//! LIVE end-to-end checkpoint for P3c-1: proves that ONE real agent process is BOTH
//! (a) an OCSF telemetry source AND (b) a secure mutual-TLS remediation control endpoint,
//! at the same time, over its OWN control loop — with a signed remediation lifecycle driven
//! across the wire and an untrusted client rejected at the handshake.
//!
//! Everything below the app is the SAME production wiring the `torda` binary uses:
//!   * `torda::{load_config, spawn_control_service}` stand up the REAL control
//!     service (`crates/agent/src/lib.rs`) — a dedicated std::thread running synchronous
//!     rustls + the UNCHANGED `AgentControlLoop`, with REQUIRED client-cert mTLS and the
//!     default DRY-RUN executor (no host mutation).
//!   * the SAME asset module + shared substrate stub the collection cycle in `main.rs` runs
//!     emits a REAL OCSF envelope — captured here to show telemetry and control coexist.
//!
//! Checkpoints (each self-asserts, so a regression exits non-zero):
//!   [1] the real agent control service is provisioned from files and listening on mTLS.
//!   [2] the SAME agent, via the SAME substrate + asset module as `main.rs`, emits a genuine
//!       OCSF record — one process is a telemetry source too.
//!   [3] a signed, AUTHORIZED remediation command (alice=Operator Draft) is driven over real
//!       mTLS against the agent's OWN live loop and returns `Applied` — the agent drafted it
//!       on its own audited bridge. (The wire lifecycle exposes Draft here; the remaining
//!       dry-run -> submit -> approve -> canary -> rollout state machine — including the
//!       four-eyes approval gate — is exercised end to end by `remediation-demo`.)
//!   [4] an untrusted client (foreign CA) is rejected at the mTLS handshake — nothing applied.
//!   [5] the control service shuts down cleanly (no hang); the temp PKI is removed.
//!
//! DEMO-ONLY: no library was edited. Read timeouts bound every socket so a rejected handshake
//! can never hang; the accept thread joins on shutdown. On Windows an intermittent `LNK1104`
//! (linker cannot open output file — AV/lock flake) can fail the FIRST build; simply re-run.

use std::fs;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::pki_types::ServerName;

use torda_control_plane::{CommandOutcome, CommandSigner, ControlPlaneClient, Ed25519Verifier};
use torda_remediation::action::{AssetSelector, CanarySpec, Method, RemediationAction, VerifySpec};
use torda_remediation::control::{CommandKind, ControlCommand};
use torda_transport_tls::{
    client_config_from_files, connect, generate_test_pki, write_pki_to_pem, CertFilePaths,
};

use torda_core::{
    Module, ModuleCtx, OcsfEmitter, ResourceBudget, ResourceGovernor, ResourceSampler,
    ResourceUsage,
};
use torda_ocsf::OcsfEnvelope;
use torda_substrate::{StubBus, StubSnapshot};

use torda::{load_config, spawn_control_service, AgentConfig, CertPaths, ControlConfig, RoleEntry};

/// Bounds any client-side read so a bug can never hang the demo. Loopback round-trips are
/// sub-millisecond; this is a safety net only.
const CLIENT_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Deterministic ed25519 seeds. alice authors the Draft (Operator); the agent signs its
/// result acknowledgments.
const ALICE_SEED: [u8; 32] = [7u8; 32];
const AGENT_SEED: [u8; 32] = [42u8; 32];

/// A capturing emitter: records every OCSF envelope a module emits so the demo can show a
/// genuine telemetry record (the production binary's `StdoutEmitter` writes NDJSON instead).
#[derive(Default)]
struct CapturingEmitter {
    records: Arc<Mutex<Vec<OcsfEnvelope>>>,
}
impl OcsfEmitter for CapturingEmitter {
    fn emit(&self, rec: OcsfEnvelope) {
        self.records.lock().expect("emitter lock").push(rec);
    }
}

/// A zero-usage sampler: the governor needs a sampler, but this demo does not exercise
/// throttling, so a constant-ZERO reading keeps the one collection cycle dependency-free.
struct ZeroSampler;
impl ResourceSampler for ZeroSampler {
    fn sample(&self) -> ResourceUsage {
        ResourceUsage::ZERO
    }
}

/// A fresh, uniquely-named temp dir (pid + nanos) so concurrent runs never collide on disk.
fn unique_temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "torda-agent-e2e-{tag}-{}-{}",
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

/// Write a full agent-config setup to disk and return the loaded [`ControlConfig`] (the
/// `[control]` section `spawn_control_service` consumes) plus the mTLS file paths and the
/// client leaf DER (needed for cert-bound session derivation).
///
/// Provisions: a test PKI (server chain/key + a client-auth CA), an ed25519 signing-key
/// trust dir holding alice's PUBLIC key, and the agent's OWN private key at `agent-1.key`.
/// Roles: alice=operator.
fn write_config(
    dir: &Path,
) -> (
    ControlConfig,
    CertFilePaths,
    rustls::pki_types::CertificateDer<'static>,
) {
    // mTLS material: one CA signs both the agent (server) leaf and the client leaf.
    let pki = generate_test_pki();
    let client_leaf = pki.client_cert_chain[0].clone();
    let pki_paths = write_pki_to_pem(&pki, dir).expect("write test PKI to PEM");

    // ed25519 command-verifier trust dir: alice's PUBLIC key, filename stem = actor.
    let trust_dir = dir.join("trust");
    fs::create_dir_all(&trust_dir).unwrap();
    let alice_pub = hex::encode(
        CommandSigner::from_seed("alice", ALICE_SEED)
            .verifying_key()
            .to_bytes(),
    );
    fs::write(trust_dir.join("alice.pub"), format!("{alice_pub}\n")).unwrap();

    // The agent's OWN signing key (private seed); its stem "agent-1" is the actor it signs
    // results under, so the issuer trusts results from "agent-1".
    let agent_key_file = dir.join("agent-1.key");
    fs::write(&agent_key_file, format!("{}\n", hex::encode(AGENT_SEED))).unwrap();

    let cfg = AgentConfig {
        agent: Default::default(),
        output: None,
        control: Some(ControlConfig {
            control_addr: "127.0.0.1:0".to_string(),
            tenant_id: "tenant-e2e".to_string(),
            cert: CertPaths {
                ca_paths: vec![pki_paths.ca.clone()],
                cert_chain: pki_paths.server_chain.clone(),
                key: pki_paths.server_key.clone(),
                crl_paths: vec![],
            },
            trust_dir,
            agent_key_file,
            roles: vec![RoleEntry {
                actor: "alice".into(),
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
    (control, pki_paths, client_leaf)
}

/// Connect an mTLS client to `addr` using `paths`' client cert/key (trusting the CA as the
/// server root). Returns the connected transport + the cert-bound session id.
fn connect_client(
    addr: std::net::SocketAddr,
    paths: &CertFilePaths,
    client_leaf: &rustls::pki_types::CertificateDer<'static>,
) -> (torda_transport_tls::TlsClientTransport, String) {
    let client_cfg = client_config_from_files(&[&paths.ca], &paths.client_chain, &paths.client_key)
        .expect("client cfg from files");
    let stream = TcpStream::connect(addr).expect("client TCP connect");
    stream.set_read_timeout(Some(CLIENT_READ_TIMEOUT)).unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    connect(stream, client_cfg, name, client_leaf).expect("mTLS handshake + server auth")
}

/// Best-effort: does an already-connected client obtain an `Applied` outcome for an
/// alice-signed Draft? Used to prove a rejected peer is served NOTHING even if its own
/// `connect` optimistically returned `Ok` under TLS 1.3.
fn client_gets_applied(
    transport: &mut torda_transport_tls::TlsClientTransport,
    session: &str,
) -> bool {
    let alice = CommandSigner::from_seed("alice", ALICE_SEED);
    let agent_id = CommandSigner::from_seed("agent-1", AGENT_SEED);
    let mut server_v = Ed25519Verifier::new();
    server_v.trust("agent-1", agent_id.verifying_key());
    let mut client = ControlPlaneClient::new(alice, server_v);

    let mut cmd = draft_cmd("alice", session, 1);
    client.sign(&mut cmd);
    if client.send_command(transport, cmd).is_err() {
        return false;
    }
    matches!(client.await_result(transport), Ok(Some(r)) if r.outcome == CommandOutcome::Applied)
}

fn main() {
    println!("== Agent LIVE end-to-end — one process: OCSF telemetry + mTLS remediation control (P3c-1) ==\n");

    let dir = unique_temp_dir("run");

    // -----------------------------------------------------------------------------------
    // [1] Provision + start the REAL agent control service (from files, mutual-TLS).
    // -----------------------------------------------------------------------------------
    println!("[1] Provision + start the REAL agent control service");
    let (cfg, paths, client_leaf) = write_config(&dir);
    let handle = spawn_control_service(&cfg).expect("real agent control service spawns");
    let addr = handle.local_addr();
    println!("    real agent control service listening on {addr} (mTLS)  \u{2713}");
    println!("    (same wiring as `torda --config <cfg>`: DryRun executor, no host mutation)\n");

    // -----------------------------------------------------------------------------------
    // [2] Telemetry side — the SAME agent is also an OCSF source.
    // -----------------------------------------------------------------------------------
    println!("[2] Telemetry side — the same agent emits genuine OCSF");
    // Run ONE collection step through the SAME substrate stub + asset module `main.rs` uses,
    // capturing the emitted OCSF envelope. This is the real module reading the real snapshot
    // provider — not a hand-crafted record.
    let records: Arc<Mutex<Vec<OcsfEnvelope>>> = Arc::new(Mutex::new(Vec::new()));
    let emitter: Arc<dyn OcsfEmitter> = Arc::new(CapturingEmitter {
        records: records.clone(),
    });
    let governor = Arc::new(ResourceGovernor::new(
        ResourceBudget::from_env(),
        Box::new(ZeroSampler),
    ));
    let ctx = ModuleCtx {
        bus: StubBus::new(),
        snapshot: StubSnapshot::new(),
        emitter,
        governor,
        tenant_id: cfg.tenant_id.clone(),
        product: "torda".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime for one collection step");
    rt.block_on(async {
        let mut asset = torda_mod_asset::AssetModule::new();
        asset.init(ctx.clone()).await.expect("asset module init");
        asset
            .start()
            .await
            .expect("asset module start (emits OCSF)");
    });
    let captured = records.lock().unwrap();
    assert!(
        !captured.is_empty(),
        "the asset module emitted at least one OCSF record"
    );
    let ocsf_line = serde_json::to_string(&captured[0]).expect("serialize OCSF envelope");
    println!("    same substrate + asset module as main.rs emitted a genuine OCSF record:");
    println!("    {ocsf_line}");
    println!("    telemetry + control coexist in one agent process  \u{2713}");
    println!(
        "    (`torda --config <cfg>` runs the FULL collection cycle AND this control channel)\n"
    );

    // -----------------------------------------------------------------------------------
    // [3] Signed, authorized remediation command over real mTLS against the agent's OWN loop.
    // -----------------------------------------------------------------------------------
    println!("[3] Signed remediation command over real mTLS (agent's own loop)");
    let (mut transport, session) = connect_client(addr, &paths, &client_leaf);
    println!("    mTLS handshake complete — authenticated peer, session = {session}");

    // The client trusts the agent's result-signing key so a genuine ack verifies.
    let alice = CommandSigner::from_seed("alice", ALICE_SEED);
    let agent_id = CommandSigner::from_seed("agent-1", AGENT_SEED);
    let mut server_v = Ed25519Verifier::new();
    server_v.trust("agent-1", agent_id.verifying_key());
    let mut client = ControlPlaneClient::new(alice, server_v);

    // alice=Operator authors + SIGNS the Draft; the agent's live loop verifies + authorizes it
    // and drafts it on its own audited bridge -> Applied, then signs the result back.
    let mut cmd = draft_cmd("alice", &session, 1);
    client.sign(&mut cmd); // alice's ed25519 signature
    client
        .send_command(&mut transport, cmd)
        .expect("send Draft over mTLS");
    let r = client
        .await_result(&mut transport)
        .expect("await Draft result")
        .expect("a genuine, correlated Draft result returns");
    assert_eq!(
        r.outcome,
        CommandOutcome::Applied,
        "alice's authorized Draft is Applied by the agent loop"
    );
    assert_eq!(
        r.agent, "agent-1",
        "the result is signed by the agent's OWN key"
    );
    assert_eq!(
        r.session, session,
        "the signed result echoes the cert-bound session"
    );
    println!(
        "    alice (Operator) Draft over real mTLS -> {:?}  <- agent drafted it on its OWN loop",
        r.outcome
    );
    println!(
        "    result signed by agent '{}', bound to session {}  \u{2713}",
        r.agent, r.session
    );
    println!("    (dry-run -> submit -> approve [four-eyes] -> canary -> rollout is driven end to end by `remediation-demo`)\n");

    drop(transport); // close the connection so the agent's serve loop sees EOF

    // -----------------------------------------------------------------------------------
    // [4] Untrusted client (foreign CA) rejected at the mTLS handshake.
    // -----------------------------------------------------------------------------------
    println!("[4] Untrusted client rejected at the handshake");
    let attacker_dir = unique_temp_dir("attacker");
    let attacker_pki = generate_test_pki(); // its OWN independent CA — untrusted by the agent
    let attacker_paths = write_pki_to_pem(&attacker_pki, &attacker_dir).unwrap();
    let attacker_leaf = attacker_pki.client_cert_chain[0].clone();

    let stream = TcpStream::connect(addr).expect("attacker TCP connect");
    stream.set_read_timeout(Some(CLIENT_READ_TIMEOUT)).unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    let attacker_cfg = client_config_from_files(
        &[&attacker_paths.ca],
        &attacker_paths.client_chain,
        &attacker_paths.client_key,
    )
    .unwrap();
    // The agent REQUIRES a cert signed by ITS CA; the foreign-CA cert is rejected at the
    // handshake. Under TLS 1.3 the attacker's own `connect` may return Ok before the server's
    // fatal alert arrives, so assert the security-critical fact: nothing is ever applied.
    let applied = match connect(stream, attacker_cfg, name, &attacker_leaf) {
        Err(_) => false, // handshake failed outright
        Ok((mut t, s)) => client_gets_applied(&mut t, &s),
    };
    assert!(
        !applied,
        "an untrusted foreign-CA client is served nothing — no command is applied"
    );
    println!("    untrusted client (foreign CA) -> rejected at the mTLS handshake  <- caught\n");

    // -----------------------------------------------------------------------------------
    // [5] Clean shutdown + cleanup.
    // -----------------------------------------------------------------------------------
    println!("[5] Clean shutdown");
    handle.shutdown(); // signals the accept thread and joins it (bounded, no hang)
    println!("    control service stopped cleanly  \u{2713}");
    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&attacker_dir);
    println!("    temp PKI removed\n");

    println!(
        "== demo complete: ONE agent process was simultaneously an OCSF telemetry source AND a \
         secure mTLS remediation endpoint. A signed, authorized remediation command (alice=Operator \
         Draft) crossed a REAL mutual-TLS socket to the agent's OWN control loop and was Applied + \
         signed back; an untrusted foreign-CA client was rejected at the handshake. =="
    );
    println!(
        "note: commands are ed25519-SIGNED + role-AUTHORIZED + replay-guarded; the default \
         executor is DRY-RUN (records the target, mutates NO host state) — a real host-applying \
         executor is a separate, safety-gated slice."
    );
}
