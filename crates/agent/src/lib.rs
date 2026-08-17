//! # torda library — the secure control service
//!
//! This is the LIB half of the agent package (the `[[bin]]` in `main.rs` is the P0/P1
//! collection cycle and is unchanged). It stands up the agent's **mutual-TLS remediation
//! control channel** by wiring three EXISTING, unmodified pieces together:
//!
//! - `torda-transport-tls` — the real mTLS carrier (`accept`, `ReloadableServerConfig`),
//!   whose loaders install the REQUIRED client-cert verifier, so mutual auth is mandatory
//!   and there is NO accept-any / `dangerous()` path anywhere below the seam.
//! - `torda-control-plane` — the `AgentControlLoop` + `AgentControlHandler` command gate
//!   (ed25519 authentication + role authorization + replay guard + lifecycle guards).
//! - `torda-remediation` — the `Bridge` (audited pre-execution state machine) and the
//!   `Executor`/`Verifier` seams.
//!
//! ## Security posture (the three invariants this slice must hold)
//!
//! 1. **Mutual auth is intact.** The listener serves configs built ONLY through the
//!    file loaders (via [`ReloadableServerConfig::from_files`]); those require a CA-signed
//!    client certificate. An untrusted or absent client cert fails the handshake inside
//!    [`accept`] and never reaches the control loop.
//! 2. **The default executor does NOT mutate the host.** [`DryRunExecutor::apply`] RECORDS
//!    the target and returns `Ok(())` — it spawns no process and touches no file. A real
//!    host-applying executor is a separate, safety-gated slice.
//! 3. **Config load is fail-closed.** [`load_config`] size-caps the read and maps a missing
//!    or malformed file to an `Err` (never a panic); an unknown role string is likewise an
//!    `Err`. The agent never comes up on a half-parsed or ambiguous config.
//!
//! The control service runs on a DEDICATED `std::thread` (plain `std::net` + synchronous
//! rustls), entirely OFF any tokio runtime.

use std::io;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use torda_control_plane::{
    AgentControlHandler, AgentControlLoop, CommandSigner, Ed25519Verifier, ReloadableVerifier,
};
use torda_remediation::action::RemediationAction;
use torda_remediation::audit::VecAuditSink;
use torda_remediation::bridge::{Bridge, Executor, Verifier, VerifyOutcome};
use torda_remediation::control::{Role, RolePolicy, SystemClock};
use torda_transport_tls::{accept, CertFileSpec, ReloadableServerConfig};

/// Upper bound on the size of an agent config file [`load_config`] will read. A real
/// config is a few hundred bytes to a few KiB; this 1 MiB cap is generous headroom while
/// still refusing to allocate against a pathologically large or accidental file (rejected
/// from its on-disk size BEFORE it is read into memory).
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// Read timeout applied to each accepted control connection. It bounds a misbehaving or
/// silent peer so a stuck read can never wedge the accept thread, and — combined with the
/// per-iteration shutdown check in the serve loop — lets a shutdown be noticed within this
/// interval even while a connection is idle mid-session. Loopback round-trips complete in
/// milliseconds, so this only ever fires on an abnormal peer.
const CONN_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// How long the non-blocking accept loop sleeps between polls when no connection is
/// pending. Short enough that [`ControlServiceHandle::shutdown`] returns promptly; long
/// enough that idle polling costs nothing.
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Mirrors [`CertFileSpec`]'s fields as a serde-loadable config fragment: the
/// ops-provisioned mutual-TLS material the control listener is built from.
///
/// - `ca_paths`: CA file(s) forming the client-auth trust root (the CA that signed the
///   control-plane client certs).
/// - `cert_chain` / `key`: the agent's own server leaf chain + private key.
/// - `crl_paths`: optional CRL file(s); empty = no CRL enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertPaths {
    pub ca_paths: Vec<PathBuf>,
    pub cert_chain: PathBuf,
    pub key: PathBuf,
    #[serde(default)]
    pub crl_paths: Vec<PathBuf>,
}

impl CertPaths {
    /// Convert to the transport crate's [`CertFileSpec`] (a field-for-field copy).
    fn to_spec(&self) -> CertFileSpec {
        CertFileSpec {
            ca_paths: self.ca_paths.clone(),
            cert_chain: self.cert_chain.clone(),
            key: self.key.clone(),
            crl_paths: self.crl_paths.clone(),
        }
    }
}

/// One actor -> role assignment for the control-plane authorization policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleEntry {
    pub actor: String,
    pub role: String,
}

/// The agent's on-disk configuration, a single **TOML** file with THREE optional sections,
/// loaded fail-closed by [`load_config`]. Every section carries serde defaults so a MINIMAL
/// config is valid: an EMPTY file, an `[output]`-only file, and a `[control]`-only file all
/// load cleanly. In particular a "just write OCSF to a file" config needs NO mTLS field.
///
/// ```toml
/// [agent]
/// daemon = true
///
/// [output]
/// sink = "file"
/// path = "/var/log/torda/events.ndjson"
/// rotate_mb = 64
///
/// [control]
/// control_addr = "127.0.0.1:9443"
/// tenant_id = "tenant-a"
/// trust_dir = "/etc/torda/trust"
/// agent_key_file = "/etc/torda/agent-1.key"
/// enabled = true
/// [control.cert]
/// ca_paths = ["/etc/torda/ca.pem"]
/// cert_chain = "/etc/torda/server.pem"
/// key = "/etc/torda/server.key"
/// ```
///
/// NOTE (Task 1/Task 2 boundary): the `[agent]` and `[output]` sections PARSE and are TESTED
/// here, but are NOT yet read for run-mode/sink behavior — the agent binary still resolves
/// daemon/output from the MA-1 CLI flags/env. Task 2 wires the flag>env>config>default
/// precedence. Only the `[control]` section is consumed for behavior in this slice.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AgentConfig {
    /// The `[agent]` section: run-mode knobs. Parsed but not yet wired (see the note above).
    #[serde(default)]
    pub agent: AgentSection,
    /// The `[output]` section (OPTIONAL): OCSF sink selection. Absent → the default stdout
    /// sink. Parsed but not yet wired (see the note above).
    #[serde(default)]
    pub output: Option<OutputConfig>,
    /// The `[control]` section (OPTIONAL): the mutual-TLS remediation channel. Absent → no
    /// control (today's `control_enabled = false`). Present + `enabled = true` → control runs.
    #[serde(default)]
    pub control: Option<ControlConfig>,
}

/// The `[agent]` section: agent-wide run-mode settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSection {
    /// Run continuously (stream) instead of one-shot. Defaults to `false`. Task 2 reads this
    /// (behind the `--daemon`/`$TORDA_DAEMON` override); Task 1 only parses it.
    #[serde(default)]
    pub daemon: bool,
}

/// The `[output]` section: which OCSF sink the agent writes to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputConfig {
    /// `"stdout"` (default) or `"file"`. An unknown value is left for Task 2's sink
    /// resolution to reject; Task 1 only parses it.
    #[serde(default = "default_sink")]
    pub sink: String,
    /// For `sink = "file"`, the path to write NDJSON to. Ignored for stdout.
    #[serde(default)]
    pub path: Option<PathBuf>,
    /// For `sink = "file"`, rotate after this many MiB. Absent → the binary's default.
    #[serde(default)]
    pub rotate_mb: Option<u64>,
}

fn default_sink() -> String {
    "stdout".to_string()
}

/// The `[control]` section: the ops-provisioned mutual-TLS remediation control channel.
/// Holds the EXACT fields the control service was configured with before this slice; only
/// the container changed (a nested TOML section instead of the flat JSON root). The mTLS /
/// roles / verifier LOGIC in [`spawn_control_service`] is behaviorally UNCHANGED.
///
/// Field declaration order is deliberate: all scalar values precede the `cert` sub-table and
/// the `roles` array-of-tables so `toml::to_string` never emits a value after a table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlConfig {
    /// Address the control listener binds, e.g. `"127.0.0.1:0"` (0 = ephemeral port).
    pub control_addr: String,
    /// The tenant this agent belongs to (carried for provenance; not a security boundary).
    pub tenant_id: String,
    /// Directory of ed25519 signing-key trust files (one `<actor>.<ext>` per issuer,
    /// holding that actor's trusted PUBLIC key(s)) — the store the command verifier uses.
    pub trust_dir: PathBuf,
    /// The agent's OWN ed25519 signing key file (private seed), used to sign command
    /// results. The actor name the agent signs under is the file's stem.
    pub agent_key_file: PathBuf,
    /// Whether the control service should run. Honored by the CALLER (the agent binary) —
    /// [`spawn_control_service`] itself always builds the service when called.
    #[serde(default)]
    pub enabled: bool,
    /// Actor -> role assignments for the command authorization policy.
    #[serde(default)]
    pub roles: Vec<RoleEntry>,
    /// Ops-provisioned mutual-TLS material for the control listener.
    pub cert: CertPaths,
}

/// Load and validate an [`AgentConfig`] from a **TOML** file, FAIL-CLOSED and panic-free.
///
/// The file's on-disk size is checked FIRST: a file exceeding [`MAX_CONFIG_BYTES`] is
/// rejected with `Err(InvalidData)` WITHOUT being read into memory. Non-UTF-8 or malformed
/// TOML is mapped to `Err(InvalidData)` (never an `unwrap`/panic). A missing/unreadable file
/// surfaces the underlying I/O error (e.g. `NotFound`) — still an `Err`, never a panic, so
/// the agent cannot come up on an absent or ambiguous config. Thanks to the per-section
/// serde defaults, an EMPTY file parses to an all-defaults config (no daemon, stdout, no
/// control) rather than an error.
pub fn load_config(path: &Path) -> io::Result<AgentConfig> {
    // Size-cap from metadata BEFORE reading, so an oversized/accidental file never forces
    // an unbounded read.
    let len = std::fs::metadata(path)?.len();
    if len > MAX_CONFIG_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "agent config {} too large: {len} bytes exceeds the {MAX_CONFIG_BYTES}-byte cap",
                path.display()
            ),
        ));
    }
    let bytes = std::fs::read(path)?;
    // TOML is text: reject non-UTF-8 fail-closed rather than lossily decoding.
    let text = std::str::from_utf8(&bytes).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("agent config is not valid UTF-8: {e}"),
        )
    })?;
    toml::from_str(text).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("malformed agent config: {e}"),
        )
    })
}

/// Map a config role string to a [`Role`], FAIL-CLOSED: an unknown role is an
/// `Err(InvalidData)` rather than a silent default, so a typo can never widen authority.
fn parse_role(s: &str) -> io::Result<Role> {
    match s {
        "operator" => Ok(Role::Operator),
        "approver" => Ok(Role::Approver),
        "responder" => Ok(Role::Responder),
        "admin" => Ok(Role::Admin),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown role '{other}' (expected operator|approver|responder|admin)"),
        )),
    }
}

/// Build a [`RolePolicy`] from the config's role entries, fail-closed on any unknown role.
fn build_policy(entries: &[RoleEntry]) -> io::Result<RolePolicy> {
    let mut policy = RolePolicy::new();
    for e in entries {
        policy.assign(&e.actor, parse_role(&e.role)?);
    }
    Ok(policy)
}

/// The DEFAULT control-channel executor: a strict **dry-run / no-op**.
///
/// # SAFETY GUARANTEE — this executor NEVER mutates the host.
///
/// [`apply`](Self::apply) RECORDS the target it was asked to act on and returns `Ok(())`
/// WITHOUT running any command, spawning any process, or touching any file. [`preview`]
/// and [`rollback`] are likewise side-effect-free. This upholds the P3 invariant that "no
/// code path applies a fix the user did not author and trigger": the control channel can
/// be stood up and exercised end to end with ZERO risk of an unintended host change.
///
/// A REAL host-applying executor (one whose `apply` actually runs the user's payload) is a
/// **separate, safety-gated slice** — it must add sign/dry-run/canary/rollback/kill-switch/
/// audit gates before any real mutation. Until then this dry-run executor is the only thing
/// wired behind the live control loop, by design.
#[derive(Debug, Default)]
pub struct DryRunExecutor {
    /// Targets `apply` was asked to act on. Purely a record of what a real executor WOULD
    /// have touched — nothing here was actually mutated on the host.
    applied: Vec<String>,
}

impl DryRunExecutor {
    pub fn new() -> Self {
        Self::default()
    }
    /// The targets `apply` recorded (all no-ops — none was mutated on the host).
    pub fn applied(&self) -> &[String] {
        &self.applied
    }
}

impl Executor for DryRunExecutor {
    fn preview(&self, action: &RemediationAction) -> String {
        format!("[dry-run] would run: {}", action.payload)
    }
    /// Records `target` and returns `Ok(())` — NO process is spawned and NO file is
    /// touched. This is the host-safety guarantee of the default executor.
    fn apply(&mut self, _action: &RemediationAction, target: &str) -> anyhow::Result<()> {
        self.applied.push(target.to_string());
        Ok(())
    }
    /// No-op rollback: there is nothing to undo because `apply` changed nothing.
    fn rollback(&mut self, _action: &RemediationAction, _target: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

/// The DEFAULT control-channel re-score verifier, paired with [`DryRunExecutor`].
///
/// It always returns [`VerifyOutcome::NotFixed`], and that is the HONEST answer: the
/// dry-run executor changes nothing on the host, so no linked finding could have been
/// fixed. Reporting `NotFixed` means an executed action can only ever reach
/// `AppliedUnverified` (or roll back) — NEVER a false `Closed`. Wiring a real
/// Findings-Engine re-score here is a separate slice, alongside a real executor.
#[derive(Debug, Default)]
pub struct DryRunVerifier;

impl Verifier for DryRunVerifier {
    fn verify(&self, _action: &RemediationAction, _applied: &[String]) -> VerifyOutcome {
        // NotFixed is honest: a dry-run executor mutated nothing, so nothing is fixed.
        VerifyOutcome::NotFixed
    }
}

/// A running control service: the bound address, a shutdown flag, and the accept thread's
/// join handle. Dropping it (or calling [`shutdown`](Self::shutdown)) signals the thread to
/// stop and joins it, so the service never leaks past the handle.
pub struct ControlServiceHandle {
    local_addr: SocketAddr,
    shutdown_flag: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl ControlServiceHandle {
    /// The address the control listener actually bound (with `:0` this is the OS-chosen
    /// ephemeral port a client connects to).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Signal the accept thread to stop and JOIN it. Returns only once the thread has
    /// fully exited (no hang): the accept loop polls the shutdown flag every
    /// [`ACCEPT_POLL_INTERVAL`], and any in-flight connection's blocking reads are bounded
    /// by [`CONN_READ_TIMEOUT`] plus a per-iteration flag check.
    pub fn shutdown(mut self) {
        self.signal_and_join();
    }

    fn signal_and_join(&mut self) {
        self.shutdown_flag.store(true, Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for ControlServiceHandle {
    /// Defense-in-depth: if the handle is dropped without an explicit
    /// [`shutdown`](Self::shutdown), still signal + join so the thread cannot outlive it.
    fn drop(&mut self) {
        self.signal_and_join();
    }
}

/// Stand up the mutual-TLS remediation control service on a DEDICATED `std::thread`.
///
/// All fallible setup runs on the CALLER's thread and fails closed via `?` BEFORE the
/// listener thread is spawned, so `spawn_control_service` returns `Err` (constructing no
/// thread) if any of the following do not load:
/// - the mutual-TLS [`ReloadableServerConfig`] from `cfg.cert` (required client-cert auth),
/// - the ed25519 command-verifier trust store from `cfg.trust_dir`,
/// - the role policy from `cfg.roles` (unknown role => `Err`),
/// - the agent's own signing key from `cfg.agent_key_file`,
/// - the TCP bind of `cfg.control_addr`.
///
/// The spawned thread OWNS the verifier, policy, and signer as locals, so the `&` borrows
/// inside each per-connection [`AgentControlHandler`] are always valid — they outlive every
/// loop that borrows them. One shared [`Bridge`] serves every connection on the thread.
///
/// The thread is a plain `std::net` + synchronous-rustls accept loop with NO tokio runtime.
/// It is non-blocking with a short poll so a shutdown is noticed promptly; each accepted
/// connection is handed to [`accept`] (the mTLS handshake — an untrusted/absent client cert
/// is rejected HERE and never reaches the loop), then driven via
/// [`AgentControlLoop::serve_one`] against the shared bridge until the peer closes.
///
/// NOTE: `spawn_control_service` does not itself consult `cfg.enabled` — that gate belongs to
/// the caller (the agent binary). Calling this function means "start it". Its input is the
/// nested `[control]` section ([`ControlConfig`]); the mTLS / roles / verifier LOGIC below is
/// UNCHANGED from when it read the flat config — only the container type moved.
pub fn spawn_control_service(cfg: &ControlConfig) -> io::Result<ControlServiceHandle> {
    // --- All fallible setup on the caller's thread, fail-closed BEFORE spawning. ---

    // Mutual-TLS server config (required client-cert auth — inherited from the file
    // loaders; no accept-any path exists here). Hot-reloadable for future cert rotation.
    let server_cfg = ReloadableServerConfig::from_files(cfg.cert.to_spec())?;

    // ed25519 command-verifier trust store (who may SIGN commands), behind a reloadable
    // wrapper so ops can rotate trusted keys on a running agent.
    let verifier = ReloadableVerifier::new(Ed25519Verifier::load_trust_dir(&cfg.trust_dir)?);

    // Role policy (who may ISSUE which command) — fail-closed on any unknown role.
    let policy = build_policy(&cfg.roles)?;

    // The agent's own signing key (signs result acknowledgments). The actor name it signs
    // under is the key file's stem, so the issuer trusts results under that name.
    let agent_actor = cfg
        .agent_key_file
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "agent key file {} has no valid actor stem",
                    cfg.agent_key_file.display()
                ),
            )
        })?;
    let signer = CommandSigner::from_key_file(agent_actor, &cfg.agent_key_file)?;

    // Bind now (on the caller's thread) so we can return the real local_addr synchronously.
    let listener = TcpListener::bind(&cfg.control_addr)?;
    let local_addr = listener.local_addr()?;

    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let thread_flag = shutdown_flag.clone();

    // --- The dedicated accept thread (OFF tokio): owns verifier/policy/signer so the
    //     handler's `&` borrows are valid for the life of each per-connection loop. ---
    let join = thread::Builder::new()
        .name("torda-control".to_string())
        .spawn(move || {
            control_accept_loop(listener, server_cfg, verifier, policy, signer, thread_flag);
        })?;

    Ok(ControlServiceHandle {
        local_addr,
        shutdown_flag,
        join: Some(join),
    })
}

/// The accept loop body, running on the dedicated control thread. Owns the auth material so
/// every [`AgentControlHandler`] built per connection borrows locals that outlive it.
fn control_accept_loop(
    listener: TcpListener,
    server_cfg: ReloadableServerConfig,
    verifier: ReloadableVerifier,
    policy: RolePolicy,
    signer: CommandSigner,
    shutdown: Arc<AtomicBool>,
) {
    // One audited bridge shared across every connection served by this thread.
    let mut bridge = Bridge::new(VecAuditSink::default());

    // Non-blocking accept + short poll so setting `shutdown` unblocks the loop WITHOUT any
    // self-connection trick: the next poll observes the flag and the thread returns.
    if listener.set_nonblocking(true).is_err() {
        // If the platform refuses non-blocking mode we cannot guarantee a clean shutdown;
        // bail rather than risk a hung join. (Not expected on any supported target.)
        return;
    }

    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _peer)) => {
                // The accepted socket is served with BLOCKING, timeout-bounded reads (the
                // synchronous rustls handshake + framed reads expect blocking I/O).
                if stream.set_nonblocking(false).is_err()
                    || stream.set_read_timeout(Some(CONN_READ_TIMEOUT)).is_err()
                {
                    continue; // cannot configure the socket safely; drop it
                }

                // mTLS handshake + REQUIRED client-cert auth happens HERE. An untrusted or
                // absent client cert makes this return Err — no control frame is processed.
                let (mut transport, session) = match accept(stream, server_cfg.current()) {
                    Ok(pair) => pair,
                    Err(_) => continue, // rejected at the handshake; loop for the next peer
                };

                // Build the gate fresh per connection, borrowing the thread-owned locals.
                let handler = AgentControlHandler::new(&verifier, &policy, &signer);
                let mut agent_loop = AgentControlLoop::with_session(
                    handler,
                    &session,
                    0,
                    Box::new(DryRunExecutor::new()),
                    Box::new(DryRunVerifier),
                );

                // Serve commands on this connection until it closes / errors / we shut down.
                serve_connection(&mut agent_loop, &mut transport, &mut bridge, &shutdown);
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL_INTERVAL); // nothing pending; poll again
            }
            Err(_) => {
                // Transient accept error: pause briefly, then re-check shutdown + retry.
                thread::sleep(ACCEPT_POLL_INTERVAL);
            }
        }
    }
}

/// Drive one authenticated connection through the control loop until it ends. A read
/// timeout surfaces as `WouldBlock`/`TimedOut`; that is NOT a fatal error — we re-check the
/// shutdown flag and keep waiting for the next frame, so an idle peer can't wedge the thread
/// and a shutdown is still observed within [`CONN_READ_TIMEOUT`].
fn serve_connection(
    agent_loop: &mut AgentControlLoop<'_>,
    transport: &mut torda_transport_tls::TlsServerTransport,
    bridge: &mut Bridge<VecAuditSink>,
    shutdown: &Arc<AtomicBool>,
) {
    while !shutdown.load(Ordering::SeqCst) {
        match agent_loop.serve_one(transport, bridge, &SystemClock) {
            Ok(true) => {}      // served a frame; keep serving on this connection
            Ok(false) => break, // clean EOF: peer closed
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                // Idle read timeout — loop back to re-check shutdown, then keep waiting.
                continue;
            }
            Err(_) => break, // real I/O error: drop the connection
        }
    }
}

#[cfg(test)]
mod config_tests {
    //! Unit tests for the restructured TOML config: section defaults, round-trip, and the
    //! fail-closed / panic-free / size-capped loader. These exercise `load_config` on real
    //! temp files so the size-cap-before-read path is covered too.
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// A fresh, uniquely-named temp dir so concurrent test runs never collide.
    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "torda-cfg-test-{tag}-{}-{}",
            std::process::id(),
            nanos
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A fully-populated config (all three sections) for the round-trip test. The cert paths
    /// are placeholders — `load_config` parses, it does not stat cert files.
    fn full_config() -> AgentConfig {
        AgentConfig {
            agent: AgentSection { daemon: true },
            output: Some(OutputConfig {
                sink: "file".to_string(),
                path: Some(PathBuf::from("/var/log/torda/events.ndjson")),
                rotate_mb: Some(64),
            }),
            control: Some(ControlConfig {
                control_addr: "127.0.0.1:9443".to_string(),
                tenant_id: "tenant-a".to_string(),
                trust_dir: PathBuf::from("/etc/torda/trust"),
                agent_key_file: PathBuf::from("/etc/torda/agent-1.key"),
                enabled: true,
                roles: vec![RoleEntry {
                    actor: "operator".to_string(),
                    role: "operator".to_string(),
                }],
                cert: CertPaths {
                    ca_paths: vec![PathBuf::from("/etc/torda/ca.pem")],
                    cert_chain: PathBuf::from("/etc/torda/server.pem"),
                    key: PathBuf::from("/etc/torda/server.key"),
                    crl_paths: vec![],
                },
            }),
        }
    }

    #[test]
    fn full_config_round_trips_through_toml_and_loader() {
        let cfg = full_config();
        let dir = temp_dir("roundtrip");
        let path = dir.join("agent.toml");
        // Serialize -> write -> load_config back -> must equal the original.
        let text = toml::to_string(&cfg).expect("serialize full config to TOML");
        std::fs::write(&path, &text).unwrap();
        let loaded = load_config(&path).expect("load_config parses the full config");
        assert_eq!(
            cfg, loaded,
            "full config round-trips byte-for-byte through TOML"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn minimal_output_only_config_needs_no_mtls_field() {
        // A "just write OCSF to a file" config: only [output], NO [control], NO mTLS field.
        let dir = temp_dir("output-only");
        let path = dir.join("agent.toml");
        std::fs::write(
            &path,
            "[output]\nsink = \"file\"\npath = \"/var/log/ua/events.ndjson\"\n",
        )
        .unwrap();
        let cfg = load_config(&path).expect("output-only config loads without any control field");
        assert!(cfg.control.is_none(), "no [control] -> control is None");
        assert!(
            !cfg.agent.daemon,
            "absent [agent] -> daemon defaults to false"
        );
        let output = cfg.output.expect("[output] present");
        assert_eq!(output.sink, "file");
        assert_eq!(
            output.path,
            Some(PathBuf::from("/var/log/ua/events.ndjson"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn control_only_config_yields_usable_control_section() {
        let dir = temp_dir("control-only");
        let path = dir.join("agent.toml");
        let toml = r#"
[control]
control_addr = "127.0.0.1:0"
tenant_id = "tenant-x"
trust_dir = "/t/trust"
agent_key_file = "/t/agent-1.key"
enabled = true
[[control.roles]]
actor = "operator"
role = "operator"
[control.cert]
ca_paths = ["/t/ca.pem"]
cert_chain = "/t/server.pem"
key = "/t/server.key"
"#;
        std::fs::write(&path, toml).unwrap();
        let cfg = load_config(&path).expect("control-only config loads");
        assert!(cfg.output.is_none(), "no [output] -> output is None");
        assert!(!cfg.agent.daemon, "no [agent] -> daemon defaults to false");
        let control = cfg.control.expect("[control] present");
        assert!(control.enabled, "enabled = true is read");
        assert_eq!(control.control_addr, "127.0.0.1:0");
        assert_eq!(control.roles.len(), 1);
        assert_eq!(control.cert.ca_paths, vec![PathBuf::from("/t/ca.pem")]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_config_yields_all_defaults() {
        let dir = temp_dir("empty");
        let path = dir.join("agent.toml");
        std::fs::write(&path, "").unwrap();
        let cfg = load_config(&path).expect("empty config parses to all-defaults");
        assert!(!cfg.agent.daemon, "default daemon is false");
        assert!(cfg.output.is_none(), "default output is None (stdout)");
        assert!(
            cfg.control.is_none(),
            "default control is None (no control)"
        );
        assert_eq!(
            cfg,
            AgentConfig::default(),
            "empty file == AgentConfig::default()"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_toml_is_invaliddata_not_panic() {
        let dir = temp_dir("malformed");
        let path = dir.join("bad.toml");
        // Not a valid TOML document (a bare `{` at the root is a syntax error).
        std::fs::write(&path, b"{ not valid toml ").unwrap();
        let err = load_config(&path).expect_err("malformed TOML -> Err, never a panic");
        assert_eq!(
            err.kind(),
            io::ErrorKind::InvalidData,
            "malformed TOML is InvalidData"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_file_is_rejected_before_read() {
        let dir = temp_dir("oversized");
        let path = dir.join("huge.toml");
        // One byte over the cap: rejected from its on-disk size BEFORE it is read in.
        let big = vec![b' '; (MAX_CONFIG_BYTES as usize) + 1];
        std::fs::write(&path, &big).unwrap();
        let err = load_config(&path).expect_err("oversized config -> Err");
        assert_eq!(
            err.kind(),
            io::ErrorKind::InvalidData,
            "oversized config is InvalidData"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_file_is_err_not_panic() {
        let dir = temp_dir("missing");
        let err = load_config(&dir.join("does-not-exist.toml")).expect_err("missing config -> Err");
        // Underlying I/O error surfaces (NotFound) — an Err, never a panic.
        assert_eq!(
            err.kind(),
            io::ErrorKind::NotFound,
            "missing config surfaces NotFound"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
