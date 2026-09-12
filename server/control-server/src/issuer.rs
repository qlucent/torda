//! Operator-side control-channel driver and result correlation.
//!
//! These are the ISSUER halves of the P3b control channel — the pieces an operator /
//! orchestrator uses to drive an agent. They complement the Apache agent-side types in
//! `torda-control-plane` (the [`AgentControlLoop`](torda_control_plane::AgentControlLoop),
//! handler, signer, verifier, and wire [`ControlFrame`](torda_control_plane::ControlFrame)),
//! which the shipped agent links; this issuer surface is FSL (see `LICENSING.md`).

use std::collections::HashSet;

use torda_control_plane::{CommandResult, CommandSigner, ControlFrame, Ed25519Verifier};
// `SignatureVerifier` is the trait that provides `Ed25519Verifier::verify`; it must be in
// scope for the correlator's return-leg signature check.
use torda_remediation::control::{ControlCommand, SignatureVerifier};
use torda_transport::Transport;

/// Issuer-side correlation + replay rejection for agent results. The issuer records each
/// (session, seq) it issued as outstanding; a result is accepted only if its (session, seq)
/// is outstanding-and-unconsumed AND its signature verifies under the agent key; acceptance
/// consumes it (a second identical result is rejected). This defeats result-replay and the
/// drop-and-substitute attack: a captured older result whose (session, seq) was already
/// consumed can never be re-accepted, and a still-outstanding request stays unanswered until
/// its OWN genuine result arrives.
#[derive(Default)]
pub struct ResultCorrelator {
    outstanding: HashSet<(String, u64)>,
}

impl ResultCorrelator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a command the issuer just sent as awaiting a result.
    pub fn issue(&mut self, session: &str, seq: u64) {
        self.outstanding.insert((session.into(), seq));
    }

    /// Accept `result` iff BOTH hold: (1) its (session, seq) is outstanding — i.e. issued and
    /// not yet consumed — AND (2) its signature verifies under the agent key. Acceptance
    /// CONSUMES the outstanding entry (a second identical result is then rejected). A forged
    /// result for an otherwise-outstanding (session, seq) is rejected WITHOUT consuming the
    /// entry, so the genuine result can still arrive. Order: outstanding is checked FIRST
    /// (cheap set lookup) then the signature, but both conditions must hold for acceptance and
    /// the entry is removed ONLY when both pass — a signature failure leaves the request
    /// outstanding.
    pub fn accept(&mut self, result: &CommandResult, verifier: &Ed25519Verifier) -> bool {
        let key = (result.session.clone(), result.seq);
        if !self.outstanding.contains(&key) {
            return false; // not outstanding / already consumed / stale
        }
        if !verifier.verify(&result.payload(), &result.signature, &result.agent) {
            return false; // forged/tampered — do NOT consume; genuine result may still come
        }
        self.outstanding.remove(&key); // consume
        true
    }
}

/// The operator-side control channel driver. It issues signed commands over a [`Transport`]
/// and accepts agent results ONLY through a [`ResultCorrelator`], so a forged, stale, or
/// replayed result can never be treated as a genuine acknowledgment. It owns the issuer's
/// [`CommandSigner`], the correlator, and a server-side [`Ed25519Verifier`] that trusts the
/// agent's key (used to authenticate results).
pub struct ControlPlaneClient {
    signer: CommandSigner,
    corr: ResultCorrelator,
    verifier: Ed25519Verifier,
}

impl ControlPlaneClient {
    /// Build a client from the issuer's `signer` and a `verifier` trusting the agent's key
    /// (under the agent's actor name), with a fresh correlator.
    pub fn new(signer: CommandSigner, verifier: Ed25519Verifier) -> Self {
        Self {
            signer,
            corr: ResultCorrelator::new(),
            verifier,
        }
    }

    /// Sign `cmd` in place with the issuer's key. Convenience for callers building a command to
    /// send; the wire path itself never signs — a command is authenticated by whatever signature
    /// it already carries when it reaches [`send_command`](Self::send_command).
    pub fn sign(&self, cmd: &mut ControlCommand) {
        self.signer.sign(cmd);
    }

    /// Record `cmd`'s `(session, seq)` as outstanding in the correlator, then send it as a
    /// `ControlFrame::Command`. Registering BEFORE sending is what lets
    /// [`await_result`](Self::await_result) later recognize the genuine reply; a result whose
    /// `(session, seq)` was never issued (or was already consumed) is refused.
    pub fn send_command<T: Transport>(
        &mut self,
        transport: &mut T,
        cmd: ControlCommand,
    ) -> std::io::Result<()> {
        self.corr.issue(&cmd.session, cmd.seq);
        let out = serde_json::to_vec(&ControlFrame::Command(cmd)).map_err(std::io::Error::other)?;
        transport.send(&out)
    }

    /// Receive AT MOST ONE frame and return a genuine agent result, or `None`.
    ///
    /// Returns `Ok(Some(result))` ONLY when the frame is a `ControlFrame::Result` that the
    /// [`ResultCorrelator`] accepts — i.e. its `(session, seq)` is outstanding AND its signature
    /// verifies under the trusted agent key; acceptance consumes the outstanding entry, so a
    /// replayed copy of that same result is refused on a later call. Returns `Ok(None)` for
    /// every other case — `recv` yielded nothing, a wrong-direction `Command` frame arrived at
    /// the operator, the correlator rejected the result (forged / stale / already-consumed), or
    /// the bytes were malformed. Never panics on hostile bytes.
    pub fn await_result<T: Transport>(
        &mut self,
        transport: &mut T,
    ) -> std::io::Result<Option<CommandResult>> {
        let Some(bytes) = transport.recv()? else {
            return Ok(None);
        };
        let frame: ControlFrame = match serde_json::from_slice(&bytes) {
            Ok(f) => f,
            Err(_) => return Ok(None), // malformed / hostile: ignored, no panic
        };
        match frame {
            ControlFrame::Result(r) if self.corr.accept(&r, &self.verifier) => Ok(Some(r)),
            // Wrong-direction Command, or a result the correlator refuses (forged / stale /
            // replayed): not a genuine acknowledgment.
            _ => Ok(None),
        }
    }
}

/// Derive a deterministic control-session id for `(peer, nonce)`.
///
/// STUB — deliberately deterministic and network-free. The real handshake binds the session id
/// to the mTLS peer certificate and a per-connection nonce so a session cannot be spoofed or
/// reused across connections (see [`crate::connect`] /
/// [`torda_transport_tls::session_from_cert`]). This gives tests and the in-memory transport a
/// stable, reproducible session id with no clock, randomness, or network involved.
pub fn establish_session(peer: &str, nonce: u64) -> String {
    format!("sess-{peer}-{nonce}")
}
