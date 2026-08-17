//! Golden vectors for the P3b-4 **bidirectional** signed control channel, with REAL
//! ed25519 end to end (no stubs, no clock, no rand, no network — seeded keys only).
//!
//! Each vector drives a full round trip across a *distinct key set per direction*:
//!   * the OPERATOR signs a `ControlCommand`; the agent's `AgentControlHandler`
//!     (whose verifier trusts operator keys, authz = a `RolePolicy`) processes it
//!     through the real `dispatch` gate and returns a `CommandResult` signed by the
//!     AGENT's own key;
//!   * a SEPARATE "server" `Ed25519Verifier` — trusting the AGENT's verifying key
//!     under the agent id — authenticates `result.signature` over `result.payload()`.
//!     This is the *return-leg* authentication: the issuer proves who reported the
//!     outcome and that a MITM did not flip it in transit.
//!
//! ## Telemetry separation (honest form)
//! This channel is deliberately independent of OCSF telemetry. That is a *type/manifest*
//! fact, asserted two ways below: (a) `torda-control-plane`'s manifest carries NO
//! `torda-ocsf`/ocsf dependency — this test file never imports `torda_ocsf` and it still
//! compiles + links, which it could not if the crate needed OCSF to move a command;
//! (b) a full command round trip constructs zero OCSF envelopes — there is no emitter
//! in this path at all; `CommandResult` is a standalone type with no OCSF field, and
//! the only sink a round trip touches is the remediation `AuditSink`.

use torda_control_plane::{
    AgentControlHandler, CommandOutcome, CommandResult, CommandSigner, Ed25519Verifier,
    ResultCorrelator,
};
use torda_remediation::action::{
    ActionState, AssetSelector, CanarySpec, Method, RemediationAction, VerifySpec,
};
use torda_remediation::audit::VecAuditSink;
use torda_remediation::bridge::Bridge;
use torda_remediation::control::{
    AllowAll, CommandKind, ControlCommand, Role, RolePolicy, SignatureVerifier,
};

// --- Deterministic key seeds (distinct per direction / per identity) ------------
const OPERATOR_SEED: [u8; 32] = [7u8; 32];
const AGENT_SEED: [u8; 32] = [42u8; 32];
const ATTACKER_SEED: [u8; 32] = [9u8; 32];
const OTHER_AGENT_SEED: [u8; 32] = [99u8; 32];

/// A benign `RemediationAction` (same shape as the existing suite's helper).
fn action(id: &str) -> RemediationAction {
    RemediationAction {
        id: id.into(),
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
    }
}

/// An unsigned control command for `kind` from `actor` targeting `action_id`.
fn command(action_id: &str, kind: CommandKind, actor: &str) -> ControlCommand {
    ControlCommand {
        action_id: action_id.into(),
        kind,
        actor: actor.into(),
        session: "s1".into(),
        seq: 1,
        schedule: None,
        signature: String::new(),
    }
}

fn operator_signer() -> CommandSigner {
    CommandSigner::from_seed("operator", OPERATOR_SEED)
}

fn agent_signer() -> CommandSigner {
    CommandSigner::from_seed("agent-1", AGENT_SEED)
}

/// An agent-side verifier that trusts `operator`'s key under its actor name (the
/// forward-leg trust: authenticating command issuers).
fn agent_verifier_trusting(operator: &CommandSigner) -> Ed25519Verifier {
    let mut v = Ed25519Verifier::new();
    v.trust(&operator.actor, operator.verifying_key());
    v
}

/// A server-side verifier that trusts `agent`'s key under its actor name (the
/// return-leg trust: authenticating the agent's acknowledgment).
fn server_verifier_trusting(agent: &CommandSigner) -> Ed25519Verifier {
    let mut v = Ed25519Verifier::new();
    v.trust(&agent.actor, agent.verifying_key());
    v
}

/// Vector 1 — the happy path. An authorized, authentically operator-signed Draft is
/// applied by the agent, and the AGENT-signed `Applied` result verifies under a
/// SEPARATE server verifier that trusts the agent key. Full bidirectional round trip.
#[test]
fn authorized_command_round_trips_to_applied_and_verifies() {
    let operator = operator_signer();
    let agent = agent_signer();
    let verifier = agent_verifier_trusting(&operator);
    let mut policy = RolePolicy::new();
    policy.assign("operator", Role::Operator); // Operator MAY Draft

    let mut cmd = command("a", CommandKind::Draft(Box::new(action("a"))), "operator");
    operator.sign(&mut cmd);

    let handler = AgentControlHandler::new(&verifier, &policy, &agent);
    let mut bridge = Bridge::new(VecAuditSink::default());
    let result = handler.handle(&mut bridge, cmd);

    assert_eq!(result.outcome, CommandOutcome::Applied);
    assert_eq!(result.detail, "applied");
    assert_eq!(result.action_id, "a");
    assert_eq!(result.agent, "agent-1");
    assert_eq!(
        bridge.state("a"),
        Some(ActionState::Drafted),
        "the gated draft was applied"
    );

    // Return leg: a distinct server verifier (agent key set) ACCEPTS the signature.
    let server = server_verifier_trusting(&agent);
    assert!(
        server.verify(&result.payload(), &result.signature, &result.agent),
        "the agent-signed Applied result authenticates under the server's return-leg trust",
    );
}

/// Vector 2 — a forged command still yields an AUTHENTIC rejection. The command is
/// signed by a key the agent's verifier does NOT trust, so dispatch rejects it; but
/// the agent signs the `Rejected` result with its own key, so the issuer can trust the
/// rejection is real. Assert BOTH: outcome is `Rejected` AND the server accepts the sig.
#[test]
fn forged_command_yields_authentic_rejected_result() {
    let operator = operator_signer();
    let attacker = CommandSigner::from_seed("operator", ATTACKER_SEED); // same claimed id, wrong key
    let agent = agent_signer();
    let verifier = agent_verifier_trusting(&operator); // trusts ONLY the real operator key

    let mut cmd = command("a", CommandKind::Draft(Box::new(action("a"))), "operator");
    attacker.sign(&mut cmd); // forged: signed by the untrusted key

    let handler = AgentControlHandler::new(&verifier, &AllowAll, &agent);
    let mut bridge = Bridge::new(VecAuditSink::default());
    let result = handler.handle(&mut bridge, cmd);

    assert_eq!(
        result.outcome,
        CommandOutcome::Rejected,
        "forged command is refused at the auth gate"
    );
    assert!(
        result.detail.contains("signature"),
        "rejection detail names the signature failure"
    );
    assert_eq!(
        bridge.state("a"),
        None,
        "the forged command never reached the bridge"
    );

    let server = server_verifier_trusting(&agent);
    assert!(
        server.verify(&result.payload(), &result.signature, &result.agent),
        "even a rejection is an authentic, agent-signed acknowledgment",
    );
}

/// Vector 3 — a validly-signed but UNAUTHORIZED command yields an authentic rejection.
/// The operator's signature is genuine, but the RolePolicy denies an Operator role the
/// `Approve` command (separation of duties). Rejected, and the result still verifies.
#[test]
fn unauthorized_actor_yields_rejected_result() {
    let operator = operator_signer();
    let agent = agent_signer();
    let verifier = agent_verifier_trusting(&operator);
    let mut policy = RolePolicy::new();
    policy.assign("operator", Role::Operator); // Operator MAY NOT Approve

    let mut cmd = command("a", CommandKind::Approve, "operator");
    operator.sign(&mut cmd); // authentic signature

    let handler = AgentControlHandler::new(&verifier, &policy, &agent);
    let mut bridge = Bridge::new(VecAuditSink::default());
    let result = handler.handle(&mut bridge, cmd);

    assert_eq!(
        result.outcome,
        CommandOutcome::Rejected,
        "authenticated but unauthorized"
    );
    assert!(
        result.detail.contains("not authorized"),
        "rejection detail names the authorization failure"
    );
    assert_eq!(
        bridge.state("a"),
        None,
        "unauthorized command never reached the bridge"
    );

    let server = server_verifier_trusting(&agent);
    assert!(
        server.verify(&result.payload(), &result.signature, &result.agent),
        "the authorization rejection is authentically agent-signed",
    );
}

/// Vector 4 — the P3b-4 anti-spoof core (and closes Task 1's deferred nit 3). Take a
/// GENUINE `Applied` result and tamper with it in transit WITHOUT re-signing. Because
/// the signature binds the canonical unsigned payload, the SEPARATE server verifier's
/// real ed25519 check must now REJECT the signature over the mutated payload. A MITM
/// cannot flip `Applied` -> `Rejected` nor rewrite `detail`. This is a GENUINE crypto
/// failure — we call the real `Ed25519Verifier::verify` and assert it returns false,
/// NOT an assertion on the `outcome` field.
#[test]
fn tampered_result_fails_server_verification() {
    let operator = operator_signer();
    let agent = agent_signer();
    let verifier = agent_verifier_trusting(&operator);
    let mut policy = RolePolicy::new();
    policy.assign("operator", Role::Operator);

    let mut cmd = command("a", CommandKind::Draft(Box::new(action("a"))), "operator");
    operator.sign(&mut cmd);

    let handler = AgentControlHandler::new(&verifier, &policy, &agent);
    let mut bridge = Bridge::new(VecAuditSink::default());
    let genuine = handler.handle(&mut bridge, cmd);
    assert_eq!(genuine.outcome, CommandOutcome::Applied);

    let server = server_verifier_trusting(&agent);
    // Sanity: the untouched genuine result verifies.
    assert!(server.verify(&genuine.payload(), &genuine.signature, &genuine.agent));

    // (a) FLIP the outcome Applied -> Rejected, keeping the ORIGINAL signature.
    let mut flipped = genuine.clone();
    flipped.outcome = CommandOutcome::Rejected;
    assert!(
        !server.verify(&flipped.payload(), &flipped.signature, &flipped.agent),
        "flipping the outcome without re-signing must fail real ed25519 verification",
    );

    // (b) MUTATE the detail text, keeping the ORIGINAL signature.
    let mut retexted = genuine.clone();
    retexted.detail = "rejected: attacker-supplied reason".into();
    assert!(
        !server.verify(&retexted.payload(), &retexted.signature, &retexted.agent),
        "rewriting the detail without re-signing must fail real ed25519 verification",
    );
}

/// Vector 5 — a result signed by an agent key the SERVER does not trust is rejected.
/// Two facets: (a) the result is signed by a DIFFERENT agent key than the server trusts
/// under that id; (b) a result that claims a different `agent` id has no trusted key at
/// all. Both fail the real verifier.
#[test]
fn result_signed_by_untrusted_agent_key_is_rejected() {
    let operator = operator_signer();
    let agent = agent_signer(); // "agent-1", the key the SERVER trusts
    let verifier = agent_verifier_trusting(&operator);
    let mut policy = RolePolicy::new();
    policy.assign("operator", Role::Operator);
    let server = server_verifier_trusting(&agent); // trusts ONLY agent-1's key

    // (a) A rogue agent shares the same actor NAME but a different key. Its genuine
    // self-signed result must not authenticate under the server's trust of agent-1.
    let rogue = CommandSigner::from_seed("agent-1", OTHER_AGENT_SEED);
    let mut cmd = command("a", CommandKind::Draft(Box::new(action("a"))), "operator");
    operator.sign(&mut cmd);
    let rogue_handler = AgentControlHandler::new(&verifier, &policy, &rogue);
    let mut bridge = Bridge::new(VecAuditSink::default());
    let rogue_result = rogue_handler.handle(&mut bridge, cmd);
    assert_eq!(
        rogue_result.outcome,
        CommandOutcome::Applied,
        "rogue agent produced a well-formed result"
    );
    assert!(
        !server.verify(
            &rogue_result.payload(),
            &rogue_result.signature,
            &rogue_result.agent
        ),
        "a result signed by an untrusted key under the same agent id fails verification",
    );

    // (b) A genuine agent-1 result whose `agent` id is rewritten to one the server
    // does not know: no trusted key -> fail-closed rejection.
    let mut cmd2 = command("a", CommandKind::Draft(Box::new(action("a"))), "operator");
    operator.sign(&mut cmd2);
    let good_handler = AgentControlHandler::new(&verifier, &policy, &agent);
    let mut bridge2 = Bridge::new(VecAuditSink::default());
    let mut result = good_handler.handle(&mut bridge2, cmd2);
    assert!(
        server.verify(&result.payload(), &result.signature, &result.agent),
        "genuine result verifies first"
    );
    result.agent = "unknown-agent".into();
    assert!(
        !server.verify(&result.payload(), &result.signature, &result.agent),
        "a result claiming an unknown agent id has no trusted key and fails verification",
    );
}

/// Telemetry separation. The control channel is a standalone type surface with no OCSF
/// coupling. This is asserted honestly at the type/manifest level:
///   * this file never imports `torda_ocsf` yet compiles + links, and `torda-control-plane`'s
///     `Cargo.toml` carries no `torda-ocsf`/ocsf dependency (its `[dependencies]` are
///     anyhow, ed25519-dalek, hex, serde, serde_json, torda-remediation — confirmed);
///   * a full command round trip constructs ZERO OCSF envelopes — there is no emitter
///     in this path. `CommandResult`'s entire field set is the acknowledgment
///     (action_id, outcome, detail, agent, signature); no telemetry rides along, and
///     the only sink the round trip touches is the remediation `AuditSink`.
#[test]
fn control_result_carries_no_telemetry_and_crate_has_no_ocsf_dep() {
    let operator = operator_signer();
    let agent = agent_signer();
    let verifier = agent_verifier_trusting(&operator);
    let mut policy = RolePolicy::new();
    policy.assign("operator", Role::Operator);

    let mut cmd = command("a", CommandKind::Draft(Box::new(action("a"))), "operator");
    operator.sign(&mut cmd);

    let handler = AgentControlHandler::new(&verifier, &policy, &agent);
    let mut bridge = Bridge::new(VecAuditSink::default());
    let result: CommandResult = handler.handle(&mut bridge, cmd);

    // The whole result serializes to exactly the acknowledgment fields — no telemetry.
    let json = serde_json::to_string(&result).expect("result serializes");
    for field in ["action_id", "outcome", "detail", "agent", "signature"] {
        assert!(
            json.contains(field),
            "result carries the acknowledgment field `{field}`"
        );
    }
    // No OCSF surface leaks into the control result (no class_uid / OCSF envelope keys).
    assert!(
        !json.contains("class_uid"),
        "the control result carries no OCSF telemetry"
    );
    assert!(
        !json.contains("ocsf"),
        "the control result carries no OCSF telemetry"
    );

    // The round trip's only observable effect is on the remediation audit sink.
    assert_eq!(result.outcome, CommandOutcome::Applied);
    assert_eq!(bridge.state("a"), Some(ActionState::Drafted));
}

// ===================================================================================
// P3b-5 issuer-side result correlation + replay rejection (`ResultCorrelator`).
// A result is accepted only if its (session, seq) is outstanding-and-unconsumed AND
// its signature verifies under the agent key; acceptance consumes it.
// ===================================================================================

/// Build a genuine, ed25519-signed `CommandResult` from `agent` on `(session, seq)`.
fn signed_result(
    agent: &CommandSigner,
    action_id: &str,
    outcome: CommandOutcome,
    detail: &str,
    session: &str,
    seq: u64,
) -> CommandResult {
    let mut r = CommandResult {
        action_id: action_id.into(),
        outcome,
        detail: detail.into(),
        agent: agent.actor.clone(),
        session: session.into(),
        seq,
        signature: String::new(),
    };
    r.signature = agent.sign_payload(&r.payload());
    r
}

/// Vector 5 — RESULT REPLAY. `issue(s, seq)`, then `accept` a genuine result once →
/// true; `accept` the SAME result again → false, because acceptance CONSUMED the
/// outstanding entry. A captured result cannot be replayed to double-acknowledge.
#[test]
fn result_replay_is_rejected_after_consumption() {
    let agent = agent_signer();
    let server = server_verifier_trusting(&agent);
    let mut corr = ResultCorrelator::new();
    corr.issue("s1", 7);

    let result = signed_result(&agent, "a", CommandOutcome::Applied, "applied", "s1", 7);
    assert!(
        corr.accept(&result, &server),
        "first genuine, outstanding, signed result is accepted"
    );
    assert!(
        !corr.accept(&result, &server),
        "the SAME result again is rejected — already consumed"
    );
}

/// Vector 6 — DROP-AND-SUBSTITUTE (the P3b-4 attack), the CORE vector.
///
/// Scenario: the issuer sends command seq=3; the agent returns `Applied`; the issuer
/// accepts + CONSUMES it. Later the issuer sends command seq=5; the agent returns
/// `Rejected`. A man-in-the-middle DROPS the seq=5 `Rejected` result and RE-INJECTS the
/// captured seq=3 `Applied` result, hoping the issuer records "applied" for the seq=5
/// command. The correlator must REFUSE the stale seq=3 `Applied`: seq=3 was already
/// consumed, and seq=5 remains outstanding-and-unanswered. The attacker cannot pass an
/// old genuine result off as the answer to a newer outstanding request.
#[test]
fn drop_and_substitute_stale_applied_is_refused_while_new_request_stays_outstanding() {
    let agent = agent_signer();
    let server = server_verifier_trusting(&agent);
    let mut corr = ResultCorrelator::new();

    // Round 1: issue seq=3; agent returns Applied; issuer accepts + consumes.
    corr.issue("sess", 3);
    let applied_seq3 = signed_result(&agent, "a", CommandOutcome::Applied, "applied", "sess", 3);
    assert!(
        corr.accept(&applied_seq3, &server),
        "seq=3 Applied accepted and consumed"
    );

    // Round 2: issue seq=5 (a DIFFERENT command); agent genuinely returns Rejected.
    corr.issue("sess", 5);
    let _rejected_seq5 = signed_result(
        &agent,
        "b",
        CommandOutcome::Rejected,
        "rejected: illegal transition",
        "sess",
        5,
    );

    // Attack: MITM DROPS the seq=5 Rejected and RE-INJECTS the captured seq=3 Applied
    // while seq=5 is still outstanding. THE CORE ASSERTION — the stale Applied is refused:
    assert!(
        !corr.accept(&applied_seq3, &server),
        "stale seq=3 Applied is REFUSED (seq=3 already consumed); it cannot answer the outstanding seq=5",
    );

    // seq=5 is still outstanding and unanswered: the GENUINE seq=5 Rejected still lands.
    assert!(
        corr.accept(&_rejected_seq5, &server),
        "the genuine seq=5 Rejected is still accepted — the drop-and-substitute did not consume it",
    );
}

/// Vector 7 — FORGED RESULT FOR AN OUTSTANDING REQUEST. A result carries the right
/// (session, seq) for an outstanding request but is signed by an UNTRUSTED key. `accept`
/// returns false AND — critically — does NOT consume the outstanding entry, so the
/// genuine result can still arrive and be accepted afterwards.
#[test]
fn forged_result_is_refused_without_consuming_the_outstanding_request() {
    let agent = agent_signer(); // the key the server trusts under "agent-1"
    let forger = CommandSigner::from_seed("agent-1", ATTACKER_SEED); // same id, untrusted key
    let server = server_verifier_trusting(&agent);
    let mut corr = ResultCorrelator::new();
    corr.issue("s1", 4);

    // Forged: right (session, seq), agent id "agent-1", but signed by the untrusted key.
    let forged = signed_result(&forger, "a", CommandOutcome::Applied, "applied", "s1", 4);
    assert!(
        !corr.accept(&forged, &server),
        "a forged result for an outstanding request is refused"
    );

    // The request was NOT consumed: the genuine agent result still arrives and is accepted.
    let genuine = signed_result(&agent, "a", CommandOutcome::Applied, "applied", "s1", 4);
    assert!(
        corr.accept(&genuine, &server),
        "the forged attempt left the request outstanding, so the genuine result is still accepted",
    );
    // ...and now it is consumed (replay of the genuine result also fails).
    assert!(
        !corr.accept(&genuine, &server),
        "genuine result is consumed on acceptance"
    );
}
