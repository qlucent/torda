//! Golden vectors for the P3b-5 issuer-side result correlation + replay rejection
//! (`ResultCorrelator`), with REAL ed25519 end to end (seeded keys only — no stubs, no clock,
//! no rand, no network). A result is accepted only if its (session, seq) is
//! outstanding-and-unconsumed AND its signature verifies under the agent key; acceptance
//! consumes it.
//!
//! These moved from `torda-control-plane`'s `result_vectors.rs` together with
//! `ResultCorrelator` when the FSL issuer surface was carved into `torda-control-server`. The
//! agent-side result *signing* (`CommandSigner`) and *verification* (`Ed25519Verifier`) they
//! exercise stay in the Apache `torda-control-plane` crate.

use torda_control_plane::{CommandOutcome, CommandResult, CommandSigner, Ed25519Verifier};
use torda_control_server::ResultCorrelator;

// --- Deterministic key seeds (distinct per identity) ------------------------------
const AGENT_SEED: [u8; 32] = [42u8; 32];
const ATTACKER_SEED: [u8; 32] = [9u8; 32];

fn agent_signer() -> CommandSigner {
    CommandSigner::from_seed("agent-1", AGENT_SEED)
}

/// A server-side verifier that trusts `agent`'s key under its actor name (the return-leg
/// trust: authenticating the agent's acknowledgment).
fn server_verifier_trusting(agent: &CommandSigner) -> Ed25519Verifier {
    let mut v = Ed25519Verifier::new();
    v.trust(&agent.actor, agent.verifying_key());
    v
}

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
