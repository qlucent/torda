//! The audit trail. Every state transition the bridge attempts — accepted OR
//! rejected — is recorded here with the actor, the from/to states, the outcome,
//! and a human-readable detail. A blocked action is as auditable as an applied one.
use serde::{Deserialize, Serialize};

use crate::action::ActionState;

/// Whether an attempted transition was applied or rejected by a gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    Ok,
    Rejected,
    Failed,
}

/// One audited transition attempt. `from` is `None` for the initial draft.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub seq: u64,
    pub action_id: String,
    pub from: Option<ActionState>,
    pub to: ActionState,
    pub actor: String,
    pub outcome: Outcome,
    pub detail: String,
}

/// The audit destination. P3b swaps `VecAuditSink` for the durable, control-plane
/// audit store without touching the bridge.
pub trait AuditSink {
    fn record(&mut self, event: AuditEvent);
}

/// In-memory audit sink (default P3a-1 store + test fake).
#[derive(Default)]
pub struct VecAuditSink {
    pub events: Vec<AuditEvent>,
}

impl AuditSink for VecAuditSink {
    fn record(&mut self, event: AuditEvent) {
        self.events.push(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vec_sink_records_in_order() {
        let mut sink = VecAuditSink::default();
        sink.record(AuditEvent {
            seq: 0,
            action_id: "a".into(),
            from: None,
            to: ActionState::Drafted,
            actor: "user".into(),
            outcome: Outcome::Ok,
            detail: "drafted".into(),
        });
        sink.record(AuditEvent {
            seq: 1,
            action_id: "a".into(),
            from: Some(ActionState::PendingApproval),
            to: ActionState::Approved,
            actor: "approver".into(),
            outcome: Outcome::Rejected,
            detail: "not in dry-run".into(),
        });
        assert_eq!(sink.events.len(), 2);
        assert_eq!(sink.events[0].outcome, Outcome::Ok);
        assert_eq!(sink.events[1].outcome, Outcome::Rejected);
        assert_eq!(sink.events[1].actor, "approver");
    }

    #[test]
    fn audit_event_round_trips() {
        let ev = AuditEvent {
            seq: 3,
            action_id: "a".into(),
            from: Some(ActionState::DryRun),
            to: ActionState::PendingApproval,
            actor: "user".into(),
            outcome: Outcome::Ok,
            detail: "submitted".into(),
        };
        let back: AuditEvent = serde_json::from_str(&serde_json::to_string(&ev).unwrap()).unwrap();
        assert_eq!(back, ev);
    }
}
