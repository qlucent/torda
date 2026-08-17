//! Remediation Bridge — a secure, audited execution channel for the USER'S OWN
//! remediation methods, plus verification. It never decides what to fix and never
//! auto-applies anything the user did not author and trigger. The safety machinery
//! (scope, dry-run, approval, canary, rollback, kill switch, audit) IS the module.
//!
//! This crate is the deterministic core: the action model and the pre-execution
//! state machine with its gates. Execution, canary/rollout, verification, and the
//! signed control channel land in later P3a slices behind the `Executor` and
//! control-message seams.
pub mod action;
pub mod audit;
pub mod bridge;
pub mod control;
pub mod scheduler;
