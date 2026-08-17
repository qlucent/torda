//! Compliance/posture control library. A `Control` is a deterministic check over
//! one snapshot table; a `FrameworkProfile` maps framework control ids to check
//! ids (the crosswalk). Checks are separate from frameworks — one check can
//! satisfy many framework controls. Pure: no OCSF, no engine, no OS access here.
//!
//! Snapshot row contract: each table's rows are flat JSON objects with
//! string-or-number scalar fields (checks read `key`/`value`/`name`). A table
//! that is PRESENT is the complete effective state for its domain — checks treat
//! a missing directive in a present table as non-compliant, so the substrate
//! must emit whole tables, not partial/delta ones. An ABSENT table means the
//! control is skipped (unassessable), not failed.
pub mod control;
pub mod controls;
pub mod drift;
pub mod fim;
pub mod framework;
pub mod policy;
pub mod record;
