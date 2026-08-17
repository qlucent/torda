//! The control model: a `Control` (check + metadata), the `ControlResult` it
//! yields, an injectable `Snapshot` of table→rows, and the `evaluate` driver.
use serde::Serialize;
use std::collections::HashMap;

/// A deterministic compliance check over one snapshot table, plus the metadata a
/// finding needs later. `check` returns `true` when the asset is COMPLIANT
/// (passes). `weight` (0..1) is the canonical severity input used by scoring in
/// slice 2a-2 — a framework's own stock severity is never used.
#[derive(Clone)]
pub struct Control {
    pub id: String,
    pub title: String,
    pub table: String,
    pub subject: String,
    pub location: String,
    pub weight: f32,
    pub remediation_key: String,
    pub check: fn(&[serde_json::Value]) -> bool,
}

/// The outcome of evaluating one `Control` against a snapshot.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ControlResult {
    pub control_id: String,
    pub passed: bool,
    pub weight: f32,
    pub subject: String,
    pub location: String,
    pub remediation_key: String,
}

/// A point-in-time view of the snapshot tables the controls read. In the agent
/// this is backed by the `SnapshotProvider` (wired in slice 2a-2); here it is an
/// injectable map so the control library stays pure and fixture-testable.
#[derive(Default)]
pub struct Snapshot(pub HashMap<String, Vec<serde_json::Value>>);

impl Snapshot {
    pub fn table(&self, name: &str) -> Option<&[serde_json::Value]> {
        self.0.get(name).map(|v| v.as_slice())
    }
}

/// Evaluates all controls against a snapshot. A control whose table is absent is
/// SKIPPED (an unassessable control is neither compliant nor a finding).
pub fn evaluate(controls: &[Control], snapshot: &Snapshot) -> Vec<ControlResult> {
    controls
        .iter()
        .filter_map(|c| {
            let rows = snapshot.table(&c.table)?;
            Some(ControlResult {
                control_id: c.id.clone(),
                passed: (c.check)(rows),
                weight: c.weight,
                subject: c.subject.clone(),
                location: c.location.clone(),
                remediation_key: c.remediation_key.clone(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn always_pass(_rows: &[serde_json::Value]) -> bool {
        true
    }
    fn nonempty(rows: &[serde_json::Value]) -> bool {
        !rows.is_empty()
    }

    fn ctrl(id: &str, table: &str, check: fn(&[serde_json::Value]) -> bool) -> Control {
        Control {
            id: id.into(),
            title: "t".into(),
            table: table.into(),
            subject: "subj".into(),
            location: "loc".into(),
            weight: 0.5,
            remediation_key: "fix".into(),
            check,
        }
    }

    fn snapshot(entries: &[(&str, serde_json::Value)]) -> Snapshot {
        let mut m = HashMap::new();
        for (k, v) in entries {
            m.insert(k.to_string(), v.as_array().cloned().unwrap_or_default());
        }
        Snapshot(m)
    }

    #[test]
    fn snapshot_table_hit_and_miss() {
        let s = snapshot(&[("packages", serde_json::json!([{"name":"openssl"}]))]);
        assert_eq!(s.table("packages").unwrap().len(), 1);
        assert!(s.table("missing").is_none());
    }

    #[test]
    fn evaluate_runs_check_and_carries_metadata() {
        let controls = vec![ctrl("c-nonempty", "packages", nonempty)];
        let s = snapshot(&[("packages", serde_json::json!([{"name":"x"}]))]);
        let out = evaluate(&controls, &s);
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0],
            ControlResult {
                control_id: "c-nonempty".into(),
                passed: true,
                weight: 0.5,
                subject: "subj".into(),
                location: "loc".into(),
                remediation_key: "fix".into(),
            }
        );
    }

    #[test]
    fn evaluate_marks_failing_check() {
        let controls = vec![ctrl("c", "packages", nonempty)];
        let s = snapshot(&[("packages", serde_json::json!([]))]);
        assert!(
            !evaluate(&controls, &s)[0].passed,
            "empty table -> nonempty check fails"
        );
    }

    #[test]
    fn evaluate_skips_control_when_table_absent() {
        let controls = vec![ctrl("c", "sshd_config", always_pass)];
        let s = snapshot(&[("packages", serde_json::json!([]))]);
        assert!(
            evaluate(&controls, &s).is_empty(),
            "absent table -> control skipped, not emitted"
        );
    }
}
