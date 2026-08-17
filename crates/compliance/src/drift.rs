//! Config drift: compares the live substrate snapshot against a declarative,
//! org-customizable baseline of expected configuration, reporting each deviation
//! with its expected and observed (actual) value so the drift is explainable.
//! Pure — reads an injected snapshot, never the OS. Scored server-side from the
//! baseline weight (the compliance path), never from any source severity.
use serde::{Deserialize, Serialize};

use crate::control::Snapshot;

/// What a baseline entry expects of the selected config row.
#[derive(Clone, Debug, PartialEq)]
pub enum Expectation {
    /// The selected row's `value_field` must equal `expected`; drift if it
    /// differs OR the row is missing.
    ValueEquals {
        value_field: String,
        expected: String,
    },
    /// No row may match the selector; drift if one is present.
    Absent,
}

/// One declarative, org-customizable baseline rule: identify a row in `table`
/// where `selector_field == selector_value`, then assert `expectation` on it.
#[derive(Clone, Debug, PartialEq)]
pub struct BaselineEntry {
    pub id: String,
    pub table: String,
    pub selector_field: String,
    pub selector_value: String,
    pub subject: String,
    pub location: String,
    pub weight: f32,
    pub expectation: Expectation,
    pub remediation_key: String,
}

/// The outcome of one baseline entry against the snapshot: whether it drifted,
/// plus the expected and observed (actual) values for explainability.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DriftResult {
    pub entry_id: String,
    pub drifted: bool,
    pub subject: String,
    pub location: String,
    pub weight: f32,
    pub expected: String,
    pub actual: Option<String>,
    pub remediation_key: String,
}

/// Compares each baseline entry against the snapshot. An entry whose table is
/// absent from the snapshot is SKIPPED (unassessable), not reported as drift.
pub fn detect_drift(baseline: &[BaselineEntry], snapshot: &Snapshot) -> Vec<DriftResult> {
    baseline
        .iter()
        .filter_map(|e| {
            let rows = snapshot.table(&e.table)?; // absent table -> skip
            let matched = rows.iter().find(|r| {
                r.get(e.selector_field.as_str()).and_then(|v| v.as_str())
                    == Some(e.selector_value.as_str())
            });
            let (drifted, expected, actual) = match &e.expectation {
                Expectation::ValueEquals {
                    value_field,
                    expected,
                } => {
                    let actual = matched
                        .and_then(|r| r.get(value_field.as_str()))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let drifted = actual.as_deref() != Some(expected.as_str());
                    (drifted, expected.clone(), actual)
                }
                Expectation::Absent => {
                    let present = matched.is_some();
                    let actual = present.then(|| "present".to_string());
                    (present, "absent".to_string(), actual)
                }
            };
            Some(DriftResult {
                entry_id: e.id.clone(),
                drifted,
                subject: e.subject.clone(),
                location: e.location.clone(),
                weight: e.weight,
                expected,
                actual,
                remediation_key: e.remediation_key.clone(),
            })
        })
        .collect()
}

/// The wire shape for one drift outcome — a `DriftResult` made serde-round-trippable
/// so the agent emits it and the server ingest parses it back. Carries `expected`
/// and `actual` so the finding is explainable; the score is recomputed server-side
/// from `weight`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DriftRecord {
    pub entry_id: String,
    pub drifted: bool,
    pub subject: String,
    pub location: String,
    pub weight: f32,
    pub expected: String,
    pub actual: Option<String>,
    pub remediation_key: String,
}

/// Maps drift results to wire records 1:1.
pub fn to_drift_records(results: &[DriftResult]) -> Vec<DriftRecord> {
    results
        .iter()
        .map(|r| DriftRecord {
            entry_id: r.entry_id.clone(),
            drifted: r.drifted,
            subject: r.subject.clone(),
            location: r.location.clone(),
            weight: r.weight,
            expected: r.expected.clone(),
            actual: r.actual.clone(),
            remediation_key: r.remediation_key.clone(),
        })
        .collect()
}

/// Example baseline shipped with the agent. Real deployments replace this with an
/// org-specific set. Every entry targets the `packages` table, which the v0
/// substrate serves, so drift is assessable on a live host today.
pub fn builtin_baseline() -> Vec<BaselineEntry> {
    vec![
        BaselineEntry {
            id: "openssl-pinned".into(),
            table: "packages".into(),
            selector_field: "name".into(),
            selector_value: "openssl".into(),
            subject: "openssl".into(),
            location: "packages".into(),
            weight: 0.7,
            expectation: Expectation::ValueEquals {
                value_field: "version".into(),
                expected: "3.0.14".into(),
            },
            remediation_key: "upgrade:openssl=3.0.14".into(),
        },
        BaselineEntry {
            id: "telnet-absent".into(),
            table: "packages".into(),
            selector_field: "name".into(),
            selector_value: "telnet".into(),
            subject: "telnet".into(),
            location: "packages".into(),
            weight: 0.6,
            expectation: Expectation::Absent,
            remediation_key: "remove:telnet".into(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn pkg_snapshot(rows: Vec<serde_json::Value>) -> Snapshot {
        let mut m = HashMap::new();
        m.insert("packages".to_string(), rows);
        Snapshot(m)
    }

    fn openssl_pinned() -> BaselineEntry {
        BaselineEntry {
            id: "openssl-pinned".into(),
            table: "packages".into(),
            selector_field: "name".into(),
            selector_value: "openssl".into(),
            subject: "openssl".into(),
            location: "packages".into(),
            weight: 0.7,
            expectation: Expectation::ValueEquals {
                value_field: "version".into(),
                expected: "3.0.14".into(),
            },
            remediation_key: "upgrade:openssl=3.0.14".into(),
        }
    }

    fn telnet_absent() -> BaselineEntry {
        BaselineEntry {
            id: "telnet-absent".into(),
            table: "packages".into(),
            selector_field: "name".into(),
            selector_value: "telnet".into(),
            subject: "telnet".into(),
            location: "packages".into(),
            weight: 0.6,
            expectation: Expectation::Absent,
            remediation_key: "remove:telnet".into(),
        }
    }

    #[test]
    fn value_equals_drifts_when_actual_differs() {
        let snap = pkg_snapshot(vec![
            serde_json::json!({"name":"openssl","version":"3.0.2","source":"dpkg"}),
        ]);
        let r = detect_drift(&[openssl_pinned()], &snap);
        assert_eq!(r.len(), 1);
        assert!(r[0].drifted);
        assert_eq!(r[0].expected, "3.0.14");
        assert_eq!(r[0].actual.as_deref(), Some("3.0.2"));
        assert_eq!(r[0].entry_id, "openssl-pinned");
        assert_eq!(r[0].weight, 0.7);
    }

    #[test]
    fn value_equals_in_spec_does_not_drift() {
        let snap = pkg_snapshot(vec![
            serde_json::json!({"name":"openssl","version":"3.0.14","source":"dpkg"}),
        ]);
        let r = detect_drift(&[openssl_pinned()], &snap);
        assert!(!r[0].drifted);
        assert_eq!(r[0].actual.as_deref(), Some("3.0.14"));
    }

    #[test]
    fn value_equals_missing_row_drifts_with_no_actual() {
        let snap = pkg_snapshot(vec![]);
        let r = detect_drift(&[openssl_pinned()], &snap);
        assert!(r[0].drifted, "expected value absent entirely -> drift");
        assert_eq!(r[0].actual, None);
    }

    #[test]
    fn absent_drifts_when_present() {
        let snap = pkg_snapshot(vec![
            serde_json::json!({"name":"telnet","version":"0.17","source":"dpkg"}),
        ]);
        let r = detect_drift(&[telnet_absent()], &snap);
        assert!(r[0].drifted);
        assert_eq!(r[0].expected, "absent");
        assert_eq!(r[0].actual.as_deref(), Some("present"));
    }

    #[test]
    fn absent_in_spec_does_not_drift() {
        let snap = pkg_snapshot(vec![]);
        let r = detect_drift(&[telnet_absent()], &snap);
        assert!(!r[0].drifted);
        assert_eq!(r[0].actual, None);
    }

    #[test]
    fn absent_table_is_skipped_not_drifted() {
        let snap = Snapshot(HashMap::new()); // no "packages" table
        let r = detect_drift(&[openssl_pinned(), telnet_absent()], &snap);
        assert!(
            r.is_empty(),
            "entries whose table is absent are skipped, not reported"
        );
    }

    #[test]
    fn builtin_baseline_targets_packages_table() {
        let b = builtin_baseline();
        assert_eq!(b.len(), 2);
        let openssl = b.iter().find(|e| e.id == "openssl-pinned").unwrap();
        assert_eq!(openssl.table, "packages");
        assert_eq!(openssl.weight, 0.7);
        assert_eq!(
            openssl.expectation,
            Expectation::ValueEquals {
                value_field: "version".into(),
                expected: "3.0.14".into()
            }
        );
        let telnet = b.iter().find(|e| e.id == "telnet-absent").unwrap();
        assert_eq!(telnet.expectation, Expectation::Absent);
        assert_eq!(telnet.weight, 0.6);
        // Every builtin entry targets a table the v0 substrate actually serves.
        assert!(b.iter().all(|e| e.table == "packages"));
    }

    #[test]
    fn to_drift_records_maps_one_to_one() {
        let snap = pkg_snapshot(vec![
            serde_json::json!({"name":"openssl","version":"3.0.2","source":"dpkg"}),
        ]);
        let results = detect_drift(&builtin_baseline(), &snap);
        let records = to_drift_records(&results);
        assert_eq!(records.len(), results.len());
        let openssl = records
            .iter()
            .find(|r| r.entry_id == "openssl-pinned")
            .unwrap();
        assert!(openssl.drifted);
        assert_eq!(openssl.expected, "3.0.14");
        assert_eq!(openssl.actual.as_deref(), Some("3.0.2"));
        assert_eq!(openssl.remediation_key, "upgrade:openssl=3.0.14");
    }

    #[test]
    fn drift_record_round_trips() {
        let rec = DriftRecord {
            entry_id: "e".into(),
            drifted: true,
            subject: "s".into(),
            location: "l".into(),
            weight: 0.7,
            expected: "x".into(),
            actual: Some("y".into()),
            remediation_key: "fix".into(),
        };
        let back: DriftRecord =
            serde_json::from_str(&serde_json::to_string(&rec).unwrap()).unwrap();
        assert_eq!(back, rec);
    }
}
