//! File Integrity Monitoring: compares the substrate `files` table against a
//! declarative, org-customizable watchlist of expected file hashes, reporting each
//! violation (content changed, or file deleted/missing) with expected vs actual
//! digest for explainability. Pure — reads an injected snapshot, never a file.
//! Scored server-side from the watch weight (the shared posture path).
use serde::{Deserialize, Serialize};

use crate::control::Snapshot;

/// One declarative, org-customizable file-integrity rule: the file at `path`
/// must hash to `expected_sha256`.
#[derive(Clone, Debug, PartialEq)]
pub struct WatchEntry {
    pub id: String,
    pub path: String,
    pub expected_sha256: String,
    pub weight: f32,
    pub remediation_key: String,
}

/// The outcome of one watch entry against the `files` snapshot: whether integrity
/// was violated, plus the expected and observed digest for explainability.
/// `actual_sha256` is `Some(digest)` when present, `Some("<deleted>")` when the
/// file is tracked-but-deleted, and `None` when the watched path was not collected.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct IntegrityResult {
    pub entry_id: String,
    pub violated: bool,
    pub path: String,
    pub weight: f32,
    pub expected_sha256: String,
    pub actual_sha256: Option<String>,
    pub remediation_key: String,
}

const DELETED: &str = "<deleted>";

/// Compares each watch entry against the `files` table. If the table is ABSENT
/// (FIM not collected) every entry is SKIPPED. A watched path missing from a
/// present table, a deleted file, or a digest mismatch are all violations.
pub fn check_integrity(watchlist: &[WatchEntry], snapshot: &Snapshot) -> Vec<IntegrityResult> {
    watchlist
        .iter()
        .filter_map(|w| {
            let rows = snapshot.table("files")?; // absent table -> skip entry
            let matched = rows
                .iter()
                .find(|r| r.get("path").and_then(|v| v.as_str()) == Some(w.path.as_str()));
            let (violated, actual) = match matched {
                None => (true, None), // watched path not collected -> missing
                Some(r) => {
                    // A row missing `exists` is treated as present (forward-compat);
                    // the substrate always emits it today.
                    let exists = r.get("exists").and_then(|v| v.as_bool()).unwrap_or(true);
                    if !exists {
                        (true, Some(DELETED.to_string()))
                    } else {
                        let actual = r
                            .get("sha256")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        let violated = actual.as_deref() != Some(w.expected_sha256.as_str());
                        (violated, actual)
                    }
                }
            };
            Some(IntegrityResult {
                entry_id: w.id.clone(),
                violated,
                path: w.path.clone(),
                weight: w.weight,
                expected_sha256: w.expected_sha256.clone(),
                actual_sha256: actual,
                remediation_key: w.remediation_key.clone(),
            })
        })
        .collect()
}

/// The wire shape for one integrity outcome — an `IntegrityResult` made
/// serde-round-trippable so the agent emits it and the server ingest parses it
/// back. Carries expected/actual digests; the score is recomputed from `weight`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FimRecord {
    pub entry_id: String,
    pub violated: bool,
    pub path: String,
    pub weight: f32,
    pub expected_sha256: String,
    pub actual_sha256: Option<String>,
    pub remediation_key: String,
}

/// Maps integrity results to wire records 1:1.
pub fn to_fim_records(results: &[IntegrityResult]) -> Vec<FimRecord> {
    results
        .iter()
        .map(|r| FimRecord {
            entry_id: r.entry_id.clone(),
            violated: r.violated,
            path: r.path.clone(),
            weight: r.weight,
            expected_sha256: r.expected_sha256.clone(),
            actual_sha256: r.actual_sha256.clone(),
            remediation_key: r.remediation_key.clone(),
        })
        .collect()
}

/// Example watchlist shipped with the agent. Real deployments replace this with an
/// org-specific set (with baselines captured from their known-good hosts). The
/// `sshd_config` expected digest matches the substrate stub fixture (intact); the
/// `passwd` digest differs from the stub (violation), so FIM is demonstrable.
pub fn builtin_watchlist() -> Vec<WatchEntry> {
    vec![
        WatchEntry {
            id: "fim-sshd-config".into(),
            path: "/etc/ssh/sshd_config".into(),
            expected_sha256: "1111111111111111111111111111111111111111111111111111111111111111"
                .into(),
            weight: 0.8,
            remediation_key: "restore:/etc/ssh/sshd_config".into(),
        },
        WatchEntry {
            id: "fim-passwd".into(),
            path: "/etc/passwd".into(),
            expected_sha256: "2222222222222222222222222222222222222222222222222222222222222222"
                .into(),
            weight: 0.9,
            remediation_key: "investigate:/etc/passwd".into(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn files_snapshot(rows: Vec<serde_json::Value>) -> Snapshot {
        let mut m = HashMap::new();
        m.insert("files".to_string(), rows);
        Snapshot(m)
    }

    fn passwd_watch() -> WatchEntry {
        WatchEntry {
            id: "fim-passwd".into(),
            path: "/etc/passwd".into(),
            expected_sha256: "2222222222222222222222222222222222222222222222222222222222222222"
                .into(),
            weight: 0.9,
            remediation_key: "investigate:/etc/passwd".into(),
        }
    }

    #[test]
    fn violates_when_hash_differs() {
        let snap = files_snapshot(vec![serde_json::json!({
            "path":"/etc/passwd","sha256":"9999999999999999999999999999999999999999999999999999999999999999","exists":true
        })]);
        let r = check_integrity(&[passwd_watch()], &snap);
        assert_eq!(r.len(), 1);
        assert!(r[0].violated);
        assert_eq!(
            r[0].expected_sha256,
            "2222222222222222222222222222222222222222222222222222222222222222"
        );
        assert_eq!(
            r[0].actual_sha256.as_deref(),
            Some("9999999999999999999999999999999999999999999999999999999999999999")
        );
        assert_eq!(r[0].entry_id, "fim-passwd");
        assert_eq!(r[0].weight, 0.9);
    }

    #[test]
    fn intact_when_hash_matches() {
        let snap = files_snapshot(vec![serde_json::json!({
            "path":"/etc/passwd","sha256":"2222222222222222222222222222222222222222222222222222222222222222","exists":true
        })]);
        let r = check_integrity(&[passwd_watch()], &snap);
        assert!(!r[0].violated);
        assert_eq!(
            r[0].actual_sha256.as_deref(),
            Some("2222222222222222222222222222222222222222222222222222222222222222")
        );
    }

    #[test]
    fn violates_when_file_deleted() {
        let snap = files_snapshot(vec![serde_json::json!({
            "path":"/etc/passwd","sha256":"","exists":false
        })]);
        let r = check_integrity(&[passwd_watch()], &snap);
        assert!(r[0].violated);
        assert_eq!(r[0].actual_sha256.as_deref(), Some("<deleted>"));
    }

    #[test]
    fn violates_when_watched_path_missing_from_present_table() {
        let snap = files_snapshot(vec![]); // files table present but empty -> path not collected
        let r = check_integrity(&[passwd_watch()], &snap);
        assert!(
            r[0].violated,
            "a watched file absent from a present files table is a violation"
        );
        assert_eq!(r[0].actual_sha256, None);
    }

    #[test]
    fn absent_files_table_is_skipped() {
        let snap = Snapshot(HashMap::new()); // no files table at all -> FIM not collected
        let r = check_integrity(&[passwd_watch()], &snap);
        assert!(
            r.is_empty(),
            "no files table -> unassessable -> skipped, not violated"
        );
    }

    #[test]
    fn builtin_watchlist_has_expected_entries() {
        let w = builtin_watchlist();
        assert_eq!(w.len(), 2);
        let sshd = w.iter().find(|e| e.id == "fim-sshd-config").unwrap();
        assert_eq!(sshd.path, "/etc/ssh/sshd_config");
        assert_eq!(sshd.weight, 0.8);
        assert_eq!(
            sshd.expected_sha256,
            "1111111111111111111111111111111111111111111111111111111111111111"
        );
        let passwd = w.iter().find(|e| e.id == "fim-passwd").unwrap();
        assert_eq!(passwd.weight, 0.9);
        assert_eq!(
            passwd.expected_sha256,
            "2222222222222222222222222222222222222222222222222222222222222222"
        );
    }

    #[test]
    fn to_fim_records_maps_one_to_one_and_round_trips() {
        let snap = files_snapshot(vec![serde_json::json!({
            "path":"/etc/passwd","sha256":"9999999999999999999999999999999999999999999999999999999999999999","exists":true
        })]);
        let records = to_fim_records(&check_integrity(&[passwd_watch()], &snap));
        assert_eq!(records.len(), 1);
        assert!(records[0].violated);
        let back: FimRecord =
            serde_json::from_str(&serde_json::to_string(&records[0]).unwrap()).unwrap();
        assert_eq!(back, records[0]);
    }
}
