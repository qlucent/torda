//! OCSF conformance (spec §7.1) — validated against the REAL envelope type.
//!
//! A record is conformant iff it deserializes into [`torda_ocsf::OcsfEnvelope`]
//! (every required attribute present + correctly typed — the struct has no
//! optional fields) AND its `class_uid` is one the agent actually emits. Because
//! we link the real type, this check tracks the agent's contract automatically —
//! there is no hand-maintained schema to drift. (Upgrading to the upstream
//! per-class OCSF JSON-schema is a tracked follow-up; this interface stays.)

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;
use torda_ocsf::OcsfEnvelope;

use crate::model::{class_name, is_known_class};

#[derive(Debug, Clone, Serialize)]
pub struct ClassConformance {
    pub class_name: String,
    pub total: usize,
    pub passed: usize,
    pub pass_pct: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Conformance {
    pub records: usize,
    pub pass_pct: f64,
    pub per_class: BTreeMap<u32, ClassConformance>,
    /// (violation label, count), most common first.
    pub top_violations: Vec<(String, usize)>,
}

/// `[]` = conformant. Otherwise a short list of violation labels.
pub fn validate_record(rec: &Value) -> Vec<String> {
    let mut v = Vec::new();
    match serde_json::from_value::<OcsfEnvelope>(rec.clone()) {
        Ok(env) => {
            if !is_known_class(env.class_uid) {
                v.push(format!("unknown_class:{}", env.class_uid));
            }
            if !(1..=6).contains(&env.severity_id) {
                v.push("enum:severity_id".into());
            }
        }
        Err(e) => {
            // serde's message names the first offending/missing field.
            let msg = e.to_string();
            let short = msg.split(" at line").next().unwrap_or(&msg);
            v.push(format!("envelope:{short}"));
        }
    }
    v
}

fn raw_class(rec: &Value) -> i64 {
    rec.get("class_uid").and_then(Value::as_i64).unwrap_or(-1)
}

pub fn validate_records(records: &[Value]) -> Conformance {
    let mut total_by: BTreeMap<i64, usize> = BTreeMap::new();
    let mut pass_by: BTreeMap<i64, usize> = BTreeMap::new();
    let mut violations: BTreeMap<String, usize> = BTreeMap::new();

    for rec in records {
        let cls = raw_class(rec);
        *total_by.entry(cls).or_default() += 1;
        let vs = validate_record(rec);
        if vs.is_empty() {
            *pass_by.entry(cls).or_default() += 1;
        } else {
            for x in vs {
                *violations.entry(x).or_default() += 1;
            }
        }
    }

    let mut per_class = BTreeMap::new();
    for (cls, total) in &total_by {
        let passed = *pass_by.get(cls).unwrap_or(&0);
        let uid = if *cls >= 0 { *cls as u32 } else { 0 };
        per_class.insert(
            uid,
            ClassConformance {
                class_name: if *cls >= 0 {
                    class_name(uid).to_string()
                } else {
                    "?".into()
                },
                total: *total,
                passed,
                pass_pct: if *total == 0 {
                    0.0
                } else {
                    (1000.0 * passed as f64 / *total as f64).round() / 10.0
                },
            },
        );
    }
    let total: usize = total_by.values().sum();
    let passed: usize = pass_by.values().sum();
    let mut top: Vec<(String, usize)> = violations.into_iter().collect();
    top.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    top.truncate(10);

    Conformance {
        records: total,
        pass_pct: if total == 0 {
            0.0
        } else {
            (1000.0 * passed as f64 / total as f64).round() / 10.0
        },
        per_class,
        top_violations: top,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn fixture_records_all_conform() {
        let root = env!("CARGO_MANIFEST_DIR");
        let caps =
            crate::model::load_captures(format!("{root}/tests/fixtures/captures_synthetic.json"))
                .unwrap();
        let recs: Vec<Value> = caps.cases.iter().flat_map(|c| c.records.clone()).collect();
        let out = validate_records(&recs);
        assert_eq!(out.pass_pct, 100.0, "{:?}", out.top_violations);
    }

    #[test]
    fn malformed_record_is_flagged() {
        // Missing time/severity/metadata/device/data → fails to deserialize.
        let bad = json!({"class_uid": 1007, "class_name": "Process Activity"});
        assert!(!validate_record(&bad).is_empty());
        // Well-formed envelope but an unknown class UID is flagged too.
        let unknown = json!({
            "class_uid": 9999, "class_name": "x", "time": 1, "severity_id": 1,
            "metadata": {"product": "t", "version": "0", "tenant_id": "b"},
            "device": {"hostname": "h", "os": "L", "os_version": "1"}, "data": {}
        });
        assert!(validate_record(&unknown)
            .iter()
            .any(|s| s.starts_with("unknown_class")));
    }
}
