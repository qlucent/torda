//! Per-class detection latency (spec §6.2): first matching record's engine time
//! minus the atomic's trigger time. Median + p95 per OCSF class over HIT cases.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::model::{class_name, record_class, record_rules, record_time_ms, Captures, Case};

#[derive(Debug, Clone, Serialize)]
pub struct ClassLatency {
    pub class_name: String,
    pub n: usize,
    pub median_ms: i64,
    pub p95_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Latency {
    pub agent: String,
    pub per_class: BTreeMap<u32, ClassLatency>,
    pub per_case_ms: BTreeMap<String, i64>,
}

fn percentile(sorted: &[i64], pct: f64) -> i64 {
    if sorted.is_empty() {
        return 0;
    }
    let k = (((pct / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize).min(sorted.len() - 1);
    sorted[k]
}

fn median(sorted: &[i64]) -> i64 {
    let n = sorted.len();
    if n == 0 {
        0
    } else if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2
    }
}

pub fn latency(cases: &[Case], captures: &Captures) -> Latency {
    let by_id: BTreeMap<&str, &crate::model::CaseCapture> = captures
        .cases
        .iter()
        .map(|c| (c.case_id.as_str(), c))
        .collect();

    let mut per_class_raw: BTreeMap<u32, Vec<i64>> = BTreeMap::new();
    let mut per_case_ms = BTreeMap::new();

    for case in cases {
        let (expect, cap) = match (&case.expects, by_id.get(case.id.as_str())) {
            (Some(e), Some(c)) => (e, *c),
            _ => continue,
        };
        let first = cap
            .records
            .iter()
            .filter(|r| {
                record_class(r) == Some(expect.ocsf_class) && record_rules(r).contains(&expect.rule)
            })
            .filter_map(record_time_ms)
            .min();
        if let Some(t) = first {
            let lat = (t - cap.trigger_time).max(0);
            per_case_ms.insert(case.id.clone(), lat);
            per_class_raw
                .entry(expect.ocsf_class)
                .or_default()
                .push(lat);
        }
    }

    let mut per_class = BTreeMap::new();
    for (cls, mut vals) in per_class_raw {
        vals.sort_unstable();
        per_class.insert(
            cls,
            ClassLatency {
                class_name: class_name(cls).to_string(),
                n: vals.len(),
                median_ms: median(&vals),
                p95_ms: percentile(&vals, 95.0),
            },
        );
    }
    Latency {
        agent: captures.agent.clone(),
        per_class,
        per_case_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_is_first_matching_record_minus_trigger() {
        let root = env!("CARGO_MANIFEST_DIR");
        let cases = crate::model::load_registry(format!("{root}/config/techniques.toml")).unwrap();
        let caps =
            crate::model::load_captures(format!("{root}/tests/fixtures/captures_synthetic.json"))
                .unwrap();
        let l = latency(&cases, &caps);
        assert_eq!(l.per_case_ms.get("lolbin-basic"), Some(&500)); // 1500 - 1000
        assert!(l.per_class.contains_key(&1007));
    }
}
