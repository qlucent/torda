//! Detection-coverage scoring: captured OCSF vs the declared registry (spec §6.1).
//!
//! Pure — consumes a registry + [`Captures`] and produces [`Scored`] + a matrix.
//! No live agent, so this is what the synthetic self-test proves first.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

use crate::model::{record_class, record_rules, record_time_ms, Captures, Case, Expect};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Verdict {
    /// Right class AND declared rule fired (Tier-A success).
    Hit,
    /// Window closed with no record of the declared class.
    Miss,
    /// Declared class fired but not the declared rule (adjacent/wrong rule).
    Partial,
    /// Tier-B expected miss, confirmed.
    Gap,
    /// Tier-B expected miss, but a matching record DID fire (a sensor closed it).
    GapClosed,
    /// No captures entry for this case — it never ran.
    NoData,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Hit => "HIT",
            Verdict::Miss => "MISS",
            Verdict::Partial => "PARTIAL",
            Verdict::Gap => "GAP",
            Verdict::GapClosed => "GAP_CLOSED",
            Verdict::NoData => "NO_DATA",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CaseResult {
    pub case_id: String,
    pub tier: String,
    pub technique: String,
    pub verdict: Verdict,
    pub matched_rules: Vec<String>,
    pub latency_ms: Option<i64>,
    pub fp_rules: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Scored {
    pub agent: String,
    pub run_id: String,
    pub tier_a_total: usize,
    pub tier_a_hits: usize,
    pub coverage_pct: f64,
    pub false_positives: usize,
    pub gap_closed: Vec<String>,
    pub results: Vec<CaseResult>,
}

fn in_window(expect: &Expect, trigger_ms: i64, rec: &Value) -> bool {
    match record_time_ms(rec) {
        // A timeless record cannot be windowed out — count it.
        None => true,
        Some(t) => t >= trigger_ms && t <= trigger_ms + (expect.within_seconds * 1000.0) as i64,
    }
}

/// Reverse map declared-rule → technique, for false-positive attribution.
fn rule_to_technique(cases: &[Case]) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for c in cases {
        if let Some(e) = &c.expects {
            m.entry(e.rule.clone())
                .or_insert_with(|| c.attack_technique.clone());
        }
    }
    m
}

fn score_case(
    case: &Case,
    cap: Option<&crate::model::CaseCapture>,
    rule2tech: &BTreeMap<String, String>,
) -> CaseResult {
    let mut result = CaseResult {
        case_id: case.id.clone(),
        tier: case.tier.clone(),
        technique: case.attack_technique.clone(),
        verdict: Verdict::NoData,
        matched_rules: vec![],
        latency_ms: None,
        fp_rules: vec![],
    };
    let cap = match cap {
        Some(c) => c,
        None => return result,
    };

    // Records in this case's window (all records if the case has no expectation).
    let windowed: Vec<&Value> = cap
        .records
        .iter()
        .filter(|r| {
            case.expects
                .as_ref()
                .is_none_or(|e| in_window(e, cap.trigger_time, r))
        })
        .collect();

    // False positives: an in-window record whose rule maps to a DIFFERENT technique.
    for r in &windowed {
        for rule in record_rules(r) {
            if let Some(tech) = rule2tech.get(&rule) {
                if *tech != case.attack_technique && !result.fp_rules.contains(&rule) {
                    result.fp_rules.push(rule);
                }
            }
        }
    }

    let expect = match &case.expects {
        // Pure Tier-B gap with no declared sensor: can only confirm the gap.
        None => {
            result.verdict = Verdict::Gap;
            return result;
        }
        Some(e) => e,
    };

    let want = expect.ocsf_class;
    let mut class_present = false;
    let mut rule_hit_times: Vec<i64> = Vec::new();
    for r in &windowed {
        if record_class(r) == Some(want) {
            class_present = true;
            if record_rules(r).contains(&expect.rule) {
                if let Some(t) = record_time_ms(r) {
                    rule_hit_times.push(t);
                }
            }
        }
    }
    let rule_present = !rule_hit_times.is_empty()
        // A rule can match on a timeless record too (kept in-window); treat any
        // class+rule match as a hit even if none carried a usable timestamp.
        || windowed.iter().any(|r| {
            record_class(r) == Some(want) && record_rules(r).contains(&expect.rule)
        });

    if rule_present {
        result.matched_rules = vec![expect.rule.clone()];
        if let Some(first) = rule_hit_times.iter().min() {
            result.latency_ms = Some((first - cap.trigger_time).max(0));
        }
    }

    result.verdict = if case.expected_result == "miss" {
        if rule_present {
            Verdict::GapClosed
        } else {
            Verdict::Gap
        }
    } else if rule_present {
        Verdict::Hit
    } else if class_present {
        Verdict::Partial
    } else {
        Verdict::Miss
    };
    result
}

pub fn score(cases: &[Case], captures: &Captures) -> Scored {
    let rule2tech = rule_to_technique(cases);
    let by_id: BTreeMap<&str, &crate::model::CaseCapture> = captures
        .cases
        .iter()
        .map(|c| (c.case_id.as_str(), c))
        .collect();

    let results: Vec<CaseResult> = cases
        .iter()
        .map(|c| score_case(c, by_id.get(c.id.as_str()).copied(), &rule2tech))
        .collect();

    let tier_a_total = results.iter().filter(|r| r.tier == "A").count();
    let tier_a_hits = results
        .iter()
        .filter(|r| r.tier == "A" && r.verdict == Verdict::Hit)
        .count();
    let false_positives = results.iter().map(|r| r.fp_rules.len()).sum();
    let gap_closed = results
        .iter()
        .filter(|r| r.verdict == Verdict::GapClosed)
        .map(|r| r.case_id.clone())
        .collect();

    Scored {
        agent: captures.agent.clone(),
        run_id: captures.run_id.clone(),
        tier_a_total,
        tier_a_hits,
        coverage_pct: if tier_a_total == 0 {
            0.0
        } else {
            (1000.0 * tier_a_hits as f64 / tier_a_total as f64).round() / 10.0
        },
        false_positives,
        gap_closed,
        results,
    }
}

pub fn matrix_md(s: &Scored) -> String {
    let mut out = String::new();
    out.push_str(&format!("# Detection matrix - {}\n\n", s.agent));
    out.push_str(&format!(
        "- Tier-A coverage: **{}/{} ({}%)**\n",
        s.tier_a_hits, s.tier_a_total, s.coverage_pct
    ));
    out.push_str(&format!("- False positives: **{}**\n", s.false_positives));
    if !s.gap_closed.is_empty() {
        out.push_str(&format!(
            "- Gap-closed (Tier-B now detected): **{}**\n",
            s.gap_closed.join(", ")
        ));
    }
    out.push_str("\n| Case | Tier | ATT&CK | Verdict | Latency (ms) | FP rules |\n|---|---|---|---|---|---|\n");
    for r in &s.results {
        let lat = r.latency_ms.map(|l| l.to_string()).unwrap_or_default();
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            r.case_id,
            r.tier,
            r.technique,
            r.verdict.as_str(),
            lat,
            r.fp_rules.join(", ")
        ));
    }
    out
}

/// True if every Tier-A case is a HIT (used as the CLI/CI gate).
pub fn all_tier_a_hit(s: &Scored) -> bool {
    s.results
        .iter()
        .filter(|r| r.tier == "A")
        .all(|r| r.verdict == Verdict::Hit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::load_captures;

    fn fixture() -> (Vec<Case>, Captures) {
        let root = env!("CARGO_MANIFEST_DIR");
        let cases = crate::model::load_registry(format!("{root}/config/techniques.toml")).unwrap();
        let caps = load_captures(format!("{root}/tests/fixtures/captures_synthetic.json")).unwrap();
        (cases, caps)
    }

    fn verdict(s: &Scored, id: &str) -> Verdict {
        s.results.iter().find(|r| r.case_id == id).unwrap().verdict
    }

    #[test]
    fn registry_tiers_are_sane() {
        let (cases, _) = fixture();
        let a = cases.iter().filter(|c| c.tier == "A").count();
        let b = cases.iter().filter(|c| c.tier == "B").count();
        assert!(a >= 10 && b >= 1);
        assert!(cases
            .iter()
            .filter(|c| c.tier == "A")
            .all(|c| c.expects.is_some()));
    }

    #[test]
    fn verdicts_cover_every_branch() {
        let (cases, caps) = fixture();
        let s = score(&cases, &caps);
        assert_eq!(verdict(&s, "lolbin-basic"), Verdict::Hit);
        assert_eq!(verdict(&s, "lolbin-susp-path"), Verdict::Hit);
        assert_eq!(verdict(&s, "susp-path-exec"), Verdict::Partial);
        assert_eq!(verdict(&s, "c2-port-connect"), Verdict::Hit);
        assert_eq!(verdict(&s, "write-system-dir"), Verdict::Miss);
        assert_eq!(verdict(&s, "proc-injection"), Verdict::Gap);
        assert_eq!(verdict(&s, "ancestry-chain"), Verdict::GapClosed);
        assert_eq!(verdict(&s, "read-secret"), Verdict::NoData);
    }

    #[test]
    fn false_positive_attribution() {
        let (cases, caps) = fixture();
        let s = score(&cases, &caps);
        let c2 = s
            .results
            .iter()
            .find(|r| r.case_id == "c2-port-connect")
            .unwrap();
        assert!(c2.fp_rules.contains(&"lolbin".to_string()));
        assert!(s.false_positives >= 1);
    }

    #[test]
    fn coverage_headline_and_gate() {
        let (cases, caps) = fixture();
        let s = score(&cases, &caps);
        assert_eq!(s.tier_a_hits, 3);
        assert_eq!(s.gap_closed, vec!["ancestry-chain".to_string()]);
        assert!(s.coverage_pct > 0.0 && s.coverage_pct < 100.0);
        assert!(!all_tier_a_hit(&s)); // fixture is partial → gate would fail (correct)
    }
}
