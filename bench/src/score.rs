//! Detection-coverage scoring: captured OCSF vs the declared registry (spec §6.1).
//!
//! Pure — consumes a registry + [`Captures`] and produces [`Scored`] + a matrix.
//! No live agent, so this is what the synthetic self-test proves first.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

use crate::model::{
    is_peer_agent, record_class, record_rules, record_techniques, record_time_ms, Captures, Case,
    Expect,
};

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
    /// The HONEST false-positive number: detection-bearing records seen during the
    /// idle baseline (nothing malicious running). 0 is the goal.
    pub idle_false_positives: usize,
    /// The distinct rules that fired during the idle baseline.
    pub idle_fp_rules: Vec<String>,
    /// Per-case cross-technique attributions — informational only; noisy for
    /// multi-behavior atomics (a chain case fires its own component rules). The
    /// `idle_false_positives` above is the metric to trust.
    pub cross_technique_hits: usize,
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
    peer: bool,
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

    // PEER mode (Wazuh/Falco/…): the tool emits neither OCSF classes nor torda
    // rule names, so it is scored by ATT&CK TECHNIQUE — HIT if an in-window alert
    // maps to a component of this case's declared technique. An ATT&CK-tagged alert
    // for a DIFFERENT technique is a cross-technique attribution (informational).
    if peer {
        let case_components: Vec<&str> = case.attack_technique.split('+').collect();
        let mut matched = false;
        for r in &windowed {
            let techs = record_techniques(r);
            if techs.iter().any(|t| case_components.contains(&t.as_str())) {
                matched = true;
            } else if !techs.is_empty() {
                if let Some(rule) = r.get("rule").and_then(Value::as_str) {
                    if !result.fp_rules.iter().any(|x| x == rule) {
                        result.fp_rules.push(rule.to_string());
                    }
                }
            }
        }
        result.verdict = if case.expected_result == "miss" {
            if matched {
                Verdict::GapClosed
            } else {
                Verdict::Gap
            }
        } else if matched {
            Verdict::Hit
        } else {
            Verdict::Miss
        };
        return result;
    }

    // False positives: an in-window record whose rule belongs to a technique that
    // shares NO component with this case. A chain case declares a compound
    // technique (e.g. "T1105+T1571"); its component rules (the write AND the
    // connect) are expected, so we compare SPLIT component sets and intersect.
    // The case's OWN declared rule is never an FP (its rule maps to the case's own
    // compound string, which would otherwise not match its split components).
    let case_components: Vec<&str> = case.attack_technique.split('+').collect();
    for r in &windowed {
        for rule in record_rules(r) {
            if case.expects.as_ref().is_some_and(|e| e.rule == rule) {
                continue;
            }
            if let Some(tech) = rule2tech.get(&rule) {
                let shares = tech.split('+').any(|rc| case_components.contains(&rc));
                if !shares && !result.fp_rules.contains(&rule) {
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
    let peer = is_peer_agent(&captures.agent);
    let rule2tech = rule_to_technique(cases);
    let by_id: BTreeMap<&str, &crate::model::CaseCapture> = captures
        .cases
        .iter()
        .map(|c| (c.case_id.as_str(), c))
        .collect();

    let results: Vec<CaseResult> = cases
        .iter()
        .map(|c| score_case(c, by_id.get(c.id.as_str()).copied(), &rule2tech, peer))
        .collect();

    let tier_a_total = results.iter().filter(|r| r.tier == "A").count();
    let tier_a_hits = results
        .iter()
        .filter(|r| r.tier == "A" && r.verdict == Verdict::Hit)
        .count();
    let cross_technique_hits = results.iter().map(|r| r.fp_rules.len()).sum();
    let gap_closed = results
        .iter()
        .filter(|r| r.verdict == Verdict::GapClosed)
        .map(|r| r.case_id.clone())
        .collect();

    // Idle-baseline FP: a detection-bearing record during the no-atomic window is
    // a genuine false positive (it fired against benign background activity).
    let mut idle_fp_rules: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut idle_false_positives = 0usize;
    for rec in &captures.baseline {
        if peer {
            // Every peer alert during the idle window is a false positive (it fired
            // against benign background); label it by the peer rule.
            idle_false_positives += 1;
            if let Some(r) = rec.get("rule").and_then(Value::as_str) {
                idle_fp_rules.insert(r.to_string());
            }
        } else {
            let rules = record_rules(rec);
            if !rules.is_empty() {
                idle_false_positives += 1;
                idle_fp_rules.extend(rules);
            }
        }
    }

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
        idle_false_positives,
        idle_fp_rules: idle_fp_rules.into_iter().collect(),
        cross_technique_hits,
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
    out.push_str(&format!(
        "- Idle-baseline false positives: **{}**{}\n",
        s.idle_false_positives,
        if s.idle_fp_rules.is_empty() {
            String::new()
        } else {
            format!(" ({})", s.idle_fp_rules.join(", "))
        }
    ));
    out.push_str(&format!(
        "- Cross-technique attributions (informational): {}\n",
        s.cross_technique_hits
    ));
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
    use serde_json::json;

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
        assert!(s.cross_technique_hits >= 1);
    }

    #[test]
    fn idle_baseline_false_positives() {
        let (cases, caps) = fixture();
        let s = score(&cases, &caps);
        // The fixture baseline has one detection-bearing record (suspicious_port)
        // and one benign record → exactly one idle FP.
        assert_eq!(s.idle_false_positives, 1);
        assert_eq!(s.idle_fp_rules, vec!["suspicious_port".to_string()]);
    }

    #[test]
    fn peer_mode_scores_by_attack_technique() {
        let root = env!("CARGO_MANIFEST_DIR");
        let cases = crate::model::load_registry(format!("{root}/config/techniques.toml")).unwrap();
        // A peer (wazuh) captures file: records carry `attack_techniques`, scored by
        // technique, not OCSF class/rule.
        let caps = Captures {
            run_id: "t".into(),
            agent: "wazuh".into(),
            cases: vec![
                crate::model::CaseCapture {
                    case_id: "lolbin-basic".into(), // technique T1059
                    trigger_time: 0,
                    records: vec![json!({"attack_techniques": ["T1059"], "rule": "wazuh:92052"})],
                },
                crate::model::CaseCapture {
                    case_id: "c2-port-connect".into(), // technique T1571
                    trigger_time: 0,
                    records: vec![json!({"attack_techniques": ["T1046"], "rule": "wazuh:200"})],
                },
                crate::model::CaseCapture {
                    case_id: "chain-dropper-c2".into(), // compound T1105+T1571
                    trigger_time: 0,
                    records: vec![json!({"attack_techniques": ["T1571"], "rule": "wazuh:9"})],
                },
            ],
            baseline: vec![json!({"attack_techniques": [], "rule": "wazuh:5501"})],
        };
        let s = score(&cases, &caps);
        assert_eq!(verdict(&s, "lolbin-basic"), Verdict::Hit); // T1059 matches
        assert_eq!(verdict(&s, "c2-port-connect"), Verdict::Miss); // T1046 != T1571
        assert_eq!(verdict(&s, "chain-dropper-c2"), Verdict::Hit); // T1571 is a component
                                                                   // The wrong-technique alert is a cross-technique attribution.
        let c2 = s
            .results
            .iter()
            .find(|r| r.case_id == "c2-port-connect")
            .unwrap();
        assert!(c2.fp_rules.contains(&"wazuh:200".to_string()));
        // Every idle alert is a peer FP.
        assert_eq!(s.idle_false_positives, 1);
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
