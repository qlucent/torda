//! Collate scored artifacts into a human report.md (spec §10).

use crate::conformance::Conformance;
use crate::latency::Latency;
use crate::score::{Scored, Verdict};

pub fn build_report(run_id: &str, scored: &Scored, lat: &Latency, conf: &Conformance) -> String {
    let mut o = String::new();
    o.push_str(&format!("# Torda benchmark report\n\n_Run: {run_id}_\n\n"));

    o.push_str("## Detection coverage (Tier A)\n\n");
    o.push_str(&format!(
        "- **{}/{} ({}%)** — agent `{}`\n- False positives: {}\n",
        scored.tier_a_hits,
        scored.tier_a_total,
        scored.coverage_pct,
        scored.agent,
        scored.false_positives
    ));
    if !scored.gap_closed.is_empty() {
        o.push_str(&format!(
            "- Gap-closed (Tier-B now detected): {}\n",
            scored.gap_closed.join(", ")
        ));
    }
    let open_gaps: Vec<&str> = scored
        .results
        .iter()
        .filter(|r| r.tier == "B" && r.verdict == Verdict::Gap)
        .map(|r| r.case_id.as_str())
        .collect();
    if !open_gaps.is_empty() {
        o.push_str(&format!(
            "- Open gaps (Tier B, expected miss): {}\n",
            open_gaps.join(", ")
        ));
    }

    if !lat.per_class.is_empty() {
        o.push_str(
            "\n## Detection latency\n\n| Class | n | median (ms) | p95 (ms) |\n|---|---|---|---|\n",
        );
        for (cls, s) in &lat.per_class {
            o.push_str(&format!(
                "| {} ({}) | {} | {} | {} |\n",
                s.class_name, cls, s.n, s.median_ms, s.p95_ms
            ));
        }
    }

    o.push_str(&format!(
        "\n## OCSF conformance\n\n- Overall: **{}%** of {} records pass the envelope contract.\n",
        conf.pass_pct, conf.records
    ));
    if !conf.top_violations.is_empty() {
        o.push_str(&format!("- Top violations: {:?}\n", conf.top_violations));
    }
    o
}
