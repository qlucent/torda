//! Shared Finding construction for weight-scored posture signals (compliance,
//! drift, and — later — FIM). One place recomputes the canonical score from a
//! weight and builds the `Finding`, so every posture source scores identically
//! and no source severity is ever trusted.
use serde::de::DeserializeOwned;
use torda_findings::{
    DetectionMethod, Enrichment, ExploitMaturity, Finding, FindingState, Identity, Provenance,
    VexStatus,
};
use torda_findings_engine::decide::decide;
use torda_findings_engine::finding_id_for;
use torda_findings_engine::input::AssetContextSource;
use torda_findings_engine::score::recompute_compliance_score;

/// Enrichment for a posture finding: no CVE data. The score never reads it;
/// `Affected` is the safe non-suppressing default for a real deviation.
pub(crate) fn neutral_enrichment() -> Enrichment {
    Enrichment {
        cvss_vector: None,
        cvss_env: None,
        epss: None,
        epss_pct: None,
        kev: false,
        exploit_maturity: ExploitMaturity::None,
        vex: VexStatus::Affected,
    }
}

/// Builds a `Finding` scored from a policy `weight` (control or baseline) and the
/// asset context. `reported_severity` is `None` — no source severity is trusted.
pub(crate) fn weighted_finding(
    asset_id: &str,
    vuln_id: String,
    component: String,
    location: String,
    weight: f32,
    remediation_key: String,
    assets: &dyn AssetContextSource,
) -> Finding {
    let identity = Identity {
        asset_id: asset_id.to_string(),
        vuln_id,
        component,
        location,
    };
    let ctx = assets.context(asset_id);
    let score = recompute_compliance_score(weight, &ctx);
    let (decision, sla_hours) = decide(score.r, false, true, score.explain.reach);
    Finding {
        finding_id: finding_id_for(&identity),
        identity,
        provenance: vec![Provenance {
            source: "torda".to_string(),
            method: DetectionMethod::Authenticated,
            reported_severity: None,
            confidence: 0.95,
        }],
        enrichment: neutral_enrichment(),
        asset_ctx: ctx,
        score,
        decision,
        sla_hours,
        remediation_key,
        status: FindingState::Open,
        first_seen: None,
        last_seen: None,
        closed_at: None,
    }
}

/// Deserializes each element of a JSON array independently, keeping the ones that
/// succeed and skipping the ones that fail — a malformed record must never discard
/// its well-formed siblings (fail-safe, not fail-open). A non-array yields empty.
pub(crate) fn parse_lenient<T: DeserializeOwned>(value: &serde_json::Value) -> Vec<T> {
    value
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| serde_json::from_value(v.clone()).ok())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_lenient_skips_bad_elements_keeps_good() {
        // A non-array yields empty; a mixed array keeps only the elements that
        // deserialize, never dropping the whole batch for one bad element.
        assert_eq!(
            parse_lenient::<i64>(&serde_json::json!("not an array")),
            Vec::<i64>::new()
        );
        let mixed = serde_json::json!([1, "x", 3, {"a": 1}, 4]);
        assert_eq!(parse_lenient::<i64>(&mixed), vec![1, 3, 4]);
    }
}
