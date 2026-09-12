//! Group-by-fix: findings sharing a `remediation_key`
//! collapse into one Remediation Item ops acts on. `risk` = max member R,
//! `closes` = distinct member vuln_ids, `assets` = distinct member asset_ids.
use std::collections::BTreeMap;
use torda_findings::{Finding, RemediationItem};

/// Collapses findings sharing a `remediation_key` into one `RemediationItem`.
/// `BTreeMap` keeps output ordered by key; `closes`/`assets` are sorted+deduped
/// for deterministic, explainable items.
/// Caller must pass only actionable findings — this groups whatever it receives,
/// so a Suppressed finding would inflate an item's `closes`/`assets`. Filter
/// Suppressed before calling.
pub fn group_by_fix(findings: &[Finding]) -> Vec<RemediationItem> {
    let mut groups: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        groups
            .entry(f.remediation_key.as_str())
            .or_default()
            .push(f);
    }
    groups
        .into_iter()
        .map(|(key, members)| {
            let risk = members.iter().map(|f| f.score.r).max().unwrap_or(0);
            let closes = dedup_sorted(members.iter().map(|f| f.identity.vuln_id.clone()));
            let assets = dedup_sorted(members.iter().map(|f| f.identity.asset_id.clone()));
            RemediationItem {
                remediation_key: key.to_string(),
                risk,
                closes,
                assets,
            }
        })
        .collect()
}

fn dedup_sorted(iter: impl Iterator<Item = String>) -> Vec<String> {
    let mut v: Vec<String> = iter.collect();
    v.sort();
    v.dedup();
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use torda_findings::{
        AssetContext, Criticality, Decision, DetectionMethod, Enrichment, ExploitMaturity,
        Identity, Provenance, Score, ScoreExplain, VexStatus,
    };

    fn finding(asset: &str, vuln: &str, key: &str, r: u8) -> Finding {
        Finding {
            finding_id: format!("{asset}|{vuln}"),
            identity: Identity {
                asset_id: asset.into(),
                vuln_id: vuln.into(),
                component: "openssl".into(),
                location: "dpkg".into(),
            },
            provenance: vec![Provenance {
                source: "torda".into(),
                method: DetectionMethod::Authenticated,
                reported_severity: None,
                confidence: 0.95,
            }],
            enrichment: Enrichment {
                cvss_vector: None,
                cvss_env: None,
                epss: None,
                epss_pct: None,
                kev: false,
                exploit_maturity: ExploitMaturity::None,
                vex: VexStatus::Affected,
                feed_version: None,
            },
            asset_ctx: AssetContext {
                internet_facing: false,
                criticality: Criticality::Normal,
                compensating_controls: false,
            },
            score: Score {
                r,
                explain: ScoreExplain {
                    sev: 0.0,
                    likelihood: 0.0,
                    exposure: 0.8,
                    crit: 0.9,
                    reach: 1.0,
                },
            },
            decision: Decision::Track,
            sla_hours: 720,
            remediation_key: key.into(),
            status: Default::default(),
            first_seen: None,
            last_seen: None,
            closed_at: None,
        }
    }

    #[test]
    fn tv4_group_by_fix_collapses_shared_key() {
        // CVE-A/B/C all fixed by the same upgrade, across 2 assets.
        let key = "upgrade:openssl>=3.0.14";
        let findings = vec![
            finding("host-1", "CVE-A", key, 91),
            finding("host-1", "CVE-B", key, 40),
            finding("host-2", "CVE-C", key, 77),
        ];
        let items = group_by_fix(&findings);
        assert_eq!(items.len(), 1, "one remediation item for the shared key");
        let it = &items[0];
        assert_eq!(it.remediation_key, key);
        assert_eq!(it.risk, 91, "risk = max member R");
        assert_eq!(it.closes, vec!["CVE-A", "CVE-B", "CVE-C"]);
        assert_eq!(it.assets, vec!["host-1", "host-2"], "distinct assets");
    }

    #[test]
    fn distinct_keys_stay_separate() {
        let findings = vec![
            finding("h", "CVE-A", "fix-a", 50),
            finding("h", "CVE-B", "fix-b", 60),
        ];
        let items = group_by_fix(&findings);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].closes, vec!["CVE-A"]);
        assert_eq!(items[1].closes, vec!["CVE-B"]);
    }

    #[test]
    fn closes_and_assets_are_sorted_regardless_of_input_order() {
        let key = "upgrade:openssl>=3.0.14";
        let findings = vec![
            finding("host-2", "CVE-C", key, 10),
            finding("host-1", "CVE-A", key, 20),
            finding("host-1", "CVE-B", key, 30),
        ];
        let items = group_by_fix(&findings);
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0].closes,
            vec!["CVE-A", "CVE-B", "CVE-C"],
            "sorted despite reverse input"
        );
        assert_eq!(
            items[0].assets,
            vec!["host-1", "host-2"],
            "distinct + sorted"
        );
    }
}
