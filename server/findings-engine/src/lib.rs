//! Findings engine — turns raw, multi-source vulnerability detections into one
//! canonical, explainable, deduped, decision-bearing finding per identity. The
//! score is recomputed from canonical inputs ONLY; a source's severity label is
//! retained as provenance but never scored. Group-by-fix and lifecycle/regression
//! are slice 1.4b.
pub mod aggregate;
pub mod correlate;
pub mod decide;
pub mod input;
pub mod lifecycle;
pub mod score;

use crate::correlate::correlate;
use crate::decide::decide;
use crate::input::{AssetContextSource, EnrichmentSource, RawDetection};
use crate::score::recompute_score;
use torda_findings::{Enrichment, Finding, Identity};

/// The findings engine: correlate → enrich → recompute score → decide. Produces
/// canonical, deduped, scored, decision-bearing findings. Group-by-fix and
/// lifecycle/regression are slice 1.4b.
pub struct Engine<'a> {
    enrichment: &'a dyn EnrichmentSource,
    assets: &'a dyn AssetContextSource,
}

impl<'a> Engine<'a> {
    pub fn new(enrichment: &'a dyn EnrichmentSource, assets: &'a dyn AssetContextSource) -> Self {
        Self { enrichment, assets }
    }

    /// Runs the pipeline over a batch of detections.
    pub fn run(&self, detections: Vec<RawDetection>) -> Vec<Finding> {
        correlate(detections)
            .into_iter()
            .map(|c| {
                let ctx = self.assets.context(&c.identity.asset_id);
                let enr = self
                    .enrichment
                    .lookup(&c.identity.vuln_id)
                    .unwrap_or_else(unknown_enrichment);
                let score = recompute_score(&enr, &ctx);
                let (decision, sla_hours) = decide(score.r, enr.kev, true, score.explain.reach);
                let status = if enr.vex == torda_findings::VexStatus::NotAffected {
                    torda_findings::FindingState::Suppressed
                } else {
                    torda_findings::FindingState::Open
                };
                Finding {
                    finding_id: finding_id_for(&c.identity),
                    identity: c.identity,
                    provenance: c.provenance,
                    enrichment: enr,
                    asset_ctx: ctx,
                    score,
                    decision,
                    sla_hours,
                    remediation_key: c.remediation_key,
                    status,
                    // Stamped by `reconcile` (from the batch's event time) after the
                    // Engine builds the fresh finding; None until then.
                    first_seen: None,
                    last_seen: None,
                    closed_at: None,
                }
            })
            .collect()
    }
}

/// Deterministic finding id from the identity tuple. Real UUID/persistence
/// arrives with the storage slice; this keeps the engine pure and testable.
pub fn finding_id_for(id: &Identity) -> String {
    format!(
        "{}|{}|{}|{}",
        id.asset_id, id.vuln_id, id.component, id.location
    )
}

/// Enrichment for a vuln with no feed data: unknown reachability, no exploit,
/// no KEV — scores conservatively rather than guessing high.
fn unknown_enrichment() -> Enrichment {
    Enrichment {
        cvss_vector: None,
        cvss_env: None,
        epss: None,
        epss_pct: None,
        kev: false,
        exploit_maturity: torda_findings::ExploitMaturity::None,
        vex: torda_findings::VexStatus::Unknown,
        feed_version: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::{MapAssetContext, MapEnrichment};
    use std::collections::HashMap;
    use torda_findings::{
        AssetContext, Criticality, Decision, DetectionMethod, ExploitMaturity, VexStatus,
    };

    fn enr(cvss_env: f32, epss: f32, m: ExploitMaturity, kev: bool, vex: VexStatus) -> Enrichment {
        Enrichment {
            cvss_vector: None,
            cvss_env: Some(cvss_env),
            epss: Some(epss),
            epss_pct: None,
            kev,
            exploit_maturity: m,
            vex,
            feed_version: None,
        }
    }
    fn ctx(internet: bool, crit: Criticality, controls: bool) -> AssetContext {
        AssetContext {
            internet_facing: internet,
            criticality: crit,
            compensating_controls: controls,
        }
    }
    fn det(
        asset: &str,
        vuln: &str,
        source: &str,
        method: DetectionMethod,
        sev: Option<&str>,
        conf: f32,
    ) -> RawDetection {
        RawDetection {
            identity: Identity {
                asset_id: asset.into(),
                vuln_id: vuln.into(),
                component: "openssl".into(),
                location: "dpkg".into(),
            },
            source: source.into(),
            method,
            reported_severity: sev.map(|s| s.into()),
            confidence: conf,
            remediation_key: "upgrade:openssl>=3.0.14".into(),
        }
    }

    #[test]
    fn tv1_one_finding_score_independent_of_source_labels() {
        let mut e = HashMap::new();
        e.insert(
            "CVE-X".to_string(),
            enr(
                7.0,
                0.2,
                ExploitMaturity::Functional,
                false,
                VexStatus::Affected,
            ),
        );
        let enrichment = MapEnrichment(e);
        let assets = MapAssetContext {
            by_asset: HashMap::new(),
            default: ctx(false, Criticality::Normal, false),
        };
        let engine = Engine::new(&enrichment, &assets);

        let dets = vec![
            det(
                "host-A",
                "CVE-X",
                "torda",
                DetectionMethod::Authenticated,
                None,
                0.95,
            ),
            det(
                "host-A",
                "CVE-X",
                "nessus",
                DetectionMethod::Authenticated,
                Some("High"),
                0.8,
            ),
            det(
                "host-A",
                "CVE-X",
                "network-scan",
                DetectionMethod::Unauthenticated,
                Some("Critical"),
                0.5,
            ),
        ];
        let findings = engine.run(dets);
        assert_eq!(findings.len(), 1, "3 sources -> 1 finding");
        let f = &findings[0];
        assert_eq!(f.provenance.len(), 3);
        assert_eq!(f.provenance[0].source, "torda");
        // The score equals the canonical recompute — identical no matter the "High"/"Critical" labels.
        let expected = recompute_score(
            &enr(
                7.0,
                0.2,
                ExploitMaturity::Functional,
                false,
                VexStatus::Affected,
            ),
            &ctx(false, Criticality::Normal, false),
        );
        assert_eq!(f.score, expected);
    }

    #[test]
    fn tv2_kev_low_cvss_forces_act() {
        let mut e = HashMap::new();
        e.insert(
            "CVE-Y".to_string(),
            enr(5.1, 0.04, ExploitMaturity::None, true, VexStatus::Affected),
        );
        let enrichment = MapEnrichment(e);
        let assets = MapAssetContext {
            by_asset: HashMap::new(),
            default: ctx(true, Criticality::Normal, false),
        };
        let engine = Engine::new(&enrichment, &assets);
        let findings = engine.run(vec![det(
            "host-A",
            "CVE-Y",
            "torda",
            DetectionMethod::Authenticated,
            None,
            0.95,
        )]);
        assert_eq!(
            findings[0].decision,
            Decision::Act,
            "KEV + reachable -> ACT despite low CVSS/EPSS"
        );
    }

    #[test]
    fn tv5_kev_overrides_lagging_epss() {
        let mut e = HashMap::new();
        e.insert(
            "CVE-W".to_string(),
            enr(6.0, 0.05, ExploitMaturity::None, true, VexStatus::Affected),
        );
        let enrichment = MapEnrichment(e);
        let assets = MapAssetContext {
            by_asset: HashMap::new(),
            default: ctx(true, Criticality::Normal, false),
        };
        let engine = Engine::new(&enrichment, &assets);
        let findings = engine.run(vec![det(
            "host-A",
            "CVE-W",
            "torda",
            DetectionMethod::Authenticated,
            None,
            0.95,
        )]);
        assert_eq!(
            findings[0].decision,
            Decision::Act,
            "KEV decides; low EPSS does not downgrade"
        );
    }

    #[test]
    fn tv6_same_cve_splits_by_asset_context() {
        let mut e = HashMap::new();
        e.insert(
            "CVE-V".to_string(),
            enr(
                7.0,
                0.2,
                ExploitMaturity::Functional,
                false,
                VexStatus::Affected,
            ),
        );
        let enrichment = MapEnrichment(e);
        let mut by_asset = HashMap::new();
        by_asset.insert(
            "prod".to_string(),
            ctx(true, Criticality::CrownJewel, false),
        );
        by_asset.insert("dev".to_string(), ctx(false, Criticality::Low, true));
        let assets = MapAssetContext {
            by_asset,
            default: ctx(false, Criticality::Normal, false),
        };
        let engine = Engine::new(&enrichment, &assets);

        let findings = engine.run(vec![
            det(
                "prod",
                "CVE-V",
                "torda",
                DetectionMethod::Authenticated,
                None,
                0.95,
            ),
            det(
                "dev",
                "CVE-V",
                "torda",
                DetectionMethod::Authenticated,
                None,
                0.95,
            ),
        ]);
        assert_eq!(findings.len(), 2, "same CVE on two assets -> two findings");
        let prod = findings
            .iter()
            .find(|f| f.identity.asset_id == "prod")
            .unwrap();
        let dev = findings
            .iter()
            .find(|f| f.identity.asset_id == "dev")
            .unwrap();
        assert!(
            prod.score.r > dev.score.r,
            "prod (crown-jewel, internet-facing) scores higher than isolated dev"
        );
        assert_eq!(prod.decision, Decision::Act);
        assert!(matches!(dev.decision, Decision::Track | Decision::Defer));
    }

    #[test]
    fn finding_id_is_deterministic_from_identity() {
        let id = Identity {
            asset_id: "a".into(),
            vuln_id: "CVE-1".into(),
            component: "openssl".into(),
            location: "dpkg".into(),
        };
        assert_eq!(finding_id_for(&id), "a|CVE-1|openssl|dpkg");
    }

    #[test]
    fn tv3_vex_not_affected_suppresses() {
        use torda_findings::FindingState;
        let mut e = HashMap::new();
        e.insert(
            "CVE-Z".to_string(),
            enr(
                9.8,
                0.9,
                ExploitMaturity::InTheWild,
                false,
                VexStatus::NotAffected,
            ),
        );
        let enrichment = MapEnrichment(e);
        let assets = MapAssetContext {
            by_asset: HashMap::new(),
            default: ctx(true, Criticality::CrownJewel, false),
        };
        let engine = Engine::new(&enrichment, &assets);
        let findings = engine.run(vec![det(
            "host-A",
            "CVE-Z",
            "torda",
            DetectionMethod::Authenticated,
            None,
            0.95,
        )]);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].status,
            FindingState::Suppressed,
            "VEX not_affected -> Suppressed"
        );
        assert_eq!(findings[0].score.r, 0, "reach 0 -> R 0 even at CVSS 9.8");
    }

    #[test]
    fn affected_finding_stays_open() {
        use torda_findings::FindingState;
        let mut e = HashMap::new();
        e.insert(
            "CVE-Q".to_string(),
            enr(
                7.0,
                0.2,
                ExploitMaturity::Functional,
                false,
                VexStatus::Affected,
            ),
        );
        let enrichment = MapEnrichment(e);
        let assets = MapAssetContext {
            by_asset: HashMap::new(),
            default: ctx(false, Criticality::Normal, false),
        };
        let engine = Engine::new(&enrichment, &assets);
        let findings = engine.run(vec![det(
            "host-A",
            "CVE-Q",
            "torda",
            DetectionMethod::Authenticated,
            None,
            0.95,
        )]);
        assert_eq!(findings[0].status, FindingState::Open);
    }
}
