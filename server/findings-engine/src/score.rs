//! Canonical risk recompute. Inputs are ONLY the
//! enrichment feed values and the asset context — never a source's severity
//! label. All weights are v0 constants, calibratable, kept explainable.
use torda_findings::{
    AssetContext, Criticality, Enrichment, ExploitMaturity, Score, ScoreExplain, VexStatus,
};

/// Exploit-maturity → likelihood weight (§4). v0.
pub fn exploit_maturity_weight(m: ExploitMaturity) -> f32 {
    match m {
        ExploitMaturity::None => 0.0,
        ExploitMaturity::Poc => 0.4,
        ExploitMaturity::Functional => 0.7,
        ExploitMaturity::Weaponized => 0.9,
        ExploitMaturity::InTheWild => 1.0,
    }
}

/// VEX reachability gate (§4): not_affected zeroes the score.
pub fn reach_gate(v: VexStatus) -> f32 {
    match v {
        VexStatus::Affected => 1.0,
        VexStatus::Unknown => 0.3,
        VexStatus::NotAffected => 0.0,
    }
}

/// Asset business value, 0.5..1.5 (v0).
pub fn criticality_weight(c: Criticality) -> f32 {
    match c {
        Criticality::CrownJewel => 1.5,
        Criticality::High => 1.2,
        Criticality::Normal => 0.9,
        Criticality::Low => 0.5,
    }
}

/// Exposure factor, 0.2..1.5 (v0): internet-facing raises it; compensating
/// controls halve it.
pub fn exposure_factor(ctx: &AssetContext) -> f32 {
    let mut e: f32 = if ctx.internet_facing { 1.4 } else { 0.8 };
    if ctx.compensating_controls {
        e *= 0.5;
    }
    e.clamp(0.2, 1.5)
}

/// Recomputes the canonical risk score from canonical inputs ONLY (§4). The
/// returned `explain` persists every factor so the score is auditable.
///   sev        = cvss_env / 10                              (0..1)
///   likelihood = max(epss, exploit_maturity_weight)         (0..1)
///   exposure   = exposure_factor(asset_ctx)                 (0.2..1.5)
///   crit       = criticality_weight(asset_ctx.criticality)  (0.5..1.5)
///   reach      = reach_gate(vex)                            (0 | 0.3 | 1)
///   R = round(100 * clamp01( sev * (0.4 + 0.6*likelihood) * exposure * crit * reach ))
pub fn recompute_score(enr: &Enrichment, ctx: &AssetContext) -> Score {
    recompute_score_with_reach(enr, ctx, reach_gate(enr.vex))
}

/// Like [`recompute_score`] but with the `reach` factor supplied by the caller
/// instead of derived from `enr.vex`. This is the seam runtime-confirmed
/// reachability uses to **upgrade** `reach` (e.g. VEX `Unknown` 0.3 → 1.0 once a
/// runtime observation confirms the component's library was loaded). All other
/// factors are identical to [`recompute_score`]. `explain.runtime_reachable` is
/// left `None` here — the engine sets it, since only the engine knows whether a
/// runtime observation was consulted.
pub fn recompute_score_with_reach(enr: &Enrichment, ctx: &AssetContext, reach: f32) -> Score {
    let sev = (enr.cvss_env.unwrap_or(0.0) / 10.0).clamp(0.0, 1.0);
    let likelihood = enr
        .epss
        .unwrap_or(0.0)
        .max(exploit_maturity_weight(enr.exploit_maturity))
        .clamp(0.0, 1.0);
    let exposure = exposure_factor(ctx);
    let crit = criticality_weight(ctx.criticality);

    let raw = (sev * (0.4 + 0.6 * likelihood) * exposure * crit * reach).clamp(0.0, 1.0);
    Score {
        r: (100.0 * raw).round() as u8,
        explain: ScoreExplain {
            sev,
            likelihood,
            exposure,
            crit,
            reach,
            runtime_reachable: None,
        },
    }
}

/// Compliance recompute: swaps CVSS-derived `sev` for the control `weight` and
/// drops the exploit-likelihood / VEX-reach terms (a failed control is a definite
/// misconfiguration, not a probabilistic exploit). Reuses the same exposure and
/// criticality factors as the vuln score, so compliance findings score on the
/// same asset-context axis. `explain` records `likelihood`/`reach` as 1.0 (no-ops)
/// so the multiplicative structure stays parallel and auditable.
///   R = round(100 * clamp01( weight * exposure_factor(ctx) * criticality_weight(ctx) ))
pub fn recompute_compliance_score(weight: f32, ctx: &AssetContext) -> Score {
    let sev = weight.clamp(0.0, 1.0);
    let exposure = exposure_factor(ctx);
    let crit = criticality_weight(ctx.criticality);
    let raw = (sev * exposure * crit).clamp(0.0, 1.0);
    Score {
        r: (100.0 * raw).round() as u8,
        explain: ScoreExplain {
            sev,
            likelihood: 1.0,
            exposure,
            crit,
            reach: 1.0,
            runtime_reachable: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enr(
        cvss_env: Option<f32>,
        epss: Option<f32>,
        m: ExploitMaturity,
        vex: VexStatus,
    ) -> Enrichment {
        Enrichment {
            cvss_vector: None,
            cvss_env,
            epss,
            epss_pct: None,
            kev: false,
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

    #[test]
    fn weight_tables_match_spec() {
        assert_eq!(exploit_maturity_weight(ExploitMaturity::None), 0.0);
        assert_eq!(exploit_maturity_weight(ExploitMaturity::Poc), 0.4);
        assert_eq!(exploit_maturity_weight(ExploitMaturity::Functional), 0.7);
        assert_eq!(exploit_maturity_weight(ExploitMaturity::Weaponized), 0.9);
        assert_eq!(exploit_maturity_weight(ExploitMaturity::InTheWild), 1.0);
        assert_eq!(reach_gate(VexStatus::Affected), 1.0);
        assert_eq!(reach_gate(VexStatus::Unknown), 0.3);
        assert_eq!(reach_gate(VexStatus::NotAffected), 0.0);
        assert_eq!(criticality_weight(Criticality::CrownJewel), 1.5);
        assert_eq!(criticality_weight(Criticality::High), 1.2);
        assert_eq!(criticality_weight(Criticality::Normal), 0.9);
        assert_eq!(criticality_weight(Criticality::Low), 0.5);
    }

    #[test]
    fn exposure_factor_reflects_flags() {
        assert!((exposure_factor(&ctx(true, Criticality::Normal, false)) - 1.4).abs() < 1e-6);
        assert!((exposure_factor(&ctx(false, Criticality::Normal, false)) - 0.8).abs() < 1e-6);
        // compensating controls halve exposure (internet-facing 1.4 -> 0.7).
        assert!((exposure_factor(&ctx(true, Criticality::Normal, true)) - 0.7).abs() < 1e-6);
    }

    #[test]
    fn recompute_uses_canonical_inputs() {
        // sev=0.5, likelihood=max(0.5,0.4)=0.5, exposure=0.8, crit=0.9, reach=1.0
        // raw = 0.5 * (0.4 + 0.6*0.5) * 0.8 * 0.9 * 1.0 = 0.5*0.7*0.8*0.9 = 0.252 -> R=25
        let s = recompute_score(
            &enr(
                Some(5.0),
                Some(0.5),
                ExploitMaturity::Poc,
                VexStatus::Affected,
            ),
            &ctx(false, Criticality::Normal, false),
        );
        assert_eq!(s.r, 25);
        assert!((s.explain.sev - 0.5).abs() < 1e-6);
        assert!((s.explain.likelihood - 0.5).abs() < 1e-6);
        assert!((s.explain.exposure - 0.8).abs() < 1e-6);
        assert!((s.explain.crit - 0.9).abs() < 1e-6);
        assert!((s.explain.reach - 1.0).abs() < 1e-6);
    }

    #[test]
    fn likelihood_takes_max_of_epss_and_maturity() {
        // epss 0.2 but weaponized (0.9) -> likelihood 0.9
        let s = recompute_score(
            &enr(
                Some(10.0),
                Some(0.2),
                ExploitMaturity::Weaponized,
                VexStatus::Affected,
            ),
            &ctx(false, Criticality::Normal, false),
        );
        assert!((s.explain.likelihood - 0.9).abs() < 1e-6);
    }

    #[test]
    fn not_affected_gates_score_to_zero() {
        let s = recompute_score(
            &enr(
                Some(9.8),
                Some(0.9),
                ExploitMaturity::InTheWild,
                VexStatus::NotAffected,
            ),
            &ctx(true, Criticality::CrownJewel, false),
        );
        assert_eq!(s.r, 0, "VEX not_affected -> reach 0 -> R 0");
        assert_eq!(s.explain.reach, 0.0);
    }

    #[test]
    fn score_clamps_at_100() {
        // High everything; the product exceeds 1.0 and must clamp to R=100.
        let s = recompute_score(
            &enr(
                Some(10.0),
                Some(1.0),
                ExploitMaturity::InTheWild,
                VexStatus::Affected,
            ),
            &ctx(true, Criticality::CrownJewel, false),
        );
        assert_eq!(s.r, 100);
    }

    #[test]
    fn compliance_score_is_weight_times_exposure_times_crit() {
        // weight 0.5, internal (exposure 0.8), Normal crit (0.9) -> 0.5*0.8*0.9=0.36 -> R=36
        let s = recompute_compliance_score(0.5, &ctx(false, Criticality::Normal, false));
        assert_eq!(s.r, 36);
        assert_eq!(s.explain.sev, 0.5);
        assert_eq!(s.explain.likelihood, 1.0);
        assert_eq!(s.explain.reach, 1.0);
        assert!((s.explain.exposure - 0.8).abs() < 1e-6);
        assert!((s.explain.crit - 0.9).abs() < 1e-6);
    }

    #[test]
    fn compliance_score_saturates_at_100() {
        // weight 0.6, internet (1.4), High (1.2) -> 1.008 -> clamp -> R=100
        let s = recompute_compliance_score(0.6, &ctx(true, Criticality::High, false));
        assert_eq!(s.r, 100);
    }

    #[test]
    fn compliance_score_ignores_no_cvss_or_vex() {
        // Never touches Enrichment — a low weight on a low-value asset scores low.
        let s = recompute_compliance_score(0.2, &ctx(false, Criticality::Low, true));
        // 0.2 * (0.8*0.5 compensating) * 0.5 = 0.2*0.4*0.5 = 0.04 -> R=4
        assert_eq!(s.r, 4);
    }
}
