//! SSVC-style decision + SLA. KEV overrides: a
//! known-exploited, reachable, in-scope vuln is always ACT — never gated on EPSS.
use torda_findings::Decision;

/// Decision + SLA. KEV override fires first (§5): known-exploited + in scope +
/// reachable ⇒ ACT, regardless of R or EPSS. Otherwise thresholds on R apply.
pub fn decide(r: u8, kev: bool, in_scope: bool, reach: f32) -> (Decision, u32) {
    let decision = if (kev && in_scope && reach > 0.0) || r >= 70 {
        Decision::Act
    } else if r >= 40 {
        Decision::Attend
    } else if r >= 20 {
        Decision::Track
    } else {
        Decision::Defer
    };
    (decision, sla_hours(decision))
}

/// Default SLA hours per decision (v0): ACT 24-72h policy (v0: 48), ATTEND 1-2 weeks,
/// TRACK next maintenance, DEFER quarterly.
pub fn sla_hours(d: Decision) -> u32 {
    match d {
        Decision::Act => 48,
        Decision::Attend => 336,
        Decision::Track => 720,
        Decision::Defer => 2160,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kev_overrides_low_score_when_reachable() {
        // TV-2 / TV-5: low R but KEV + reachable -> ACT.
        let (d, sla) = decide(27, true, true, 1.0);
        assert_eq!(d, Decision::Act);
        assert_eq!(sla, 48);
    }

    #[test]
    fn kev_does_not_override_when_not_reachable() {
        // KEV but reach 0 (not_affected) -> falls through to thresholds; R low -> DEFER.
        let (d, _) = decide(10, true, true, 0.0);
        assert_eq!(d, Decision::Defer);
    }

    #[test]
    fn kev_does_not_override_out_of_scope() {
        let (d, _) = decide(10, true, false, 1.0);
        assert_eq!(d, Decision::Defer);
    }

    #[test]
    fn thresholds_map_score_to_decision() {
        assert_eq!(decide(70, false, true, 1.0).0, Decision::Act);
        assert_eq!(decide(69, false, true, 1.0).0, Decision::Attend);
        assert_eq!(decide(40, false, true, 1.0).0, Decision::Attend);
        assert_eq!(decide(39, false, true, 1.0).0, Decision::Track);
        assert_eq!(decide(20, false, true, 1.0).0, Decision::Track);
        assert_eq!(decide(19, false, true, 1.0).0, Decision::Defer);
    }

    #[test]
    fn sla_hours_per_decision() {
        assert_eq!(sla_hours(Decision::Act), 48);
        assert_eq!(sla_hours(Decision::Attend), 336);
        assert_eq!(sla_hours(Decision::Track), 720);
        assert_eq!(sla_hours(Decision::Defer), 2160);
    }
}
