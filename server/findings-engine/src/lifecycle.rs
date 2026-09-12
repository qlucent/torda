//! Regression handling: a fresh finding whose
//! identity matches a prior CLOSED finding is Reopened, not created anew.
use std::collections::HashMap;
use torda_findings::{Finding, FindingState, Identity};

/// Reconciles fresh findings against prior state and stamps lifecycle timestamps.
///
/// Two jobs:
/// 1. **Regression:** a fresh Open finding whose identity matches a prior CLOSED
///    finding becomes `Reopened` (not created anew), and its `closed_at` clears.
/// 2. **Lifecycle timestamps** (from `batch_time` — the batch's event time, so it
///    is deterministic and replayable, never a wall clock): a brand-new finding
///    gets `first_seen = last_seen = batch_time`; a recurring one preserves the
///    prior `first_seen` and bumps `last_seen`. `closed_at` is set elsewhere (where
///    a finding transitions to Closed) and preserved on carry-forward.
///
/// Scope: it does NOT carry forward Accepted/Suppressed status for continuing
/// findings — that is a later (wiring) concern (`store::carry_forward_ops_states`).
pub fn reconcile(prior: &[Finding], mut fresh: Vec<Finding>, batch_time: i64) -> Vec<Finding> {
    // Index prior findings by identity for O(1) lookup of prior state + timestamps.
    let prior_by_identity: HashMap<Identity, &Finding> =
        prior.iter().map(|f| (f.identity.clone(), f)).collect();
    for f in fresh.iter_mut() {
        match prior_by_identity.get(&f.identity) {
            Some(p) => {
                // Recurring identity: preserve the original first_seen; bump last_seen.
                // (`.or` covers a prior persisted before timestamps existed.)
                f.first_seen = p.first_seen.or(Some(batch_time));
                f.last_seen = Some(batch_time);
                // A fresh Open matching a prior CLOSED finding regressed -> Reopened.
                if f.status == FindingState::Open && p.status == FindingState::Closed {
                    f.status = FindingState::Reopened;
                    f.closed_at = None; // reopened -> no longer closed
                }
            }
            None => {
                // Brand-new finding this batch.
                f.first_seen = Some(batch_time);
                f.last_seen = Some(batch_time);
            }
        }
    }
    fresh
}

#[cfg(test)]
mod tests {
    use super::*;
    use torda_findings::{
        AssetContext, Criticality, Decision, DetectionMethod, Enrichment, ExploitMaturity,
        Identity, Provenance, Score, ScoreExplain, VexStatus,
    };

    fn finding(vuln: &str, status: FindingState) -> Finding {
        Finding {
            finding_id: format!("host-A|{vuln}"),
            identity: Identity {
                asset_id: "host-A".into(),
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
                cvss_env: Some(7.0),
                epss: Some(0.2),
                epss_pct: None,
                kev: false,
                exploit_maturity: ExploitMaturity::Functional,
                vex: VexStatus::Affected,
                feed_version: None,
            },
            asset_ctx: AssetContext {
                internet_facing: false,
                criticality: Criticality::Normal,
                compensating_controls: false,
            },
            score: Score {
                r: 41,
                explain: ScoreExplain {
                    sev: 0.7,
                    likelihood: 0.7,
                    exposure: 0.8,
                    crit: 0.9,
                    reach: 1.0,
                },
            },
            decision: Decision::Attend,
            sla_hours: 336,
            remediation_key: "upgrade:openssl>=3.0.14".into(),
            status,
            first_seen: None,
            last_seen: None,
            closed_at: None,
        }
    }

    #[test]
    fn tv7_closed_finding_reappears_is_reopened() {
        let prior = vec![finding("CVE-R", FindingState::Closed)];
        let fresh = vec![finding("CVE-R", FindingState::Open)];
        let out = reconcile(&prior, fresh, 1000);
        assert_eq!(out.len(), 1, "same identity -> not a second finding");
        assert_eq!(
            out[0].status,
            FindingState::Reopened,
            "closed + reappeared -> Reopened"
        );
        assert_eq!(
            out[0].finding_id, "host-A|CVE-R",
            "same finding id, not a new one"
        );
    }

    #[test]
    fn fresh_finding_with_no_closed_prior_stays_open() {
        let prior = vec![finding("CVE-OTHER", FindingState::Closed)];
        let fresh = vec![finding("CVE-NEW", FindingState::Open)];
        let out = reconcile(&prior, fresh, 1000);
        assert_eq!(out[0].status, FindingState::Open);
    }

    #[test]
    fn prior_open_finding_does_not_reopen() {
        // Only a CLOSED prior triggers reopen; an already-open prior does not change status.
        let prior = vec![finding("CVE-R", FindingState::Open)];
        let fresh = vec![finding("CVE-R", FindingState::Open)];
        assert_eq!(reconcile(&prior, fresh, 1000)[0].status, FindingState::Open);
    }

    #[test]
    fn new_finding_gets_first_and_last_seen_from_batch_time() {
        let fresh = vec![finding("CVE-NEW", FindingState::Open)];
        let out = reconcile(&[], fresh, 4242);
        assert_eq!(out[0].first_seen, Some(4242));
        assert_eq!(out[0].last_seen, Some(4242));
        assert_eq!(out[0].closed_at, None);
    }

    #[test]
    fn recurring_finding_preserves_first_seen_and_bumps_last_seen() {
        let mut prior = finding("CVE-R", FindingState::Open);
        prior.first_seen = Some(1000);
        prior.last_seen = Some(1000);
        let out = reconcile(&[prior], vec![finding("CVE-R", FindingState::Open)], 5000);
        assert_eq!(
            out[0].first_seen,
            Some(1000),
            "original open time preserved"
        );
        assert_eq!(
            out[0].last_seen,
            Some(5000),
            "last_seen bumped to this batch"
        );
    }

    #[test]
    fn reopen_preserves_first_seen_and_clears_closed_at() {
        let mut prior = finding("CVE-R", FindingState::Closed);
        prior.first_seen = Some(1000);
        prior.closed_at = Some(2000);
        let out = reconcile(&[prior], vec![finding("CVE-R", FindingState::Open)], 6000);
        assert_eq!(out[0].status, FindingState::Reopened);
        assert_eq!(
            out[0].first_seen,
            Some(1000),
            "keeps the original first_seen"
        );
        assert_eq!(out[0].last_seen, Some(6000));
        assert_eq!(out[0].closed_at, None, "reopened -> closed_at cleared");
    }

    #[test]
    fn prior_without_timestamps_reconciles_without_panic() {
        // Backward compat: a prior finding persisted before timestamps existed
        // (first_seen = None) recurs; first_seen falls back to the batch time.
        let prior = finding("CVE-R", FindingState::Open); // first_seen None
        let out = reconcile(&[prior], vec![finding("CVE-R", FindingState::Open)], 7000);
        assert_eq!(out[0].first_seen, Some(7000));
        assert_eq!(out[0].last_seen, Some(7000));
    }
}
