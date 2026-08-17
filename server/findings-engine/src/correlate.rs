//! Correlation: detections sharing an identity
//! collapse into one finding; provenance from every source is retained, ordered
//! highest-confidence first (authenticated agent > authenticated scanner >
//! unauthenticated scan). Identity is the dedup key.
use crate::input::RawDetection;
use std::collections::BTreeMap;
use torda_findings::{Identity, Provenance};

/// One finding's correlated detections: a single identity with provenance from
/// every reporting source, plus the remediation key.
#[derive(Clone, Debug, PartialEq)]
pub struct Correlated {
    pub identity: Identity,
    pub provenance: Vec<Provenance>,
    pub remediation_key: String,
}

/// Collapses detections sharing an identity into one `Correlated`. Uses a
/// `BTreeMap` so output order is deterministic (by identity). Within a finding,
/// provenance is ordered highest-confidence first, and the remediation key is
/// taken from the highest-confidence detection.
pub fn correlate(detections: Vec<RawDetection>) -> Vec<Correlated> {
    let mut groups: BTreeMap<Identity, Vec<RawDetection>> = BTreeMap::new();
    for d in detections {
        groups.entry(d.identity.clone()).or_default().push(d);
    }
    groups
        .into_iter()
        .map(|(identity, mut dets)| {
            dets.sort_by(|a, b| {
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            let remediation_key = dets[0].remediation_key.clone();
            let provenance = dets
                .into_iter()
                .map(|d| Provenance {
                    source: d.source,
                    method: d.method,
                    reported_severity: d.reported_severity,
                    confidence: d.confidence,
                })
                .collect();
            Correlated {
                identity,
                provenance,
                remediation_key,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use torda_findings::DetectionMethod;

    fn ident() -> Identity {
        Identity {
            asset_id: "host-A".into(),
            vuln_id: "CVE-2024-X".into(),
            component: "openssl".into(),
            location: "dpkg".into(),
        }
    }
    fn det(source: &str, method: DetectionMethod, sev: Option<&str>, conf: f32) -> RawDetection {
        RawDetection {
            identity: ident(),
            source: source.into(),
            method,
            reported_severity: sev.map(|s| s.into()),
            confidence: conf,
            remediation_key: "upgrade:openssl>=3.0.14".into(),
        }
    }

    #[test]
    fn three_sources_collapse_to_one_finding_highest_confidence_first() {
        // TV-1: agent(auth, .95) + nessus(auth, "High", .8) + network(unauth, "Critical", .5)
        let mut agent = det("torda", DetectionMethod::Authenticated, None, 0.95);
        agent.remediation_key = "AGENT-FIX".into();
        let mut nessus = det("nessus", DetectionMethod::Authenticated, Some("High"), 0.8);
        nessus.remediation_key = "NESSUS-FIX".into();
        let mut network = det(
            "network-scan",
            DetectionMethod::Unauthenticated,
            Some("Critical"),
            0.5,
        );
        network.remediation_key = "NETWORK-FIX".into();
        let out = correlate(vec![nessus, network, agent]);
        assert_eq!(out.len(), 1, "same identity -> one finding");
        let c = &out[0];
        assert_eq!(c.provenance.len(), 3, "all sources retained as provenance");
        assert_eq!(c.provenance[0].source, "torda", "highest confidence first");
        assert_eq!(c.provenance[0].confidence, 0.95);
        assert_eq!(
            out[0].remediation_key, "AGENT-FIX",
            "remediation key comes from the highest-confidence detection"
        );
    }

    #[test]
    fn distinct_identities_stay_separate() {
        let mut a = det("agent", DetectionMethod::Authenticated, None, 0.9);
        let mut b = det("agent", DetectionMethod::Authenticated, None, 0.9);
        a.identity.vuln_id = "CVE-1".into();
        b.identity.vuln_id = "CVE-2".into();
        assert_eq!(correlate(vec![a, b]).len(), 2);
    }
}
