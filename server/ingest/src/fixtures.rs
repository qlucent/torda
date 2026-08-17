//! Offline fixtures for the ingest bin + the end-to-end gate: a small CVE feed,
//! enrichment (NVD/EPSS/KEV/VEX stand-in), and asset context. These stand in for
//! the real feed-synced sources until a later slice.
use std::collections::HashMap;
use torda_findings::{AssetContext, Criticality, Enrichment, ExploitMaturity, VexStatus};
use torda_findings_engine::input::{MapAssetContext, MapEnrichment};

use crate::matching::{CveFeed, CveHit};

/// A small, deterministic CVE feed matching the agent's sample packages.
pub fn default_feed() -> CveFeed {
    CveFeed(vec![
        CveHit {
            name: "openssl".into(),
            version: "3.0.2".into(),
            vuln_id: "CVE-2022-3602".into(),
            remediation_key: "upgrade:openssl>=3.0.14".into(),
        },
        CveHit {
            name: "openssh-server".into(),
            version: "9.6p1".into(),
            vuln_id: "CVE-2024-6387".into(),
            remediation_key: "upgrade:openssh-server>=9.8p1".into(),
        },
        CveHit {
            name: "glibc".into(),
            version: "2.39".into(),
            vuln_id: "CVE-2024-2961".into(),
            remediation_key: "upgrade:glibc>=2.40".into(),
        },
    ])
}

/// Offline enrichment fixture keyed by vuln id (stands in for NVD/EPSS/KEV/VEX).
pub fn default_enrichment() -> MapEnrichment {
    let mut m = HashMap::new();
    m.insert(
        "CVE-2022-3602".into(),
        Enrichment {
            cvss_vector: None,
            cvss_env: Some(7.5),
            epss: Some(0.4),
            epss_pct: None,
            kev: false,
            exploit_maturity: ExploitMaturity::Functional,
            vex: VexStatus::Affected,
        },
    );
    m.insert(
        "CVE-2024-6387".into(),
        Enrichment {
            cvss_vector: None,
            cvss_env: Some(8.1),
            epss: Some(0.6),
            epss_pct: None,
            kev: true,
            exploit_maturity: ExploitMaturity::Weaponized,
            vex: VexStatus::Affected,
        },
    );
    m.insert(
        "CVE-2024-2961".into(),
        Enrichment {
            cvss_vector: None,
            cvss_env: Some(9.0),
            epss: Some(0.5),
            epss_pct: None,
            kev: false,
            exploit_maturity: ExploitMaturity::Functional,
            vex: VexStatus::NotAffected,
        },
    );
    MapEnrichment(m)
}

/// Asset-context fixture: the default applies to any host (v0 uses hostname as
/// the asset id, so there are no per-asset overrides yet).
pub fn default_assets() -> MapAssetContext {
    MapAssetContext {
        by_asset: HashMap::new(),
        default: AssetContext {
            internet_facing: true,
            criticality: Criticality::High,
            compensating_controls: false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::run_ingest;
    use torda_findings::{Decision, FindingState};
    use torda_ocsf::OcsfEnvelope;

    // A real agent SBOM record (OCSF class 5020), exactly as the vuln module emits it.
    const AGENT_SBOM_NDJSON: &str = r#"{"class_uid":5020,"class_name":"Software Inventory Info","time":0,"severity_id":1,"metadata":{"product":"torda","version":"0.0.1","tenant_id":"t"},"device":{"hostname":"host-1","os":"Test","os_version":"1"},"data":{"sbom":{"format":"torda-native","components":[{"name":"openssl","version":"3.0.2","source":"dpkg"},{"name":"glibc","version":"2.39","source":"dpkg"},{"name":"openssh-server","version":"9.6p1","source":"dpkg"}],"component_count":3}}}"#;

    #[test]
    fn end_to_end_agent_sbom_to_scored_findings() {
        // agent SBOM in -> parse -> match -> engine -> report out. Deterministic.
        let env: OcsfEnvelope = serde_json::from_str(AGENT_SBOM_NDJSON).unwrap();
        let report = run_ingest(
            &[env],
            &default_feed(),
            &default_enrichment(),
            &default_assets(),
            &[],
        );

        // Three components match the feed -> three findings.
        assert_eq!(report.findings.len(), 3);

        // openssh-server's CVE is KEV -> ACT.
        let ssh = report
            .findings
            .iter()
            .find(|f| f.identity.component == "openssh-server")
            .unwrap();
        assert_eq!(ssh.decision, Decision::Act, "KEV forces ACT");

        // glibc's CVE is VEX not_affected -> Suppressed, R=0.
        let glibc = report
            .findings
            .iter()
            .find(|f| f.identity.component == "glibc")
            .unwrap();
        assert_eq!(glibc.status, FindingState::Suppressed);
        assert_eq!(glibc.score.r, 0);

        // Remediation items: openssl + openssh (glibc suppressed -> excluded).
        assert_eq!(report.remediation_items.len(), 2);
        let keys: Vec<&str> = report
            .remediation_items
            .iter()
            .map(|i| i.remediation_key.as_str())
            .collect();
        assert!(keys.contains(&"upgrade:openssl>=3.0.14"));
        assert!(keys.contains(&"upgrade:openssh-server>=9.8p1"));
        assert!(
            !keys.iter().any(|k| k.contains("glibc")),
            "suppressed glibc not in items"
        );
    }
}
