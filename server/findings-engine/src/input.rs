//! Engine inputs: a raw detection and the injected enrichment / asset-context
//! sources. The traits keep the engine pure; real feed-sync plugs in later.
use std::collections::HashMap;
use torda_findings::{AssetContext, DetectionMethod, Enrichment, Identity};

/// A single raw vulnerability detection from one source, before correlation.
/// `reported_severity` is the source's label — kept for audit, never scored.
#[derive(Clone, Debug, PartialEq)]
pub struct RawDetection {
    pub identity: Identity,
    pub source: String,
    pub method: DetectionMethod,
    pub reported_severity: Option<String>,
    pub confidence: f32,
    pub remediation_key: String,
}

/// Looks up enrichment (NVD/EPSS/KEV/exploit/VEX) by vuln id. The real
/// feed-synced source (server/enrichment) implements this later.
pub trait EnrichmentSource {
    fn lookup(&self, vuln_id: &str) -> Option<Enrichment>;
}

/// Supplies per-asset business context (criticality, exposure flags).
pub trait AssetContextSource {
    fn context(&self, asset_id: &str) -> AssetContext;
}

/// In-memory enrichment fixture, keyed by vuln id.
#[derive(Default)]
pub struct MapEnrichment(pub HashMap<String, Enrichment>);

impl EnrichmentSource for MapEnrichment {
    fn lookup(&self, vuln_id: &str) -> Option<Enrichment> {
        self.0.get(vuln_id).cloned()
    }
}

/// In-memory asset-context fixture with a default for unknown assets.
pub struct MapAssetContext {
    pub by_asset: HashMap<String, AssetContext>,
    pub default: AssetContext,
}

impl AssetContextSource for MapAssetContext {
    fn context(&self, asset_id: &str) -> AssetContext {
        self.by_asset
            .get(asset_id)
            .cloned()
            .unwrap_or_else(|| self.default.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use torda_findings::{Criticality, ExploitMaturity, VexStatus};

    fn sample_enrichment() -> Enrichment {
        Enrichment {
            cvss_vector: None,
            cvss_env: Some(7.4),
            epss: Some(0.83),
            epss_pct: Some(0.97),
            kev: true,
            exploit_maturity: ExploitMaturity::Weaponized,
            vex: VexStatus::Affected,
        }
    }

    #[test]
    fn map_enrichment_looks_up_and_misses() {
        let mut m = HashMap::new();
        m.insert("CVE-2024-0001".to_string(), sample_enrichment());
        let src = MapEnrichment(m);
        assert_eq!(src.lookup("CVE-2024-0001"), Some(sample_enrichment()));
        assert_eq!(src.lookup("CVE-9999-9999"), None);
    }

    #[test]
    fn map_asset_context_falls_back_to_default() {
        let crown = AssetContext {
            internet_facing: true,
            criticality: Criticality::CrownJewel,
            compensating_controls: false,
        };
        let dev = AssetContext {
            internet_facing: false,
            criticality: Criticality::Low,
            compensating_controls: true,
        };
        let mut by_asset = HashMap::new();
        by_asset.insert("prod-1".to_string(), crown.clone());
        let src = MapAssetContext {
            by_asset,
            default: dev.clone(),
        };
        assert_eq!(src.context("prod-1"), crown);
        assert_eq!(src.context("unknown"), dev);
    }
}
