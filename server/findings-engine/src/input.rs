//! Engine inputs: a raw detection and the injected enrichment / asset-context /
//! reachability sources. The traits keep the engine pure; real feed-sync and
//! runtime-reachability sources plug in later.
use std::collections::{HashMap, HashSet};
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

/// Runtime-reachability signal: whether a finding's component was observed
/// **loaded at runtime**. It is **upgrade-only** — the engine uses it to
/// *confirm* (raise) a finding's `reach`, never to lower it.
///
/// `has_data` is load-bearing for honesty: it separates "we collected no runtime
/// telemetry for this asset" (absence is not evidence → the engine records
/// `runtime_reachable = None` and leaves `reach` at its VEX baseline) from "we
/// had telemetry but did not observe this component loaded" (`Some(false)`,
/// which still never lowers the score).
pub trait ReachabilitySource {
    /// Whether ANY runtime-reachability observation exists for this asset.
    fn has_data(&self, asset_id: &str) -> bool;
    /// Whether this finding's component was observed loaded at runtime.
    fn confirmed(&self, id: &Identity) -> bool;
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

/// In-memory reachability fixture: which assets produced any observation, and
/// which `(asset_id, component)` pairs were confirmed loaded.
#[derive(Default)]
pub struct MapReachability {
    pub assets_with_data: HashSet<String>,
    pub confirmed: HashSet<(String, String)>,
}

impl ReachabilitySource for MapReachability {
    fn has_data(&self, asset_id: &str) -> bool {
        self.assets_with_data.contains(asset_id)
    }
    fn confirmed(&self, id: &Identity) -> bool {
        self.confirmed
            .contains(&(id.asset_id.clone(), id.component.clone()))
    }
}

/// A reachability source with no data at all: `has_data` is always false, so
/// nothing is ever confirmed and the engine leaves every `reach` at its VEX
/// baseline. The safe default for ingest paths with no runtime telemetry.
pub struct NoReachability;

impl ReachabilitySource for NoReachability {
    fn has_data(&self, _asset_id: &str) -> bool {
        false
    }
    fn confirmed(&self, _id: &Identity) -> bool {
        false
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
            feed_version: None,
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

    fn id(asset: &str, component: &str) -> Identity {
        Identity {
            asset_id: asset.into(),
            vuln_id: "CVE-2024-0001".into(),
            component: component.into(),
            location: "dpkg".into(),
        }
    }

    #[test]
    fn map_reachability_confirms_only_observed_components_on_assets_with_data() {
        let mut src = MapReachability::default();
        src.assets_with_data.insert("host-A".into());
        src.confirmed.insert(("host-A".into(), "openssl".into()));

        // Observed component on an asset with data -> confirmed.
        assert!(src.has_data("host-A"));
        assert!(src.confirmed(&id("host-A", "openssl")));
        // Same asset, a different (unobserved) component -> not confirmed, but data exists.
        assert!(!src.confirmed(&id("host-A", "zlib")));
        // An asset with no telemetry at all -> no data, nothing confirmed.
        assert!(!src.has_data("host-B"));
        assert!(!src.confirmed(&id("host-B", "openssl")));
    }

    #[test]
    fn no_reachability_never_has_data_or_confirms() {
        let src = NoReachability;
        assert!(!src.has_data("host-A"));
        assert!(!src.confirmed(&id("host-A", "openssl")));
    }
}
