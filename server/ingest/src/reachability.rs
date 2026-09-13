//! Runtime-confirmed reachability: join `RUNTIME_MODULE_LOAD` (9003) observations
//! against the SBOM's per-package library files to decide which packages had
//! their code **actually loaded at runtime**.
//!
//! This is the reachability *logic* — the moat — kept server-side. The agent
//! (Apache) only emits the raw signals: the SBOM (5020) now carries each
//! package's provided `libraries`, and `torda-mod-libload` emits one 9003 per
//! distinct shared library loaded. Here we join them per asset:
//! - `has_data(asset)` — the asset produced ≥1 `9003` (we had runtime visibility);
//!   without it, absence is NOT evidence and the engine records
//!   `runtime_reachable = None`.
//! - a `(asset, package)` is **confirmed** iff any of that package's library
//!   files (from the SBOM) was observed loaded on that asset.
//!
//! The engine consumes this as an [`torda_findings_engine::input::ReachabilitySource`]
//! and applies it **upgrade-only** (it can raise `reach`, never lower it).
//!
//! Matching is by exact library path (the loader opens the same absolute path
//! dpkg records). A miss is safe: under upgrade-only it simply leaves the score
//! at its VEX baseline.

use std::collections::{HashMap, HashSet};

use torda_findings::Identity;
use torda_findings_engine::input::ReachabilitySource;
use torda_ocsf::OcsfEnvelope;

/// The reachability view built from one OCSF batch.
#[derive(Default)]
pub struct RuntimeReachability {
    /// Assets that produced at least one 9003 observation (we had visibility).
    assets_with_data: HashSet<String>,
    /// Confirmed `(asset_id, package name)` pairs — a provided library was loaded.
    confirmed: HashSet<(String, String)>,
}

impl RuntimeReachability {
    /// Build the reachability view from a batch: read library-load observations
    /// (9003) and the SBOM's per-package libraries (5020), then join per asset.
    pub fn from_envelopes(envelopes: &[OcsfEnvelope]) -> Self {
        // Per asset: the set of library paths observed loaded at runtime.
        let mut loaded: HashMap<String, HashSet<String>> = HashMap::new();
        // Per asset: (package name, its provided library paths) from the SBOM.
        let mut pkg_libs: HashMap<String, Vec<(String, Vec<String>)>> = HashMap::new();

        for env in envelopes {
            let asset = env.device.hostname.clone();
            if env.class_uid == torda_ocsf::class::RUNTIME_MODULE_LOAD {
                if let Some(path) = env.data["module"]["path"].as_str() {
                    loaded.entry(asset).or_default().insert(path.to_string());
                }
            } else if env.class_uid == torda_ocsf::class::SOFTWARE_INVENTORY_INFO {
                if let Some(components) = env.data["sbom"]["components"].as_array() {
                    let entry = pkg_libs.entry(asset).or_default();
                    for comp in components {
                        let Some(name) = comp["name"].as_str().filter(|n| !n.is_empty()) else {
                            continue;
                        };
                        let libs: Vec<String> = comp["libraries"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default();
                        if !libs.is_empty() {
                            entry.push((name.to_string(), libs));
                        }
                    }
                }
            }
        }

        // Join: a package is confirmed on an asset if any of its libraries was
        // among that asset's observed loads.
        let mut assets_with_data = HashSet::new();
        let mut confirmed = HashSet::new();
        for (asset, loaded_paths) in &loaded {
            assets_with_data.insert(asset.clone());
            if let Some(pkgs) = pkg_libs.get(asset) {
                for (name, libs) in pkgs {
                    if libs.iter().any(|l| loaded_paths.contains(l)) {
                        confirmed.insert((asset.clone(), name.clone()));
                    }
                }
            }
        }

        Self {
            assets_with_data,
            confirmed,
        }
    }
}

impl ReachabilitySource for RuntimeReachability {
    fn has_data(&self, asset_id: &str) -> bool {
        self.assets_with_data.contains(asset_id)
    }
    fn confirmed(&self, id: &Identity) -> bool {
        self.confirmed
            .contains(&(id.asset_id.clone(), id.component.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use torda_ocsf::{class, Device, Metadata, OcsfEnvelope};

    fn env(class_uid: u32, hostname: &str, data: serde_json::Value) -> OcsfEnvelope {
        OcsfEnvelope::new(
            class_uid,
            "test",
            Metadata {
                product: "torda".into(),
                version: "0".into(),
                tenant_id: "t".into(),
            },
            Device {
                hostname: hostname.into(),
                os: "Linux".into(),
                os_version: "1".into(),
            },
            data,
        )
    }

    fn sbom(hostname: &str, name: &str, libs: &[&str]) -> OcsfEnvelope {
        env(
            class::SOFTWARE_INVENTORY_INFO,
            hostname,
            serde_json::json!({
                "sbom": { "components": [
                    { "name": name, "version": "1", "source": "dpkg", "libraries": libs }
                ] }
            }),
        )
    }

    fn load(hostname: &str, path: &str) -> OcsfEnvelope {
        env(
            class::RUNTIME_MODULE_LOAD,
            hostname,
            serde_json::json!({ "module": { "path": path }, "pid": 1, "image": "x" }),
        )
    }

    fn id(asset: &str, component: &str) -> Identity {
        Identity {
            asset_id: asset.into(),
            vuln_id: "CVE-1".into(),
            component: component.into(),
            location: "dpkg".into(),
        }
    }

    #[test]
    fn loaded_library_confirms_its_package() {
        let batch = vec![
            sbom(
                "host-A",
                "openssl",
                &["/usr/lib/x86_64-linux-gnu/libssl.so.3"],
            ),
            load("host-A", "/usr/lib/x86_64-linux-gnu/libssl.so.3"),
        ];
        let r = RuntimeReachability::from_envelopes(&batch);
        assert!(r.has_data("host-A"));
        assert!(r.confirmed(&id("host-A", "openssl")));
    }

    #[test]
    fn unloaded_package_is_not_confirmed_even_with_data() {
        let batch = vec![
            sbom("host-A", "openssl", &["/usr/lib/libssl.so.3"]),
            sbom("host-A", "zlib", &["/usr/lib/libz.so.1"]),
            load("host-A", "/usr/lib/libssl.so.3"), // only openssl loaded
        ];
        let r = RuntimeReachability::from_envelopes(&batch);
        assert!(r.confirmed(&id("host-A", "openssl")));
        assert!(!r.confirmed(&id("host-A", "zlib")), "zlib was never loaded");
    }

    #[test]
    fn asset_with_no_load_observations_has_no_data() {
        // SBOM present, but no 9003 for this asset -> no runtime visibility.
        let batch = vec![sbom("host-B", "openssl", &["/usr/lib/libssl.so.3"])];
        let r = RuntimeReachability::from_envelopes(&batch);
        assert!(!r.has_data("host-B"));
        assert!(!r.confirmed(&id("host-B", "openssl")));
    }

    #[test]
    fn load_of_a_path_not_in_any_package_confirms_nothing() {
        let batch = vec![
            sbom("host-A", "openssl", &["/usr/lib/libssl.so.3"]),
            load("host-A", "/opt/custom/libwhatever.so"),
        ];
        let r = RuntimeReachability::from_envelopes(&batch);
        assert!(r.has_data("host-A"), "we still had visibility");
        assert!(!r.confirmed(&id("host-A", "openssl")));
    }
}
