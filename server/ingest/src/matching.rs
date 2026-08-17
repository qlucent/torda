//! CVE matching: turn an agent OCSF SBOM (class 5020) into engine detections by
//! matching each component (name, version) against a fixture CVE feed. The agent
//! is an authenticated source (confidence 0.95); the real feed-synced matcher
//! replaces `CveFeed` later.
use torda_findings::{DetectionMethod, Identity};
use torda_findings_engine::input::RawDetection;
use torda_ocsf::OcsfEnvelope;

use crate::cve_source::CveSource;

/// One CVE affecting a specific package name+version, with the fix that closes it.
#[derive(Clone, Debug, PartialEq)]
pub struct CveHit {
    pub name: String,
    pub version: String,
    pub vuln_id: String,
    pub remediation_key: String,
}

/// Fixture CVE feed. A component `(name, version)` matches the hits whose name
/// AND version equal it. The real server/enrichment feed replaces this later.
#[derive(Default)]
pub struct CveFeed(pub Vec<CveHit>);

impl CveFeed {
    pub fn matches(&self, name: &str, version: &str) -> Vec<&CveHit> {
        self.0
            .iter()
            .filter(|h| h.name == name && h.version == version)
            .collect()
    }
}

/// Builds detections from ONE agent SBOM envelope (OCSF Software Inventory,
/// class 5020). Non-SBOM envelopes yield no detections. The agent is an
/// authenticated source (confidence 0.95); `asset_id` = device hostname;
/// `location` = the package source (dpkg/rpm/registry).
///
/// Queries a [`CveSource`] — the exact-match [`CveFeed`] fixture or the
/// range-aware `OsvSource` — with each component's `(source, name, version)`.
pub fn detections_from_sbom(env: &OcsfEnvelope, cves: &dyn CveSource) -> Vec<RawDetection> {
    if env.class_uid != torda_ocsf::class::SOFTWARE_INVENTORY_INFO {
        return Vec::new();
    }
    let asset_id = env.device.hostname.clone();
    // Host OS from the ENVELOPE's device (never a trusted external label): it
    // scopes dpkg matching to the host's own distro so a Debian host is not
    // flagged by a Ubuntu advisory (or vice versa).
    let os = env.device.os.as_str();
    let os_version = env.device.os_version.as_str();
    let components = env.data["sbom"]["components"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut out = Vec::new();
    for c in &components {
        let name = c["name"].as_str().unwrap_or_default();
        let version = c["version"].as_str().unwrap_or_default();
        let source = c["source"].as_str().unwrap_or_default();
        for hit in cves.hits_for(source, os, os_version, name, version) {
            out.push(RawDetection {
                identity: Identity {
                    asset_id: asset_id.clone(),
                    vuln_id: hit.vuln_id.clone(),
                    component: name.to_string(),
                    location: source.to_string(),
                },
                source: "torda".to_string(),
                method: DetectionMethod::Authenticated,
                reported_severity: None,
                confidence: 0.95,
                remediation_key: hit.remediation_key.clone(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cve_source::OsvSource;
    use torda_ocsf::{class, Device, Metadata};

    fn sbom_env(hostname: &str, components: serde_json::Value) -> OcsfEnvelope {
        sbom_env_os(hostname, "Test", "1", components)
    }

    fn sbom_env_os(
        hostname: &str,
        os: &str,
        os_version: &str,
        components: serde_json::Value,
    ) -> OcsfEnvelope {
        OcsfEnvelope::new(
            class::SOFTWARE_INVENTORY_INFO,
            "Software Inventory Info",
            Metadata {
                product: "torda".into(),
                version: "0".into(),
                tenant_id: "t".into(),
            },
            Device {
                hostname: hostname.into(),
                os: os.into(),
                os_version: os_version.into(),
            },
            serde_json::json!({ "sbom": { "format": "torda-native", "components": components, "component_count": 0 } }),
        )
    }

    fn feed() -> CveFeed {
        CveFeed(vec![CveHit {
            name: "openssl".into(),
            version: "3.0.2".into(),
            vuln_id: "CVE-2022-3602".into(),
            remediation_key: "upgrade:openssl>=3.0.14".into(),
        }])
    }

    #[test]
    fn matches_component_to_detection() {
        let env = sbom_env(
            "host-1",
            serde_json::json!([
                {"name":"openssl","version":"3.0.2","source":"dpkg"},
                {"name":"glibc","version":"2.39","source":"dpkg"}
            ]),
        );
        let dets = detections_from_sbom(&env, &feed());
        assert_eq!(dets.len(), 1, "only openssl matches the feed");
        let d = &dets[0];
        assert_eq!(
            d.identity,
            Identity {
                asset_id: "host-1".into(),
                vuln_id: "CVE-2022-3602".into(),
                component: "openssl".into(),
                location: "dpkg".into(),
            }
        );
        assert_eq!(d.source, "torda");
        assert_eq!(d.method, DetectionMethod::Authenticated);
        assert_eq!(d.reported_severity, None);
        assert_eq!(d.confidence, 0.95);
        assert_eq!(d.remediation_key, "upgrade:openssl>=3.0.14");
    }

    #[test]
    fn version_mismatch_does_not_match() {
        let env = sbom_env(
            "h",
            serde_json::json!([{"name":"openssl","version":"3.0.99","source":"dpkg"}]),
        );
        assert!(detections_from_sbom(&env, &feed()).is_empty());
    }

    #[test]
    fn envelope_os_scopes_matching_to_host_distro() {
        // Same dpkg package on two distros with different fixed versions. The
        // host OS comes from the ENVELOPE's device, and scopes matching so a
        // Debian host is not flagged by the Ubuntu-only advisory (and vice versa).
        let osv = OsvSource::from_json(
            r#"[
              { "id": "DEB-FOO", "affected": [
                { "package": {"ecosystem":"Debian:12","name":"foo"},
                  "ranges": [ {"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0-1"}]} ] } ] },
              { "id": "UBU-FOO", "affected": [
                { "package": {"ecosystem":"Ubuntu:22.04:LTS","name":"foo"},
                  "ranges": [ {"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0-2"}]} ] } ] }
            ]"#,
        )
        .unwrap();
        let components = serde_json::json!([{"name":"foo","version":"1.0-1","source":"dpkg"}]);

        // Debian host at 1.0-1: patched per Debian, must NOT pick up the Ubuntu advisory.
        let deb = sbom_env_os("deb-host", "Debian", "12", components.clone());
        assert!(detections_from_sbom(&deb, &osv).is_empty());

        // Ubuntu host at 1.0-1: still vulnerable per Ubuntu (fixed 1.0-2).
        let ubu = sbom_env_os("ubu-host", "Ubuntu", "22.04", components);
        let dets = detections_from_sbom(&ubu, &osv);
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].identity.vuln_id, "UBU-FOO");
    }

    #[test]
    fn non_sbom_envelope_yields_no_detections() {
        let mut env = sbom_env(
            "h",
            serde_json::json!([{"name":"openssl","version":"3.0.2","source":"dpkg"}]),
        );
        env.class_uid = class::INVENTORY_INFO; // 5001, not the SBOM class
        assert!(detections_from_sbom(&env, &feed()).is_empty());
    }

    #[test]
    fn windows_registry_sbom_matches_through_nvd() {
        // End-to-end at the matching layer: a Windows `registry` SBOM component
        // (DisplayName + DisplayVersion) resolves to an NVD detection with the
        // full identity + fix key. The un-vulnerable 7-Zip (>= fixed) does not.
        use crate::nvd_source::NvdSource;
        let nvd = NvdSource::from_json(
            r#"[ { "id": "CVE-WIN-1", "affected_windows": [
              { "product": "putty", "aliases": ["putty"], "ranges": [ {"fixed":"0.81"} ] } ] } ]"#,
        )
        .unwrap();
        let env = sbom_env_os(
            "win-host",
            "Windows",
            "11",
            serde_json::json!([
                {"name":"PuTTY release 0.80","version":"0.80","source":"registry"},
                {"name":"7-Zip 24.08 (x64)","version":"24.08","source":"registry"}
            ]),
        );
        let dets = detections_from_sbom(&env, &nvd);
        assert_eq!(dets.len(), 1, "only the vulnerable PuTTY matches");
        let d = &dets[0];
        assert_eq!(d.identity.vuln_id, "CVE-WIN-1");
        assert_eq!(d.identity.component, "PuTTY release 0.80");
        assert_eq!(d.identity.location, "registry");
        assert_eq!(d.remediation_key, "upgrade:putty>=0.81");
        assert_eq!(d.method, DetectionMethod::Authenticated);
        assert_eq!(d.confidence, 0.95);
    }
}
