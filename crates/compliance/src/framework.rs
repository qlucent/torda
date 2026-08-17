//! Framework crosswalk: maps framework control ids to our library check ids. A
//! `Control` never names a framework; this mapping is the ONLY place check↔
//! framework knowledge lives, so one check can satisfy many framework controls
//! and adding a framework (P2b) is data, not code.

/// One row of the crosswalk: our library `check_id` satisfies `framework_control_id`.
#[derive(Clone, Debug, PartialEq)]
pub struct ControlMapping {
    pub check_id: String,
    pub framework_control_id: String,
}

/// A framework profile: the declarative crosswalk of framework control ids to
/// our check ids. Adding a framework is adding one of these — no check changes.
pub struct FrameworkProfile {
    pub framework: String,
    pub mappings: Vec<ControlMapping>,
}

impl FrameworkProfile {
    /// The framework control ids satisfied by the given check id (may be several).
    pub fn framework_ids_for(&self, check_id: &str) -> Vec<&str> {
        self.mappings
            .iter()
            .filter(|m| m.check_id == check_id)
            .map(|m| m.framework_control_id.as_str())
            .collect()
    }
}

/// The CIS Benchmark profile (v0 subset), mapping CIS control ids to our checks.
/// `sshd-root-login-disabled` satisfies two CIS controls — the one-to-many
/// crosswalk this slice proves.
pub fn cis_profile() -> FrameworkProfile {
    let map = |check: &str, cis: &str| ControlMapping {
        check_id: check.into(),
        framework_control_id: cis.into(),
    };
    FrameworkProfile {
        framework: "CIS".into(),
        mappings: vec![
            map("sshd-root-login-disabled", "CIS-5.2.8"),
            map("sshd-root-login-disabled", "CIS-5.2.10"),
            map("telnet-not-installed", "CIS-2.3.1"),
            map("password-max-days", "CIS-5.4.1.1"),
        ],
    }
}

/// Builds a profile from `(check_id, framework_control_id)` pairs.
fn profile(framework: &str, rows: &[(&str, &str)]) -> FrameworkProfile {
    FrameworkProfile {
        framework: framework.into(),
        mappings: rows
            .iter()
            .map(|(check, id)| ControlMapping {
                check_id: (*check).into(),
                framework_control_id: (*id).into(),
            })
            .collect(),
    }
}

/// NIST SP 800-53 Rev.5 (illustrative subset).
pub fn nist_800_53_profile() -> FrameworkProfile {
    profile(
        "NIST 800-53",
        &[
            ("sshd-root-login-disabled", "AC-6"),
            ("sshd-root-login-disabled", "AC-17"),
            ("telnet-not-installed", "CM-7"),
            ("password-max-days", "IA-5"),
        ],
    )
}

/// PCI-DSS v4.0 (illustrative subset).
pub fn pci_dss_profile() -> FrameworkProfile {
    profile(
        "PCI-DSS",
        &[
            ("sshd-root-login-disabled", "7.2.1"),
            ("telnet-not-installed", "2.2.4"),
            ("password-max-days", "8.3.9"),
        ],
    )
}

/// HIPAA Security Rule (illustrative subset).
pub fn hipaa_profile() -> FrameworkProfile {
    profile(
        "HIPAA",
        &[
            ("sshd-root-login-disabled", "164.312(a)(1)"),
            ("telnet-not-installed", "164.312(e)(1)"),
            ("password-max-days", "164.308(a)(5)"),
        ],
    )
}

/// SOC 2 Trust Services Criteria (illustrative subset).
pub fn soc2_profile() -> FrameworkProfile {
    profile(
        "SOC 2",
        &[
            ("sshd-root-login-disabled", "CC6.1"),
            ("telnet-not-installed", "CC6.6"),
            ("password-max-days", "CC6.1"),
        ],
    )
}

/// ISO/IEC 27001:2022 Annex A (illustrative subset).
pub fn iso_27001_profile() -> FrameworkProfile {
    profile(
        "ISO 27001",
        &[
            ("sshd-root-login-disabled", "A.8.2"),
            ("telnet-not-installed", "A.8.20"),
            ("password-max-days", "A.5.17"),
        ],
    )
}

/// DISA STIG (SRG-OS, illustrative subset).
pub fn disa_stig_profile() -> FrameworkProfile {
    profile(
        "DISA STIG",
        &[
            ("sshd-root-login-disabled", "SRG-OS-000480"),
            ("telnet-not-installed", "SRG-OS-000095"),
            ("password-max-days", "SRG-OS-000076"),
        ],
    )
}

/// Every framework the agent ships a crosswalk for. An org replaces or extends
/// this set with its own audited profiles.
pub fn all_frameworks() -> Vec<FrameworkProfile> {
    vec![
        cis_profile(),
        nist_800_53_profile(),
        pci_dss_profile(),
        hipaa_profile(),
        soc2_profile(),
        iso_27001_profile(),
        disa_stig_profile(),
    ]
}

/// Looks up a shipped profile by its framework name (e.g. "CIS", "HIPAA").
pub fn profile_by_name(name: &str) -> Option<FrameworkProfile> {
    all_frameworks().into_iter().find(|p| p.framework == name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::evaluate;
    use crate::controls::builtin_controls;
    use std::collections::HashMap;

    #[test]
    fn cis_profile_is_named_cis() {
        assert_eq!(cis_profile().framework, "CIS");
    }

    #[test]
    fn one_check_maps_to_multiple_framework_controls() {
        // The crosswalk is one-to-many: a single check can satisfy several CIS controls.
        let profile = cis_profile();
        let ids = profile.framework_ids_for("sshd-root-login-disabled");
        assert!(ids.contains(&"CIS-5.2.8"));
        assert!(ids.contains(&"CIS-5.2.10"));
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn every_builtin_check_is_mapped_and_unknown_is_empty() {
        let profile = cis_profile();
        for c in builtin_controls() {
            assert!(
                !profile.framework_ids_for(&c.id).is_empty(),
                "check {} must map to >=1 CIS control",
                c.id
            );
        }
        assert!(profile.framework_ids_for("no-such-check").is_empty());
    }

    #[test]
    fn evaluated_result_crosswalks_to_framework_ids() {
        // End-to-end: evaluate a control, then map its check id to CIS control ids.
        let mut m = HashMap::new();
        m.insert(
            "packages".to_string(),
            vec![serde_json::json!({"name":"telnet","version":"0.17"})],
        );
        let snap = crate::control::Snapshot(m);
        let results = evaluate(&builtin_controls(), &snap);
        // Only the packages-backed control (telnet) can evaluate against this snapshot.
        let telnet = results
            .iter()
            .find(|r| r.control_id == "telnet-not-installed")
            .unwrap();
        assert!(!telnet.passed, "telnet present -> control fails");
        let profile = cis_profile();
        assert_eq!(
            profile.framework_ids_for(&telnet.control_id),
            vec!["CIS-2.3.1"]
        );
    }

    #[test]
    fn every_framework_maps_every_builtin_check() {
        // Each shipped framework profile must cover all builtin checks — else a
        // failed control would silently report no control id for that framework.
        for profile in all_frameworks() {
            for c in builtin_controls() {
                assert!(
                    !profile.framework_ids_for(&c.id).is_empty(),
                    "{} does not map check {}",
                    profile.framework,
                    c.id
                );
            }
        }
    }

    #[test]
    fn registry_lists_all_seven_named_frameworks() {
        let names: Vec<String> = all_frameworks().into_iter().map(|p| p.framework).collect();
        for expected in [
            "CIS",
            "NIST 800-53",
            "PCI-DSS",
            "HIPAA",
            "SOC 2",
            "ISO 27001",
            "DISA STIG",
        ] {
            assert!(
                names.contains(&expected.to_string()),
                "missing framework {expected}"
            );
        }
        assert_eq!(names.len(), 7);
    }

    #[test]
    fn profile_by_name_selects_or_none() {
        assert_eq!(profile_by_name("HIPAA").unwrap().framework, "HIPAA");
        assert!(profile_by_name("NOT-A-FRAMEWORK").is_none());
    }

    #[test]
    fn spot_check_a_mapping_per_framework() {
        // A representative control id per framework, to pin the crosswalk data.
        assert_eq!(
            nist_800_53_profile().framework_ids_for("telnet-not-installed"),
            vec!["CM-7"]
        );
        assert_eq!(
            pci_dss_profile().framework_ids_for("telnet-not-installed"),
            vec!["2.2.4"]
        );
        assert_eq!(
            hipaa_profile().framework_ids_for("telnet-not-installed"),
            vec!["164.312(e)(1)"]
        );
        assert_eq!(
            soc2_profile().framework_ids_for("telnet-not-installed"),
            vec!["CC6.6"]
        );
        assert_eq!(
            iso_27001_profile().framework_ids_for("telnet-not-installed"),
            vec!["A.8.20"]
        );
        assert_eq!(
            disa_stig_profile().framework_ids_for("telnet-not-installed"),
            vec!["SRG-OS-000095"]
        );
    }
}
