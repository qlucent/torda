//! The compliance wire record: a `ControlResult` plus, per shipped framework, the
//! control ids it satisfies (from that framework's crosswalk). This is what the
//! agent emits inside an OCSF Compliance Finding and what the server ingest
//! parses back.
use serde::{Deserialize, Serialize};

use crate::control::ControlResult;
use crate::framework::FrameworkProfile;

/// One framework's control ids satisfied by a check — the multi-framework wire
/// shape. A record carries one of these per framework that maps the check.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FrameworkMapping {
    pub framework: String,
    pub control_ids: Vec<String>,
}

/// A control result plus every framework's control ids it satisfies — the
/// compliance wire shape the agent emits and the server ingests. `frameworks` is
/// carried for reporting; the score is recomputed server-side from `weight`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ComplianceRecord {
    pub control_id: String,
    pub passed: bool,
    pub weight: f32,
    pub subject: String,
    pub location: String,
    pub remediation_key: String,
    #[serde(default)]
    pub frameworks: Vec<FrameworkMapping>,
}

/// Maps evaluation results to wire records, attaching — per result — one
/// `FrameworkMapping` for every profile that maps the check to >=1 control id.
/// Profiles that don't map the check are omitted (no empty mappings).
pub fn to_records(
    results: &[ControlResult],
    profiles: &[FrameworkProfile],
) -> Vec<ComplianceRecord> {
    results
        .iter()
        .map(|r| ComplianceRecord {
            control_id: r.control_id.clone(),
            passed: r.passed,
            weight: r.weight,
            subject: r.subject.clone(),
            location: r.location.clone(),
            remediation_key: r.remediation_key.clone(),
            frameworks: profiles
                .iter()
                .filter_map(|p| {
                    let ids: Vec<String> = p
                        .framework_ids_for(&r.control_id)
                        .iter()
                        .map(|s| s.to_string())
                        .collect();
                    (!ids.is_empty()).then(|| FrameworkMapping {
                        framework: p.framework.clone(),
                        control_ids: ids,
                    })
                })
                .collect(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{evaluate, Snapshot};
    use crate::controls::builtin_controls;
    use std::collections::HashMap;

    #[test]
    fn to_records_attaches_all_matching_frameworks() {
        use crate::framework::all_frameworks;
        let mut m = HashMap::new();
        m.insert(
            "packages".to_string(),
            vec![serde_json::json!({"name":"telnet","version":"0.17"})],
        );
        let results = evaluate(&builtin_controls(), &Snapshot(m));
        let records = to_records(&results, &all_frameworks());
        let telnet = records
            .iter()
            .find(|r| r.control_id == "telnet-not-installed")
            .unwrap();
        assert!(!telnet.passed);
        assert_eq!(telnet.weight, 0.6);
        assert_eq!(telnet.subject, "telnet");
        assert_eq!(telnet.remediation_key, "remove:telnet");
        // Every shipped framework maps telnet, so all 7 appear, each with >=1 id.
        assert_eq!(telnet.frameworks.len(), 7);
        let cis = telnet
            .frameworks
            .iter()
            .find(|f| f.framework == "CIS")
            .unwrap();
        assert_eq!(cis.control_ids, vec!["CIS-2.3.1"]);
        let nist = telnet
            .frameworks
            .iter()
            .find(|f| f.framework == "NIST 800-53")
            .unwrap();
        assert_eq!(nist.control_ids, vec!["CM-7"]);
    }

    #[test]
    fn to_records_with_single_profile_lists_only_that_framework() {
        use crate::framework::cis_profile;
        let mut m = HashMap::new();
        m.insert(
            "packages".to_string(),
            vec![serde_json::json!({"name":"telnet","version":"0.17"})],
        );
        let results = evaluate(&builtin_controls(), &Snapshot(m));
        let records = to_records(&results, &[cis_profile()]);
        let telnet = records
            .iter()
            .find(|r| r.control_id == "telnet-not-installed")
            .unwrap();
        assert_eq!(telnet.frameworks.len(), 1);
        assert_eq!(telnet.frameworks[0].framework, "CIS");
    }

    #[test]
    fn compliance_record_round_trips() {
        let rec = ComplianceRecord {
            control_id: "c".into(),
            passed: false,
            weight: 0.6,
            subject: "s".into(),
            location: "l".into(),
            remediation_key: "fix".into(),
            frameworks: vec![FrameworkMapping {
                framework: "CIS".into(),
                control_ids: vec!["CIS-1.1".into()],
            }],
        };
        let back: ComplianceRecord =
            serde_json::from_str(&serde_json::to_string(&rec).unwrap()).unwrap();
        assert_eq!(back, rec);
    }
}
