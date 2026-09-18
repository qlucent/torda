//! Normalize a peer EDR's native alerts into the harness's by-technique scoring
//! model. A peer (Wazuh, Falco, …) emits neither OCSF nor torda rule names, so —
//! per spec §5/§6.1 — it is scored by the ATT&CK TECHNIQUE its alert maps to.
//! This module extracts those techniques from each peer's alert format so the
//! SAME registry + `score` (in by-technique mode) grade every tool identically.
//!
//! Adding a tool is one function here (its technique extractor) + a target image;
//! the scoring, matrix, and registry are shared. That is why the harness compares
//! N peers cleanly, not just Wazuh.

use serde_json::{json, Value};

/// Peer alert formats the harness understands.
pub fn supported() -> &'static [&'static str] {
    &["wazuh", "falco"]
}

/// ATT&CK techniques a Wazuh `alerts.json` record maps to: `rule.mitre.id` is the
/// list of technique ids Wazuh's ruleset tagged the alert with.
pub fn wazuh_techniques(alert: &Value) -> Vec<String> {
    alert
        .get("rule")
        .and_then(|r| r.get("mitre"))
        .and_then(|m| m.get("id"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// ATT&CK techniques a Falco JSON alert maps to: Falco carries them in `tags` as
/// bare ids (e.g. `"T1059"`) alongside tactic tags (`"mitre_execution"`).
pub fn falco_techniques(alert: &Value) -> Vec<String> {
    alert
        .get("tags")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .filter(|t| is_attack_id(t))
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// A `T####` / `T####.###` ATT&CK technique id (Falco tags mix these with
/// non-ATT&CK tags, so we filter).
fn is_attack_id(s: &str) -> bool {
    match s.strip_prefix('T') {
        Some(rest) if !rest.is_empty() => rest
            .split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())),
        _ => false,
    }
}

/// A short human label for the peer rule that fired (for the matrix's FP column).
fn label(agent: &str, alert: &Value) -> String {
    match agent {
        "wazuh" => alert
            .get("rule")
            .and_then(|r| r.get("id"))
            .and_then(Value::as_str)
            .map(|id| format!("wazuh:{id}"))
            .unwrap_or_else(|| "wazuh:?".into()),
        "falco" => alert
            .get("rule")
            .and_then(Value::as_str)
            .map(|r| format!("falco:{r}"))
            .unwrap_or_else(|| "falco:?".into()),
        _ => agent.to_string(),
    }
}

/// Normalize one raw peer alert into a captures record: its ATT&CK techniques + a
/// label. Returns `None` only if `agent` is unknown. An alert with NO ATT&CK
/// mapping still normalizes (empty `attack_techniques`) so it counts toward the
/// idle-baseline FP — it just cannot HIT a technique case.
pub fn normalize(agent: &str, alert: &Value) -> Option<Value> {
    let techs = match agent {
        "wazuh" => wazuh_techniques(alert),
        "falco" => falco_techniques(alert),
        _ => return None,
    };
    Some(json!({
        "attack_techniques": techs,
        "rule": label(agent, alert),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wazuh_mitre_ids_extract() {
        let a = json!({"rule": {"id": "92052", "mitre": {"id": ["T1059", "T1059.004"]}}});
        assert_eq!(wazuh_techniques(&a), vec!["T1059", "T1059.004"]);
        let n = normalize("wazuh", &a).unwrap();
        assert_eq!(n["attack_techniques"][0], "T1059");
        assert_eq!(n["rule"], "wazuh:92052");
    }

    #[test]
    fn falco_tags_filter_to_attack_ids() {
        let a = json!({"rule": "Launch Suspicious Network Tool", "tags": ["mitre_execution", "T1059", "network"]});
        assert_eq!(falco_techniques(&a), vec!["T1059"]);
        assert_eq!(
            normalize("falco", &a).unwrap()["rule"],
            "falco:Launch Suspicious Network Tool"
        );
    }

    #[test]
    fn no_mapping_still_normalizes_for_fp_counting() {
        let a = json!({"rule": {"id": "1002", "description": "generic"}});
        let n = normalize("wazuh", &a).unwrap();
        assert!(n["attack_techniques"].as_array().unwrap().is_empty());
        assert_eq!(normalize("nope", &a), None);
    }

    #[test]
    fn attack_id_shape() {
        assert!(is_attack_id("T1059"));
        assert!(is_attack_id("T1059.004"));
        assert!(!is_attack_id("mitre_execution"));
        assert!(!is_attack_id("T"));
        assert!(!is_attack_id("network"));
    }
}
