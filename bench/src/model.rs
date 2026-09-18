//! Registry schema + OCSF-record helpers — the one place the case schema and the
//! way a torda record is parsed live.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Declared ground truth for a case: the OCSF class + torda rule that should fire,
/// within `within_seconds` of the atomic's trigger.
#[derive(Debug, Clone, Deserialize)]
pub struct Expect {
    pub ocsf_class: u32,
    pub rule: String,
    #[serde(default = "default_within")]
    pub within_seconds: f64,
}
fn default_within() -> f64 {
    5.0
}

/// One atomic test case from the registry.
#[derive(Debug, Clone, Deserialize)]
pub struct Case {
    pub id: String,
    #[serde(default)]
    pub attack_technique: String,
    #[serde(default)]
    pub attack_tactic: String,
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_platform")]
    pub platform: String,
    #[serde(default = "default_tier")]
    pub tier: String,
    #[serde(default)]
    pub atomic: Option<String>,
    #[serde(default)]
    pub cleanup: Option<String>,
    /// Absent for a pure Tier-B gap (no sensor at all).
    #[serde(default)]
    pub expects: Option<Expect>,
    #[serde(default = "default_expected")]
    pub expected_result: String, // "hit" (Tier A) | "miss" (Tier B)
    #[serde(default)]
    pub notes: String,
}
fn default_platform() -> String {
    "linux".into()
}
fn default_tier() -> String {
    "A".into()
}
fn default_expected() -> String {
    "hit".into()
}

#[derive(Deserialize)]
struct RegistryFile {
    #[serde(default)]
    case: Vec<Case>,
}

/// Parse `config/techniques.toml`. Fails loudly on a duplicate id — a silently
/// dropped case would corrupt the coverage denominator.
pub fn load_registry(path: impl AsRef<Path>) -> Result<Vec<Case>> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading registry {}", path.display()))?;
    let reg: RegistryFile =
        toml::from_str(&text).with_context(|| format!("parsing registry {}", path.display()))?;
    let mut seen = BTreeSet::new();
    for c in &reg.case {
        if !seen.insert(c.id.clone()) {
            anyhow::bail!("{}: duplicate case id {:?}", path.display(), c.id);
        }
    }
    Ok(reg.case)
}

// ─────────────────────────── captures.json ───────────────────────────
// The intermediate the live runner writes and the pure scorer reads, so scoring
// is decoupled from any live agent.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseCapture {
    pub case_id: String,
    pub trigger_time: i64, // epoch ms
    pub records: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Captures {
    #[serde(default)]
    pub run_id: String,
    #[serde(default = "default_agent")]
    pub agent: String,
    #[serde(default)]
    pub cases: Vec<CaseCapture>,
}
fn default_agent() -> String {
    "torda".into()
}

pub fn load_captures(path: impl AsRef<Path>) -> Result<Captures> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading captures {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing captures {}", path.display()))
}

// ─────────────────────────── OCSF record helpers ───────────────────────────

pub fn record_class(rec: &Value) -> Option<u32> {
    rec.get("class_uid")?.as_u64().map(|u| u as u32)
}

pub fn record_time_ms(rec: &Value) -> Option<i64> {
    rec.get("time")?.as_i64()
}

/// Every rule name anywhere under the record's `data` — the `rule` value of any
/// object that has one, at any depth (top-level detections, and for 9002 the
/// nested `process`/`connection` detections).
pub fn record_rules(rec: &Value) -> BTreeSet<String> {
    fn walk(node: &Value, out: &mut BTreeSet<String>) {
        match node {
            Value::Object(m) => {
                if let Some(Value::String(r)) = m.get("rule") {
                    out.insert(r.clone());
                }
                for v in m.values() {
                    walk(v, out);
                }
            }
            Value::Array(a) => {
                for v in a {
                    walk(v, out);
                }
            }
            _ => {}
        }
    }
    let mut out = BTreeSet::new();
    if let Some(data) = rec.get("data") {
        walk(data, &mut out);
    }
    out
}

/// Human name for an OCSF class UID, defined via the REAL [`torda_ocsf::class`]
/// constants so a UID change in the agent is caught at compile time here.
pub fn class_name(uid: u32) -> &'static str {
    use torda_ocsf::class::*;
    match uid {
        INVENTORY_INFO => "Inventory Info",
        PROCESS_ACTIVITY => "Process Activity",
        FILE_SYSTEM_ACTIVITY => "File System Activity",
        NETWORK_ACTIVITY => "Network Activity",
        SOFTWARE_INVENTORY_INFO => "Software Inventory Info",
        VULNERABILITY_FINDING => "Vulnerability Finding",
        COMPLIANCE_FINDING => "Compliance Finding",
        DEVICE_CONFIG_STATE => "Device Config State",
        FILE_INTEGRITY_FINDING => "File Integrity Finding",
        AGENT_HEALTH => "Agent Health",
        CORRELATED_ACTIVITY => "Correlated Activity",
        RUNTIME_MODULE_LOAD => "Runtime Module Load",
        AI_INVENTORY_INFO => "AI Inventory Info",
        _ => "?",
    }
}

/// Whether `uid` is a class the agent actually emits (a known UID).
pub fn is_known_class(uid: u32) -> bool {
    class_name(uid) != "?"
}
