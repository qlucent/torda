//! Minimal OCSF envelope shared between agent and backend.
//! Only the fields P0 needs; extend toward full OCSF as modules land.
use serde::{Deserialize, Serialize};

/// A subset of OCSF class UIDs we use in P0/P1.
pub mod class {
    pub const INVENTORY_INFO: u32 = 5001;
    pub const PROCESS_ACTIVITY: u32 = 1007; // OCSF Category 1 System Activity / Process Activity
    pub const FILE_SYSTEM_ACTIVITY: u32 = 1001; // OCSF Category 1 System Activity / File System Activity
    pub const NETWORK_ACTIVITY: u32 = 4001; // OCSF Category 4 Network Activity / Network Activity
    pub const SOFTWARE_INVENTORY_INFO: u32 = 5020;
    pub const VULNERABILITY_FINDING: u32 = 2002;
    pub const COMPLIANCE_FINDING: u32 = 2003;
    pub const DEVICE_CONFIG_STATE: u32 = 5002;
    pub const FILE_INTEGRITY_FINDING: u32 = 2004;
    pub const AGENT_HEALTH: u32 = 9001; // custom extension class
    pub const CORRELATED_ACTIVITY: u32 = 9002; // custom extension: cross-sensor correlation
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Metadata {
    pub product: String,
    pub version: String,
    pub tenant_id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Device {
    pub hostname: String,
    pub os: String,
    pub os_version: String,
}

/// OCSF event envelope. `data` holds the class-specific payload.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OcsfEnvelope {
    pub class_uid: u32,
    pub class_name: String,
    pub time: i64, // epoch millis
    pub severity_id: u8,
    pub metadata: Metadata,
    pub device: Device,
    pub data: serde_json::Value,
}

impl OcsfEnvelope {
    pub fn new(
        class_uid: u32,
        class_name: &str,
        meta: Metadata,
        device: Device,
        data: serde_json::Value,
    ) -> Self {
        Self {
            class_uid,
            class_name: class_name.to_string(),
            time: now_millis(),
            severity_id: 1,
            metadata: meta,
            device,
            data,
        }
    }
}

pub fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
