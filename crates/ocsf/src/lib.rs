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
    pub const RUNTIME_MODULE_LOAD: u32 = 9003; // custom extension: a shared library was loaded at runtime (reachability telemetry)
    pub const AI_INVENTORY_INFO: u32 = 9004; // custom extension: AI runtimes/servers discovered on the host (local-LLM inventory)
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

#[cfg(test)]
mod conformance {
    //! OCSF conformance contract for the agent's envelope + class registry. This
    //! guards the on-the-wire shape (serde attribute names) and that every class
    //! Torda emits is either a documented STOCK OCSF class or a labeled Torda
    //! EXTENSION in the 9000 block — the regression gate behind the benchmark's
    //! "OCSF conformance" dimension. (Full validation against the official OCSF
    //! JSON schema — vendored + a JSON-Schema validator — is a follow-up for the
    //! public conformance badge.)
    use super::*;

    fn sample() -> OcsfEnvelope {
        OcsfEnvelope::new(
            class::PROCESS_ACTIVITY,
            "Process Activity",
            Metadata {
                product: "torda".into(),
                version: "0".into(),
                tenant_id: "t".into(),
            },
            Device {
                hostname: "h".into(),
                os: "o".into(),
                os_version: "1".into(),
            },
            serde_json::json!({ "k": "v" }),
        )
    }

    #[test]
    fn envelope_serializes_with_required_ocsf_attributes() {
        let v = serde_json::to_value(sample()).unwrap();
        for key in [
            "class_uid",
            "class_name",
            "time",
            "severity_id",
            "metadata",
            "device",
            "data",
        ] {
            assert!(v.get(key).is_some(), "missing OCSF attribute `{key}`");
        }
        for key in ["product", "version", "tenant_id"] {
            assert!(v["metadata"].get(key).is_some(), "metadata.{key} missing");
        }
        for key in ["hostname", "os", "os_version"] {
            assert!(v["device"].get(key).is_some(), "device.{key} missing");
        }
        assert!(v["class_uid"].is_u64(), "class_uid must be an integer");
        assert!(
            v["time"].is_i64() || v["time"].is_u64(),
            "time must be epoch int"
        );
    }

    #[test]
    fn emitted_classes_are_stock_or_labeled_extensions() {
        // Stock OCSF classes must keep their official UIDs (catch typos/drift).
        let stock = [
            (class::FILE_SYSTEM_ACTIVITY, 1001u32),
            (class::PROCESS_ACTIVITY, 1007),
            (class::VULNERABILITY_FINDING, 2002),
            (class::COMPLIANCE_FINDING, 2003),
            (class::FILE_INTEGRITY_FINDING, 2004),
            (class::NETWORK_ACTIVITY, 4001),
            (class::INVENTORY_INFO, 5001),
            (class::DEVICE_CONFIG_STATE, 5002),
            (class::SOFTWARE_INVENTORY_INFO, 5020),
        ];
        for (got, want) in stock {
            assert_eq!(got, want, "stock OCSF class UID drifted");
            assert!(
                got < 9000,
                "a stock class must not be in the extension block"
            );
        }

        // Torda custom extensions live in the 9000 block and are NOT stock OCSF.
        for ext in [
            class::AGENT_HEALTH,
            class::CORRELATED_ACTIVITY,
            class::RUNTIME_MODULE_LOAD,
            class::AI_INVENTORY_INFO,
        ] {
            assert!(
                (9001..=9999).contains(&ext),
                "extension class {ext} must be in the 9000 block"
            );
        }
    }
}
