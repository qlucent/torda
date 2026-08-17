//! Compliance module. Evaluates the shared control library against the snapshot
//! service and emits an OCSF Compliance Finding record (pass/fail per control +
//! mapped framework control ids). Detection only — the server recomputes the
//! canonical score from the control weight. Reads the snapshot; never the OS.
use async_trait::async_trait;
use std::collections::HashSet;
use torda_compliance::control::{evaluate, Snapshot};
use torda_compliance::controls::builtin_controls;
use torda_compliance::framework::{profile_by_name, FrameworkProfile};
use torda_compliance::policy::{apply_overrides, Policy};
use torda_compliance::record::to_records;
use torda_core::{Module, ModuleCtx, ModuleHealth, ModuleId};
use torda_ocsf::{class, OcsfEnvelope};

/// Evaluates the compliance control library over the snapshot and emits one OCSF
/// Compliance Finding record for the whole run.
pub struct ComplianceModule {
    ctx: Option<ModuleCtx>,
    policy: Policy,
}

impl ComplianceModule {
    pub fn new() -> Self {
        Self::with_policy(Policy::default_policy())
    }

    /// Builds the module with an org policy (framework selection + control overrides).
    pub fn with_policy(policy: Policy) -> Self {
        Self { ctx: None, policy }
    }
}

impl Default for ComplianceModule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Module for ComplianceModule {
    fn id(&self) -> ModuleId {
        "compliance".to_string()
    }

    async fn init(&mut self, ctx: ModuleCtx) -> anyhow::Result<()> {
        self.ctx = Some(ctx);
        Ok(())
    }

    async fn start(&mut self) -> anyhow::Result<()> {
        let ctx = self.ctx.as_ref().expect("init before start");
        let controls = apply_overrides(builtin_controls(), &self.policy.overrides);

        // Build the snapshot from the tables the controls need; a table the
        // provider doesn't have is simply omitted (its control then skips).
        let mut snap = Snapshot::default();
        let mut seen = HashSet::new();
        for c in &controls {
            if seen.insert(c.table.clone()) {
                if let Ok(rows) = ctx.snapshot.query(&c.table) {
                    snap.0.insert(c.table.clone(), rows.0);
                }
            }
        }

        let profiles: Vec<FrameworkProfile> = self
            .policy
            .frameworks
            .iter()
            .filter_map(|n| profile_by_name(n))
            .collect();
        let records = to_records(&evaluate(&controls, &snap), &profiles);
        let data = serde_json::json!({ "compliance": { "records": records } });
        ctx.emitter.emit(OcsfEnvelope::new(
            class::COMPLIANCE_FINDING,
            "Compliance Finding",
            ctx.meta(),
            ctx.snapshot.device(),
            data,
        ));
        Ok(())
    }

    fn health(&self) -> ModuleHealth {
        ModuleHealth {
            ok: self.ctx.is_some(),
            detail: "compliance evaluator ready".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use torda_core::{
        EventBus, EventKind, OcsfEmitter, ResourceBudget, ResourceGovernor, ResourceSampler,
        ResourceUsage, Rows, SnapshotProvider, SubstrateEvent,
    };

    struct FakeSnapshot;
    impl SnapshotProvider for FakeSnapshot {
        fn query(&self, table: &str) -> anyhow::Result<Rows> {
            match table {
                "packages" => Ok(Rows(vec![
                    serde_json::json!({"name":"telnet","version":"0.17"}),
                ])),
                other => anyhow::bail!("no table {other}"),
            }
        }
        fn device(&self) -> torda_ocsf::Device {
            torda_ocsf::Device {
                hostname: "host-1".into(),
                os: "Test".into(),
                os_version: "1".into(),
            }
        }
    }
    #[derive(Default)]
    struct CapturingEmitter {
        emitted: Mutex<Vec<OcsfEnvelope>>,
    }
    impl OcsfEmitter for CapturingEmitter {
        fn emit(&self, rec: OcsfEnvelope) {
            self.emitted.lock().unwrap().push(rec);
        }
    }
    struct FakeBus {
        tx: tokio::sync::broadcast::Sender<SubstrateEvent>,
    }
    impl EventBus for FakeBus {
        fn publish(&self, ev: SubstrateEvent) {
            let _ = self.tx.send(ev);
        }
        fn subscribe(&self, _k: &[EventKind]) -> tokio::sync::broadcast::Receiver<SubstrateEvent> {
            self.tx.subscribe()
        }
    }
    struct TestSampler;
    impl ResourceSampler for TestSampler {
        fn sample(&self) -> ResourceUsage {
            ResourceUsage::ZERO
        }
    }

    fn test_ctx(emitter: Arc<CapturingEmitter>) -> ModuleCtx {
        let (tx, _rx) = tokio::sync::broadcast::channel(16);
        ModuleCtx {
            bus: Arc::new(FakeBus { tx }),
            snapshot: Arc::new(FakeSnapshot),
            emitter,
            governor: Arc::new(ResourceGovernor::new(
                ResourceBudget::default(),
                Box::new(TestSampler),
            )),
            tenant_id: "t".into(),
            product: "torda".into(),
            version: "0".into(),
        }
    }

    #[tokio::test]
    async fn emits_compliance_finding_with_failed_telnet_control() {
        let emitter = Arc::new(CapturingEmitter::default());
        let mut m = ComplianceModule::new();
        m.init(test_ctx(emitter.clone())).await.unwrap();
        m.start().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(emitted.len(), 1);
        let env = &emitted[0];
        assert_eq!(env.class_uid, class::COMPLIANCE_FINDING);
        assert_eq!(env.class_name, "Compliance Finding");
        let records = env.data["compliance"]["records"].as_array().unwrap();
        // Only the packages-backed control evaluates (sshd/login_defs tables absent).
        let telnet = records
            .iter()
            .find(|r| r["control_id"] == "telnet-not-installed")
            .unwrap();
        assert_eq!(telnet["passed"], false);
        // Multi-framework: CIS mapping is present among the frameworks array.
        let frameworks = telnet["frameworks"].as_array().unwrap();
        let cis = frameworks.iter().find(|f| f["framework"] == "CIS").unwrap();
        assert_eq!(cis["control_ids"][0], "CIS-2.3.1");
    }

    #[tokio::test]
    async fn policy_reweight_and_framework_selection_is_reflected() {
        use torda_compliance::policy::{ControlOverride, Policy};
        let policy = Policy {
            frameworks: vec!["CIS".into(), "NIST 800-53".into()],
            overrides: vec![ControlOverride {
                control_id: "telnet-not-installed".into(),
                enabled: None,
                weight: Some(0.95),
            }],
        };
        let emitter = Arc::new(CapturingEmitter::default());
        let mut m = ComplianceModule::with_policy(policy);
        m.init(test_ctx(emitter.clone())).await.unwrap();
        m.start().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        let records = emitted[0].data["compliance"]["records"].as_array().unwrap();
        let telnet = records
            .iter()
            .find(|r| r["control_id"] == "telnet-not-installed")
            .unwrap();
        // Reweighted by the org policy. `weight` is f32 on the wire; compare against
        // the same f32-widened JSON value to avoid an f32->f64 precision mismatch.
        assert_eq!(telnet["weight"], serde_json::json!(0.95_f32));
        // Only the two selected frameworks are reported.
        let frameworks = telnet["frameworks"].as_array().unwrap();
        assert_eq!(frameworks.len(), 2);
        let names: Vec<&str> = frameworks
            .iter()
            .map(|f| f["framework"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"CIS") && names.contains(&"NIST 800-53"));
    }

    #[tokio::test]
    async fn policy_disable_removes_the_control() {
        use torda_compliance::policy::{ControlOverride, Policy};
        let policy = Policy {
            frameworks: vec!["CIS".into()],
            overrides: vec![ControlOverride {
                control_id: "telnet-not-installed".into(),
                enabled: Some(false),
                weight: None,
            }],
        };
        let emitter = Arc::new(CapturingEmitter::default());
        let mut m = ComplianceModule::with_policy(policy);
        m.init(test_ctx(emitter.clone())).await.unwrap();
        m.start().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        let records = emitted[0].data["compliance"]["records"].as_array().unwrap();
        // telnet was the only evaluatable control (sshd/login_defs tables absent)
        // and the org disabled it -> no records emitted at all.
        assert!(
            records.is_empty(),
            "disabling the only evaluatable control yields no records"
        );
    }
}
