//! Network-monitor module — the first module that CONSUMES `NetConnect` events.
//!
//! It subscribes to `NetConnect` on the shared substrate bus and emits one OCSF
//! Network Activity record per outbound connection, flagging suspicious egress
//! via the pure ruleset [`assess`]. It is the exact network counterpart of the
//! process module `torda-mod-procmon`: it reads only the bus and emits — it never
//! touches the OS. The substrate is the only door.
//!
//! # Severity scheme
//! We map a hit to a small numeric severity independent of any source label:
//! `1 = Informational`, `3 = Medium`, `4 = High`. A connection's `severity_id`
//! is the MAX over its rule hits, or `1` when nothing fired.
//!
//! # Honest limits
//! Today the ruleset sees only the destination address and port. It has no
//! process reputation, no flow volume, no directionality beyond "an outbound
//! connect was attempted", and no DNS context. A benign service listening on a
//! flagged port, or a C2 on 443, will be judged on IP-class + port alone.
use async_trait::async_trait;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;
use torda_core::{EventKind, Module, ModuleCtx, ModuleHealth, ModuleId, SubstrateEvent};
use torda_ocsf::{class, Device, Metadata, OcsfEnvelope};

// ---------------- Severity scheme ----------------
//
// `SEV_INFORMATIONAL` — no rule fired — a routine connection.
// `SEV_MEDIUM` — a connection to a suspicious port worth a human glance.
// `SEV_HIGH` — a COMBINED attacker signal — materially worse than either weak
// signal alone (a suspicious-port connection egressing to a PUBLIC address,
// i.e. plausible C2 / exfil). Reserved for correlated rules like
// `suspicious_port_to_external`.
//
// Values live in `torda_core::severity` (the single source of truth shared by
// every module); re-exported here so `torda_mod_netmon::SEV_*` keeps working.
pub use torda_core::severity::{SEV_HIGH, SEV_INFORMATIONAL, SEV_MEDIUM};

// ---------------- Ruleset (pure, deterministic, I/O-free) ----------------

/// One rule firing against a connection.
pub struct RuleHit {
    /// Stable rule identifier (e.g. `"suspicious_port"`).
    pub rule: &'static str,
    /// Human-readable rationale for this specific hit.
    pub reason: String,
}

/// The verdict for one connection: a MAX severity plus every rule that fired.
pub struct Assessment {
    /// `1 = Informational, 3 = Medium, 4 = High`. MAX over `hits`.
    pub severity_id: u8,
    pub hits: Vec<RuleHit>,
}

/// Destination ports that are commonly abused by C2 frameworks, backdoors, and
/// remote shells, matched exactly against the connection's `dport`.
///
/// Rationale: these are documented default/handler ports for well-known
/// offensive tooling. We DELIBERATELY exclude ubiquitous benign ports
/// (80/443/22/53) — flagging those would drown the signal in noise. Each entry
/// below carries a one-line rationale.
const SUSPICIOUS_PORTS: &[u16] = &[
    4444,  // Metasploit / Meterpreter default LPORT
    4445,  // common secondary Metasploit handler port
    1337,  // "leet" — classic backdoor / bind-shell convention
    31337, // "eleet" — Back Orifice / historical backdoor default
    12345, // NetBus backdoor default
    6667,  // IRC — legacy botnet C2 channel
    6697,  // IRC over TLS — botnet C2 channel
    5555,  // Android ADB / assorted RAT default
    9001,  // common Cobalt Strike / Tor-relay-style C2 port
];

/// Severity for a given rule id. Keeps the scheme explicit and per-rule.
fn rule_severity(rule: &str) -> u8 {
    match rule {
        "suspicious_port" => SEV_MEDIUM,
        // Correlated signal: a suspicious-port connection to a PUBLIC address is
        // worse than the same port to a private/loopback host, so it earns a
        // strictly HIGHER band — plausible C2 / exfil rather than local tooling.
        "suspicious_port_to_external" => SEV_HIGH,
        _ => SEV_INFORMATIONAL,
    }
}

/// Is a destination IPv4 address "external" (public) rather than private/local?
///
/// Private/local = RFC1918 private, loopback, link-local, or unspecified
/// (`0.0.0.0`). Everything else is treated as external/public. A destination
/// that does NOT parse as an `Ipv4Addr` is NOT classified as external (returns
/// `false`): we never guess reachability from a string we can't parse, so the
/// external-correlated rule cannot fire on an unparseable address.
fn is_external(daddr: &str) -> bool {
    match daddr.parse::<Ipv4Addr>() {
        Ok(ip) => {
            let private_or_local =
                ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified();
            !private_or_local
        }
        Err(_) => false,
    }
}

/// Assess an outbound connection by destination address + port. Pure +
/// deterministic: no I/O, no OS, no allocation beyond the returned hits. An
/// unparseable `daddr` never panics — it simply cannot match the external rule.
pub fn assess(daddr: &str, dport: u16) -> Assessment {
    let mut hits: Vec<RuleHit> = Vec::new();

    // (a) Suspicious destination port (exact match against the C2/backdoor set).
    let suspicious_port = SUSPICIOUS_PORTS.contains(&dport);
    if suspicious_port {
        hits.push(RuleHit {
            rule: "suspicious_port",
            reason: format!(
                "destination port {dport} is a known C2 / backdoor / remote-shell port"
            ),
        });
    }

    // (b) Correlated HIGH signal: a suspicious-port connection egressing to a
    // PUBLIC address (plausible C2 / exfil) is materially worse than the same
    // port to a private/loopback host, so it fires its own HIGH-severity rule.
    // An unparseable daddr is never external, so this rule cannot fire on it.
    if suspicious_port && is_external(daddr) {
        hits.push(RuleHit {
            rule: "suspicious_port_to_external",
            reason: format!("suspicious port {dport} connection to external address {daddr}"),
        });
    }

    let severity_id = hits
        .iter()
        .map(|h| rule_severity(h.rule))
        .max()
        .unwrap_or(SEV_INFORMATIONAL);

    Assessment { severity_id, hits }
}

// ---------------- Module ----------------

/// Subscribes to `NetConnect` and emits one OCSF Network Activity record per
/// outbound connection, flagged by [`assess`].
#[derive(Default)]
pub struct NetMonModule {
    ctx: Option<ModuleCtx>,
    /// Signals the background task to stop; `true` == please exit.
    stop_tx: Option<tokio::sync::watch::Sender<bool>>,
    /// Handle to the bus-reading task, awaited (bounded) on `stop`.
    task: Option<tokio::task::JoinHandle<()>>,
}

impl NetMonModule {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Extracts the connection fields from a `NetConnect` event and emits its
/// Network Activity record. The stub bus forwards ALL kinds regardless of the
/// subscribe filter, so a non-`NetConnect` kind is dropped by the guard. A
/// malformed event (missing/unparseable any required field) is SKIPPED — never
/// a panic, never an emit.
fn handle_event(
    ev: &SubstrateEvent,
    meta: &Metadata,
    device: &Device,
    emitter: &dyn torda_core::OcsfEmitter,
) {
    // Kind guard: the stub bus forwards every kind; only NetConnect is ours.
    if ev.kind != EventKind::NetConnect {
        return;
    }

    let daddr = match ev.fields.get("daddr").and_then(serde_json::Value::as_str) {
        Some(s) => s,
        None => return,
    };
    let dport: u16 = match ev
        .fields
        .get("dport")
        .and_then(serde_json::Value::as_u64)
        .and_then(|p| p.try_into().ok())
    {
        Some(p) => p,
        None => return,
    };
    let pid = match ev.fields.get("pid").and_then(serde_json::Value::as_u64) {
        Some(p) => p,
        None => return,
    };
    let image = match ev.fields.get("image").and_then(serde_json::Value::as_str) {
        Some(s) => s,
        None => return,
    };
    // `proto` is optional; default to "tcp" (connect(2) egress is TCP today).
    let proto = ev
        .fields
        .get("proto")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("tcp");

    let a = assess(daddr, dport);
    let detections: Vec<serde_json::Value> = a
        .hits
        .iter()
        .map(|h| serde_json::json!({ "rule": h.rule, "reason": h.reason }))
        .collect();

    let mut env = OcsfEnvelope::new(
        class::NETWORK_ACTIVITY,
        "Network Activity",
        meta.clone(),
        device.clone(),
        serde_json::json!({
            "activity": "connect",
            "connection": { "daddr": daddr, "dport": dport, "proto": proto },
            "process": { "pid": pid, "image": image },
            "detections": detections,
        }),
    );
    // OcsfEnvelope::new defaults severity_id to 1; override with our verdict.
    env.severity_id = a.severity_id;
    emitter.emit(env);
}

#[async_trait]
impl Module for NetMonModule {
    fn id(&self) -> ModuleId {
        "netmon".to_string()
    }

    async fn init(&mut self, ctx: ModuleCtx) -> anyhow::Result<()> {
        self.ctx = Some(ctx);
        Ok(())
    }

    async fn start(&mut self) -> anyhow::Result<()> {
        let ctx = self
            .ctx
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("netmon: init before start"))?;

        // Subscribe on the shared bus; capture only what the task needs (so it
        // owns no `ModuleCtx` reference and stays `'static`).
        let mut rx = ctx.bus.subscribe(&[EventKind::NetConnect]);
        let meta = ctx.meta();
        let device = ctx.snapshot.device();
        let emitter = ctx.emitter.clone();

        let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stop_rx.changed() => {
                        if *stop_rx.borrow() {
                            break;
                        }
                    }
                    r = rx.recv() => match r {
                        Ok(ev) => handle_event(&ev, &meta, &device, emitter.as_ref()),
                        Err(RecvError::Lagged(_)) => continue, // dropped events; keep reading
                        Err(RecvError::Closed) => break,        // bus gone; exit
                    },
                }
            }
        });

        self.stop_tx = Some(stop_tx);
        self.task = Some(task);
        Ok(())
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(true); // wake the task's select! arm
        }
        if let Some(task) = self.task.take() {
            // Bounded join so stop never hangs the manager.
            let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        }
        Ok(())
    }

    fn health(&self) -> ModuleHealth {
        ModuleHealth {
            ok: self.ctx.is_some(),
            detail: "network monitor ready".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use torda_core::{
        EventBus, OcsfEmitter, ResourceBudget, ResourceGovernor, ResourceSampler, ResourceUsage,
    };
    use torda_substrate::StubBus;

    // ---------- pure ruleset tests ----------

    fn rules(a: &Assessment) -> Vec<&'static str> {
        a.hits.iter().map(|h| h.rule).collect()
    }

    #[test]
    fn assess_suspicious_port_to_external_is_high_with_both_rules() {
        // Public address (TEST-NET-3 203.0.113.0/24 is a documented public range)
        // on a C2 port: BOTH the base and the correlated rule fire; MAX = High.
        let a = assess("203.0.113.1", 4444);
        assert_eq!(a.severity_id, SEV_HIGH);
        assert_eq!(
            rules(&a),
            vec!["suspicious_port", "suspicious_port_to_external"]
        );
    }

    #[test]
    fn assess_suspicious_port_to_loopback_is_medium_only() {
        // 127.0.0.1 is loopback → private/local, NOT external. Only the base
        // suspicious_port rule fires (Medium), never the external correlation.
        let a = assess("127.0.0.1", 4444);
        assert_eq!(a.severity_id, SEV_MEDIUM);
        assert_eq!(rules(&a), vec!["suspicious_port"]);
    }

    #[test]
    fn assess_suspicious_port_to_rfc1918_private_is_medium_only() {
        // 10.0.0.5 is RFC1918 private → NOT external. Medium, base rule only.
        let a = assess("10.0.0.5", 4444);
        assert_eq!(a.severity_id, SEV_MEDIUM);
        assert_eq!(rules(&a), vec!["suspicious_port"]);
    }

    #[test]
    fn assess_benign_port_to_external_is_informational_no_hits() {
        // A public address on 443 (benign, deliberately excluded from the set):
        // nothing fires → Informational, no hits.
        let a = assess("93.184.216.34", 443);
        assert_eq!(a.severity_id, SEV_INFORMATIONAL);
        assert!(a.hits.is_empty());
    }

    #[test]
    fn assess_unparseable_daddr_does_not_panic_and_matches_only_suspicious_port() {
        // DESIGN CHOICE: an unparseable daddr can still match the port-only rule
        // (Medium) but can NEVER be classified external, so the correlated High
        // rule cannot fire. It must never panic.
        let a = assess("not-an-ip", 4444);
        assert_eq!(a.severity_id, SEV_MEDIUM);
        assert_eq!(rules(&a), vec!["suspicious_port"]);
        // A benign port with an unparseable daddr fires nothing at all.
        let b = assess("not-an-ip", 443);
        assert_eq!(b.severity_id, SEV_INFORMATIONAL);
        assert!(b.hits.is_empty());
    }

    #[test]
    fn assess_severity_is_strict_max_over_differing_rule_severities() {
        // The external case matches TWO rules with DIFFERENT per-rule severities:
        // suspicious_port=Medium(3), suspicious_port_to_external=High(4). The
        // verdict must be the strict MAX (High), not the lower Medium hit — this
        // is what makes "MAX" testable (the correlated High beats the Medium).
        assert_eq!(rule_severity("suspicious_port"), SEV_MEDIUM);
        assert_eq!(rule_severity("suspicious_port_to_external"), SEV_HIGH);

        let a = assess("8.8.8.8", 1337);
        assert_eq!(
            rules(&a),
            vec!["suspicious_port", "suspicious_port_to_external"]
        );
        let max = a.hits.iter().map(|h| rule_severity(h.rule)).max().unwrap();
        assert_eq!(a.severity_id, SEV_HIGH);
        assert_eq!(a.severity_id, max, "severity is the max over all hits");
        assert_ne!(
            a.severity_id, SEV_MEDIUM,
            "max differs from the lower Medium hit"
        );
    }

    #[test]
    fn assess_link_local_and_unspecified_are_private() {
        // 169.254.x.x (link-local) and 0.0.0.0 (unspecified) are NOT external.
        assert_eq!(rules(&assess("169.254.1.1", 4444)), vec!["suspicious_port"]);
        assert_eq!(rules(&assess("0.0.0.0", 4444)), vec!["suspicious_port"]);
    }

    // ---------- end-to-end via StubBus + capturing emitter ----------

    #[derive(Default)]
    struct CapturingEmitter {
        emitted: Mutex<Vec<OcsfEnvelope>>,
    }
    impl OcsfEmitter for CapturingEmitter {
        fn emit(&self, rec: OcsfEnvelope) {
            self.emitted.lock().unwrap().push(rec);
        }
    }

    struct TestSampler;
    impl ResourceSampler for TestSampler {
        fn sample(&self) -> ResourceUsage {
            ResourceUsage::ZERO
        }
    }

    // A minimal snapshot: netmon only calls `device()`.
    struct FakeSnapshot;
    impl torda_core::SnapshotProvider for FakeSnapshot {
        fn query(&self, table: &str) -> anyhow::Result<torda_core::Rows> {
            anyhow::bail!("no table {table}")
        }
        fn device(&self) -> Device {
            Device {
                hostname: "host-1".into(),
                os: "Test".into(),
                os_version: "1".into(),
            }
        }
    }

    fn net_event(fields: serde_json::Value) -> SubstrateEvent {
        SubstrateEvent {
            kind: EventKind::NetConnect,
            ts: 0,
            fields,
        }
    }

    /// Builds a `ModuleCtx` around a StubBus + capturing emitter for the e2e tests.
    fn make_ctx(bus: Arc<StubBus>, emitter: Arc<CapturingEmitter>) -> ModuleCtx {
        ModuleCtx {
            bus,
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

    /// Drives the module's background task until it has emitted at least `want`
    /// envelopes, or a bounded number of polls elapse (so a bug can't hang CI).
    async fn drain_until(emitter: &CapturingEmitter, want: usize) {
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(2)).await;
            if emitter.emitted.lock().unwrap().len() >= want {
                break;
            }
        }
    }

    #[tokio::test]
    async fn subscribe_assess_emit_flags_suspicious_and_skips_malformed() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let ctx = make_ctx(bus.clone(), emitter.clone());

        let mut m = NetMonModule::new();
        m.init(ctx).await.unwrap();
        m.start().await.unwrap(); // subscribes before we publish

        // Benign external: 443 → Informational, no detections.
        bus.publish(net_event(serde_json::json!({
            "pid": 100, "image": "curl", "daddr": "93.184.216.34", "dport": 443, "proto": "tcp"
        })));
        // Suspicious loopback: 4444 to 127.0.0.1 → Medium, suspicious_port only.
        bus.publish(net_event(serde_json::json!({
            "pid": 200, "image": "nc", "daddr": "127.0.0.1", "dport": 4444, "proto": "tcp"
        })));
        // Suspicious external: 4444 to a public IP → High, both rules.
        bus.publish(net_event(serde_json::json!({
            "pid": 300, "image": "implant", "daddr": "203.0.113.1", "dport": 4444, "proto": "tcp"
        })));
        // Malformed: no `daddr` — must be skipped, no panic, no envelope.
        bus.publish(net_event(
            serde_json::json!({ "pid": 1, "image": "x", "dport": 4444 }),
        ));

        drain_until(&emitter, 3).await;
        m.stop().await.unwrap(); // clean shutdown

        let emitted = emitter.emitted.lock().unwrap();
        // Exactly one envelope per VALID event; malformed produced none.
        assert_eq!(
            emitted.len(),
            3,
            "one emit per valid connect, malformed skipped"
        );
        for env in emitted.iter() {
            assert_eq!(env.class_uid, class::NETWORK_ACTIVITY);
            assert_eq!(env.class_name, "Network Activity");
            assert_eq!(env.data["activity"], "connect");
        }

        let by_pid = |pid: u64| -> &OcsfEnvelope {
            emitted
                .iter()
                .find(|e| e.data["process"]["pid"] == pid)
                .expect("envelope for pid")
        };

        // Benign 443: Informational, no detections.
        let benign = by_pid(100);
        assert_eq!(benign.severity_id, SEV_INFORMATIONAL);
        assert_eq!(benign.data["detections"].as_array().unwrap().len(), 0);
        assert_eq!(benign.data["connection"]["daddr"], "93.184.216.34");
        assert_eq!(benign.data["connection"]["dport"], 443);

        // Suspicious loopback: Medium, suspicious_port only.
        let loopback = by_pid(200);
        assert_eq!(loopback.severity_id, SEV_MEDIUM);
        let lb_rules: Vec<&str> = loopback.data["detections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["rule"].as_str().unwrap())
            .collect();
        assert_eq!(lb_rules, vec!["suspicious_port"]);

        // Suspicious external: High, both rules.
        let external = by_pid(300);
        assert_eq!(external.severity_id, SEV_HIGH);
        let ext_rules: Vec<&str> = external.data["detections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["rule"].as_str().unwrap())
            .collect();
        assert_eq!(
            ext_rules,
            vec!["suspicious_port", "suspicious_port_to_external"]
        );
    }

    #[tokio::test]
    async fn missing_dport_event_is_skipped_like_missing_daddr() {
        // A NetConnect carrying a `daddr` but NO `dport` is malformed and MUST be
        // skipped — the same safety branch as the missing-`daddr` case.
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = NetMonModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // Malformed (no dport) — must produce nothing.
        bus.publish(net_event(serde_json::json!({
            "pid": 5, "image": "x", "daddr": "203.0.113.1"
        })));
        // A trailing VALID connect is a deterministic sync point: the broadcast
        // bus is ordered, so once THIS one is emitted we KNOW the malformed one
        // before it was already processed (and dropped).
        bus.publish(net_event(serde_json::json!({
            "pid": 7, "image": "nc", "daddr": "203.0.113.1", "dport": 4444
        })));

        drain_until(&emitter, 1).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(
            emitted.len(),
            1,
            "missing-dport event skipped; only the valid connect emitted"
        );
        assert_eq!(emitted[0].data["process"]["pid"], 7);
        assert_eq!(emitted[0].severity_id, SEV_HIGH);
    }

    #[tokio::test]
    async fn non_netconnect_event_is_dropped_by_kind_guard() {
        // The stub bus forwards ALL event kinds regardless of the subscribe
        // filter, so a `ProcessExec` event still reaches netmon's receiver. The
        // module's own `kind != NetConnect` guard must drop it — even though its
        // fields look like a well-formed connect. This proves the guard.
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = NetMonModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // Non-NetConnect kind with well-formed connect-looking fields: dropped.
        bus.publish(SubstrateEvent {
            kind: EventKind::ProcessExec,
            ts: 0,
            fields: serde_json::json!({
                "pid": 9, "image": "nc", "daddr": "203.0.113.1", "dport": 4444
            }),
        });
        // Trailing VALID connect = ordered sync point.
        bus.publish(net_event(serde_json::json!({
            "pid": 10, "image": "curl", "daddr": "93.184.216.34", "dport": 443
        })));

        drain_until(&emitter, 1).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(
            emitted.len(),
            1,
            "ProcessExec dropped by the kind guard; only the connect emitted"
        );
        assert_eq!(emitted[0].data["process"]["pid"], 10);
        assert_eq!(emitted[0].severity_id, SEV_INFORMATIONAL);
    }
}
