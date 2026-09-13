//! The composed ingest pipeline. Order is load-bearing:
//! `Engine::run -> reconcile -> filter(Suppressed) -> group_by_fix`.
use serde::Serialize;
use torda_findings::{Finding, FindingState, RemediationItem};
use torda_findings_engine::aggregate::group_by_fix;
use torda_findings_engine::input::{AssetContextSource, EnrichmentSource};
use torda_findings_engine::lifecycle::reconcile;
use torda_findings_engine::Engine;
use torda_ocsf::OcsfEnvelope;

use crate::cve_source::CveSource;
use crate::matching::detections_from_sbom;
use crate::reachability::RuntimeReachability;

/// The end-to-end ingest result: all scored findings (including suppressed, for
/// the record) plus the fix-grouped remediation items ops acts on.
#[derive(Clone, Debug, Serialize)]
pub struct IngestReport {
    pub findings: Vec<Finding>,
    pub remediation_items: Vec<RemediationItem>,
}

/// The batch's reference time (epoch millis) = the max event `time` across the
/// envelopes. `reconcile` stamps finding lifecycle timestamps from this, so they
/// are derived deterministically from the data (never a wall clock) and a replay
/// of the same batch yields the same timestamps. An empty batch (no events, hence
/// no findings) returns 0.
pub(crate) fn batch_time(envelopes: &[OcsfEnvelope]) -> i64 {
    envelopes.iter().map(|e| e.time).max().unwrap_or(0)
}

/// Composes the full pipeline for a batch of agent SBOM envelopes:
/// SBOM → match → `Engine::run` (correlate/score/decide/suppress) →
/// `reconcile` against prior state → filter out Suppressed → `group_by_fix`.
/// The compose ORDER is load-bearing: reconcile must precede grouping, and the
/// Suppressed filter must sit between them (a suppressed CVE must not inflate a
/// remediation item's closes/assets).
pub fn run_ingest(
    envelopes: &[OcsfEnvelope],
    feed: &dyn CveSource,
    enrichment: &dyn EnrichmentSource,
    assets: &dyn AssetContextSource,
    prior: &[Finding],
) -> IngestReport {
    let detections: Vec<_> = envelopes
        .iter()
        .flat_map(|e| detections_from_sbom(e, feed))
        .collect();
    // Runtime-confirmed reachability is derived from the SAME batch: the SBOM's
    // per-package libraries (5020) joined against library-load observations
    // (9003). The engine applies it upgrade-only. A batch with no 9003 (e.g. a
    // stub-bus agent, or a direct SBOM-only call) yields no confirmations, so
    // scoring falls back to the VEX baseline unchanged.
    let reach = RuntimeReachability::from_envelopes(envelopes);
    let scored = Engine::new(enrichment, assets, &reach).run(detections);
    let findings = reconcile(prior, scored, batch_time(envelopes));
    let actionable: Vec<Finding> = findings
        .iter()
        .filter(|f| f.status != FindingState::Suppressed)
        .cloned()
        .collect();
    let remediation_items = group_by_fix(&actionable);
    IngestReport {
        findings,
        remediation_items,
    }
}

/// Runs EVERY findings-producing mapper over one OCSF batch and composes them into
/// a SINGLE report with UNIFORM cross-run lifecycle.
///
/// Each mapper self-guards on its own `class_uid` (SBOM 5020, process 1007,
/// network 4001, file activity 1001, correlation 9002, plus the posture classes), so
/// handing the whole batch to all eight routes each envelope to exactly one mapper —
/// no double-count.
/// All eight mappers (vuln/process/network/file_activity/correlation plus the
/// posture trio — compliance/drift/fim) reconcile internally against `prior`: each
/// returns findings that are already `Closed -> Reopened` where appropriate.
///
/// The compose is: union every mapper's (already-reconciled) fresh findings,
/// filter out `Suppressed`, and recompute the authoritative `group_by_fix` over
/// what remains.
///
/// **Source-scoped identities** make the union fully reconciled without a
/// dispatcher-level pass: a finding's `Identity` carries its `location`/`vuln_id`
/// namespace (`process:…`, `network:…`, `correlation:…`, the CVE id, the drift
/// entry id, …), so each mapper's internal reconcile can only match prior
/// findings from its OWN source. One mapper never reopens another source's
/// finding, even though every mapper is handed the same `prior` slice.
pub fn run_all_ingest(
    envelopes: &[OcsfEnvelope],
    feed: &dyn CveSource,
    enrichment: &dyn EnrichmentSource,
    assets: &dyn AssetContextSource,
    prior: &[Finding],
) -> IngestReport {
    // 1. Collect the ALREADY-RECONCILED findings from every mapper over the WHOLE
    //    batch. Each mapper ignores non-matching classes, so each envelope lands in
    //    exactly one. Every mapper gets `prior` and reconciles against it
    //    internally. The per-mapper `remediation_items` are discarded — the
    //    authoritative ones are recomputed below over the merged, actionable set.
    let mut all: Vec<Finding> = Vec::new();
    all.extend(crate::pipeline::run_ingest(envelopes, feed, enrichment, assets, prior).findings);
    all.extend(crate::process::run_process_ingest(envelopes, assets, prior).findings);
    all.extend(crate::network::run_network_ingest(envelopes, assets, prior).findings);
    all.extend(crate::file_activity::run_file_activity_ingest(envelopes, assets, prior).findings);
    all.extend(crate::correlation::run_correlation_ingest(envelopes, assets, prior).findings);
    all.extend(crate::compliance::run_compliance_ingest(envelopes, assets, prior).findings);
    all.extend(crate::drift::run_drift_ingest(envelopes, assets, prior).findings);
    all.extend(crate::fim::run_fim_ingest(envelopes, assets, prior).findings);

    // 2-3. Filter Suppressed, then recompute the authoritative fix grouping over the
    //    merged actionable set (order is load-bearing: each mapper's own reconcile
    //    precedes grouping, and the Suppressed filter sits between).
    let actionable: Vec<Finding> = all
        .iter()
        .filter(|f| f.status != FindingState::Suppressed)
        .cloned()
        .collect();
    let remediation_items = group_by_fix(&actionable);
    IngestReport {
        findings: all,
        remediation_items,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matching::{CveFeed, CveHit};
    use std::collections::HashMap;
    use torda_findings::{AssetContext, Criticality, Enrichment, ExploitMaturity, VexStatus};
    use torda_findings_engine::input::{MapAssetContext, MapEnrichment};
    use torda_ocsf::{class, Device, Metadata};

    fn sbom(components: serde_json::Value) -> OcsfEnvelope {
        OcsfEnvelope::new(
            class::SOFTWARE_INVENTORY_INFO,
            "Software Inventory Info",
            Metadata {
                product: "torda".into(),
                version: "0".into(),
                tenant_id: "t".into(),
            },
            Device {
                hostname: "host-1".into(),
                os: "Test".into(),
                os_version: "1".into(),
            },
            serde_json::json!({ "sbom": { "format": "torda-native", "components": components, "component_count": 0 } }),
        )
    }
    fn feed() -> CveFeed {
        CveFeed(vec![
            CveHit {
                name: "openssl".into(),
                version: "3.0.2".into(),
                vuln_id: "CVE-AFF".into(),
                remediation_key: "fix:openssl".into(),
            },
            CveHit {
                name: "glibc".into(),
                version: "2.39".into(),
                vuln_id: "CVE-VEX".into(),
                remediation_key: "fix:glibc".into(),
            },
        ])
    }
    fn enrichment() -> MapEnrichment {
        let mut m = HashMap::new();
        m.insert(
            "CVE-AFF".into(),
            Enrichment {
                cvss_vector: None,
                cvss_env: Some(7.0),
                epss: Some(0.4),
                epss_pct: None,
                kev: false,
                exploit_maturity: ExploitMaturity::Functional,
                vex: VexStatus::Affected,
                feed_version: None,
            },
        );
        m.insert(
            "CVE-VEX".into(),
            Enrichment {
                cvss_vector: None,
                cvss_env: Some(9.0),
                epss: Some(0.5),
                epss_pct: None,
                kev: false,
                exploit_maturity: ExploitMaturity::Functional,
                vex: VexStatus::NotAffected,
                feed_version: None,
            },
        );
        MapEnrichment(m)
    }
    fn assets() -> MapAssetContext {
        MapAssetContext {
            by_asset: HashMap::new(),
            default: AssetContext {
                internet_facing: true,
                criticality: Criticality::High,
                compensating_controls: false,
            },
        }
    }

    #[test]
    fn suppressed_finding_is_recorded_but_excluded_from_remediation_items() {
        let env = sbom(serde_json::json!([
            {"name":"openssl","version":"3.0.2","source":"dpkg"},
            {"name":"glibc","version":"2.39","source":"dpkg"}
        ]));
        let report = run_ingest(&[env], &feed(), &enrichment(), &assets(), &[]);
        assert_eq!(report.findings.len(), 2, "both findings recorded");
        let glibc = report
            .findings
            .iter()
            .find(|f| f.identity.vuln_id == "CVE-VEX")
            .unwrap();
        assert_eq!(glibc.status, FindingState::Suppressed);
        // group-by-fix excludes the suppressed one -> only openssl's fix.
        assert_eq!(
            report.remediation_items.len(),
            1,
            "suppressed excluded from items"
        );
        assert_eq!(report.remediation_items[0].remediation_key, "fix:openssl");
    }

    #[test]
    fn prior_closed_finding_is_reopened() {
        let env = sbom(serde_json::json!([{"name":"openssl","version":"3.0.2","source":"dpkg"}]));
        // First run: openssl is Open.
        let first = run_ingest(
            std::slice::from_ref(&env),
            &feed(),
            &enrichment(),
            &assets(),
            &[],
        );
        let mut prior = first.findings[0].clone();
        prior.status = FindingState::Closed;
        // Second run with that finding as prior-Closed -> the fresh one reopens.
        let second = run_ingest(&[env], &feed(), &enrichment(), &assets(), &[prior]);
        assert_eq!(second.findings[0].status, FindingState::Reopened);
    }

    #[test]
    fn runtime_library_load_confirms_reach_upgrade_only() {
        // openssl provides libssl.so.3; a CVE on it that VEX leaves Unknown
        // (baseline reach 0.3). A 9003 load of that library in the same batch
        // should upgrade reach to 1.0; absent the load, it stays 0.3.
        let component = serde_json::json!([
            {"name":"openssl","version":"3.0.2","source":"dpkg","libraries":["/usr/lib/libssl.so.3"]}
        ]);
        let feed = CveFeed(vec![CveHit {
            name: "openssl".into(),
            version: "3.0.2".into(),
            vuln_id: "CVE-RCH".into(),
            remediation_key: "fix:openssl".into(),
        }]);
        let mut m = HashMap::new();
        m.insert(
            "CVE-RCH".into(),
            Enrichment {
                cvss_vector: None,
                cvss_env: Some(7.0),
                epss: Some(0.2),
                epss_pct: None,
                kev: false,
                exploit_maturity: ExploitMaturity::Functional,
                vex: VexStatus::Unknown,
                feed_version: None,
            },
        );
        let enrichment = MapEnrichment(m);

        let sbom_env = sbom(component);
        let load_env = OcsfEnvelope::new(
            class::RUNTIME_MODULE_LOAD,
            "Runtime Module Load",
            Metadata {
                product: "torda".into(),
                version: "0".into(),
                tenant_id: "t".into(),
            },
            Device {
                hostname: "host-1".into(),
                os: "Test".into(),
                os_version: "1".into(),
            },
            serde_json::json!({ "module": { "path": "/usr/lib/libssl.so.3" }, "pid": 1, "image": "curl" }),
        );

        // No load observation -> Unknown baseline reach 0.3, no runtime data.
        let base = run_ingest(
            std::slice::from_ref(&sbom_env),
            &feed,
            &enrichment,
            &assets(),
            &[],
        );
        let bf = base
            .findings
            .iter()
            .find(|f| f.identity.vuln_id == "CVE-RCH")
            .expect("openssl finding");
        assert!((bf.score.explain.reach - 0.3).abs() < 1e-6);
        assert_eq!(bf.score.explain.runtime_reachable, None);

        // Load observation in the SAME batch -> reach confirmed to 1.0.
        let confirmed = run_ingest(&[sbom_env, load_env], &feed, &enrichment, &assets(), &[]);
        let cf = confirmed
            .findings
            .iter()
            .find(|f| f.identity.vuln_id == "CVE-RCH")
            .expect("openssl finding");
        assert_eq!(cf.score.explain.reach, 1.0, "runtime load upgraded reach");
        assert_eq!(cf.score.explain.runtime_reachable, Some(true));
        assert!(
            cf.score.r > bf.score.r,
            "confirmed reachability raises the score"
        );
    }
}

/// Tests for the unified dispatcher: one batch mixing every findings-producing
/// class, composed into one report with uniform cross-run lifecycle.
#[cfg(test)]
mod all_ingest_tests {
    use super::*;
    use torda_ocsf::{class, Device, Metadata};

    use crate::fixtures::{default_assets, default_enrichment, default_feed};

    // --- envelope builders (one flagged record of each findings-producing class) ---

    /// SBOM (class 5020): openssl 3.0.2 matches `default_feed` -> CVE-2022-3602,
    /// which `default_enrichment` marks Affected -> an Open (non-suppressed) finding.
    fn sbom_env() -> OcsfEnvelope {
        OcsfEnvelope::new(
            class::SOFTWARE_INVENTORY_INFO,
            "Software Inventory Info",
            Metadata {
                product: "torda".into(),
                version: "0".into(),
                tenant_id: "t".into(),
            },
            Device {
                hostname: "host-1".into(),
                os: "Test".into(),
                os_version: "1".into(),
            },
            serde_json::json!({ "sbom": { "format": "torda-native", "components": [
                {"name":"openssl","version":"3.0.2","source":"dpkg"}
            ], "component_count": 1 } }),
        )
    }

    fn det(rule: &str) -> serde_json::Value {
        serde_json::json!({ "rule": rule, "reason": format!("{rule} fired") })
    }

    /// Process Activity (class 1007), flagged -> `process:{image}`.
    fn proc_env(image: &str, detections: serde_json::Value) -> OcsfEnvelope {
        OcsfEnvelope::new(
            class::PROCESS_ACTIVITY,
            "Process Activity",
            Metadata {
                product: "torda".into(),
                version: "0".into(),
                tenant_id: "t".into(),
            },
            Device {
                hostname: "host-1".into(),
                os: "Test".into(),
                os_version: "1".into(),
            },
            serde_json::json!({
                "process": { "pid": 42, "image": image },
                "activity": "exec",
                "detections": detections,
            }),
        )
    }

    /// Network Activity (class 4001), flagged -> `network:{daddr}:{dport}`.
    fn net_env(daddr: &str, dport: u64) -> OcsfEnvelope {
        OcsfEnvelope::new(
            class::NETWORK_ACTIVITY,
            "Network Activity",
            Metadata {
                product: "torda".into(),
                version: "0".into(),
                tenant_id: "t".into(),
            },
            Device {
                hostname: "host-1".into(),
                os: "Test".into(),
                os_version: "1".into(),
            },
            serde_json::json!({
                "connection": { "daddr": daddr, "dport": dport, "proto": "tcp", "pid": 7 },
                "detections": [det("suspicious_port_to_external")],
            }),
        )
    }

    /// Correlated Activity (class 9002), flagged chain ->
    /// `correlation:{image}->{daddr}:{dport}`.
    fn corr_env(image: &str, daddr: &str, dport: u64) -> OcsfEnvelope {
        OcsfEnvelope::new(
            class::CORRELATED_ACTIVITY,
            "Correlated Activity",
            Metadata {
                product: "torda".into(),
                version: "0".into(),
                tenant_id: "t".into(),
            },
            Device {
                hostname: "host-1".into(),
                os: "Test".into(),
                os_version: "1".into(),
            },
            serde_json::json!({
                "activity": "process_network",
                "process": { "pid": 42, "image": image, "detections": [], "attributed": true },
                "connection": { "daddr": daddr, "dport": dport, "proto": "tcp", "detections": [] },
                "detections": [det("suspicious_process_suspicious_connection")],
            }),
        )
    }

    /// Device Config State (class 5002) posture: one drifted entry -> a finding.
    /// The drift mapper reconciles internally against `prior`, same as every
    /// other mapper.
    const DRIFT_NDJSON: &str = r#"{"class_uid":5002,"class_name":"Device Config State","time":0,"severity_id":1,"metadata":{"product":"torda","version":"0","tenant_id":"t"},"device":{"hostname":"host-1","os":"Test","os_version":"1"},"data":{"drift":{"records":[{"entry_id":"openssl-pinned","drifted":true,"subject":"openssl","location":"packages","weight":0.7,"expected":"3.0.14","actual":"3.0.2","remediation_key":"pin:openssl=3.0.14"}]}}}"#;

    fn drift_env() -> OcsfEnvelope {
        serde_json::from_str(DRIFT_NDJSON).unwrap()
    }

    /// File System Activity (class 1001), flagged -> `file:{path}`.
    fn file_env(path: &str, detections: serde_json::Value) -> OcsfEnvelope {
        OcsfEnvelope::new(
            class::FILE_SYSTEM_ACTIVITY,
            "File System Activity",
            Metadata {
                product: "torda".into(),
                version: "0".into(),
                tenant_id: "t".into(),
            },
            Device {
                hostname: "host-1".into(),
                os: "Test".into(),
                os_version: "1".into(),
            },
            serde_json::json!({
                "file": { "path": path, "op": "write" },
                "pid": 42,
                "image": "vim",
                "detections": detections,
            }),
        )
    }

    // --- tests ---

    #[test]
    fn multi_class_dispatch_composes_one_report_from_every_source() {
        // A batch mixing one flagged envelope of DIFFERENT classes, plus a benign
        // process record (no detections) that must yield nothing.
        let batch = vec![
            sbom_env(),
            proc_env(
                "/tmp/nc",
                serde_json::json!([det("lolbin_in_suspicious_path")]),
            ),
            net_env("203.0.113.1", 4444),
            corr_env("powershell", "203.0.113.1", 4444),
            drift_env(),
            file_env(
                "/etc/passwd",
                serde_json::json!([det("write_to_sensitive_config")]),
            ),
            proc_env("/usr/bin/echo", serde_json::json!([])), // benign -> no finding
        ];
        let report = run_all_ingest(
            &batch,
            &default_feed(),
            &default_enrichment(),
            &default_assets(),
            &[],
        );

        // Exactly one finding from EACH of the six sources — no more (benign
        // ignored), no double-count.
        assert_eq!(
            report.findings.len(),
            6,
            "one finding per flagged source, benign ignored"
        );
        let ids: Vec<&str> = report
            .findings
            .iter()
            .map(|f| f.identity.vuln_id.as_str())
            .collect();
        assert!(ids.contains(&"CVE-2022-3602"), "vuln/SBOM finding present");
        assert!(ids.contains(&"process:/tmp/nc"), "process finding present");
        assert!(
            ids.contains(&"network:203.0.113.1:4444"),
            "network finding present"
        );
        assert!(
            ids.contains(&"correlation:powershell->203.0.113.1:4444"),
            "correlation finding present"
        );
        assert!(
            ids.contains(&"openssl-pinned"),
            "posture (drift) finding present"
        );
        assert!(
            ids.contains(&"file:/etc/passwd"),
            "file-activity finding present"
        );
        // The benign echo never becomes a finding.
        assert!(
            !ids.iter().any(|id| id.contains("echo")),
            "benign process yields nothing"
        );
        // Exactly one file finding — no double-count of the 1001 envelope.
        assert_eq!(
            ids.iter().filter(|id| id.starts_with("file:")).count(),
            1,
            "the flagged file envelope is counted exactly once"
        );
    }

    #[test]
    fn posture_prior_closed_is_reopened_natively() {
        // The KEY property: the posture (drift) mapper reconciles internally now
        // (Task 1), so a prior-Closed posture identity comes back Reopened through
        // `run_all_ingest` via the posture mapper's own reconcile, not a dispatcher
        // pass.
        let batch = vec![drift_env()];
        // First run: no prior for this identity -> the drift finding is Open.
        let first = run_all_ingest(
            &batch,
            &default_feed(),
            &default_enrichment(),
            &default_assets(),
            &[],
        );
        let drift = first
            .findings
            .iter()
            .find(|f| f.identity.vuln_id == "openssl-pinned")
            .unwrap();
        assert_eq!(drift.status, FindingState::Open, "no prior -> Open");

        // Feed that same identity back as prior-Closed.
        let mut prior = drift.clone();
        prior.status = FindingState::Closed;
        let second = run_all_ingest(
            &batch,
            &default_feed(),
            &default_enrichment(),
            &default_assets(),
            &[prior],
        );
        let reopened: Vec<_> = second
            .findings
            .iter()
            .filter(|f| f.identity.vuln_id == "openssl-pinned")
            .collect();
        assert_eq!(
            reopened.len(),
            1,
            "reopen does not duplicate the posture finding"
        );
        assert_eq!(
            reopened[0].status,
            FindingState::Reopened,
            "posture mapper reconciles natively"
        );
    }

    #[test]
    fn reconcile_capable_prior_closed_reopens_exactly_once_not_double_broken() {
        // A reconcile-capable class (process) reconciles internally; with the
        // dispatcher reconcile retired, this must still reopen exactly once via the
        // mapper's own internal reconcile — no double-reconcile to be idempotent
        // against anymore.
        let batch = vec![proc_env(
            "/tmp/nc",
            serde_json::json!([det("lolbin_in_suspicious_path")]),
        )];
        let first = run_all_ingest(
            &batch,
            &default_feed(),
            &default_enrichment(),
            &default_assets(),
            &[],
        );
        let proc = first
            .findings
            .iter()
            .find(|f| f.identity.vuln_id == "process:/tmp/nc")
            .unwrap();
        assert_eq!(proc.status, FindingState::Open, "no prior -> Open");

        let mut prior = proc.clone();
        prior.status = FindingState::Closed;
        let second = run_all_ingest(
            &batch,
            &default_feed(),
            &default_enrichment(),
            &default_assets(),
            &[prior],
        );
        let reopened: Vec<_> = second
            .findings
            .iter()
            .filter(|f| f.identity.vuln_id == "process:/tmp/nc")
            .collect();
        assert_eq!(
            reopened.len(),
            1,
            "the mapper's own reconcile does not duplicate the finding"
        );
        assert_eq!(
            reopened[0].status,
            FindingState::Reopened,
            "Closed -> Reopened via the mapper's internal reconcile"
        );
    }

    #[test]
    fn uniform_lifecycle_covers_posture_and_reconcile_capable_together() {
        // One batch, one prior carrying BOTH a Closed posture identity and a Closed
        // reconcile-capable identity -> both come back Reopened, each exactly once.
        let batch = vec![drift_env(), net_env("203.0.113.1", 4444)];
        let seed = run_all_ingest(
            &batch,
            &default_feed(),
            &default_enrichment(),
            &default_assets(),
            &[],
        );
        let prior: Vec<Finding> = seed
            .findings
            .iter()
            .filter(|f| {
                f.identity.vuln_id == "openssl-pinned"
                    || f.identity.vuln_id == "network:203.0.113.1:4444"
            })
            .map(|f| {
                let mut c = f.clone();
                c.status = FindingState::Closed;
                c
            })
            .collect();
        assert_eq!(
            prior.len(),
            2,
            "seeded both a posture and a reconcile-capable prior"
        );

        let out = run_all_ingest(
            &batch,
            &default_feed(),
            &default_enrichment(),
            &default_assets(),
            &prior,
        );
        let drift = out
            .findings
            .iter()
            .filter(|f| f.identity.vuln_id == "openssl-pinned")
            .collect::<Vec<_>>();
        let net = out
            .findings
            .iter()
            .filter(|f| f.identity.vuln_id == "network:203.0.113.1:4444")
            .collect::<Vec<_>>();
        assert_eq!(drift.len(), 1, "posture not duplicated");
        assert_eq!(net.len(), 1, "reconcile-capable not duplicated");
        assert_eq!(
            drift[0].status,
            FindingState::Reopened,
            "posture Closed -> Reopened via native mapper reconcile"
        );
        assert_eq!(
            net[0].status,
            FindingState::Reopened,
            "reconcile-capable Closed -> Reopened via its own mapper reconcile"
        );
    }

    #[test]
    fn remediation_items_are_grouped_over_the_merged_actionable_set() {
        // Distinct remediation keys across sources -> one remediation item per key,
        // recomputed authoritatively over the union (per-mapper items discarded).
        let batch = vec![
            proc_env(
                "/tmp/nc",
                serde_json::json!([det("lolbin_in_suspicious_path")]),
            ),
            net_env("203.0.113.1", 4444),
            corr_env("powershell", "203.0.113.1", 4444),
            drift_env(),
        ];
        let report = run_all_ingest(
            &batch,
            &default_feed(),
            &default_enrichment(),
            &default_assets(),
            &[],
        );
        let mut keys: Vec<&str> = report
            .remediation_items
            .iter()
            .map(|i| i.remediation_key.as_str())
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "pin:openssl=3.0.14",
                "triage-attack-chain",
                "triage-suspicious-connection",
                "triage-suspicious-process"
            ],
            "one remediation item per distinct key across every source"
        );
    }

    #[test]
    fn each_envelope_is_handled_by_exactly_one_mapper() {
        // A process envelope must produce exactly one process finding — its class
        // guard keeps every other mapper from also emitting for it (no double-count).
        let batch = vec![proc_env("/tmp/nc", serde_json::json!([det("lolbin")]))];
        let report = run_all_ingest(
            &batch,
            &default_feed(),
            &default_enrichment(),
            &default_assets(),
            &[],
        );
        assert_eq!(
            report.findings.len(),
            1,
            "one flagged process envelope -> exactly one finding total"
        );
        assert_eq!(report.findings[0].identity.vuln_id, "process:/tmp/nc");
    }
}
