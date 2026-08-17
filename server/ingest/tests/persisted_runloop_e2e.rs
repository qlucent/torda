//! Two-run CLI/run-loop end-to-end test: proves cross-invocation persistence
//! through a REAL `JsonFileStore` on a temp file — the exact code path
//! `server/ingest/src/main.rs` drives (`persisted_ingest(&store, |prior|
//! run_all_ingest(...))`).
//!
//! Run 1: a batch with one flagged network detection -> a fresh `Open`
//! finding, persisted to the store file.
//! Ops closes it (load -> mutate status -> upsert), simulating an operator
//! marking it resolved between "invocations".
//! Run 2: the SAME batch recurs. Because the on-disk prior now holds it
//! `Closed`, `run_all_ingest`'s single authoritative `reconcile` REOPENS it —
//! exactly one finding for that identity, not a duplicate and not a fresh
//! `Open`. Both the returned report and what's freshly loaded from the store
//! file must show `Reopened`.
use torda_findings::FindingState;
use torda_ocsf::{class, Device, Metadata, OcsfEnvelope};

use torda_ingest::fixtures::{default_assets, default_enrichment, default_feed};
use torda_ingest::pipeline::run_all_ingest;
use torda_ingest::store::{persisted_ingest, FindingsStore, JsonFileStore};

/// A unique temp path under the OS temp dir, cleaned up on drop.
struct TempPath {
    path: std::path::PathBuf,
}
impl TempPath {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "torda-ingest-runloop-e2e-{}-{}-{}",
            tag,
            std::process::id(),
            n
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self {
            path: dir.join("findings.json"),
        }
    }
}
impl Drop for TempPath {
    fn drop(&mut self) {
        if let Some(dir) = self.path.parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// One flagged Network Activity (class 4001) envelope -> identity
/// `network:203.0.113.1:4444`, matching how `pipeline.rs`'s dispatch test
/// builds a flagged network record.
fn flagged_net_env() -> OcsfEnvelope {
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
            "connection": { "daddr": "203.0.113.1", "dport": 4444, "proto": "tcp", "pid": 7 },
            "detections": [{ "rule": "suspicious_port_to_external", "reason": "suspicious_port_to_external fired" }],
        }),
    )
}

/// One flagged File System Activity (class 1001) envelope -> identity
/// `file:/etc/passwd`, matching how `pipeline.rs`'s dispatch test builds a
/// flagged file record (a write to a sensitive config path).
fn flagged_file_env() -> OcsfEnvelope {
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
            "file": { "path": "/etc/passwd", "op": "write" },
            "pid": 42,
            "image": "vim",
            "detections": [{ "rule": "write_to_sensitive_config", "reason": "write_to_sensitive_config fired" }],
        }),
    )
}

#[test]
fn cross_invocation_open_closed_reopened_via_real_store_file() {
    let tp = TempPath::new("net");
    let batch = vec![flagged_net_env()];

    // --- "Invocation" 1: fresh store, one flagged detection -> Open, persisted.
    let store1 = JsonFileStore::new(tp.path.clone());
    let report1 = persisted_ingest(&store1, |prior| {
        assert!(
            prior.is_empty(),
            "first invocation sees no prior (fresh store file)"
        );
        run_all_ingest(
            &batch,
            &default_feed(),
            &default_enrichment(),
            &default_assets(),
            prior,
        )
    })
    .unwrap();

    let finding1 = report1
        .findings
        .iter()
        .find(|f| f.identity.vuln_id == "network:203.0.113.1:4444")
        .expect("run 1 must produce the flagged network finding");
    assert_eq!(
        finding1.status,
        FindingState::Open,
        "no prior -> fresh finding is Open"
    );
    let finding_id = finding1.finding_id.clone();

    // A BRAND-NEW store handle on the same path sees it persisted, Open.
    let persisted_after_run1 = JsonFileStore::new(tp.path.clone()).load().unwrap();
    assert_eq!(
        persisted_after_run1.len(),
        1,
        "exactly one finding persisted after run 1"
    );
    assert_eq!(persisted_after_run1[0].finding_id, finding_id);
    assert_eq!(persisted_after_run1[0].status, FindingState::Open);

    // --- Ops closes it: fresh handle, load -> mutate -> upsert.
    let ops_store = JsonFileStore::new(tp.path.clone());
    let mut closed = ops_store.load().unwrap();
    assert_eq!(closed.len(), 1);
    closed[0].status = FindingState::Closed;
    ops_store.upsert(&closed).unwrap();

    // Sanity: a fresh handle now sees it Closed on disk.
    let persisted_after_close = JsonFileStore::new(tp.path.clone()).load().unwrap();
    assert_eq!(persisted_after_close[0].status, FindingState::Closed);

    // --- "Invocation" 2: same detection recurs. A brand-new store handle on
    // the SAME file loads the Closed prior from disk -> the dispatcher's
    // single authoritative reconcile REOPENS it.
    let store2 = JsonFileStore::new(tp.path.clone());
    let report2 = persisted_ingest(&store2, |prior| {
        assert_eq!(prior.len(), 1, "run 2 sees the one persisted prior");
        assert_eq!(
            prior[0].status,
            FindingState::Closed,
            "run 2's prior is the Closed one ops set"
        );
        run_all_ingest(
            &batch,
            &default_feed(),
            &default_enrichment(),
            &default_assets(),
            prior,
        )
    })
    .unwrap();

    let matching2: Vec<_> = report2
        .findings
        .iter()
        .filter(|f| f.identity.vuln_id == "network:203.0.113.1:4444")
        .collect();
    assert_eq!(
        matching2.len(),
        1,
        "recurrence must not duplicate the finding"
    );
    assert_eq!(
        matching2[0].finding_id, finding_id,
        "same identity, not a new finding_id"
    );
    assert_eq!(
        matching2[0].status,
        FindingState::Reopened,
        "Closed prior + recurrence -> Reopened, not a fresh Open"
    );

    // And what's now on disk (a fresh handle) reflects the same: exactly one
    // finding, Reopened.
    let persisted_after_run2 = JsonFileStore::new(tp.path.clone()).load().unwrap();
    assert_eq!(
        persisted_after_run2.len(),
        1,
        "still exactly one persisted identity"
    );
    assert_eq!(persisted_after_run2[0].finding_id, finding_id);
    assert_eq!(
        persisted_after_run2[0].status,
        FindingState::Reopened,
        "persisted state is Reopened after run 2"
    );
}

/// The file-class counterpart of the above: proves the SAME cross-invocation
/// Open -> Closed -> Reopened lifecycle through a real `JsonFileStore` file for
/// a File System Activity (class 1001) finding, dispatched via
/// `run_all_ingest`'s file_activity mapper.
#[test]
fn cross_invocation_open_closed_reopened_for_file_finding_via_real_store_file() {
    let tp = TempPath::new("file");
    let batch = vec![flagged_file_env()];

    // --- "Invocation" 1: fresh store, one flagged file write -> Open, persisted.
    let store1 = JsonFileStore::new(tp.path.clone());
    let report1 = persisted_ingest(&store1, |prior| {
        assert!(
            prior.is_empty(),
            "first invocation sees no prior (fresh store file)"
        );
        run_all_ingest(
            &batch,
            &default_feed(),
            &default_enrichment(),
            &default_assets(),
            prior,
        )
    })
    .unwrap();

    let finding1 = report1
        .findings
        .iter()
        .find(|f| f.identity.vuln_id == "file:/etc/passwd")
        .expect("run 1 must produce the flagged file finding");
    assert_eq!(
        finding1.status,
        FindingState::Open,
        "no prior -> fresh finding is Open"
    );
    let finding_id = finding1.finding_id.clone();

    // A BRAND-NEW store handle on the same path sees it persisted, Open.
    let persisted_after_run1 = JsonFileStore::new(tp.path.clone()).load().unwrap();
    assert_eq!(
        persisted_after_run1.len(),
        1,
        "exactly one finding persisted after run 1"
    );
    assert_eq!(persisted_after_run1[0].finding_id, finding_id);
    assert_eq!(persisted_after_run1[0].status, FindingState::Open);

    // --- Ops closes it: fresh handle, load -> mutate -> upsert.
    let ops_store = JsonFileStore::new(tp.path.clone());
    let mut closed = ops_store.load().unwrap();
    assert_eq!(closed.len(), 1);
    closed[0].status = FindingState::Closed;
    ops_store.upsert(&closed).unwrap();

    // Sanity: a fresh handle now sees it Closed on disk.
    let persisted_after_close = JsonFileStore::new(tp.path.clone()).load().unwrap();
    assert_eq!(persisted_after_close[0].status, FindingState::Closed);

    // --- "Invocation" 2: same detection recurs. A brand-new store handle on
    // the SAME file loads the Closed prior from disk -> the file_activity
    // mapper's own internal reconcile REOPENS it.
    let store2 = JsonFileStore::new(tp.path.clone());
    let report2 = persisted_ingest(&store2, |prior| {
        assert_eq!(prior.len(), 1, "run 2 sees the one persisted prior");
        assert_eq!(
            prior[0].status,
            FindingState::Closed,
            "run 2's prior is the Closed one ops set"
        );
        run_all_ingest(
            &batch,
            &default_feed(),
            &default_enrichment(),
            &default_assets(),
            prior,
        )
    })
    .unwrap();

    let matching2: Vec<_> = report2
        .findings
        .iter()
        .filter(|f| f.identity.vuln_id == "file:/etc/passwd")
        .collect();
    assert_eq!(
        matching2.len(),
        1,
        "recurrence must not duplicate the finding"
    );
    assert_eq!(
        matching2[0].finding_id, finding_id,
        "same identity, not a new finding_id"
    );
    assert_eq!(
        matching2[0].status,
        FindingState::Reopened,
        "Closed prior + recurrence -> Reopened, not a fresh Open"
    );

    // And what's now on disk (a fresh handle) reflects the same: exactly one
    // finding, Reopened.
    let persisted_after_run2 = JsonFileStore::new(tp.path.clone()).load().unwrap();
    assert_eq!(
        persisted_after_run2.len(),
        1,
        "still exactly one persisted identity"
    );
    assert_eq!(persisted_after_run2[0].finding_id, finding_id);
    assert_eq!(
        persisted_after_run2[0].status,
        FindingState::Reopened,
        "persisted state is Reopened after run 2"
    );
}
