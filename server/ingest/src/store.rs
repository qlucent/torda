//! Persistent findings state — the missing half of the lifecycle.
//!
//! Every ingest path (`run_ingest`, `run_network_ingest`, `run_process_ingest`,
//! …) takes `prior: &[Finding]` and runs `reconcile(prior, fresh)` so a recurring
//! detection that matched a prior **Closed** finding Reopens instead of
//! duplicating. But `prior` is only meaningful if it comes from REAL persisted
//! state across runs — otherwise `reconcile` never fires. This module supplies
//! that state.
//!
//! A [`FindingsStore`] is keyed by `Finding::finding_id` (the stable,
//! identity-derived key). [`persisted_ingest`] wires a store around any
//! `run_*_ingest` closure: load prior → run (which reconciles) → carry forward
//! ops-terminal decisions → persist → return.
//!
//! Two impls ship: [`InMemoryStore`] (tests / ephemeral) and [`JsonFileStore`]
//! (atomic temp-file+rename write; missing file → empty, not an error).
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use torda_findings::{Finding, FindingState};

use crate::pipeline::IngestReport;

/// Persistent store of findings keyed by `Finding::finding_id`.
///
/// The contract is an insert-or-replace *merge*, never a wholesale rewrite: a
/// finding already stored but ABSENT from an `upsert` batch is PRESERVED (a
/// detection that didn't recur this run keeps its last-known state — its ops
/// decision must not silently vanish).
pub trait FindingsStore {
    /// Load every persisted finding. A store that has never been written is
    /// EMPTY, not an error (first run).
    fn load(&self) -> anyhow::Result<Vec<Finding>>;

    /// Insert-or-replace each finding by `finding_id`. Findings already stored
    /// but ABSENT from `findings` are PRESERVED (not deleted).
    fn upsert(&self, findings: &[Finding]) -> anyhow::Result<()>;
}

/// In-memory store — a `Mutex<BTreeMap<finding_id, Finding>>`. The BTreeMap
/// gives `load` a deterministic (finding_id-sorted) order. For tests and any
/// ephemeral, single-process use.
pub struct InMemoryStore {
    by_id: Mutex<BTreeMap<String, Finding>>,
}

impl InMemoryStore {
    /// A fresh, empty store.
    pub fn new() -> Self {
        Self {
            by_id: Mutex::new(BTreeMap::new()),
        }
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl FindingsStore for InMemoryStore {
    fn load(&self) -> anyhow::Result<Vec<Finding>> {
        let guard = self.by_id.lock().expect("findings store mutex poisoned");
        Ok(guard.values().cloned().collect())
    }

    fn upsert(&self, findings: &[Finding]) -> anyhow::Result<()> {
        let mut guard = self.by_id.lock().expect("findings store mutex poisoned");
        for f in findings {
            guard.insert(f.finding_id.clone(), f.clone());
        }
        Ok(())
    }
}

/// File-backed store. On-disk shape is a JSON array `Vec<Finding>` (simplest to
/// diff/inspect); `load` re-keys it by `finding_id` internally. Writes are
/// ATOMIC: a temp file in the SAME directory is written then `rename`d over the
/// target, so a crash mid-write never leaves a torn/partial `path`.
pub struct JsonFileStore {
    path: PathBuf,
}

impl JsonFileStore {
    /// A store backed by the JSON file at `path`. The file need not exist yet
    /// (a missing file loads as empty).
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl FindingsStore for JsonFileStore {
    fn load(&self) -> anyhow::Result<Vec<Finding>> {
        // Missing file = first run = empty set (NOT an error). A read failure
        // for any other reason, or a parse failure, IS an error.
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(anyhow::Error::from(e)
                    .context(format!("reading findings store {}", self.path.display())));
            }
        };
        let findings: Vec<Finding> = serde_json::from_slice(&bytes)
            .map_err(|e| anyhow::anyhow!("parsing findings store {}: {e}", self.path.display()))?;
        Ok(findings)
    }

    fn upsert(&self, findings: &[Finding]) -> anyhow::Result<()> {
        // Merge onto the current on-disk set: preserve absent, replace present,
        // keyed by finding_id, deterministic order via BTreeMap.
        let mut by_id: BTreeMap<String, Finding> = self
            .load()?
            .into_iter()
            .map(|f| (f.finding_id.clone(), f))
            .collect();
        for f in findings {
            by_id.insert(f.finding_id.clone(), f.clone());
        }
        let merged: Vec<&Finding> = by_id.values().collect();
        let bytes = serde_json::to_vec_pretty(&merged)?;

        // Best-effort: ensure the parent directory exists so both the temp file
        // and the rename target have a home.
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }

        write_atomic(&self.path, &bytes)
    }
}

/// Writes `bytes` to `path` atomically: a uniquely-named temp file in the SAME
/// directory (so `rename` is a same-filesystem, atomic swap) is written and
/// flushed, then renamed over `path`. On any error the temp file is cleaned up
/// so no stray `.tmp` is left behind.
fn write_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;

    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("store path has no file name: {}", path.display()))?
        .to_string_lossy();

    // Unique temp name in the same dir: pid + a monotonic counter keeps
    // concurrent writers from colliding without pulling in an RNG dependency.
    let unique = {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("{}.{}.{}.tmp", file_name, std::process::id(), n)
    };
    let tmp_path = match dir {
        Some(d) => d.join(unique),
        None => PathBuf::from(unique),
    };

    // Write + flush + fsync, then rename. Any failure removes the temp file.
    let write_result = (|| -> anyhow::Result<()> {
        let mut f = std::fs::File::create(&tmp_path)?;
        f.write_all(bytes)?;
        f.flush()?;
        f.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e.context(format!(
            "writing temp findings store {}",
            tmp_path.display()
        )));
    }
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(anyhow::Error::from(e).context(format!(
            "atomically replacing findings store {}",
            path.display()
        )));
    }
    Ok(())
}

/// Preserve ops-terminal decisions across recurrences. For each FRESH finding
/// whose `finding_id` matches a PRIOR finding whose status is `Accepted` or
/// `Suppressed`, set the fresh finding's status to that prior status.
///
/// Why: a fresh detection is minted `Open` (or `Reopened` by `reconcile`). A
/// blind upsert would clobber an ops decision — "we accept this risk" /
/// "suppressed as not-affected" — back to `Open` on the next recurrence. This
/// carries those two TERMINAL ops states forward.
///
/// Precedence (load-bearing): this runs AFTER `reconcile` (which lives inside
/// the `run` closure). So a prior-**Closed** identity has ALREADY become
/// `Reopened` in the fresh set, and a Closed prior is intentionally NOT carried
/// here — a genuine regression must stand. Only `Accepted`/`Suppressed` are
/// carried; `Open`/`Reopened` pass through untouched.
fn carry_forward_ops_states(prior: &[Finding], fresh: &mut [Finding]) {
    let ops_terminal: BTreeMap<&str, FindingState> = prior
        .iter()
        .filter(|f| matches!(f.status, FindingState::Accepted | FindingState::Suppressed))
        .map(|f| (f.finding_id.as_str(), f.status))
        .collect();
    if ops_terminal.is_empty() {
        return;
    }
    for f in fresh.iter_mut() {
        if let Some(&status) = ops_terminal.get(f.finding_id.as_str()) {
            f.status = status;
        }
    }
}

/// Wire a [`FindingsStore`] around any `run_*_ingest` closure so the lifecycle
/// works across runs.
///
/// Flow (order is load-bearing):
/// 1. `load` the persisted prior findings.
/// 2. `run(&prior)` — the ingest reconciles fresh detections against that REAL
///    prior (Closed → Reopened).
/// 3. [`carry_forward_ops_states`] preserves prior `Accepted`/`Suppressed`
///    decisions on recurring findings.
/// 4. `upsert` the resulting findings (insert-or-replace; absent preserved).
/// 5. return the report.
///
/// Usage:
/// ```ignore
/// let report = persisted_ingest(&store, |prior| {
///     run_network_ingest(&envs, &assets, prior)
/// })?;
/// ```
pub fn persisted_ingest(
    store: &dyn FindingsStore,
    run: impl FnOnce(&[Finding]) -> IngestReport,
) -> anyhow::Result<IngestReport> {
    let prior = store.load()?;
    let mut report = run(&prior);
    carry_forward_ops_states(&prior, &mut report.findings);
    store.upsert(&report.findings)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use torda_findings::{
        AssetContext, Criticality, Decision, DetectionMethod, Enrichment, ExploitMaturity,
        Identity, Provenance, RemediationItem, Score, ScoreExplain, VexStatus,
    };
    use torda_findings_engine::lifecycle::reconcile;

    /// A minimal but complete finding with a given id + status. `component`
    /// lets tests distinguish a "changed field" replacement.
    fn finding(id: &str, status: FindingState, component: &str) -> Finding {
        Finding {
            finding_id: id.into(),
            identity: Identity {
                asset_id: "host-A".into(),
                vuln_id: id.into(),
                component: component.into(),
                location: "dpkg".into(),
            },
            provenance: vec![Provenance {
                source: "torda".into(),
                method: DetectionMethod::Authenticated,
                reported_severity: None,
                confidence: 0.95,
            }],
            enrichment: Enrichment {
                cvss_vector: None,
                cvss_env: Some(7.0),
                epss: Some(0.2),
                epss_pct: None,
                kev: false,
                exploit_maturity: ExploitMaturity::Functional,
                vex: VexStatus::Affected,
            },
            asset_ctx: AssetContext {
                internet_facing: false,
                criticality: Criticality::Normal,
                compensating_controls: false,
            },
            score: Score {
                r: 41,
                explain: ScoreExplain {
                    sev: 0.7,
                    likelihood: 0.7,
                    exposure: 0.8,
                    crit: 0.9,
                    reach: 1.0,
                },
            },
            decision: Decision::Attend,
            sla_hours: 336,
            remediation_key: "upgrade:openssl>=3.0.14".into(),
            status,
            first_seen: None,
            last_seen: None,
            closed_at: None,
        }
    }

    /// A unique temp path under the OS temp dir, cleaned up by `TempPath`.
    struct TempPath {
        path: PathBuf,
    }
    impl TempPath {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static N: AtomicU64 = AtomicU64::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "torda-ingest-store-{}-{}-{}",
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

    fn report_of(findings: Vec<Finding>) -> IngestReport {
        IngestReport {
            findings,
            remediation_items: Vec::<RemediationItem>::new(),
        }
    }

    // --- Round-trip -------------------------------------------------------

    #[test]
    fn json_store_round_trips_through_a_fresh_handle() {
        let tp = TempPath::new("roundtrip");
        let a = finding("A", FindingState::Open, "openssl");
        let b = finding("B", FindingState::Accepted, "glibc");
        JsonFileStore::new(tp.path.clone())
            .upsert(&[a.clone(), b.clone()])
            .unwrap();

        // A brand-new handle on the same path must see the identical set.
        let loaded = JsonFileStore::new(tp.path.clone()).load().unwrap();
        assert_eq!(loaded.len(), 2);
        // BTreeMap ordering by finding_id: A before B.
        assert_eq!(loaded[0], a);
        assert_eq!(loaded[1], b);
    }

    #[test]
    fn missing_file_loads_as_empty_not_error() {
        let dir = std::env::temp_dir().join(format!("torda-ingest-missing-{}", std::process::id()));
        let path = dir.join("does-not-exist.json");
        let loaded = JsonFileStore::new(path).load().unwrap();
        assert!(
            loaded.is_empty(),
            "a never-written store loads empty, not error"
        );
    }

    // --- Upsert merge / preserve -----------------------------------------

    #[test]
    fn upsert_merges_preserving_absent_and_replacing_present() {
        let tp = TempPath::new("merge");
        let store = JsonFileStore::new(tp.path.clone());
        let a = finding("A", FindingState::Open, "openssl");
        let b = finding("B", FindingState::Open, "glibc");
        store.upsert(&[a.clone(), b.clone()]).unwrap();

        // B' = B with a changed field; C is new. A is ABSENT from this batch.
        let b_prime = finding("B", FindingState::Open, "glibc-2");
        let c = finding("C", FindingState::Open, "curl");
        store.upsert(&[b_prime.clone(), c.clone()]).unwrap();

        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 3, "A preserved, B replaced, C added");
        let by = |id: &str| loaded.iter().find(|f| f.finding_id == id).unwrap();
        assert_eq!(
            by("A").identity.component,
            "openssl",
            "A preserved (absent != deleted)"
        );
        assert_eq!(
            by("B").identity.component,
            "glibc-2",
            "B replaced with the changed field"
        );
        assert_eq!(by("C").identity.component, "curl", "C added");
    }

    #[test]
    fn in_memory_store_merges_the_same_way() {
        let store = InMemoryStore::new();
        store
            .upsert(&[
                finding("A", FindingState::Open, "openssl"),
                finding("B", FindingState::Open, "glibc"),
            ])
            .unwrap();
        store
            .upsert(&[
                finding("B", FindingState::Open, "glibc-2"),
                finding("C", FindingState::Open, "curl"),
            ])
            .unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 3);
        // Deterministic finding_id order A,B,C.
        assert_eq!(
            loaded
                .iter()
                .map(|f| f.finding_id.as_str())
                .collect::<Vec<_>>(),
            ["A", "B", "C"]
        );
        assert_eq!(loaded[1].identity.component, "glibc-2");
    }

    // --- Cross-run reopen (headline) -------------------------------------

    #[test]
    fn cross_run_closed_prior_reopens_via_persisted_ingest() {
        let store = InMemoryStore::new();
        let fresh_open = finding("host-A|CVE-R", FindingState::Open, "openssl");

        // Run 1: no prior -> the Open finding is persisted.
        let r1 = persisted_ingest(&store, |prior| {
            assert!(prior.is_empty(), "first run sees no prior");
            report_of(reconcile(prior, vec![fresh_open.clone()], 1000))
        })
        .unwrap();
        assert_eq!(r1.findings.len(), 1);
        assert_eq!(r1.findings[0].status, FindingState::Open);

        // Ops closes the stored finding (load -> mutate -> upsert).
        let mut closed = store.load().unwrap();
        closed[0].status = FindingState::Closed;
        store.upsert(&closed).unwrap();

        // Run 2: same identity recurs. persisted_ingest loads the Closed prior,
        // the closure's reconcile Reopens it -> stored + returned as Reopened,
        // NOT a fresh Open and NOT duplicated.
        let r2 = persisted_ingest(&store, |prior| {
            assert_eq!(
                prior[0].status,
                FindingState::Closed,
                "run 2 sees the Closed prior"
            );
            report_of(reconcile(prior, vec![fresh_open.clone()], 1000))
        })
        .unwrap();
        assert_eq!(r2.findings.len(), 1, "reopen does not duplicate");
        assert_eq!(r2.findings[0].status, FindingState::Reopened);

        let stored = store.load().unwrap();
        assert_eq!(stored.len(), 1, "single identity persists as one finding");
        assert_eq!(
            stored[0].status,
            FindingState::Reopened,
            "store now holds it Reopened"
        );
    }

    // --- Carry-forward Accepted / Suppressed -----------------------------

    #[test]
    fn carry_forward_preserves_accepted_across_recurrence() {
        let store = InMemoryStore::new();
        let fresh = finding("host-A|CVE-ACC", FindingState::Open, "openssl");

        persisted_ingest(&store, |prior| {
            report_of(reconcile(prior, vec![fresh.clone()], 1000))
        })
        .unwrap();
        // Ops accepts the risk.
        let mut v = store.load().unwrap();
        v[0].status = FindingState::Accepted;
        store.upsert(&v).unwrap();

        // Recurs fresh-Open -> result STILL Accepted (not clobbered to Open).
        let r = persisted_ingest(&store, |prior| {
            report_of(reconcile(prior, vec![fresh.clone()], 1000))
        })
        .unwrap();
        assert_eq!(r.findings[0].status, FindingState::Accepted);
        assert_eq!(store.load().unwrap()[0].status, FindingState::Accepted);
    }

    #[test]
    fn carry_forward_preserves_suppressed_across_recurrence() {
        let store = InMemoryStore::new();
        let fresh = finding("host-A|CVE-SUP", FindingState::Open, "openssl");

        persisted_ingest(&store, |prior| {
            report_of(reconcile(prior, vec![fresh.clone()], 1000))
        })
        .unwrap();
        let mut v = store.load().unwrap();
        v[0].status = FindingState::Suppressed;
        store.upsert(&v).unwrap();

        let r = persisted_ingest(&store, |prior| {
            report_of(reconcile(prior, vec![fresh.clone()], 1000))
        })
        .unwrap();
        assert_eq!(r.findings[0].status, FindingState::Suppressed);
    }

    #[test]
    fn carry_forward_does_not_override_reconcile_reopen() {
        // A prior Closed + a recurrence must Reopen (reconcile), and carry-forward
        // must NOT touch it back to Closed — Closed is not an ops-terminal carry.
        let prior = vec![finding("X", FindingState::Closed, "openssl")];
        let mut fresh = reconcile(
            &prior,
            vec![finding("X", FindingState::Open, "openssl")],
            1000,
        );
        assert_eq!(
            fresh[0].status,
            FindingState::Reopened,
            "reconcile reopened it"
        );
        carry_forward_ops_states(&prior, &mut fresh);
        assert_eq!(
            fresh[0].status,
            FindingState::Reopened,
            "carry-forward leaves the Reopen standing"
        );
    }

    #[test]
    fn carry_forward_passes_through_open_when_no_ops_prior() {
        let prior = vec![finding("Y", FindingState::Open, "openssl")];
        let mut fresh = vec![finding("Y", FindingState::Open, "openssl")];
        carry_forward_ops_states(&prior, &mut fresh);
        assert_eq!(
            fresh[0].status,
            FindingState::Open,
            "no ops-terminal prior -> unchanged"
        );
    }

    // --- Atomic write -----------------------------------------------------

    #[test]
    fn upsert_leaves_valid_json_and_no_temp_file() {
        let tp = TempPath::new("atomic");
        let store = JsonFileStore::new(tp.path.clone());
        store
            .upsert(&[finding("A", FindingState::Open, "openssl")])
            .unwrap();

        // Target parses as a Vec<Finding>.
        let bytes = std::fs::read(&tp.path).unwrap();
        let parsed: Vec<Finding> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.len(), 1);

        // The directory contains ONLY the target file — no leftover .tmp.
        let dir = tp.path.parent().unwrap();
        let entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            entries,
            [tp.path.file_name().unwrap().to_owned()],
            "only the target, no temp file"
        );
    }
}
