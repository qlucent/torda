//! Small, honest demo of the CROSS-RUN lifecycle that `torda_ingest::store`
//! unlocks: `reconcile`'s `prior: &[Finding]` is only meaningful if it comes
//! from REAL persisted state across separate runs — otherwise Closed -> Reopened
//! never fires and Accepted/Suppressed decisions never survive a recurrence.
//!
//! This binary drives a single detection identity through THREE simulated
//! agent runs against a REAL `JsonFileStore` on a unique temp path (genuinely
//! written to and re-loaded from disk between each step, not one in-memory
//! pass), with ops actions (close / accept) applied to the on-disk store in
//! between:
//!
//!   run 1 (empty store)              -> Open            (persisted)
//!   ops closes it (load/mutate/upsert) -> Closed          (persisted)
//!   run 2 (same detection recurs)    -> Reopened        <- HEADLINE #1
//!   ops accepts it (load/mutate/upsert) -> Accepted       (persisted)
//!   run 3 (same detection recurs)    -> Accepted (kept) <- HEADLINE #2
//!
//! Deliberately uses ONLY the crate's existing production dependencies
//! (`torda-ingest`, `torda-findings`, `torda-findings-engine`) — no test-only crates.
//! `torda_ingest::scoring::weighted_finding` (the helper the real posture paths
//! use to build a weight-scored `Finding`) is `pub(crate)`, so it is not
//! visible from this binary (a separate crate); the small `detection()`
//! helper below reconstructs the same construction from the engine's public
//! API (`finding_id_for`, `recompute_compliance_score`, `decide`).
use std::collections::HashMap;
use std::path::PathBuf;

use torda_findings::{
    AssetContext, Criticality, DetectionMethod, Enrichment, ExploitMaturity, Finding, FindingState,
    Identity, Provenance, VexStatus,
};
use torda_findings_engine::aggregate::group_by_fix;
use torda_findings_engine::decide::decide;
use torda_findings_engine::finding_id_for;
use torda_findings_engine::input::{AssetContextSource, MapAssetContext};
use torda_findings_engine::lifecycle::reconcile;
use torda_findings_engine::score::recompute_compliance_score;

use torda_ingest::pipeline::IngestReport;
use torda_ingest::store::{persisted_ingest, FindingsStore, JsonFileStore};

/// The one detection identity this whole demo follows across every run — a
/// suspicious-process posture signal, same shape as `torda_ingest::process`.
const ASSET_ID: &str = "host-1";
const VULN_ID: &str = "process:/tmp/nc";
const COMPONENT: &str = "/tmp/nc";
const LOCATION: &str = "process";
const REMEDIATION_KEY: &str = "triage-suspicious-process";
const WEIGHT: f32 = 0.7;

/// A fixed asset context, same for the whole demo — the point here is the
/// LIFECYCLE, not score variation.
fn assets() -> MapAssetContext {
    MapAssetContext {
        by_asset: HashMap::new(),
        default: AssetContext {
            internet_facing: true,
            criticality: Criticality::Normal,
            compensating_controls: false,
        },
    }
}

/// Builds the ONE weight-scored `Finding` this demo's detection always
/// produces. Mirrors `torda_ingest::scoring::weighted_finding` (same identity,
/// same score recompute, same "no source severity trusted" contract) using
/// only the engine's public API, since that helper is `pub(crate)` in
/// `torda-ingest` and unreachable from this separate binary crate.
fn detection(assets: &dyn AssetContextSource) -> Finding {
    let identity = Identity {
        asset_id: ASSET_ID.into(),
        vuln_id: VULN_ID.into(),
        component: COMPONENT.into(),
        location: LOCATION.into(),
    };
    let ctx = assets.context(ASSET_ID);
    let score = recompute_compliance_score(WEIGHT, &ctx);
    let (decision, sla_hours) = decide(score.r, false, true, score.explain.reach);
    Finding {
        finding_id: finding_id_for(&identity),
        identity,
        provenance: vec![Provenance {
            source: "torda".into(),
            method: DetectionMethod::Authenticated,
            reported_severity: None,
            confidence: 0.95,
        }],
        enrichment: Enrichment {
            cvss_vector: None,
            cvss_env: None,
            epss: None,
            epss_pct: None,
            kev: false,
            exploit_maturity: ExploitMaturity::None,
            vex: VexStatus::Affected,
        },
        asset_ctx: ctx,
        score,
        decision,
        sla_hours,
        remediation_key: REMEDIATION_KEY.into(),
        status: FindingState::Open,
        first_seen: None,
        last_seen: None,
        closed_at: None,
    }
}

/// A real ingest run for this demo's single detection: build the fresh
/// finding, `reconcile` it against the REAL prior the caller loaded from the
/// store, then `group_by_fix` — the same compose order every `run_*_ingest`
/// in this crate uses (`aggregate -> reconcile -> group_by_fix`).
fn run_detection(prior: &[Finding], assets: &dyn AssetContextSource) -> IngestReport {
    let fresh = vec![detection(assets)];
    // This demo builds findings directly (no envelopes); use a fixed batch time.
    let findings = reconcile(prior, fresh, 1_784_500_000_000);
    let remediation_items = group_by_fix(&findings);
    IngestReport {
        findings,
        remediation_items,
    }
}

/// A unique path under the OS temp dir — no two runs of this demo (even
/// concurrent ones) collide.
fn unique_temp_path() -> PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "torda-persisted-findings-demo-{}-{nanos}.json",
        std::process::id()
    ))
}

/// Loads and prints the store's full contents (finding_id + status), so the
/// lifecycle is visible at every step — not just asserted internally.
fn print_store(store: &dyn FindingsStore, label: &str) -> Vec<Finding> {
    let all = store.load().expect("load store");
    println!("  store contents ({label}): {} finding(s)", all.len());
    for f in &all {
        println!("    finding_id={:<40} status={:?}", f.finding_id, f.status);
    }
    all
}

/// Removes the demo's temp file on the way out, success or panic.
struct Cleanup(PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn main() {
    println!(
        "== persisted-findings-demo — cross-run lifecycle via a REAL on-disk JsonFileStore ==\n"
    );

    let path = unique_temp_path();
    println!("store path: {}\n", path.display());
    let _cleanup = Cleanup(path.clone());

    let store = JsonFileStore::new(path.clone());
    let assets = assets();

    // -----------------------------------------------------------------
    // Run 1 (fresh process, no prior on disk) -> ONE Open finding, persisted.
    // -----------------------------------------------------------------
    println!("--- Run 1 (fresh; store has never been written) ---");
    let r1 = persisted_ingest(&store, |prior| {
        println!("  prior loaded from disk: {} finding(s)", prior.len());
        assert!(
            prior.is_empty(),
            "run 1 must see an empty store (first run)"
        );
        run_detection(prior, &assets)
    })
    .expect("run 1 persisted_ingest");
    assert_eq!(r1.findings.len(), 1, "one detection -> one finding");
    assert_eq!(
        r1.findings[0].status,
        FindingState::Open,
        "no prior -> Open"
    );
    let fid = r1.findings[0].finding_id.clone();
    println!(
        "run 1 returned: finding_id={fid} status={:?}",
        r1.findings[0].status
    );
    let after_r1 = print_store(&store, "after run 1");
    assert_eq!(after_r1.len(), 1, "store now has exactly one finding");
    assert_eq!(
        after_r1[0].status,
        FindingState::Open,
        "store now has 1 Open finding"
    );
    println!();

    // -----------------------------------------------------------------
    // Ops closes it: load -> mutate -> upsert (a genuine disk round-trip).
    // -----------------------------------------------------------------
    println!("--- Ops closes the finding (load, mutate, upsert) ---");
    let mut loaded = store.load().expect("load before close");
    loaded
        .iter_mut()
        .find(|f| f.finding_id == fid)
        .expect("the finding is present")
        .status = FindingState::Closed;
    store.upsert(&loaded).expect("upsert closed");
    let after_close = print_store(&store, "after ops closes it");
    assert_eq!(after_close.len(), 1);
    assert_eq!(
        after_close[0].status,
        FindingState::Closed,
        "store shows it Closed"
    );
    println!();

    // -----------------------------------------------------------------
    // Run 2 (recurrence): the SAME detection, but the store's prior on disk
    // now has it Closed -> reconcile REOPENS it. Not a fresh Open, not a
    // duplicate — this is the cross-run headline persistence unlocks.
    // -----------------------------------------------------------------
    println!("--- Run 2 (same detection recurs) ---");
    let r2 = persisted_ingest(&store, |prior| {
        println!(
            "  prior loaded from disk: {} finding(s), status={:?}",
            prior.len(),
            prior.first().map(|f| f.status)
        );
        assert_eq!(prior.len(), 1, "run 2 must see the one persisted prior");
        assert_eq!(
            prior[0].status,
            FindingState::Closed,
            "run 2 must see the Closed prior from disk"
        );
        run_detection(prior, &assets)
    })
    .expect("run 2 persisted_ingest");
    assert_eq!(
        r2.findings.len(),
        1,
        "the recurrence must not duplicate the finding"
    );
    println!(
        "run 2 returned: finding_id={} status={:?}",
        r2.findings[0].finding_id, r2.findings[0].status
    );
    let after_r2 = print_store(&store, "after run 2");
    assert_eq!(
        after_r2.len(),
        1,
        "still exactly one finding for this identity"
    );
    assert_eq!(
        after_r2[0].status,
        FindingState::Reopened,
        "HEADLINE: same identity recurring after a Closed prior on disk must Reopen across runs, \
         not reset to Open and not duplicate"
    );
    println!();

    // -----------------------------------------------------------------
    // Ops accepts it: load -> mutate -> upsert.
    // -----------------------------------------------------------------
    println!("--- Ops accepts the risk (load, mutate, upsert) ---");
    let mut loaded = store.load().expect("load before accept");
    loaded
        .iter_mut()
        .find(|f| f.finding_id == fid)
        .expect("the finding is present")
        .status = FindingState::Accepted;
    store.upsert(&loaded).expect("upsert accepted");
    let after_accept = print_store(&store, "after ops accepts it");
    assert_eq!(after_accept.len(), 1);
    assert_eq!(
        after_accept[0].status,
        FindingState::Accepted,
        "store shows it Accepted"
    );
    println!();

    // -----------------------------------------------------------------
    // Run 3 (recurrence): the SAME detection again. persisted_ingest's
    // carry_forward_ops_states keeps the Accepted decision — it must NOT be
    // clobbered back to Open/Reopened just because the detection fired again.
    // -----------------------------------------------------------------
    println!("--- Run 3 (same detection recurs again) ---");
    let r3 = persisted_ingest(&store, |prior| {
        println!(
            "  prior loaded from disk: {} finding(s), status={:?}",
            prior.len(),
            prior.first().map(|f| f.status)
        );
        assert_eq!(prior.len(), 1, "run 3 must see the one persisted prior");
        assert_eq!(
            prior[0].status,
            FindingState::Accepted,
            "run 3 must see the Accepted prior from disk"
        );
        run_detection(prior, &assets)
    })
    .expect("run 3 persisted_ingest");
    assert_eq!(
        r3.findings.len(),
        1,
        "still no duplication on the third run"
    );
    println!(
        "run 3 returned: finding_id={} status={:?}",
        r3.findings[0].finding_id, r3.findings[0].status
    );
    let after_r3 = print_store(&store, "after run 3");
    assert_eq!(
        after_r3.len(),
        1,
        "exactly one finding for this identity, throughout every step"
    );
    assert_eq!(
        after_r3[0].status,
        FindingState::Accepted,
        "HEADLINE: an ops-terminal Accepted decision must survive a recurrence across runs — \
         it is carried forward, not clobbered back to Open"
    );

    println!(
        "\nOK: cross-run lifecycle proven via a REAL JsonFileStore at {}",
        path.display()
    );
    println!(
        "    Open (run 1) -> Closed (ops) -> Reopened (run 2, recurrence) -> Accepted (ops) -> Accepted (run 3, carried forward)."
    );
    println!("    Exactly one finding for finding_id={fid} at every step — no duplication. Temp store cleaned up on exit.");
}
