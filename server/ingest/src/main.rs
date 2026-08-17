//! Thin ingest CLI: reads agent OCSF records (any findings-producing class —
//! SBOM, process, network, correlation, compliance, drift, FIM) as NDJSON on
//! stdin, dispatches them through `torda_ingest::pipeline::run_all_ingest`
//! against the built-in offline fixtures, and prints the resulting findings +
//! remediation items as JSON.
//!
//! Findings PERSIST across invocations: prior state is loaded from (and the
//! result written back to) a `torda_ingest::store::JsonFileStore` at the path
//! named by `TORDA_FINDINGS_STORE` (default: `<temp dir>/torda-findings-store.json`).
//! That real, on-disk prior is what lets the lifecycle (Open -> Closed ->
//! Reopened, Accepted/Suppressed carried forward) work across separate runs
//! of this binary rather than only within one process.
use std::io::{self, Read};

use torda_ingest::fixtures::{default_assets, default_enrichment, default_feed};
use torda_ingest::pipeline::run_all_ingest;
use torda_ingest::store::{persisted_ingest, FindingsStore, JsonFileStore};
use torda_ocsf::OcsfEnvelope;

fn main() -> anyhow::Result<()> {
    let mut buf = String::new();
    io::stdin().read_to_string(&mut buf)?;
    let envelopes: Vec<OcsfEnvelope> = buf
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;

    let store_path = std::env::var_os("TORDA_FINDINGS_STORE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("torda-findings-store.json"));
    let store = JsonFileStore::new(&store_path);

    // Brief note to STDERR only — stdout must stay clean JSON. A cheap extra
    // read of the store just for the prior count; `persisted_ingest` below
    // loads it again itself.
    let prior_count = store.load()?.len();
    eprintln!(
        "torda-ingest: findings store = {} ({} prior)",
        store_path.display(),
        prior_count
    );

    let report = persisted_ingest(&store, |prior| {
        run_all_ingest(
            &envelopes,
            &default_feed(),
            &default_enrichment(),
            &default_assets(),
            prior,
        )
    })?;

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
