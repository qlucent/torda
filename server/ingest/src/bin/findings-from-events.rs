//! `findings-from-events` — the Findings Engine in the tryable path.
//!
//! The agent emits OCSF *detection events* to a file; this binary turns that
//! batch into the differentiation the events stream never shows: **scored,
//! deduped, fix-grouped findings**. It reads the agent's OCSF NDJSON (its
//! `--output`), runs the REAL findings engine (`torda_ingest::pipeline::run_all_ingest`)
//! over the batch, and writes two NDJSON files:
//!
//! - `--findings-out`: one `Finding` per line (canonical `score.R`, `remediation_key`, `status`, `identity`, `provenance`).
//! - `--remediation-out`: one `RemediationItem` per line (`remediation_key`, `risk`, `closes`, `assets`) — the "fix N findings with one action" queue.
//!
//! An optional `--store <path>` persists findings across runs (a `JsonFileStore`
//! wrapped by `persisted_ingest`) so the cross-run lifecycle works: a recurring
//! detection that was `Closed` comes back `Reopened`, and an `Accepted`/`Suppressed`
//! ops decision is carried forward instead of being clobbered back to `Open`.
//!
//! Contracts held here:
//!
//! - Score is recomputed canonically — the engine derives `score.R` from policy weights + asset context, never from a source's `severity_id`/label. This binary passes raw envelopes straight to the engine and never reads `severity_id`.
//! - Panic-free on untrusted input — a malformed NDJSON line is logged to stderr and skipped, never a panic.
//! - Fail-closed on I/O — an unreadable input or an unwritable output is a hard error (stderr + non-zero exit), never a silent no-op.
//! - Deterministic — no network, no LLM; an empty CVE feed + no-op enrichment mean the vuln path yields nothing (runtime detections + posture still become findings), and the same batch always yields the same output.
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use serde::Serialize;

use torda_findings::{AssetContext, Criticality, Finding};
use torda_findings_engine::input::{EnrichmentSource, MapAssetContext, MapEnrichment};
use torda_ocsf::OcsfEnvelope;

use torda_ingest::cve_source::{CompositeCveSource, CveSource, OsvSource};
use torda_ingest::enrichment::BundledEnrichment;
use torda_ingest::matching::CveFeed;
use torda_ingest::nvd_source::NvdSource;
use torda_ingest::pipeline::{run_all_ingest, IngestReport};
use torda_ingest::store::{persisted_ingest, JsonFileStore};

const USAGE: &str = "\
findings-from-events — OCSF detection events -> scored, fix-grouped findings NDJSON

USAGE:
    findings-from-events --input <events.ndjson> --findings-out <findings.ndjson> \
--remediation-out <remediation.ndjson> [--store <store.json>] [--osv <path>] [--nvd <path>]

FLAGS:
    --input           OCSF NDJSON produced by the agent (one envelope per line)
    --findings-out    where to write the scored findings NDJSON (one Finding/line)
    --remediation-out where to write the fix-grouped queue NDJSON (one RemediationItem/line)
    --store           optional JSON findings store for cross-run lifecycle
                      (Open -> Closed -> Reopened; Accepted/Suppressed carried forward)
    --osv             optional path to a bundled OSV-format CVE snapshot (a single
                      JSON file, or a directory of them) to match SBOM (class 5020)
                      components against real, range-aware CVE data. Without this
                      flag the vuln/SBOM path matches nothing (unchanged default).
                      An unreadable or unparseable path is a hard error.
    --nvd             optional path to a bundled NVD community snapshot (a single
                      JSON file, or a directory of them) covering Windows registry
                      SBOM components, which OSV does not. Composes with --osv (OSV
                      resolves dpkg/rpm, NVD resolves registry) with no double
                      counting. An unreadable or unparseable path is a hard error.
    --enrich          optional path to a directory holding the bundled enrichment
                      snapshots (osv-bundle.json for CVSS, epss-sample.csv, and
                      kev-sample.json). Supplies real CVSS/EPSS/KEV/VEX so matched
                      CVEs get a real, explainable Score.R. Without this flag matched
                      CVEs score R=0 (neutral, unchanged default). An unreadable or
                      unparseable snapshot is a hard error (fail-closed).";

/// Parsed CLI arguments.
struct Args {
    input: PathBuf,
    findings_out: PathBuf,
    remediation_out: PathBuf,
    store: Option<PathBuf>,
    osv: Option<PathBuf>,
    nvd: Option<PathBuf>,
    enrich: Option<PathBuf>,
}

/// Pull the value that must follow a value-taking flag, or a helpful error.
fn next_val(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    it.next()
        .ok_or_else(|| format!("missing value for {flag}\n\n{USAGE}"))
}

/// Parse the flags. Unknown flags and missing required flags are errors (the
/// caller fails closed) rather than silently ignored.
fn parse_args(mut it: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut input = None;
    let mut findings_out = None;
    let mut remediation_out = None;
    let mut store = None;
    let mut osv = None;
    let mut nvd = None;
    let mut enrich = None;
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--input" => input = Some(PathBuf::from(next_val(&mut it, "--input")?)),
            "--findings-out" => {
                findings_out = Some(PathBuf::from(next_val(&mut it, "--findings-out")?))
            }
            "--remediation-out" => {
                remediation_out = Some(PathBuf::from(next_val(&mut it, "--remediation-out")?))
            }
            "--store" => store = Some(PathBuf::from(next_val(&mut it, "--store")?)),
            "--osv" => osv = Some(PathBuf::from(next_val(&mut it, "--osv")?)),
            "--nvd" => nvd = Some(PathBuf::from(next_val(&mut it, "--nvd")?)),
            "--enrich" => enrich = Some(PathBuf::from(next_val(&mut it, "--enrich")?)),
            "-h" | "--help" => return Err(USAGE.to_string()),
            other => return Err(format!("unknown argument: {other}\n\n{USAGE}")),
        }
    }
    Ok(Args {
        input: input.ok_or_else(|| format!("--input is required\n\n{USAGE}"))?,
        findings_out: findings_out
            .ok_or_else(|| format!("--findings-out is required\n\n{USAGE}"))?,
        remediation_out: remediation_out
            .ok_or_else(|| format!("--remediation-out is required\n\n{USAGE}"))?,
        store,
        osv,
        nvd,
        enrich,
    })
}

/// Empty CVE feed: the default when `--osv` is not given, so the vuln/SBOM path
/// scores nothing (an SBOM envelope matches no CVE) and behavior stays byte-
/// identical to before `--osv` existed. Runtime detections and posture still
/// become findings.
fn empty_feed() -> CveFeed {
    CveFeed(Vec::new())
}

/// Load a range-aware [`OsvSource`] from a bundled OSV snapshot at `path`, which
/// may be a single JSON file (a JSON array of OSV records) or a directory of
/// such files (merged together, read in a stable sorted order). Fails closed:
/// an unreadable path, a non-`.json` bundle dir, or a parse error is a hard
/// `anyhow::Error` the caller propagates rather than silently falling back to
/// an empty feed.
fn load_osv_source(path: &Path) -> anyhow::Result<OsvSource> {
    let combined_json = if path.is_dir() {
        let mut files: Vec<PathBuf> = std::fs::read_dir(path)
            .with_context(|| format!("reading OSV bundle directory {}", path.display()))?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
            .collect();
        files.sort();
        if files.is_empty() {
            anyhow::bail!(
                "no .json files found in OSV bundle directory {}",
                path.display()
            );
        }
        let mut records: Vec<serde_json::Value> = Vec::new();
        for file in &files {
            let text = std::fs::read_to_string(file)
                .with_context(|| format!("reading OSV bundle file {}", file.display()))?;
            let mut parsed: Vec<serde_json::Value> = serde_json::from_str(&text)
                .with_context(|| format!("parsing OSV JSON in {}", file.display()))?;
            records.append(&mut parsed);
        }
        serde_json::to_string(&records)
            .with_context(|| format!("re-serializing merged OSV bundle from {}", path.display()))?
    } else {
        std::fs::read_to_string(path)
            .with_context(|| format!("reading OSV bundle {}", path.display()))?
    };
    OsvSource::from_json(&combined_json)
        .with_context(|| format!("parsing OSV bundle {}", path.display()))
}

/// Load an [`NvdSource`] from a bundled NVD community snapshot at `path` — a single
/// JSON file (a wrapped `{feed_tier, records}` object or a bare records array) or a
/// directory of them (records merged, read in a stable sorted order). Fails closed:
/// an unreadable path, a non-`.json` bundle dir, a bundle object without a
/// `records` array, or a parse error is a hard `anyhow::Error` the caller
/// propagates rather than silently falling back to an empty feed.
fn load_nvd_source(path: &Path) -> anyhow::Result<NvdSource> {
    if path.is_dir() {
        let mut files: Vec<PathBuf> = std::fs::read_dir(path)
            .with_context(|| format!("reading NVD bundle directory {}", path.display()))?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
            .collect();
        files.sort();
        if files.is_empty() {
            anyhow::bail!(
                "no .json files found in NVD bundle directory {}",
                path.display()
            );
        }
        let mut records: Vec<serde_json::Value> = Vec::new();
        for file in &files {
            let text = std::fs::read_to_string(file)
                .with_context(|| format!("reading NVD bundle file {}", file.display()))?;
            let value: serde_json::Value = serde_json::from_str(&text)
                .with_context(|| format!("parsing NVD JSON in {}", file.display()))?;
            match value {
                serde_json::Value::Array(arr) => records.extend(arr),
                serde_json::Value::Object(mut map) => match map.remove("records") {
                    Some(serde_json::Value::Array(arr)) => records.extend(arr),
                    _ => anyhow::bail!(
                        "NVD bundle object in {} has no `records` array",
                        file.display()
                    ),
                },
                _ => anyhow::bail!(
                    "NVD bundle in {} is neither a records array nor an object",
                    file.display()
                ),
            }
        }
        let merged = serde_json::to_string(&records)
            .with_context(|| format!("re-serializing merged NVD bundle from {}", path.display()))?;
        NvdSource::from_json(&merged)
            .with_context(|| format!("parsing NVD bundle {}", path.display()))
    } else {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading NVD bundle {}", path.display()))?;
        NvdSource::from_json(&text)
            .with_context(|| format!("parsing NVD bundle {}", path.display()))
    }
}

/// No-op enrichment: every lookup misses. With an empty feed the vuln path never
/// even queries it, so no external source is contacted (deterministic, no network).
fn noop_enrichment() -> MapEnrichment {
    MapEnrichment(HashMap::new())
}

/// Default asset context for a host that has no inventory record yet. Internal +
/// `Normal` keeps recomputed scores in a DISCRIMINATING band (not clamped to 100),
/// so the fix-first differentiation stays VISIBLE: a correlated attack chain
/// (weight 0.9) outranks a lone single-sensor component (weight <= 0.7). This is a
/// scoring INPUT the engine recomputes against — never a trusted source label.
fn default_asset_ctx() -> MapAssetContext {
    MapAssetContext {
        by_asset: HashMap::new(),
        default: AssetContext {
            internet_facing: false,
            criticality: Criticality::Normal,
            compensating_controls: false,
        },
    }
}

/// Run the full findings engine over one OCSF batch against `prior`.
/// `run_all_ingest` routes every envelope to exactly one mapper (vuln/process/
/// network/file/correlation + the posture trio), reconciles each against `prior`,
/// filters `Suppressed`, and recomputes the authoritative `group_by_fix`. This is
/// the single function both `main` and the tests drive.
/// Test-only convenience wrapper: [`run_engine_with`] with the no-op enrichment,
/// so the existing engine tests read unchanged. Production always goes through
/// [`run_engine_with`] with an explicit enrichment source.
#[cfg(test)]
fn run_engine(envelopes: &[OcsfEnvelope], feed: &dyn CveSource, prior: &[Finding]) -> IngestReport {
    run_engine_with(envelopes, feed, &noop_enrichment(), prior)
}

/// Same as [`run_engine`] but with an explicit enrichment source, so the real
/// bundled `BundledEnrichment` (from `--enrich`) can supply CVSS/EPSS/KEV/VEX and
/// matched CVEs score a real `Score.R`. With `noop_enrichment` this is byte-
/// identical to the enrichment-free path.
fn run_engine_with(
    envelopes: &[OcsfEnvelope],
    feed: &dyn CveSource,
    enrichment: &dyn EnrichmentSource,
    prior: &[Finding],
) -> IngestReport {
    run_all_ingest(envelopes, feed, enrichment, &default_asset_ctx(), prior)
}

/// Parse OCSF NDJSON from `reader`, one envelope per line. A blank line is skipped
/// silently; a malformed line is logged to stderr and skipped (never a panic).
/// Returns `(envelopes, skipped_count)`. A genuine read error (I/O) propagates so
/// the caller fails closed.
fn parse_envelopes<R: BufRead>(reader: R) -> std::io::Result<(Vec<OcsfEnvelope>, usize)> {
    let mut envelopes = Vec::new();
    let mut skipped = 0usize;
    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<OcsfEnvelope>(trimmed) {
            Ok(env) => envelopes.push(env),
            Err(e) => {
                skipped += 1;
                eprintln!(
                    "findings-from-events: skipping malformed input line {}: {e}",
                    i + 1
                );
            }
        }
    }
    Ok((envelopes, skipped))
}

/// Write each item as one compact JSON line to `path`, creating parent dirs as
/// needed. Any failure is returned (the caller fails closed).
fn write_ndjson<T: Serialize>(path: &Path, items: &[T]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating parent dir for {}", path.display()))?;
        }
    }
    let file =
        File::create(path).with_context(|| format!("creating output file {}", path.display()))?;
    let mut w = BufWriter::new(file);
    for item in items {
        serde_json::to_writer(&mut w, item)
            .with_context(|| format!("serializing a record for {}", path.display()))?;
        w.write_all(b"\n")
            .with_context(|| format!("writing {}", path.display()))?;
    }
    w.flush()
        .with_context(|| format!("flushing {}", path.display()))?;
    Ok(())
}

/// The real body: parse args, read + parse the batch, run the engine (optionally
/// persisted), and write both NDJSON outputs. Returns an error on any I/O failure.
fn run(argv: impl Iterator<Item = String>) -> anyhow::Result<()> {
    let args = parse_args(argv).map_err(|e| anyhow::anyhow!(e))?;

    let file = File::open(&args.input)
        .with_context(|| format!("opening input {}", args.input.display()))?;
    let (envelopes, skipped) = parse_envelopes(BufReader::new(file))
        .with_context(|| format!("reading input {}", args.input.display()))?;

    // Build the CVE source from whichever feeds were given. OSV covers dpkg/rpm,
    // NVD covers Windows registry; when both are present they compose (each
    // answers for a disjoint component source, so no double count). With neither,
    // an empty feed keeps the vuln/SBOM path a no-op — byte-identical to before
    // either flag existed. An unreadable/unparseable path fails closed via `?`.
    let feed: Box<dyn CveSource> = match (&args.osv, &args.nvd) {
        (None, None) => Box::new(empty_feed()),
        (Some(osv_path), None) => Box::new(load_osv_source(osv_path)?),
        (None, Some(nvd_path)) => Box::new(load_nvd_source(nvd_path)?),
        (Some(osv_path), Some(nvd_path)) => Box::new(
            CompositeCveSource::new()
                .with(Box::new(load_osv_source(osv_path)?))
                .with(Box::new(load_nvd_source(nvd_path)?)),
        ),
    };

    // Without --enrich, use the no-op enrichment so matched CVEs stay neutral
    // (R=0) — byte-identical to before the flag existed. With it, load the real
    // bundled CVSS/EPSS/KEV snapshots; an unreadable/unparseable one fails closed.
    let enrichment: Box<dyn EnrichmentSource> = match &args.enrich {
        Some(dir) => Box::new(BundledEnrichment::load_from_dir(dir)?),
        None => Box::new(noop_enrichment()),
    };

    let report = match &args.store {
        Some(store_path) => {
            let store = JsonFileStore::new(store_path.clone());
            persisted_ingest(&store, |prior| {
                run_engine_with(&envelopes, feed.as_ref(), enrichment.as_ref(), prior)
            })
            .with_context(|| format!("running persisted ingest against {}", store_path.display()))?
        }
        None => run_engine_with(&envelopes, feed.as_ref(), enrichment.as_ref(), &[]),
    };

    write_ndjson(&args.findings_out, &report.findings)?;
    write_ndjson(&args.remediation_out, &report.remediation_items)?;

    eprintln!(
        "findings-from-events: {} events -> {} findings -> {} remediation items ({} malformed lines skipped)",
        envelopes.len(),
        report.findings.len(),
        report.remediation_items.len(),
        skipped,
    );
    Ok(())
}

fn main() -> ExitCode {
    match run(std::env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("findings-from-events: error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    use torda_findings::FindingState;
    use torda_ocsf::{class, Device, Metadata};

    fn det(rule: &str) -> serde_json::Value {
        serde_json::json!({ "rule": rule, "reason": format!("{rule} fired") })
    }

    /// A Process Activity (1007) envelope in the agent's shape. `severity_id` is a
    /// deliberately wrong band the engine must ignore.
    fn proc_env(image: &str, detections: serde_json::Value, severity_id: u8) -> OcsfEnvelope {
        let mut e = OcsfEnvelope::new(
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
                "process": { "pid": 4242, "image": image },
                "activity": "exec",
                "detections": detections,
            }),
        );
        e.severity_id = severity_id;
        e
    }

    /// A Network Activity (4001) component detection.
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
                "connection": { "daddr": daddr, "dport": dport, "proto": "tcp", "pid": 4242 },
                "detections": [det("suspicious_port_to_external")],
            }),
        )
    }

    /// A File System Activity (1001) component detection.
    fn file_env(path: &str) -> OcsfEnvelope {
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
                "pid": 4242,
                "image": "vim",
                "detections": [det("write_to_sensitive_config")],
            }),
        )
    }

    /// The TOP-LEVEL correlated attack chain (class 9002) — a suspicious process
    /// joined to a suspicious connection (the recognized 0.9 rule).
    fn corr_env(image: &str, daddr: &str, dport: u64) -> OcsfEnvelope {
        let mut e = OcsfEnvelope::new(
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
                "process": { "pid": 4242, "image": image, "detections": [det("lolbin")], "attributed": true },
                "connection": { "daddr": daddr, "dport": dport, "proto": "tcp", "detections": [det("suspicious_port")] },
                "detections": [det("suspicious_process_suspicious_connection")],
            }),
        );
        // A deliberately inflated source band the engine must NOT trust.
        e.severity_id = 4;
        e
    }

    /// One drifted posture entry (Device Config State, class 5002).
    const DRIFT_NDJSON: &str = r#"{"class_uid":5002,"class_name":"Device Config State","time":0,"severity_id":1,"metadata":{"product":"torda","version":"0","tenant_id":"t"},"device":{"hostname":"host-1","os":"Test","os_version":"1"},"data":{"drift":{"records":[{"entry_id":"openssl-pinned","drifted":true,"subject":"openssl","location":"packages","weight":0.7,"expected":"3.0.14","actual":"3.0.2","remediation_key":"pin:openssl=3.0.14"}]}}}"#;

    /// A representative batch: a correlated attack-chain triple + its component
    /// process/network/file detections + two suspicious processes sharing a fix +
    /// a posture event + a benign process (no detections).
    fn sample_batch() -> Vec<OcsfEnvelope> {
        vec![
            corr_env("powershell", "203.0.113.1", 4444),
            proc_env(
                "/tmp/nc",
                serde_json::json!([det("lolbin_in_suspicious_path")]),
                1,
            ),
            proc_env("/usr/bin/certutil", serde_json::json!([det("lolbin")]), 4),
            net_env("203.0.113.1", 4444),
            file_env("/etc/passwd"),
            serde_json::from_str(DRIFT_NDJSON).unwrap(),
            proc_env("/usr/bin/echo", serde_json::json!([]), 1), // benign -> no finding
        ]
    }

    #[test]
    fn engine_produces_canonically_scored_findings() {
        let report = run_engine(&sample_batch(), &empty_feed(), &[]);
        assert!(!report.findings.is_empty(), "the batch must yield findings");
        // Canonical score is a real 0..=100 risk, recomputed by the engine.
        for f in &report.findings {
            assert!(
                f.score.r <= 100,
                "score.R must be a canonical 0..=100 risk, got {}",
                f.score.r
            );
            // Source severity is never trusted / carried as a scored input.
            assert_eq!(
                f.provenance[0].reported_severity, None,
                "the engine must never trust a source's severity label"
            );
        }
    }

    #[test]
    fn correlated_chain_outranks_a_lone_component() {
        let report = run_engine(&sample_batch(), &empty_feed(), &[]);
        let chain = report
            .findings
            .iter()
            .find(|f| f.identity.vuln_id.starts_with("correlation:"))
            .expect("the correlated attack-chain finding is present");
        let component = report
            .findings
            .iter()
            .find(|f| f.identity.vuln_id == "process:/tmp/nc")
            .expect("the lone process component finding is present");
        assert!(
            chain.score.r >= component.score.r,
            "the correlated attack chain (R={}) must be at least as risky as a lone component (R={})",
            chain.score.r,
            component.score.r,
        );
    }

    #[test]
    fn group_by_fix_collapses_findings_sharing_a_remediation_key() {
        let report = run_engine(&sample_batch(), &empty_feed(), &[]);
        // Both suspicious processes share the `triage-suspicious-process` fix.
        let item = report
            .remediation_items
            .iter()
            .find(|i| i.remediation_key == "triage-suspicious-process")
            .expect("the suspicious-process remediation item is present");
        assert_eq!(
            item.closes.len(),
            2,
            "the two suspicious processes must collapse into one fix that closes both, got closes={:?}",
            item.closes,
        );
        // The attack chain has its own fix bucket, distinct from the components.
        assert!(
            report
                .remediation_items
                .iter()
                .any(|i| i.remediation_key == "triage-attack-chain"),
            "the attack chain groups under its own remediation item",
        );
    }

    #[test]
    fn benign_process_yields_no_finding() {
        let report = run_engine(&sample_batch(), &empty_feed(), &[]);
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.identity.vuln_id.contains("echo")),
            "a process with no detections must not become a finding",
        );
    }

    #[test]
    fn malformed_line_is_skipped_not_panicked() {
        // A good envelope, a malformed line, and a blank line.
        let good =
            serde_json::to_string(&proc_env("/tmp/nc", serde_json::json!([det("lolbin")]), 1))
                .unwrap();
        let input = format!("{good}\nthis is not json\n\n");
        let (envelopes, skipped) =
            parse_envelopes(Cursor::new(input)).expect("read must not error");
        assert_eq!(envelopes.len(), 1, "only the one valid envelope is parsed");
        assert_eq!(
            skipped, 1,
            "the malformed line is counted as skipped, the blank line is not"
        );
        // And the engine runs over the survivor without panicking.
        let report = run_engine(&envelopes, &empty_feed(), &[]);
        assert_eq!(
            report.findings.len(),
            1,
            "the one valid detection scores one finding"
        );
    }

    #[test]
    fn fresh_batch_findings_are_open() {
        let report = run_engine(&sample_batch(), &empty_feed(), &[]);
        // With no prior, every fresh finding is Open (lifecycle baseline).
        assert!(
            report
                .findings
                .iter()
                .all(|f| f.status == FindingState::Open),
            "no prior state -> every finding Open",
        );
    }

    // --- `--osv` wiring: the bundled real-CVE OSV snapshot end to end ---

    /// A Software Inventory Info (class 5020) SBOM envelope carrying one dpkg
    /// component, in the same shape the agent's real SBOM module emits.
    fn sbom_env(name: &str, version: &str) -> OcsfEnvelope {
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
                {"name": name, "version": version, "source": "dpkg"}
            ], "component_count": 1 } }),
        )
    }

    /// SBOM envelope with an explicit device OS — release-aware matching keys on it.
    fn sbom_env_os(name: &str, version: &str, os: &str, os_version: &str) -> OcsfEnvelope {
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
                os: os.into(),
                os_version: os_version.into(),
            },
            serde_json::json!({ "sbom": { "format": "torda-native", "components": [
                {"name": name, "version": version, "source": "dpkg"}
            ], "component_count": 1 } }),
        )
    }

    #[test]
    fn bundle_matches_a_host_against_its_own_distro_advisory() {
        // The bundle carries per-distro advisories for openssl CVE-2022-3602:
        // Debian fixed 3.0.7, Ubuntu fixed 3.0.2-0ubuntu1.7 (real Ubuntu Security
        // Notice version). A host is matched against its OWN distro's fix.
        let hit = |f: &IngestReport| {
            f.findings
                .iter()
                .any(|x| x.identity.vuln_id == "CVE-2022-3602")
        };
        // Ubuntu host below the Ubuntu backport fix -> flagged.
        assert!(
            hit(&run_engine(
                &[sbom_env_os("openssl", "3.0.2", "Ubuntu", "22.04")],
                &bundled_osv(),
                &[]
            )),
            "Ubuntu host openssl 3.0.2 must be flagged by the Ubuntu advisory"
        );
        // Ubuntu host at the REAL patched Ubuntu version -> cleared (above 3.0.2-0ubuntu1.7).
        assert!(
            run_engine(
                &[sbom_env_os(
                    "openssl",
                    "3.0.2-0ubuntu1.15",
                    "Ubuntu",
                    "22.04"
                )],
                &bundled_osv(),
                &[]
            )
            .findings
            .is_empty(),
            "Ubuntu host openssl 3.0.2-0ubuntu1.15 (patched per Ubuntu) must be cleared"
        );
        // Debian host below the Debian fix -> flagged by the Debian advisory.
        assert!(
            hit(&run_engine(
                &[sbom_env_os("openssl", "3.0.2", "Debian", "12")],
                &bundled_osv(),
                &[]
            )),
            "Debian host openssl 3.0.2 must be flagged by the Debian advisory"
        );
    }

    /// Load the bundled OSV snapshot committed at
    /// `deploy/collector/osv-sample/osv-bundle.json` — real advisories
    /// (CVE-2022-3602 / CVE-2022-3786 openssl, CVE-2018-25032 zlib1g,
    /// CVE-2023-38545 curl) — via the exact same `load_osv_source` the `--osv`
    /// flag drives at runtime, proving the end-to-end wiring, not a fixture.
    fn bundled_osv() -> OsvSource {
        let path = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/collector/osv-sample/osv-bundle.json"
        ));
        load_osv_source(path).expect("the bundled OSV snapshot must load")
    }

    #[test]
    fn osv_bundle_flags_vulnerable_openssl_and_clears_the_fixed_version() {
        // openssl 3.0.2 is below the CVE-2022-3602/CVE-2022-3786 fix (3.0.7) ->
        // a real CVE finding (OCSF Vulnerability Finding territory: a genuine
        // vuln_id, not a synthetic fixture id).
        let vulnerable = run_engine(&[sbom_env("openssl", "3.0.2")], &bundled_osv(), &[]);
        let ids: Vec<&str> = vulnerable
            .findings
            .iter()
            .map(|f| f.identity.vuln_id.as_str())
            .collect();
        assert!(
            ids.contains(&"CVE-2022-3602"),
            "openssl 3.0.2 must produce a CVE-2022-3602 finding from the bundled OSV data, got {ids:?}",
        );

        // openssl 3.0.7 IS the fixed version (OSV `fixed` bound is exclusive) ->
        // no finding at all: the true-negative boundary case.
        let fixed = run_engine(&[sbom_env("openssl", "3.0.7")], &bundled_osv(), &[]);
        assert!(
            fixed.findings.is_empty(),
            "openssl 3.0.7 (the fixed version) must yield NO finding, got {:?}",
            fixed
                .findings
                .iter()
                .map(|f| f.identity.vuln_id.as_str())
                .collect::<Vec<_>>(),
        );
    }

    #[test]
    fn osv_bundle_does_not_flag_versions_below_the_introduced_bound() {
        // Regression: the CVEs have a real lower bound, not "all earlier versions".
        // CVE-2022-3602/3786 affect openssl 3.0.0-3.0.6 ONLY (introduced 3.0.0) —
        // openssl 1.1.1 is NOT affected. CVE-2023-38545 affects curl 7.69.0-8.3.0
        // ONLY (introduced 7.69.0) — curl 7.68.0 is NOT affected. A bundle that used
        // `introduced: "0"` would FALSELY flag these very-common older versions.
        let old_openssl = run_engine(&[sbom_env("openssl", "1.1.1w")], &bundled_osv(), &[]);
        assert!(
            old_openssl.findings.is_empty(),
            "openssl 1.1.1w is below the 3.0.0 introduced bound — must NOT be flagged, got {:?}",
            old_openssl
                .findings
                .iter()
                .map(|f| f.identity.vuln_id.as_str())
                .collect::<Vec<_>>(),
        );
        let old_curl = run_engine(&[sbom_env("curl", "7.68.0")], &bundled_osv(), &[]);
        assert!(
            old_curl.findings.is_empty(),
            "curl 7.68.0 is below the 7.69.0 introduced bound — must NOT be flagged, got {:?}",
            old_curl
                .findings
                .iter()
                .map(|f| f.identity.vuln_id.as_str())
                .collect::<Vec<_>>(),
        );

        // Multi-window advisory: CVE-2021-3156 (sudo Baron Samedit) affects
        // 1.8.2-1.8.31p2 AND 1.9.0-1.9.5p1 — sudo 1.8.32 was FIXED in the 1.8 line
        // and must NOT be flagged just because it is below the 1.9.x fix (1.9.5p2).
        let patched_18 = run_engine(&[sbom_env("sudo", "1.8.32")], &bundled_osv(), &[]);
        assert!(
            patched_18.findings.is_empty(),
            "sudo 1.8.32 (fixed in the 1.8 line, between the two affected windows) must NOT be flagged, got {:?}",
            patched_18.findings.iter().map(|f| f.identity.vuln_id.as_str()).collect::<Vec<_>>(),
        );
        // ...but a version inside the second window IS still affected.
        let vulnerable_19 = run_engine(&[sbom_env("sudo", "1.9.5p1")], &bundled_osv(), &[]);
        assert!(
            vulnerable_19
                .findings
                .iter()
                .any(|f| f.identity.vuln_id == "CVE-2021-3156"),
            "sudo 1.9.5p1 is inside the 1.9.0-1.9.5p1 window — must be flagged",
        );
    }

    #[test]
    fn without_osv_flag_sbom_matches_nothing_unchanged_default() {
        // No --osv given -> empty_feed(), same as before the flag existed.
        let report = run_engine(&[sbom_env("openssl", "3.0.2")], &empty_feed(), &[]);
        assert!(
            report.findings.is_empty(),
            "without --osv the vuln/SBOM path must still match nothing (backward compatible)",
        );
    }

    #[test]
    fn osv_flag_fails_closed_on_an_unreadable_path() {
        let missing = Path::new("this/path/does/not/exist/osv.json");
        assert!(
            load_osv_source(missing).is_err(),
            "an unreadable --osv path must be a hard error, not a silent empty feed",
        );
    }

    // --- `--enrich` wiring: the bundled real CVSS/EPSS/KEV enrichment end to end ---

    /// Load the bundled enrichment snapshots committed under
    /// `deploy/collector/osv-sample/` (real, web-verified CVSS from NVD, EPSS from
    /// FIRST.org, KEV from CISA) via the exact same `BundledEnrichment::load_from_dir`
    /// the `--enrich` flag drives at runtime — proving the wiring, not a fixture.
    fn bundled_enrichment() -> BundledEnrichment {
        let dir = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/collector/osv-sample"
        ));
        BundledEnrichment::load_from_dir(dir).expect("the bundled enrichment snapshots must load")
    }

    /// GOLDEN: openssl 3.0.2 + the real bundled enrichment must score the EXACT
    /// canonical R the VD-3 formula yields for CVE-2022-3602 — hand-computed from
    /// REAL evidence: CVSS 7.5 (NVD) and EPSS 0.9077 (FIRST.org, 2026-07-18).
    ///
    /// default_asset_ctx() = internal (exposure 0.8), Normal crit (0.9).
    ///   sev        = 7.5/10                       = 0.75
    ///   likelihood = max(0.9077, poc 0.4)         = 0.9077
    ///   reach      = Affected                     = 1.0
    ///   R = round(100 * 0.75 * (0.4 + 0.6*0.9077) * 0.8 * 0.9 * 1.0)
    ///     = round(100 * 0.75 * 0.94462 * 0.72)    = round(51.009) = 51
    #[test]
    fn enrichment_scores_openssl_cve_to_the_exact_hand_computed_r() {
        use torda_findings_engine::score::recompute_score;

        let enr_src = bundled_enrichment();
        let report = run_engine_with(
            &[sbom_env("openssl", "3.0.2")],
            &bundled_osv(),
            &enr_src,
            &[],
        );
        let f = report
            .findings
            .iter()
            .find(|f| f.identity.vuln_id == "CVE-2022-3602")
            .expect("openssl 3.0.2 -> a CVE-2022-3602 finding");

        // Non-vacuous: assert the concrete hand-computed number.
        assert_eq!(
            f.score.r, 51,
            "CVE-2022-3602 must score the exact hand-computed R=51"
        );
        assert!((f.score.explain.sev - 0.75).abs() < 1e-6);
        assert!((f.score.explain.likelihood - 0.9077).abs() < 1e-6);
        assert!(
            (f.score.explain.reach - 1.0).abs() < 1e-6,
            "matched vuln -> Affected -> reach 1.0"
        );

        // And it tracks the real formula against the exact enrichment the source returns.
        let enr = enr_src.lookup("CVE-2022-3602").expect("enrichment present");
        let expected = recompute_score(&enr, &default_asset_ctx().default);
        assert_eq!(
            f.score, expected,
            "the finding score equals the canonical recompute"
        );
        assert!(
            f.score.r > 0,
            "with enrichment a matched CVE scores a real R>0, not neutral 0"
        );
    }

    /// GOLDEN: the genuinely KEV-listed sudo CVE (CVE-2021-3156, CISA KEV) must be
    /// flagged kev==true AND drive decide() to ACT even at a deliberately LOW R —
    /// the KEV override, not the score threshold.
    #[test]
    fn kev_sudo_cve_is_flagged_and_forces_act_even_at_low_r() {
        use torda_findings_engine::decide::decide;

        let enr_src = bundled_enrichment();
        let report = run_engine_with(&[sbom_env("sudo", "1.8.31")], &bundled_osv(), &enr_src, &[]);
        let f = report
            .findings
            .iter()
            .find(|f| f.identity.vuln_id == "CVE-2021-3156")
            .expect("sudo 1.8.31 -> a CVE-2021-3156 finding");

        assert!(
            f.enrichment.kev,
            "CVE-2021-3156 (sudo Baron Samedit) IS CISA KEV-listed"
        );
        assert_eq!(
            f.decision,
            torda_findings::Decision::Act,
            "KEV + reachable -> ACT"
        );

        // The override is KEV, not R: a deliberately low R (10, well under the 20
        // Track / 40 Attend / 70 Act thresholds) still ACTs because it is KEV.
        let enr = enr_src.lookup("CVE-2021-3156").expect("enrichment present");
        assert_eq!(
            decide(10, enr.kev, true, 1.0).0,
            torda_findings::Decision::Act,
            "KEV forces ACT independent of the score threshold",
        );
    }

    /// GOLDEN: a CVE absent from every enrichment snapshot returns None, so the
    /// engine falls through to its neutral default and the matched finding stays
    /// R=0 — exactly as a run with no enrichment at all. Contrast the SAME openssl
    /// match with vs without enrichment: neutral 0 vs a real R.
    #[test]
    fn absent_enrichment_stays_neutral_r_zero() {
        let enr_src = bundled_enrichment();
        assert!(
            enr_src.lookup("CVE-0000-0000").is_none(),
            "a CVE with no evidence in any snapshot -> None (neutral fall-through)",
        );

        // Without enrichment, the very same matched openssl CVE scores neutral R=0.
        let neutral = run_engine(&[sbom_env("openssl", "3.0.2")], &bundled_osv(), &[]);
        let n = neutral
            .findings
            .iter()
            .find(|f| f.identity.vuln_id == "CVE-2022-3602")
            .expect("still a match, just unscored");
        assert_eq!(
            n.score.r, 0,
            "no enrichment -> neutral R=0 (backward compatible)"
        );

        // With enrichment, the same CVE scores a real R>0 — the differentiation.
        let scored = run_engine_with(
            &[sbom_env("openssl", "3.0.2")],
            &bundled_osv(),
            &enr_src,
            &[],
        );
        let s = scored
            .findings
            .iter()
            .find(|f| f.identity.vuln_id == "CVE-2022-3602")
            .unwrap();
        assert!(
            s.score.r > n.score.r,
            "enrichment lifts R from neutral 0 to a real score"
        );
    }

    #[test]
    fn enrich_flag_fails_closed_on_a_missing_dir() {
        let missing = Path::new("this/path/does/not/exist/enrich");
        assert!(
            BundledEnrichment::load_from_dir(missing).is_err(),
            "an unreadable --enrich dir must be a hard error, not a silent neutral feed",
        );
    }

    #[test]
    fn osv_flag_fails_closed_on_unparseable_json() {
        let dir = std::env::temp_dir().join("torda-ingest-osv-bad-json-test");
        std::fs::create_dir_all(&dir).unwrap();
        let bad_file = dir.join("bad.json");
        std::fs::write(&bad_file, "this is not json").unwrap();
        assert!(
            load_osv_source(&bad_file).is_err(),
            "unparseable OSV JSON must be a hard error, not a silent empty feed",
        );
        let _ = std::fs::remove_file(&bad_file);
        let _ = std::fs::remove_dir(&dir);
    }
}
