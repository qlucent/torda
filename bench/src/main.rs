//! torda-bench CLI.
//!
//!   torda-bench score  --registry <t.toml> --captures <c.json> [--out-dir <d>]
//!   torda-bench run    --registry <t.toml> --sink <ndjson> [--tier AB] [--platform linux]
//!                      [--results-root results] [--no-isolate] [--no-preflight]
//!
//! `score` is pure (works anywhere; the self-test path). `run` executes atomics
//! and must run inside an isolated target with a live, privileged torda streaming
//! to `--sink` (Linux). Arg parsing is hand-rolled to add no dependency.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use torda_bench::capture;
use torda_bench::conformance::validate_records;
use torda_bench::latency::latency;
use torda_bench::model::{load_captures, load_registry, Captures, Case, CaseCapture};
use torda_bench::report::build_report;
use torda_bench::score::{all_tier_a_hit, matrix_md, score};

const ISOLATION_SENTINEL: &str = "/etc/torda-bench/ISOLATED";
const PREFLIGHT_CASE: &str = "lolbin-basic";
/// Seconds to let the event ring drain BEFORE each case's window opens (see
/// `run_case`) — the eBPF backend timestamps records at drain time, so this keeps
/// one case's late-drained tail out of the next case's window.
const QUIET_DRAIN_SECS: u64 = 3;

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(2);
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (cmd, flags) = parse_args(&args);
    match cmd.as_deref() {
        Some("score") => cmd_score(&flags),
        Some("run") => cmd_run(&flags),
        Some("help") | None => {
            print_usage();
            Ok(())
        }
        Some(other) => bail!("unknown subcommand {other:?} (try `help`)"),
    }
}

fn print_usage() {
    eprintln!(
        "torda-bench <score|run> [flags]\n\
         \n  score --registry <t.toml> --captures <c.json> [--out-dir <d>]\n\
         \n  run   --registry <t.toml> --sink <ndjson> [--tier AB] [--platform linux]\n\
         \n        [--results-root results] [--no-isolate] [--no-preflight]"
    );
}

/// Split argv into (subcommand, {--flag: value}). A bare `--flag` (no following
/// value or followed by another flag) is stored as "true" so it reads as a bool.
fn parse_args(args: &[String]) -> (Option<String>, HashMap<String, String>) {
    let mut cmd = None;
    let mut flags = HashMap::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(key) = a.strip_prefix("--") {
            let val = match args.get(i + 1) {
                Some(v) if !v.starts_with("--") => {
                    i += 1;
                    v.clone()
                }
                _ => "true".to_string(),
            };
            flags.insert(key.to_string(), val);
        } else if cmd.is_none() {
            cmd = Some(a.clone());
        }
        i += 1;
    }
    (cmd, flags)
}

fn flag<'a>(flags: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    flags.get(key).map(String::as_str)
}

fn write_artifacts(out: &Path, captures: &Captures, cases: &[Case]) -> Result<()> {
    std::fs::create_dir_all(out).with_context(|| format!("mkdir {}", out.display()))?;
    let scored = score(cases, captures);
    let lat = latency(cases, captures);
    let all_recs: Vec<serde_json::Value> = captures
        .cases
        .iter()
        .flat_map(|c| c.records.clone())
        .collect();
    let conf = validate_records(&all_recs);

    std::fs::write(
        out.join("captures.json"),
        serde_json::to_string_pretty(captures)?,
    )?;
    std::fs::write(
        out.join("coverage.json"),
        serde_json::to_string_pretty(&scored)?,
    )?;
    std::fs::write(out.join("matrix.md"), matrix_md(&scored))?;
    std::fs::write(
        out.join("latency.json"),
        serde_json::to_string_pretty(&lat)?,
    )?;
    std::fs::write(
        out.join("ocsf_conformance.json"),
        serde_json::to_string_pretty(&conf)?,
    )?;
    std::fs::write(
        out.join("report.md"),
        build_report(&captures.run_id, &scored, &lat, &conf),
    )?;
    println!("{}", matrix_md(&scored));
    println!(
        "wrote {}/  (coverage {}%)",
        out.display(),
        scored.coverage_pct
    );
    Ok(())
}

fn cmd_score(flags: &HashMap<String, String>) -> Result<()> {
    let registry = flag(flags, "registry").unwrap_or("config/techniques.toml");
    let captures_path = flag(flags, "captures").context("--captures is required")?;
    let cases = load_registry(registry)?;
    let captures = load_captures(captures_path)?;

    let scored = score(&cases, &captures);
    print!("{}", matrix_md(&scored));
    if let Some(dir) = flag(flags, "out-dir") {
        write_artifacts(Path::new(dir), &captures, &cases)?;
    }
    // Gate: non-zero if any Tier-A case did not HIT, so `make`/CI can rely on it.
    if !all_tier_a_hit(&scored) {
        std::process::exit(1);
    }
    Ok(())
}

// ─────────────────────────── live run ───────────────────────────

fn run_script(script: &Option<String>, root: &Path) {
    if let Some(s) = script {
        let _ = Command::new("bash").arg(root.join(s)).status();
    }
}

fn run_case(case: &Case, sink: &str, root: &Path, isolate: bool) -> Result<CaseCapture> {
    if isolate && !Path::new(ISOLATION_SENTINEL).exists() {
        bail!(
            "refusing to run atomics: {ISOLATION_SENTINEL} not found. Atomics run ONLY \
             inside a disposable target, never the control host (use --no-isolate to override)."
        );
    }
    let within = case
        .expects
        .as_ref()
        .map(|e| e.within_seconds)
        .unwrap_or(5.0);

    run_script(&case.cleanup, root); // reverse prior state

    // Quiet-drain gap BEFORE the window opens. The eBPF backend stamps each record
    // with its DRAIN time, not the event time, so a prior case's tail (or this
    // case's own cleanup: bash/rm/cp execs, watched-file rewrites) drained late
    // would otherwise land inside this window as a false positive. Sleeping here
    // lets the ring flush all of that with pre-trigger timestamps, so the window
    // contains only the atomic's own activity.
    std::thread::sleep(std::time::Duration::from_secs(QUIET_DRAIN_SECS));

    let trigger_time = capture::now_ms();
    run_script(&case.atomic, root);

    std::thread::sleep(std::time::Duration::from_secs_f64(within + 1.0)); // + settle
    let records = capture::window(&capture::read_ndjson(sink), trigger_time, within);

    run_script(&case.cleanup, root); // leave a known state for the next case
    Ok(CaseCapture {
        case_id: case.id.clone(),
        trigger_time,
        records,
    })
}

fn cmd_run(flags: &HashMap<String, String>) -> Result<()> {
    let registry = flag(flags, "registry").unwrap_or("config/techniques.toml");
    let sink = flag(flags, "sink").context("--sink is required (torda's --output path)")?;
    let platform = flag(flags, "platform").unwrap_or("linux");
    let tier: Vec<char> = flag(flags, "tier")
        .unwrap_or("AB")
        .to_uppercase()
        .chars()
        .collect();
    let results_root = flag(flags, "results-root").unwrap_or("results");
    let isolate = flag(flags, "no-isolate").is_none();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let cases: Vec<Case> = load_registry(registry)?
        .into_iter()
        .filter(|c| c.platform == platform && tier.contains(&c.tier.chars().next().unwrap_or('A')))
        .collect();

    // Preflight (spec §12): one known-good atomic must land, else abort so a
    // stub/unprivileged agent can't produce a suite of false MISSes.
    if flag(flags, "no-preflight").is_none() {
        if let Some(pf) = cases.iter().find(|c| c.id == PREFLIGHT_CASE) {
            let entry = run_case(pf, sink, &root, isolate)?;
            if entry.records.is_empty() {
                bail!(
                    "PREFLIGHT FAILED: the known-good atomic produced NO OCSF records. Is torda \
                     built --features linux-ebpf, privileged, and streaming to --sink? Aborting."
                );
            }
        }
    }

    let run_id = format!("{}", capture::now_ms());
    let mut captures = Captures {
        run_id: run_id.clone(),
        agent: flag(flags, "agent").unwrap_or("torda").to_string(),
        cases: vec![],
    };
    for c in &cases {
        eprintln!("[run] {} ({})", c.id, c.attack_technique);
        captures.cases.push(run_case(c, sink, &root, isolate)?);
    }

    write_artifacts(&Path::new(results_root).join(&run_id), &captures, &cases)
}
