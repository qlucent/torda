//! `torda-feed` — install/verify an enrichment feed bundle into a local store
//! and report its status. Operator tool for the backend side; hand-rolled arg
//! parsing (no clap), matching the `torda` agent binary.
//!
//! Commands:
//!   torda-feed install --from <bundle-dir> [--store <dir>] [--trust <hex|file>]...
//!   torda-feed status [--store <dir>]
//!   torda-feed gen-sample --content <dir> --out <dir> [--tier community|enterprise]
//!                         [--version <s>] [--source <s>]
//!
//! Store precedence: --store > $TORDA_FEED_STORE > <temp>/torda-feed-store.
//! Trust precedence: --trust keys if given, else the built-in sample key (so the
//! shipped community sample verifies out of the box). A real deployment always
//! passes its real published key with --trust.

use std::path::PathBuf;

use anyhow::{bail, Context};
use torda_feed::{builder, sample, verify_bundle, FeedStore, FeedTier, FeedVerifier};

fn main() {
    if let Err(e) = run() {
        eprintln!("torda-feed: error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("");
    let rest = &args[args.len().min(1)..];
    match cmd {
        "install" => cmd_install(rest),
        "status" => cmd_status(rest),
        "gen-sample" => cmd_gen_sample(rest),
        "" | "-h" | "--help" | "help" => {
            print_usage();
            Ok(())
        }
        other => {
            print_usage();
            bail!("unknown command {other:?}");
        }
    }
}

fn print_usage() {
    eprintln!(
        "usage:\n  \
         torda-feed install --from <bundle-dir> [--store <dir>] [--trust <hex|file>]...\n  \
         torda-feed status [--store <dir>]\n  \
         torda-feed gen-sample --content <dir> --out <dir> [--tier community|enterprise] [--version <s>] [--source <s>]"
    );
}

// --- arg helpers -----------------------------------------------------------

/// Pull the value for `--flag <value>` / `--flag=value`; returns the first match
/// and leaves the rest (a caller can call again for repeatable flags via
/// `take_all`).
fn take_one(args: &[String], flag: &str) -> Option<String> {
    take_all(args, flag).into_iter().next()
}

/// All values given for a (possibly repeated) `--flag`.
fn take_all(args: &[String], flag: &str) -> Vec<String> {
    let eq = format!("{flag}=");
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == flag {
            if let Some(v) = args.get(i + 1) {
                out.push(v.clone());
                i += 2;
                continue;
            }
        } else if let Some(v) = a.strip_prefix(&eq) {
            out.push(v.to_string());
        }
        i += 1;
    }
    out
}

fn store_from(args: &[String]) -> FeedStore {
    let root = take_one(args, "--store")
        .or_else(|| std::env::var("TORDA_FEED_STORE").ok())
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("torda-feed-store"));
    FeedStore::new(root)
}

/// Build a verifier from `--trust` values (each a 64-hex key or a file
/// containing one), or fall back to the built-in sample trust root.
fn verifier_from(args: &[String]) -> anyhow::Result<FeedVerifier> {
    let trusts = take_all(args, "--trust");
    if trusts.is_empty() {
        return Ok(sample::verifier());
    }
    let mut v = FeedVerifier::new();
    for t in trusts {
        let p = PathBuf::from(&t);
        let hex = if p.is_file() {
            std::fs::read_to_string(&p)
                .with_context(|| format!("reading trust key file {}", p.display()))?
        } else {
            t
        };
        v.trust_from_hex(hex.trim())?;
    }
    Ok(v)
}

// --- commands --------------------------------------------------------------

fn cmd_install(args: &[String]) -> anyhow::Result<()> {
    let from = take_one(args, "--from").context("install needs --from <bundle-dir>")?;
    let store = store_from(args);
    let verifier = verifier_from(args)?;

    let manifest = store
        .install(&PathBuf::from(&from), &verifier)
        .with_context(|| format!("installing feed from {from}"))?;

    println!(
        "installed feed {} (tier {}, source {:?}, {} content file(s)) into {}",
        manifest.feed_version,
        manifest.tier,
        manifest.source,
        manifest.entries.len(),
        store.root().display()
    );
    Ok(())
}

fn cmd_status(args: &[String]) -> anyhow::Result<()> {
    let store = store_from(args);
    match store.state()? {
        None => {
            println!("no feed installed in {}", store.root().display());
        }
        Some(state) => {
            let age_ms = store.staleness_ms(torda_feed::now_millis()).unwrap_or(0);
            println!("store:        {}", store.root().display());
            println!("feed_version: {}", state.feed_version);
            println!("tier:         {}", state.tier);
            println!("source:       {}", state.source);
            println!("created_at:   {} (epoch ms)", state.created_at);
            println!("applied_at:   {} (epoch ms)", state.applied_at);
            println!("age:          {} day(s)", age_ms / 86_400_000);
        }
    }
    Ok(())
}

fn cmd_gen_sample(args: &[String]) -> anyhow::Result<()> {
    let content = take_one(args, "--content").context("gen-sample needs --content <dir>")?;
    let out = take_one(args, "--out").context("gen-sample needs --out <dir>")?;
    let tier = match take_one(args, "--tier").as_deref() {
        None | Some("community") => FeedTier::Community,
        Some("enterprise") => FeedTier::Enterprise,
        Some(other) => bail!("unknown --tier {other:?} (want community|enterprise)"),
    };
    let created_at = torda_feed::now_millis();
    let version = take_one(args, "--version").unwrap_or_else(|| format!("v{created_at}"));
    let source = take_one(args, "--source").unwrap_or_else(|| match tier {
        FeedTier::Community => "qlucent-community".to_string(),
        FeedTier::Enterprise => "qlucent-enterprise".to_string(),
    });

    let content_dir = PathBuf::from(&content);
    let out_dir = PathBuf::from(&out);
    let manifest =
        builder::manifest_from_content_dir(&content_dir, version, created_at, source, tier)?;
    builder::write_signed_bundle(&content_dir, &out_dir, &manifest, &sample::signer())?;

    // Prove it verifies against the sample trust root before we claim success.
    verify_bundle(&out_dir, &sample::verifier())
        .context("self-verifying the freshly generated sample bundle")?;

    println!(
        "wrote signed {} bundle {} ({} file(s)) to {} — verified OK",
        manifest.tier,
        manifest.feed_version,
        manifest.entries.len(),
        out_dir.display()
    );
    Ok(())
}
