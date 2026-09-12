//! The real bundled [`EnrichmentSource`]: combines three committed, web-verified
//! snapshots — CVSS (from the OSV advisories' `severity`), EPSS (FIRST.org CSV),
//! and KEV (a CISA catalog subset) — into one [`Enrichment`] per `vuln_id`.
//!
//! This is the enrichment counterpart to [`crate::cve_source::OsvSource`]: that
//! turns installed packages into CVE *matches*; this supplies the CVSS/EPSS/KEV/VEX
//! *evidence* the Findings Engine recomputes a real, explainable `Score.R` from
//! (never a source's severity label; always recompute from
//! persisted inputs). Without it every matched CVE scores `R=0` (neutral).
//!
//! Contracts held here:
//! - **Fail-closed load.** An unreadable or unparseable snapshot is a hard
//!   `anyhow::Error` the caller propagates — never a silent empty/partial feed.
//! - **Real evidence only.** Every value comes from a committed snapshot the
//!   report cites against NVD / FIRST.org / CISA. Nothing is synthesized at runtime.
//! - **Deterministic, network-free.** It only reads the files handed to it.
//! - **Absent → neutral.** A `vuln_id` with no evidence in any snapshot returns
//!   `None`, so the engine falls through to its neutral default (R unchanged) —
//!   backward compatible with a run that has no enrichment data.
//!
//! Mapping (per the VD-3 formula in `server/findings-engine/src/score.rs`):
//! - `cvss_env` / `cvss_vector` ← the advisory `severity` (real CVSS v3.1 base + vector).
//! - `epss` / `epss_pct` ← the EPSS CSV row.
//! - `kev` ← membership in the KEV snapshot; a KEV CVE also gets
//!   `exploit_maturity = Weaponized` (known-exploited ⇒ decide() forces ACT).
//! - `exploit_maturity` (non-KEV) ← the advisory's honest `database_specific`
//!   maturity call (else `None`).
//! - `vex = Affected` for any CVE we hold evidence for: a match is a *genuinely
//!   installed vulnerable version*, so the asset IS reachable (reach 1.0).

use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::Context;
use serde::Deserialize;
use torda_findings::{Enrichment, ExploitMaturity, VexStatus};
use torda_findings_engine::input::EnrichmentSource;

/// Per-CVE CVSS evidence parsed from an OSV advisory's `severity` +
/// `database_specific`.
#[derive(Clone, Debug)]
struct CvssEvidence {
    base_score: Option<f32>,
    vector: Option<String>,
    maturity: ExploitMaturity,
}

/// One EPSS row: probability + percentile, both 0..1.
#[derive(Clone, Copy, Debug)]
struct EpssRow {
    epss: f32,
    percentile: f32,
}

// --- OSV parsing (only the enrichment-relevant subset; unknown fields ignored) ---

#[derive(Deserialize)]
struct OsvEnrichRecord {
    id: String,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    database_specific: OsvDatabaseSpecific,
}

#[derive(Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    score: String,
}

#[derive(Deserialize, Default)]
struct OsvDatabaseSpecific {
    #[serde(default)]
    cvss_base_score: Option<f32>,
    #[serde(default)]
    exploit_maturity: Option<String>,
}

/// A CVSS snapshot is EITHER a bare array of records (the OSV bundle) OR a
/// wrapped object `{ ..., records: [...] }` (the NVD bundle, which also carries
/// `feed_tier` / `snapshot_date` that enrichment ignores). Both forms deserialize
/// to the same records, so `parse_cvss` reads either.
#[derive(Deserialize)]
#[serde(untagged)]
enum CvssBundle {
    Wrapped {
        #[serde(default)]
        records: Vec<OsvEnrichRecord>,
    },
    Bare(Vec<OsvEnrichRecord>),
}

// --- KEV parsing (the real CISA catalog shape; only cveID is load-bearing) ---

#[derive(Deserialize)]
struct KevCatalog {
    #[serde(default)]
    vulnerabilities: Vec<KevEntry>,
}

#[derive(Deserialize)]
struct KevEntry {
    #[serde(rename = "cveID")]
    cve_id: String,
}

/// The bundled enrichment source: three snapshots joined by `vuln_id`.
#[derive(Default)]
pub struct BundledEnrichment {
    cvss: HashMap<String, CvssEvidence>,
    epss: HashMap<String, EpssRow>,
    kev: HashSet<String>,
    /// The feed snapshot version these snapshots came from, stamped into every
    /// returned [`Enrichment`] for explainability. `None` for the plain
    /// directory/snapshot loaders (unversioned); `Some` when loaded from a
    /// verified feed store (see [`BundledEnrichment::load_from_feed_store`]).
    feed_version: Option<String>,
}

impl BundledEnrichment {
    /// Load from a sample directory containing `osv-bundle.json` (CVSS severity),
    /// `epss-sample.csv` (FIRST.org format), and `kev-sample.json` (CISA subset).
    /// If an `nvd-bundle.json` (the Windows/NVD community feed) is ALSO present,
    /// its CVSS is merged in — EPSS/KEV for those CVEs live in the same shared
    /// `epss-sample.csv` / `kev-sample.json`. Fails closed: a missing required
    /// file, or an unparseable one (including `nvd-bundle.json` if present), is a
    /// hard error.
    pub fn load_from_dir(dir: &Path) -> anyhow::Result<Self> {
        let osv = dir.join("osv-bundle.json");
        let nvd = dir.join("nvd-bundle.json");
        let epss = dir.join("epss-sample.csv");
        let kev = dir.join("kev-sample.json");

        let osv_text = std::fs::read_to_string(&osv)
            .with_context(|| format!("reading CVSS/OSV snapshot {}", osv.display()))?;
        let epss_text = std::fs::read_to_string(&epss)
            .with_context(|| format!("reading EPSS snapshot {}", epss.display()))?;
        let kev_text = std::fs::read_to_string(&kev)
            .with_context(|| format!("reading KEV snapshot {}", kev.display()))?;

        let mut source = Self::from_snapshots(&osv_text, &epss_text, &kev_text)?;

        // Optional NVD community feed: merge its CVSS by vuln_id. Present-but-
        // unparseable is a hard error (fail-closed), same as the required files.
        if nvd.exists() {
            let nvd_text = std::fs::read_to_string(&nvd)
                .with_context(|| format!("reading NVD CVSS snapshot {}", nvd.display()))?;
            let nvd_cvss = parse_cvss(&nvd_text).context("parsing CVSS from the NVD snapshot")?;
            source.cvss.extend(nvd_cvss);
        }

        Ok(source)
    }

    /// Build from the three snapshot bodies (the unit-testable seam under
    /// [`load_from_dir`]). Any parse failure is a hard error (fail-closed).
    pub fn from_snapshots(osv_json: &str, epss_csv: &str, kev_json: &str) -> anyhow::Result<Self> {
        let cvss = parse_cvss(osv_json).context("parsing CVSS from the OSV snapshot")?;
        let epss = parse_epss(epss_csv).context("parsing the EPSS snapshot")?;
        let kev = parse_kev(kev_json).context("parsing the KEV snapshot")?;
        Ok(Self {
            cvss,
            epss,
            kev,
            feed_version: None,
        })
    }

    /// Tag every [`Enrichment`] this source returns with a feed snapshot
    /// version, so a finding scored from it cites which feed produced its
    /// inputs. Builder form for the plain loaders; the feed-store loader sets
    /// it automatically.
    pub fn with_feed_version(mut self, feed_version: Option<String>) -> Self {
        self.feed_version = feed_version;
        self
    }

    /// The feed snapshot version stamped into returned enrichments, if any.
    pub fn feed_version(&self) -> Option<&str> {
        self.feed_version.as_deref()
    }

    /// Load enrichment from a **verified** feed store: reads the store's active
    /// content directory (the osv/epss/kev/nvd snapshots the installed bundle
    /// carried) via [`load_from_dir`](Self::load_from_dir) and stamps the
    /// store's active `feed_version` into every returned [`Enrichment`].
    ///
    /// The store must already hold a verified bundle (install verifies the
    /// signature + per-file digests); this only reads what verification
    /// admitted. A store with no installed feed is a hard error (fail-closed) —
    /// the caller should fall back to an unenriched run explicitly, not
    /// silently score against nothing.
    pub fn load_from_feed_store(store: &torda_feed::FeedStore) -> anyhow::Result<Self> {
        let version = store.active_version().ok_or_else(|| {
            anyhow::anyhow!(
                "feed store {} has no installed feed; install a bundle first",
                store.root().display()
            )
        })?;
        let content = store.content_dir();
        Self::load_from_dir(&content)
            .with_context(|| {
                format!(
                    "loading enrichment from feed store content {}",
                    content.display()
                )
            })
            .map(|s| s.with_feed_version(Some(version)))
    }
}

impl EnrichmentSource for BundledEnrichment {
    fn lookup(&self, vuln_id: &str) -> Option<Enrichment> {
        let cvss = self.cvss.get(vuln_id);
        let epss = self.epss.get(vuln_id);
        let kev = self.kev.contains(vuln_id);

        // Absent from every snapshot → no evidence → neutral fall-through (R stays 0).
        if cvss.is_none() && epss.is_none() && !kev {
            return None;
        }

        // KEV is known-exploited → Weaponized, overriding any per-advisory call.
        // Otherwise use the advisory's honest maturity (default None).
        let exploit_maturity = if kev {
            ExploitMaturity::Weaponized
        } else {
            cvss.map(|c| c.maturity).unwrap_or(ExploitMaturity::None)
        };

        Some(Enrichment {
            cvss_vector: cvss.and_then(|c| c.vector.clone()),
            cvss_env: cvss.and_then(|c| c.base_score),
            epss: epss.map(|e| e.epss),
            epss_pct: epss.map(|e| e.percentile),
            kev,
            exploit_maturity,
            // We only hold evidence for a CVE we matched against a genuinely
            // installed, in-range vulnerable version → the asset IS affected.
            vex: VexStatus::Affected,
            // Explainability: which feed snapshot supplied these inputs.
            feed_version: self.feed_version.clone(),
        })
    }
}

/// Parse `exploit_maturity` strings using the same snake_case names the enum
/// serializes to. An unknown string fails closed (a bad label must not silently
/// become a high maturity) by mapping to `None`.
fn parse_maturity(s: &str) -> ExploitMaturity {
    match s {
        "poc" => ExploitMaturity::Poc,
        "functional" => ExploitMaturity::Functional,
        "weaponized" => ExploitMaturity::Weaponized,
        "in_the_wild" => ExploitMaturity::InTheWild,
        _ => ExploitMaturity::None,
    }
}

/// Extract CVSS evidence from the OSV advisories: the numeric base score from
/// `database_specific.cvss_base_score` and the vector from the first `CVSS_V3`
/// `severity` entry.
fn parse_cvss(osv_json: &str) -> anyhow::Result<HashMap<String, CvssEvidence>> {
    let records = match serde_json::from_str::<CvssBundle>(osv_json)? {
        CvssBundle::Wrapped { records } => records,
        CvssBundle::Bare(records) => records,
    };
    let mut out = HashMap::new();
    for r in records {
        let vector = r
            .severity
            .iter()
            .find(|s| s.kind.eq_ignore_ascii_case("CVSS_V3") && !s.score.is_empty())
            .map(|s| s.score.clone());
        let maturity = r
            .database_specific
            .exploit_maturity
            .as_deref()
            .map(parse_maturity)
            .unwrap_or(ExploitMaturity::None);
        out.insert(
            r.id,
            CvssEvidence {
                base_score: r.database_specific.cvss_base_score,
                vector,
                maturity,
            },
        );
    }
    Ok(out)
}

/// Parse the FIRST.org EPSS CSV: `#`-prefixed lines and a `cve,epss,percentile`
/// header are skipped; every data row must have three parseable columns (a
/// malformed data row is a hard error — fail closed, never a silent 0).
fn parse_epss(epss_csv: &str) -> anyhow::Result<HashMap<String, EpssRow>> {
    let mut out = HashMap::new();
    for line in epss_csv.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Skip the column header wherever it sits.
        if line.eq_ignore_ascii_case("cve,epss,percentile") {
            continue;
        }
        let mut cols = line.split(',');
        let cve = cols.next().unwrap_or("").trim();
        let epss_s = cols.next().map(str::trim);
        let pct_s = cols.next().map(str::trim);
        let (Some(epss_s), Some(pct_s)) = (epss_s, pct_s) else {
            anyhow::bail!("malformed EPSS row (need cve,epss,percentile): {line:?}");
        };
        let epss: f32 = epss_s
            .parse()
            .with_context(|| format!("parsing EPSS score in row {line:?}"))?;
        let percentile: f32 = pct_s
            .parse()
            .with_context(|| format!("parsing EPSS percentile in row {line:?}"))?;
        out.insert(cve.to_string(), EpssRow { epss, percentile });
    }
    Ok(out)
}

/// Parse the CISA KEV subset into the set of known-exploited CVE ids.
fn parse_kev(kev_json: &str) -> anyhow::Result<HashSet<String>> {
    let catalog: KevCatalog = serde_json::from_str(kev_json)?;
    Ok(catalog
        .vulnerabilities
        .into_iter()
        .map(|v| v.cve_id)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OSV: &str = r#"[
      { "id": "CVE-2022-3602",
        "severity": [ { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" } ],
        "database_specific": { "cvss_base_score": 7.5, "exploit_maturity": "poc" },
        "affected": [] },
      { "id": "CVE-2021-3156",
        "severity": [ { "type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" } ],
        "database_specific": { "cvss_base_score": 7.8, "exploit_maturity": "weaponized" },
        "affected": [] }
    ]"#;
    const EPSS: &str = "#model_version:test\ncve,epss,percentile\nCVE-2022-3602,0.907700,0.997940\nCVE-2021-3156,0.992950,0.999340\n";
    const KEV: &str = r#"{ "vulnerabilities": [ { "cveID": "CVE-2021-3156" } ] }"#;

    fn src() -> BundledEnrichment {
        BundledEnrichment::from_snapshots(OSV, EPSS, KEV).unwrap()
    }

    #[test]
    fn joins_cvss_epss_and_marks_affected() {
        let e = src().lookup("CVE-2022-3602").expect("has evidence");
        assert_eq!(e.cvss_env, Some(7.5));
        assert_eq!(
            e.cvss_vector.as_deref(),
            Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")
        );
        assert_eq!(e.epss, Some(0.9077));
        assert_eq!(e.epss_pct, Some(0.99794));
        assert!(!e.kev, "CVE-2022-3602 is not KEV-listed");
        assert_eq!(e.exploit_maturity, ExploitMaturity::Poc);
        assert_eq!(
            e.vex,
            VexStatus::Affected,
            "a matched vuln means the asset is affected"
        );
    }

    #[test]
    fn kev_cve_is_weaponized_and_flagged() {
        let e = src().lookup("CVE-2021-3156").expect("has evidence");
        assert!(e.kev, "CVE-2021-3156 (sudo Baron Samedit) IS KEV-listed");
        assert_eq!(
            e.exploit_maturity,
            ExploitMaturity::Weaponized,
            "KEV -> Weaponized"
        );
        assert_eq!(e.cvss_env, Some(7.8));
    }

    #[test]
    fn absent_cve_returns_none_for_neutral_fallthrough() {
        assert!(
            src().lookup("CVE-9999-0000").is_none(),
            "no evidence -> None -> neutral"
        );
    }

    #[test]
    fn kev_membership_alone_yields_evidence() {
        // A CVE present ONLY in the KEV snapshot (no CVSS/EPSS row) still returns
        // Some — KEV membership is evidence in its own right.
        let src = BundledEnrichment::from_snapshots("[]", "cve,epss,percentile\n", KEV).unwrap();
        let e = src
            .lookup("CVE-2021-3156")
            .expect("KEV-only still has evidence");
        assert!(e.kev);
        assert_eq!(e.cvss_env, None);
        assert_eq!(e.epss, None);
        assert_eq!(e.exploit_maturity, ExploitMaturity::Weaponized);
    }

    #[test]
    fn malformed_epss_row_fails_closed() {
        let bad = "cve,epss,percentile\nCVE-2022-3602,not-a-number,0.5\n";
        assert!(BundledEnrichment::from_snapshots(OSV, bad, KEV).is_err());
    }

    #[test]
    fn short_epss_row_fails_closed() {
        let bad = "cve,epss,percentile\nCVE-2022-3602,0.5\n";
        assert!(BundledEnrichment::from_snapshots(OSV, bad, KEV).is_err());
    }

    #[test]
    fn unparseable_kev_fails_closed() {
        assert!(BundledEnrichment::from_snapshots(OSV, EPSS, "not json").is_err());
    }

    #[test]
    fn parse_cvss_accepts_wrapped_nvd_bundle() {
        // The NVD bundle is a wrapped object carrying feed metadata + records;
        // enrichment reads CVSS from `records` and ignores `affected_windows`.
        let nvd = r#"{ "feed_tier": "community", "snapshot_date": "2026-07-20", "records": [
          { "id": "CVE-2024-31497",
            "severity": [ { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" } ],
            "database_specific": { "cvss_base_score": 5.9 },
            "affected_windows": [ { "product": "putty", "aliases": ["putty"], "ranges": [ {"fixed":"0.81"} ] } ] }
        ] }"#;
        let map = parse_cvss(nvd).expect("wrapped NVD bundle parses");
        let e = map.get("CVE-2024-31497").expect("record present");
        assert_eq!(e.base_score, Some(5.9));
        assert!(e.vector.as_deref().unwrap().starts_with("CVSS:3.1/"));
    }

    #[test]
    fn parse_cvss_still_accepts_bare_osv_array() {
        // The OSV bundle stays a bare array — the untagged bundle must accept both.
        let map = parse_cvss(OSV).expect("bare OSV array parses");
        assert_eq!(map.get("CVE-2022-3602").unwrap().base_score, Some(7.5));
    }
}
