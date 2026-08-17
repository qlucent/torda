//! `NvdSource`: a [`CveSource`](crate::cve_source::CveSource) for Windows
//! `registry` components, which OSV does not cover. Where [`OsvSource`] matches a
//! dpkg/rpm package name against per-distro OSV advisories, `NvdSource` matches a
//! Windows Add/Remove-Programs **DisplayName** (the only identity a registry SBOM
//! component carries — there is no separate vendor field) against a curated set of
//! NVD-derived advisories, each naming the affected product, a few DisplayName
//! **alias** substrings, and a semver version range.
//!
//! It is deliberately the mirror image of `OsvSource`: `OsvSource::hits_for`
//! returns nothing for `source == "registry"`, and `NvdSource::hits_for` returns
//! nothing for `dpkg`/`rpm`. So the two compose in a [`CompositeCveSource`]
//! (see [`crate::cve_source`]) with **no overlap and no double counting** — Linux
//! components resolve through OSV, Windows components through NVD.
//!
//! Provenance stays honest: a [`CveHit`] carries only the
//! vuln id and the fix key, never a severity. NVD's CVSS is supplied separately
//! through enrichment ([`crate::enrichment`]), which the engine recomputes a
//! score from.
//!
//! ## Feed tier — the community/enterprise seam
//! A bundle declares a [`FeedTier`] and a snapshot date. The committed sample is a
//! `Community` snapshot: a small, date-stamped, curated set of common-app CVEs
//! with an alias-based DisplayName→product mapping. The SAME `CveSource` trait
//! backs a future `Enterprise` feed — a live NVD 2.0 API sync with full
//! CPE-dictionary matching — with no change to the pipeline or any module. The
//! tier is carried explicitly so the distinction is real and inspectable, not
//! just a promise.

use std::cmp::Ordering;

use serde::Deserialize;

use crate::cve_source::CveSource;
use crate::matching::CveHit;
use crate::version::semver_compare;

/// Which feed a bundle came from. The committed sample is `Community`; a live NVD
/// sync would build the identical index as `Enterprise`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FeedTier {
    Community,
    Enterprise,
}

impl FeedTier {
    fn parse(s: Option<&str>) -> Self {
        match s.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            Some("enterprise") => FeedTier::Enterprise,
            // A bundled snapshot with no/unknown tier is a community feed.
            _ => FeedTier::Community,
        }
    }
}

// ---------------------------------------------------------------------------
// Bundle schema (a tolerant subset; unknown fields — e.g. the `severity` /
// `database_specific` that enrichment reads from the SAME file — are ignored)
// ---------------------------------------------------------------------------

/// A bundle is an object carrying feed metadata + records. A bare JSON array of
/// records is also accepted (defaults to a community feed, no date) so the format
/// stays close to the OSV bundle.
#[derive(Deserialize)]
#[serde(untagged)]
enum NvdBundle {
    Wrapped {
        #[serde(default)]
        feed_tier: Option<String>,
        #[serde(default)]
        snapshot_date: Option<String>,
        #[serde(default)]
        records: Vec<NvdRecord>,
    },
    Bare(Vec<NvdRecord>),
}

#[derive(Deserialize)]
struct NvdRecord {
    id: String,
    #[serde(default)]
    affected_windows: Vec<NvdAffected>,
}

#[derive(Deserialize)]
struct NvdAffected {
    /// The canonical product name used to build the remediation key
    /// (`upgrade:{product}>={fixed}`).
    product: String,
    /// Lower-cased DisplayName substrings that identify this product in the
    /// Windows registry (e.g. `"putty"`, `"7-zip"`). Matching is substring +
    /// case-insensitive against the normalized DisplayName.
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    ranges: Vec<NvdRange>,
}

/// A semver range. `introduced` is inclusive, `fixed` is EXCLUSIVE (`< fixed` is
/// affected), `last_affected` is inclusive. Any bound that will not parse fails
/// closed (never a false positive).
#[derive(Deserialize)]
struct NvdRange {
    #[serde(default)]
    introduced: Option<String>,
    #[serde(default)]
    fixed: Option<String>,
    #[serde(default)]
    last_affected: Option<String>,
}

/// One flattened affected clause the matcher scans.
struct IndexedAffected {
    id: String,
    product: String,
    aliases: Vec<String>,
    ranges: Vec<NvdRange>,
}

// ---------------------------------------------------------------------------
// NvdSource
// ---------------------------------------------------------------------------

/// A range-aware CVE source for Windows `registry` components. Deterministic and
/// network-free: it only matches against the records handed to it. The community
/// bundle is small, so matching is a linear scan (a curated feed, not the full
/// NVD corpus).
pub struct NvdSource {
    tier: FeedTier,
    snapshot_date: Option<String>,
    affected: Vec<IndexedAffected>,
}

impl NvdSource {
    /// Build a source from an NVD community bundle (see the module docs for the
    /// schema). Accepts the wrapped object form or a bare records array.
    pub fn from_json(json: &str) -> anyhow::Result<Self> {
        let bundle: NvdBundle = serde_json::from_str(json)?;
        let (tier, snapshot_date, records) = match bundle {
            NvdBundle::Wrapped {
                feed_tier,
                snapshot_date,
                records,
            } => (
                FeedTier::parse(feed_tier.as_deref()),
                snapshot_date,
                records,
            ),
            NvdBundle::Bare(records) => (FeedTier::Community, None, records),
        };
        let mut affected = Vec::new();
        for record in records {
            for a in record.affected_windows {
                affected.push(IndexedAffected {
                    id: record.id.clone(),
                    product: a.product,
                    aliases: a.aliases.iter().map(|s| s.to_ascii_lowercase()).collect(),
                    ranges: a.ranges,
                });
            }
        }
        Ok(Self {
            tier,
            snapshot_date,
            affected,
        })
    }

    /// The feed tier this bundle declared (community for the committed sample).
    pub fn tier(&self) -> FeedTier {
        self.tier
    }

    /// The bundle's snapshot date, if it declared one (a community feed is a
    /// point-in-time snapshot, not a live feed).
    pub fn snapshot_date(&self) -> Option<&str> {
        self.snapshot_date.as_deref()
    }
}

impl CveSource for NvdSource {
    fn hits_for(
        &self,
        source: &str,
        _os: &str,
        _os_version: &str,
        name: &str,
        version: &str,
    ) -> Vec<CveHit> {
        // NVD here covers only Windows registry components. dpkg/rpm resolve
        // through OSV; returning nothing for them is what lets the two sources
        // compose without double counting.
        if source != "registry" {
            return Vec::new();
        }
        let normalized = normalize_display_name(name);
        let mut out: Vec<CveHit> = Vec::new();
        let mut seen: Vec<String> = Vec::new();
        for entry in &self.affected {
            if seen.contains(&entry.id) {
                continue;
            }
            if !entry
                .aliases
                .iter()
                .any(|alias| normalized.contains(alias.as_str()))
            {
                continue;
            }
            if entry.ranges.iter().any(|r| range_affects(version, r)) {
                seen.push(entry.id.clone());
                out.push(CveHit {
                    name: name.to_string(),
                    version: version.to_string(),
                    vuln_id: entry.id.clone(),
                    remediation_key: remediation_key(entry),
                });
            }
        }
        out
    }
}

/// Lower-case a Windows DisplayName and drop the common architecture/edition
/// parentheticals so an alias substring matches regardless of the `(64-bit)` etc.
/// suffix. Whitespace is collapsed. This is a normalization for *alias* matching,
/// not a version parser.
fn normalize_display_name(display: &str) -> String {
    let mut s = display.to_ascii_lowercase();
    for junk in [
        "(64-bit x64)",
        "(32-bit x86)",
        "(64-bit)",
        "(32-bit)",
        "(x64)",
        "(x86)",
        "(64 bit)",
        "(32 bit)",
    ] {
        s = s.replace(junk, " ");
    }
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Evaluate one semver range for `version`. `introduced` inclusive, `fixed`
/// exclusive, `last_affected` inclusive. Any comparison the semver comparator
/// cannot make (unparseable version or bound) fails closed — a Windows
/// DisplayVersion that is not a clean dotted number never becomes a false
/// positive.
fn range_affects(version: &str, range: &NvdRange) -> bool {
    // A range with no bounds at all is a degenerate/malformed entry: match
    // nothing rather than everything (fail closed). A legitimate "all versions"
    // entry uses an explicit low `introduced` bound.
    if range.introduced.is_none() && range.fixed.is_none() && range.last_affected.is_none() {
        return false;
    }
    if let Some(introduced) = &range.introduced {
        match semver_compare(version, introduced) {
            // version < introduced -> not yet affected.
            Some(Ordering::Less) => return false,
            Some(_) => {}
            None => return false,
        }
    }
    if let Some(fixed) = &range.fixed {
        match semver_compare(version, fixed) {
            // version < fixed -> affected; >= fixed -> patched.
            Some(Ordering::Less) => {}
            Some(_) => return false,
            None => return false,
        }
    }
    if let Some(last) = &range.last_affected {
        match semver_compare(version, last) {
            // version > last_affected -> no longer affected.
            Some(Ordering::Greater) => return false,
            Some(_) => {}
            None => return false,
        }
    }
    // A range with no parseable bound triggered a `return false` above; reaching
    // here means every present bound was satisfied.
    true
}

/// Prefer `upgrade:{product}>={first fixed}`, else `patch:{product}:{id}` when no
/// range names a fixed version.
fn remediation_key(entry: &IndexedAffected) -> String {
    for range in &entry.ranges {
        if let Some(fixed) = &range.fixed {
            return format!("upgrade:{}>={}", entry.product, fixed);
        }
    }
    format!("patch:{}:{}", entry.product, entry.id)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A realistic community bundle: PuTTY affected below 0.81 (with a lower
    // bound), 7-Zip affected below 24.07 from the beginning. `severity` /
    // `database_specific` are present to prove the matcher IGNORES them (enrichment
    // reads them from the same file).
    const BUNDLE: &str = r#"{
      "feed_tier": "community",
      "snapshot_date": "2026-07-20",
      "records": [
        { "id": "CVE-2024-31497",
          "severity": [ { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" } ],
          "database_specific": { "cvss_base_score": 5.9 },
          "affected_windows": [
            { "product": "putty", "aliases": ["putty"],
              "ranges": [ { "introduced": "0.68", "fixed": "0.81" } ] } ] },
        { "id": "CVE-2024-11477",
          "affected_windows": [
            { "product": "7-zip", "aliases": ["7-zip"],
              "ranges": [ { "fixed": "24.07" } ] } ] }
      ]
    }"#;

    fn src() -> NvdSource {
        NvdSource::from_json(BUNDLE).unwrap()
    }

    #[test]
    fn tier_and_date_are_carried() {
        let s = src();
        assert_eq!(s.tier(), FeedTier::Community);
        assert_eq!(s.snapshot_date(), Some("2026-07-20"));
    }

    #[test]
    fn bare_array_defaults_to_community() {
        let s = NvdSource::from_json(
            r#"[ { "id": "CVE-X", "affected_windows": [
              { "product": "p", "aliases": ["p"], "ranges": [ {"fixed":"2.0"} ] } ] } ]"#,
        )
        .unwrap();
        assert_eq!(s.tier(), FeedTier::Community);
        assert_eq!(s.snapshot_date(), None);
    }

    #[test]
    fn registry_below_fixed_is_a_hit() {
        let hits = src().hits_for("registry", "Windows", "11", "PuTTY release 0.80", "0.80");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].vuln_id, "CVE-2024-31497");
        assert_eq!(hits[0].remediation_key, "upgrade:putty>=0.81");
    }

    #[test]
    fn registry_at_fixed_is_not_a_hit() {
        // fixed is exclusive.
        assert!(src()
            .hits_for("registry", "Windows", "11", "PuTTY release 0.81", "0.81")
            .is_empty());
        assert!(src()
            .hits_for("registry", "Windows", "11", "PuTTY", "0.82")
            .is_empty());
    }

    #[test]
    fn registry_below_introduced_is_not_a_hit() {
        // PuTTY range is introduced 0.68; 0.67 is not yet affected.
        assert!(src()
            .hits_for("registry", "Windows", "11", "PuTTY", "0.67")
            .is_empty());
    }

    #[test]
    fn alias_matches_despite_arch_suffix_and_case() {
        // "7-Zip 23.01 (x64)" normalizes to "7-zip 23.01"; alias "7-zip" hits.
        let hits = src().hits_for("registry", "Windows", "11", "7-Zip 23.01 (x64)", "23.01");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].vuln_id, "CVE-2024-11477");
        assert_eq!(hits[0].remediation_key, "upgrade:7-zip>=24.07");
    }

    #[test]
    fn non_registry_source_matches_nothing() {
        // A dpkg/rpm component must never resolve through NVD (OSV covers those).
        assert!(src()
            .hits_for("dpkg", "Debian", "12", "putty", "0.80")
            .is_empty());
        assert!(src()
            .hits_for("rpm", "Red Hat", "8", "putty", "0.80")
            .is_empty());
    }

    #[test]
    fn unknown_product_matches_nothing() {
        assert!(src()
            .hits_for("registry", "Windows", "11", "Some Other App", "1.0")
            .is_empty());
    }

    #[test]
    fn range_with_no_bounds_matches_nothing() {
        // A degenerate entry (an empty range) must not match every version.
        let s = NvdSource::from_json(
            r#"[ { "id": "CVE-EMPTY", "affected_windows": [
              { "product": "putty", "aliases": ["putty"], "ranges": [ {} ] } ] } ]"#,
        )
        .unwrap();
        assert!(s
            .hits_for("registry", "Windows", "11", "PuTTY 0.80", "0.80")
            .is_empty());
    }

    #[test]
    fn unparseable_version_fails_closed() {
        // A DisplayVersion the semver comparator cannot parse cannot be placed in
        // the range -> never a false positive. A 4-part Windows version
        // ("0.80.0.1") is the realistic case: semver has three core parts, so a
        // fourth makes it unparseable and the match fails closed. (A future 4-part-
        // tolerant comparator could match these; failing closed is the safe default
        // until then — see the deferred backlog.)
        assert!(src()
            .hits_for("registry", "Windows", "11", "PuTTY", "0.80.0.1")
            .is_empty());
        // A non-numeric core is likewise unparseable and fails closed.
        assert!(src()
            .hits_for("registry", "Windows", "11", "PuTTY", "0.8x")
            .is_empty());
    }

    #[test]
    fn severity_fields_are_ignored_by_the_matcher() {
        // The bundle carries CVSS for enrichment; the matcher must not surface it
        // (rule #5). The hit has only id + fix key.
        let hits = src().hits_for("registry", "Windows", "11", "PuTTY 0.80", "0.80");
        assert_eq!(hits.len(), 1);
        // CveHit has no severity field at all; assert the fix key is the fix, not a score.
        assert!(hits[0].remediation_key.starts_with("upgrade:"));
    }
}
