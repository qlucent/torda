//! The `CveSource` abstraction: given an SBOM component `(source, name, version)`
//! return the [`CveHit`]s that affect it. This is the seam the pipeline queries so
//! the underlying feed can change without touching `detections_from_sbom`.
//!
//! Two implementations live behind it today:
//! - [`CveFeed`] (in [`crate::matching`]) — the exact-match fixture feed, kept for
//!   the existing offline fixtures/tests.
//! - [`OsvSource`] — a real, RANGE-AWARE source that parses OSV-format advisories
//!   and matches a component's version against `introduced`/`fixed` ranges and
//!   explicit `versions[]`, using the correct per-ecosystem version comparator.
//!
//! A future `NvdSource` implements the same trait (NVD covers Windows/registry,
//! which OSV does not) with no change to the pipeline.
//!
//! Provenance stays honest: a [`CveHit`] carries only the
//! vuln id and the fix key — never a severity label. Severity is recomputed
//! downstream from enrichment.

use std::cmp::Ordering;
use std::collections::HashMap;

use serde::Deserialize;

use crate::matching::{CveFeed, CveHit};
use crate::version::{dpkg_compare, rpm_compare, semver_compare};

/// The abstraction the pipeline queries. Object-safe so `OsvSource` (now) and a
/// future `NvdSource` are both usable as `&dyn CveSource`.
///
/// `source` is the SBOM component source (`dpkg` / `rpm` / `registry`); each
/// implementation is responsible for mapping it to whatever ecosystem model it
/// uses. `os`/`os_version` come from the SBOM envelope's `device` (never a
/// trusted external label) and let a source scope matching to the host's own
/// distro — e.g. a dpkg host on Ubuntu must not be flagged by a Debian advisory
/// whose fixed version differs. Returns every distinct CVE that affects
/// `(name, version)` on that host.
pub trait CveSource {
    fn hits_for(
        &self,
        source: &str,
        os: &str,
        os_version: &str,
        name: &str,
        version: &str,
    ) -> Vec<CveHit>;
}

/// The fixture feed matches by EXACT `(name, version)` and ignores the ecosystem
/// (its hits are curated, not range-derived). Kept so the offline fixtures and
/// their golden tests keep working while OSV becomes the real path.
impl CveSource for CveFeed {
    fn hits_for(
        &self,
        _source: &str,
        _os: &str,
        _os_version: &str,
        name: &str,
        version: &str,
    ) -> Vec<CveHit> {
        self.0
            .iter()
            .filter(|h| h.name == name && h.version == version)
            .cloned()
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Ecosystem model
// ---------------------------------------------------------------------------

/// The families of OSV ecosystem we can match against, plus the comparator each
/// implies for an `ECOSYSTEM` range. `Other` collects everything we do not match
/// from an OS package source (npm, PyPI, Go, ...); such records are indexed but
/// only reachable by a source that names them (none do today).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Family {
    Debian,
    Ubuntu,
    Rpm,
    Other,
}

/// Map an OSV `ecosystem` string (e.g. `"Debian:11"`, `"Ubuntu:22.04:LTS"`,
/// `"Red Hat:8"`, `"npm"`) to its [`Family`]. Matching keys off the base name
/// before the first `:` so per-release ecosystems collapse to one family.
fn family_of(ecosystem: &str) -> Family {
    let base = ecosystem.split(':').next().unwrap_or(ecosystem).trim();
    match base {
        "Debian" => Family::Debian,
        "Ubuntu" => Family::Ubuntu,
        "Red Hat" | "Rocky Linux" | "AlmaLinux" | "CentOS" | "Oracle Linux" | "SUSE"
        | "openSUSE" | "Mageia" => Family::Rpm,
        _ => Family::Other,
    }
}

/// Map an SBOM component `source` + host OS to the OSV families we should search.
/// `registry` (Windows) has no clean OSV ecosystem, so it matches nothing here —
/// NVD covers Windows later behind the same trait.
///
/// `os` is the host OS from the SBOM envelope (never a trusted external label).
/// For `dpkg` we disambiguate Debian vs Ubuntu by the OS string so a host only
/// searches its OWN distro's advisories: matching both would let one distro's
/// advisory falsely flag a host already patched per the other distro, whose
/// fixed version differs (the VD-2/VD-3 must-fix). If the OS is unknown/empty we
/// fall back to searching BOTH families — the pre-VD-4a behavior, kept as a
/// DOCUMENTED fallback: it is no worse than before and can only over-report on
/// an unidentifiable host, never silently drop a real hit.
///
/// Selection is FAMILY-level (Debian vs Ubuntu), not release-exact
/// (`Ubuntu:22.04:LTS`). Family-level already removes the cross-distro false
/// positive, which is the correctness fix required here. Release-exact is
/// deferred: the OSV index keys by [`Family`] (`family_of` collapses
/// `Ubuntu:22.04:LTS` -> `Ubuntu`), so exact-release matching would require
/// reindexing by full ecosystem plus an `os_version`->release normalization map,
/// and risks dropping real hits when advisory and host release strings differ.
/// `os_version` is threaded through for that future refinement.
fn source_families(source: &str, os: &str, _os_version: &str) -> &'static [Family] {
    match source {
        "dpkg" => {
            let os_l = os.to_ascii_lowercase();
            if os_l.contains("ubuntu") {
                &[Family::Ubuntu]
            } else if os_l.contains("debian") {
                &[Family::Debian]
            } else {
                // Unknown/empty OS: documented fallback to both dpkg families.
                &[Family::Debian, Family::Ubuntu]
            }
        }
        "rpm" => &[Family::Rpm],
        _ => &[],
    }
}

/// The comparator used for an `ECOSYSTEM` range in a given family.
fn ecosystem_comparator(family: Family) -> Comparator {
    match family {
        Family::Debian | Family::Ubuntu => Comparator::Dpkg,
        Family::Rpm => Comparator::Rpm,
        // Unreachable via an OS package source; a sane default if it ever is.
        Family::Other => Comparator::Semver,
    }
}

#[derive(Clone, Copy)]
enum Comparator {
    Dpkg,
    Rpm,
    Semver,
}

/// Compare `a` and `b` under `cmp`. `None` means a side could not be parsed for
/// this comparator; callers treat that as "cannot confirm" and fail closed.
fn compare(cmp: Comparator, a: &str, b: &str) -> Option<Ordering> {
    match cmp {
        Comparator::Dpkg => Some(dpkg_compare(a, b)),
        Comparator::Rpm => Some(rpm_compare(a, b)),
        Comparator::Semver => semver_compare(a, b),
    }
}

// ---------------------------------------------------------------------------
// OSV parsing model (a tolerant subset of the OSV schema)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct OsvRecord {
    id: String,
    #[serde(default)]
    affected: Vec<OsvAffected>,
}

#[derive(Deserialize)]
struct OsvAffected {
    package: OsvPackage,
    #[serde(default)]
    ranges: Vec<OsvRange>,
    #[serde(default)]
    versions: Vec<String>,
}

#[derive(Deserialize)]
struct OsvPackage {
    ecosystem: String,
    name: String,
}

#[derive(Deserialize)]
struct OsvRange {
    #[serde(rename = "type", default)]
    range_type: String,
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Deserialize, Default)]
struct OsvEvent {
    #[serde(default)]
    introduced: Option<String>,
    #[serde(default)]
    fixed: Option<String>,
    #[serde(default)]
    last_affected: Option<String>,
}

// ---------------------------------------------------------------------------
// OsvSource
// ---------------------------------------------------------------------------

/// One affected-package clause, indexed by `(family, name)`, carrying just what
/// the matcher needs.
struct IndexedAffected {
    id: String,
    family: Family,
    ranges: Vec<OsvRange>,
    versions: Vec<String>,
}

/// A range-aware CVE source built from OSV advisories. Deterministic and
/// network-free: it only matches against the records handed to it.
#[derive(Default)]
pub struct OsvSource {
    index: HashMap<(Family, String), Vec<IndexedAffected>>,
}

impl OsvSource {
    /// Build a source from a JSON array of OSV records.
    pub fn from_json(json: &str) -> anyhow::Result<Self> {
        let records: Vec<OsvRecord> = serde_json::from_str(json)?;
        Ok(Self::from_records(records))
    }

    fn from_records(records: Vec<OsvRecord>) -> Self {
        let mut index: HashMap<(Family, String), Vec<IndexedAffected>> = HashMap::new();
        for record in records {
            for affected in record.affected {
                let family = family_of(&affected.package.ecosystem);
                index
                    .entry((family, affected.package.name.clone()))
                    .or_default()
                    .push(IndexedAffected {
                        id: record.id.clone(),
                        family,
                        ranges: affected.ranges,
                        versions: affected.versions,
                    });
            }
        }
        Self { index }
    }
}

impl CveSource for OsvSource {
    fn hits_for(
        &self,
        source: &str,
        os: &str,
        os_version: &str,
        name: &str,
        version: &str,
    ) -> Vec<CveHit> {
        let mut out: Vec<CveHit> = Vec::new();
        let mut seen: Vec<String> = Vec::new();
        for &family in source_families(source, os, os_version) {
            let Some(entries) = self.index.get(&(family, name.to_string())) else {
                continue;
            };
            for entry in entries {
                if seen.contains(&entry.id) {
                    continue;
                }
                if affected_matches(entry, version) {
                    seen.push(entry.id.clone());
                    out.push(CveHit {
                        name: name.to_string(),
                        version: version.to_string(),
                        vuln_id: entry.id.clone(),
                        remediation_key: remediation_key(name, entry),
                    });
                }
            }
        }
        out
    }
}

/// True iff `version` is in an explicit `versions[]` list or falls inside any
/// affected range of `entry`.
fn affected_matches(entry: &IndexedAffected, version: &str) -> bool {
    // Explicit affected versions are exact strings.
    if entry.versions.iter().any(|v| v == version) {
        return true;
    }
    for range in &entry.ranges {
        let cmp = match range.range_type.as_str() {
            "SEMVER" => Comparator::Semver,
            "ECOSYSTEM" => ecosystem_comparator(entry.family),
            // GIT (or unknown) ranges are not version-comparable here; skip.
            _ => continue,
        };
        if range_affects(version, &range.events, cmp) {
            return true;
        }
    }
    false
}

/// Evaluate one OSV range's `introduced`/`fixed`/`last_affected` events for
/// `version`. OSV requires events in ascending version order; we walk them,
/// flipping an `affected` flag. A `fixed` bound is EXCLUSIVE (`< fixed`), a
/// `last_affected` bound is INCLUSIVE, `introduced: "0"` means "from the
/// beginning", and a missing `fixed` means "all later versions". Any comparison
/// the comparator cannot make fails closed (never a false positive).
fn range_affects(version: &str, events: &[OsvEvent], cmp: Comparator) -> bool {
    let mut affected = false;
    for event in events {
        if let Some(introduced) = &event.introduced {
            if introduced == "0" {
                affected = true;
            } else if let Some(ord) = compare(cmp, version, introduced) {
                // version >= introduced turns the range on; a future introduced
                // (version < introduced) does nothing.
                if ord != Ordering::Less {
                    affected = true;
                }
            }
        }
        if let Some(fixed) = &event.fixed {
            match compare(cmp, version, fixed) {
                // version >= fixed -> patched, no longer affected.
                Some(ord) if ord != Ordering::Less => affected = false,
                Some(_) => {}
                // Cannot compare against the fix -> fail closed.
                None => affected = false,
            }
        }
        if let Some(last) = &event.last_affected {
            match compare(cmp, version, last) {
                // version > last_affected -> no longer affected.
                Some(Ordering::Greater) => affected = false,
                Some(_) => {}
                None => affected = false,
            }
        }
    }
    affected
}

/// Derive a stable remediation key: prefer `upgrade:{name}>={first fixed}`,
/// else `patch:{name}:{id}` when the advisory names no fixed version.
fn remediation_key(name: &str, entry: &IndexedAffected) -> String {
    for range in &entry.ranges {
        for event in &range.events {
            if let Some(fixed) = &event.fixed {
                return format!("upgrade:{name}>={fixed}");
            }
        }
    }
    format!("patch:{name}:{}", entry.id)
}

// ---------------------------------------------------------------------------
// CompositeCveSource
// ---------------------------------------------------------------------------

/// Query several [`CveSource`]s as one. `hits_for` concatenates every sub-source's
/// hits and dedups by `vuln_id`, so `OsvSource` (dpkg/rpm) and `NvdSource`
/// (Windows registry) compose into the single `&dyn CveSource` the pipeline
/// expects — with **no change to `run_all_ingest`**. Each source answers for a
/// disjoint set of component sources (OSV returns nothing for `registry`, NVD
/// returns nothing for `dpkg`/`rpm`), so there is normally nothing to dedup; the
/// dedup is a safety net against a CVE two feeds both claim, so it is never
/// double-counted.
#[derive(Default)]
pub struct CompositeCveSource {
    sources: Vec<Box<dyn CveSource>>,
}

impl CompositeCveSource {
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
        }
    }

    /// Add a sub-source (builder style).
    pub fn with(mut self, source: Box<dyn CveSource>) -> Self {
        self.sources.push(source);
        self
    }

    /// Add a sub-source in place.
    pub fn push(&mut self, source: Box<dyn CveSource>) {
        self.sources.push(source);
    }

    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    pub fn len(&self) -> usize {
        self.sources.len()
    }
}

impl CveSource for CompositeCveSource {
    fn hits_for(
        &self,
        source: &str,
        os: &str,
        os_version: &str,
        name: &str,
        version: &str,
    ) -> Vec<CveHit> {
        let mut out: Vec<CveHit> = Vec::new();
        for s in &self.sources {
            for hit in s.hits_for(source, os, os_version, name, version) {
                if !out.iter().any(|h| h.vuln_id == hit.vuln_id) {
                    out.push(hit);
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nvd_source::NvdSource;

    // A realistic OSV advisory: openssl on Debian, affected from the beginning
    // up to (but not including) the 3.0.7-1 fix.
    const OSV_OPENSSL_DEBIAN: &str = r#"[
      {
        "id": "CVE-2022-3602",
        "affected": [
          {
            "package": { "ecosystem": "Debian:12", "name": "openssl" },
            "ranges": [
              { "type": "ECOSYSTEM", "events": [ {"introduced": "0"}, {"fixed": "3.0.7-1"} ] }
            ]
          }
        ]
      }
    ]"#;

    fn openssl_source() -> OsvSource {
        OsvSource::from_json(OSV_OPENSSL_DEBIAN).unwrap()
    }

    #[test]
    fn dpkg_below_fixed_is_a_hit() {
        let hits =
            openssl_source().hits_for("dpkg", "Debian", "12", "openssl", "3.0.2-0ubuntu1.15");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].vuln_id, "CVE-2022-3602");
        assert_eq!(hits[0].remediation_key, "upgrade:openssl>=3.0.7-1");
    }

    #[test]
    fn dpkg_exactly_fixed_is_not_a_hit() {
        // fixed is exclusive.
        assert!(openssl_source()
            .hits_for("dpkg", "Debian", "12", "openssl", "3.0.7-1")
            .is_empty());
    }

    #[test]
    fn dpkg_above_fixed_is_not_a_hit() {
        assert!(openssl_source()
            .hits_for("dpkg", "Debian", "12", "openssl", "3.0.14")
            .is_empty());
    }

    #[test]
    fn dpkg_below_introduced_is_not_a_hit() {
        // introduced at 3.0.0; anything earlier is not yet affected.
        let src = OsvSource::from_json(
            r#"[
              { "id": "CVE-TEST", "affected": [
                { "package": {"ecosystem":"Ubuntu:22.04:LTS","name":"foo"},
                  "ranges": [ {"type":"ECOSYSTEM","events":[{"introduced":"3.0.0"},{"fixed":"3.0.14"}]} ] }
              ] }
            ]"#,
        )
        .unwrap();
        // Fixture ecosystem is Ubuntu:22.04:LTS, so search as an Ubuntu host.
        assert!(
            src.hits_for("dpkg", "Ubuntu", "22.04", "foo", "2.9.9")
                .is_empty(),
            "below introduced"
        );
        assert_eq!(
            src.hits_for("dpkg", "Ubuntu", "22.04", "foo", "3.0.2")
                .len(),
            1,
            "inside range"
        );
        assert!(
            src.hits_for("dpkg", "Ubuntu", "22.04", "foo", "3.0.14")
                .is_empty(),
            "at fixed"
        );
    }

    #[test]
    fn explicit_versions_list_matches() {
        let src = OsvSource::from_json(
            r#"[
              { "id": "CVE-LIST", "affected": [
                { "package": {"ecosystem":"Debian:11","name":"bar"},
                  "versions": ["1.2.3-1", "1.2.4-1"] }
              ] }
            ]"#,
        )
        .unwrap();
        assert_eq!(
            src.hits_for("dpkg", "Debian", "11", "bar", "1.2.3-1").len(),
            1
        );
        assert!(src
            .hits_for("dpkg", "Debian", "11", "bar", "1.2.5-1")
            .is_empty());
        // No fixed version named -> patch-style remediation key.
        assert_eq!(
            src.hits_for("dpkg", "Debian", "11", "bar", "1.2.3-1")[0].remediation_key,
            "patch:bar:CVE-LIST"
        );
    }

    #[test]
    fn missing_fixed_means_all_later_versions() {
        let src = OsvSource::from_json(
            r#"[
              { "id": "CVE-OPEN", "affected": [
                { "package": {"ecosystem":"Debian:12","name":"baz"},
                  "ranges": [ {"type":"ECOSYSTEM","events":[{"introduced":"2.0"}]} ] }
              ] }
            ]"#,
        )
        .unwrap();
        assert_eq!(src.hits_for("dpkg", "Debian", "12", "baz", "2.0").len(), 1);
        assert_eq!(src.hits_for("dpkg", "Debian", "12", "baz", "99.0").len(), 1);
        assert!(src
            .hits_for("dpkg", "Debian", "12", "baz", "1.9")
            .is_empty());
        assert_eq!(
            src.hits_for("dpkg", "Debian", "12", "baz", "2.0")[0].remediation_key,
            "patch:baz:CVE-OPEN"
        );
    }

    #[test]
    fn registry_source_matches_nothing() {
        // Windows/registry has no clean OSV ecosystem: return nothing (NVD later).
        let src = OsvSource::from_json(
            r#"[
              { "id": "CVE-WIN", "affected": [
                { "package": {"ecosystem":"Debian:12","name":"openssl"},
                  "ranges": [ {"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"9.9"}]} ] }
              ] }
            ]"#,
        )
        .unwrap();
        assert!(src
            .hits_for("registry", "Windows", "11", "openssl", "3.0.2")
            .is_empty());
    }

    #[test]
    fn ecosystem_mismatch_does_not_match() {
        // A dpkg component must not match an npm (SEMVER) advisory of the same name.
        let src = OsvSource::from_json(
            r#"[
              { "id": "GHSA-xxxx", "affected": [
                { "package": {"ecosystem":"npm","name":"openssl"},
                  "ranges": [ {"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"9.9.9"}]} ] }
              ] }
            ]"#,
        )
        .unwrap();
        assert!(src
            .hits_for("dpkg", "Debian", "12", "openssl", "3.0.2")
            .is_empty());
    }

    #[test]
    fn unknown_component_matches_nothing() {
        assert!(openssl_source()
            .hits_for("dpkg", "Debian", "12", "not-installed", "1.0")
            .is_empty());
    }

    #[test]
    fn semver_range_matches_for_a_semver_ecosystem() {
        // Sanity that the SEMVER comparator path works when the source names it.
        // (No OS source maps to npm today; this exercises the range logic via a
        // direct family match by constructing a Debian record with a SEMVER range.)
        let src = OsvSource::from_json(
            r#"[
              { "id": "CVE-SEMVER", "affected": [
                { "package": {"ecosystem":"Debian:12","name":"lib"},
                  "ranges": [ {"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"1.2.0"}]} ] }
              ] }
            ]"#,
        )
        .unwrap();
        assert_eq!(
            src.hits_for("dpkg", "Debian", "12", "lib", "1.1.5").len(),
            1
        );
        assert!(src
            .hits_for("dpkg", "Debian", "12", "lib", "1.2.0")
            .is_empty());
        assert!(src
            .hits_for("dpkg", "Debian", "12", "lib", "0.9.0")
            .is_empty());
    }

    #[test]
    fn rpm_source_uses_rpm_comparator() {
        let src = OsvSource::from_json(
            r#"[
              { "id": "CVE-RPM", "affected": [
                { "package": {"ecosystem":"Red Hat:8","name":"httpd"},
                  "ranges": [ {"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.4.37-30.el8"}]} ] }
              ] }
            ]"#,
        )
        .unwrap();
        assert_eq!(
            src.hits_for("rpm", "Red Hat", "8", "httpd", "2.4.37-10.el8")
                .len(),
            1
        );
        assert!(src
            .hits_for("rpm", "Red Hat", "8", "httpd", "2.4.37-30.el8")
            .is_empty());
        // A dpkg component must not pick up an rpm advisory.
        assert!(src
            .hits_for("dpkg", "Debian", "12", "httpd", "2.4.37-10.el8")
            .is_empty());
    }

    // Two advisories for the SAME dpkg package on DIFFERENT distros, with
    // DIFFERENT fixed versions. This is the VD-4a cross-distro false-positive
    // scenario: under the old both-families behavior a host would be matched
    // against both, so one distro's advisory could flag a host already patched
    // per its own distro. "foo": Debian fixed 1.0-1, Ubuntu fixed 1.0-2.
    // "bar" is the mirror image: Debian fixed 2.0-2, Ubuntu fixed 2.0-1.
    const OSV_CROSS_DISTRO: &str = r#"[
      { "id": "DEB-FOO", "affected": [
        { "package": {"ecosystem":"Debian:12","name":"foo"},
          "ranges": [ {"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0-1"}]} ] } ] },
      { "id": "UBU-FOO", "affected": [
        { "package": {"ecosystem":"Ubuntu:22.04:LTS","name":"foo"},
          "ranges": [ {"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0-2"}]} ] } ] },
      { "id": "DEB-BAR", "affected": [
        { "package": {"ecosystem":"Debian:12","name":"bar"},
          "ranges": [ {"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0-2"}]} ] } ] },
      { "id": "UBU-BAR", "affected": [
        { "package": {"ecosystem":"Ubuntu:22.04:LTS","name":"bar"},
          "ranges": [ {"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0-1"}]} ] } ] }
    ]"#;

    fn cross_distro_source() -> OsvSource {
        OsvSource::from_json(OSV_CROSS_DISTRO).unwrap()
    }

    #[test]
    fn debian_host_ignores_ubuntu_only_advisory() {
        let src = cross_distro_source();
        // Debian host at 1.0-1: patched per Debian (fixed 1.0-1 is exclusive).
        // The Ubuntu advisory (fixed 1.0-2) WOULD have matched 1.0-1 under the
        // old both-families behavior — the cross-distro false positive. It must
        // not now: a Debian host searches only Debian advisories.
        assert!(
            src.hits_for("dpkg", "Debian", "12", "foo", "1.0-1")
                .is_empty(),
            "Debian host patched per Debian must not be flagged by the Ubuntu advisory"
        );
    }

    #[test]
    fn ubuntu_host_still_flagged_by_ubuntu_advisory() {
        let src = cross_distro_source();
        // Ubuntu host at 1.0-1: Ubuntu fixed is 1.0-2, so 1.0-1 is still vulnerable.
        let hits = src.hits_for("dpkg", "Ubuntu", "22.04", "foo", "1.0-1");
        assert_eq!(
            hits.len(),
            1,
            "Ubuntu host still vulnerable per its own advisory"
        );
        assert_eq!(hits[0].vuln_id, "UBU-FOO");
    }

    #[test]
    fn reverse_pairing_debian_vulnerable_ubuntu_patched() {
        let src = cross_distro_source();
        // "bar" at 2.0-1: Debian fixed is 2.0-2 (still vulnerable), Ubuntu fixed
        // is 2.0-1 (patched). Each host must see only its own distro's verdict.
        let deb = src.hits_for("dpkg", "Debian", "12", "bar", "2.0-1");
        assert_eq!(
            deb.len(),
            1,
            "Debian host at 2.0-1 is vulnerable per Debian"
        );
        assert_eq!(deb[0].vuln_id, "DEB-BAR");
        assert!(
            src.hits_for("dpkg", "Ubuntu", "22.04", "bar", "2.0-1")
                .is_empty(),
            "Ubuntu host at 2.0-1 is patched per Ubuntu"
        );
    }

    #[test]
    fn os_string_match_is_case_insensitive_and_substring() {
        let src = cross_distro_source();
        // Real device.os strings ("Ubuntu 22.04.3 LTS") are matched by substring,
        // case-insensitively.
        let hits = src.hits_for("dpkg", "Ubuntu 22.04.3 LTS", "22.04", "foo", "1.0-1");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].vuln_id, "UBU-FOO");
        assert!(src
            .hits_for("dpkg", "debian gnu/linux 12", "12", "foo", "1.0-1")
            .is_empty());
    }

    #[test]
    fn unknown_os_falls_back_to_both_families() {
        let src = cross_distro_source();
        // Empty/unknown OS: documented fallback to BOTH families, so a hit from
        // either distro is reported (no worse than pre-VD-4a). At foo=1.0-1 the
        // Debian advisory is patched but the Ubuntu one still matches.
        let hits = src.hits_for("dpkg", "", "", "foo", "1.0-1");
        assert_eq!(hits.len(), 1, "unknown OS searches both families");
        assert_eq!(hits[0].vuln_id, "UBU-FOO");
    }

    // --- CompositeCveSource: OSV (dpkg/rpm) + NVD (registry) compose cleanly ---

    fn composite_osv_and_nvd() -> CompositeCveSource {
        let osv = OsvSource::from_json(
            r#"[ { "id": "CVE-DEB", "affected": [
              { "package": {"ecosystem":"Debian:12","name":"openssl"},
                "ranges": [ {"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.7-1"}]} ] } ] } ]"#,
        )
        .unwrap();
        let nvd = NvdSource::from_json(
            r#"[ { "id": "CVE-WIN", "affected_windows": [
              { "product": "putty", "aliases": ["putty"], "ranges": [ {"fixed":"0.81"} ] } ] } ]"#,
        )
        .unwrap();
        CompositeCveSource::new()
            .with(Box::new(osv))
            .with(Box::new(nvd))
    }

    #[test]
    fn composite_routes_dpkg_to_osv_and_registry_to_nvd() {
        let c = composite_osv_and_nvd();
        assert_eq!(c.len(), 2);
        // dpkg component resolves through OSV only.
        let deb = c.hits_for("dpkg", "Debian", "12", "openssl", "3.0.2-1");
        assert_eq!(deb.len(), 1);
        assert_eq!(deb[0].vuln_id, "CVE-DEB");
        // registry component resolves through NVD only.
        let win = c.hits_for("registry", "Windows", "11", "PuTTY 0.80", "0.80");
        assert_eq!(win.len(), 1);
        assert_eq!(win[0].vuln_id, "CVE-WIN");
    }

    #[test]
    fn composite_no_cross_source_leak() {
        let c = composite_osv_and_nvd();
        // A dpkg component named "putty" must NOT pick up the NVD (registry) advisory.
        assert!(c
            .hits_for("dpkg", "Debian", "12", "putty", "0.80")
            .is_empty());
        // A registry component named "openssl" must NOT pick up the OSV (dpkg) advisory.
        assert!(c
            .hits_for("registry", "Windows", "11", "openssl", "3.0.2-1")
            .is_empty());
    }

    #[test]
    fn composite_dedups_a_cve_claimed_by_two_sources() {
        // Two sources both claim the same vuln_id for the same registry component;
        // the composite reports it once (never double-counted).
        let mk = || {
            NvdSource::from_json(
                r#"[ { "id": "CVE-DUP", "affected_windows": [
                  { "product": "putty", "aliases": ["putty"], "ranges": [ {"fixed":"0.81"} ] } ] } ]"#,
            )
            .unwrap()
        };
        let c = CompositeCveSource::new()
            .with(Box::new(mk()))
            .with(Box::new(mk()));
        let hits = c.hits_for("registry", "Windows", "11", "PuTTY 0.80", "0.80");
        assert_eq!(
            hits.len(),
            1,
            "same vuln_id from two sources -> reported once"
        );
    }

    #[test]
    fn empty_composite_matches_nothing() {
        let c = CompositeCveSource::new();
        assert!(c.is_empty());
        assert!(c
            .hits_for("dpkg", "Debian", "12", "openssl", "3.0.2-1")
            .is_empty());
    }
}
