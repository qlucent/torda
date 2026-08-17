//! Version comparators for range-aware CVE matching.
//!
//! Three schemes, picked by OSV range type / ecosystem:
//! - [`dpkg_compare`]  — the reference dpkg `--compare-versions` algorithm
//!   (Debian/Ubuntu `ECOSYSTEM` ranges). This is the subtle, correctness-critical
//!   one; it is a faithful port of dpkg's `verrevcmp`.
//! - [`rpm_compare`]   — the reference rpm `rpmvercmp` algorithm (rpm-distro
//!   `ECOSYSTEM` ranges).
//! - [`semver_compare`] — semantic-version comparison (`SEMVER` ranges). Returns
//!   `None` when a side does not parse, so the matcher can fail closed.
//!
//! dpkg/rpm comparisons are TOTAL over any ASCII string (every string is a valid
//! package version), so they return `Ordering` directly and never panic.

use std::cmp::Ordering;

// ---------------------------------------------------------------------------
// dpkg  (reference `dpkg --compare-versions`)
// ---------------------------------------------------------------------------

/// Weight of a single non-digit character in dpkg's ordering (`verrevcmp`'s
/// `order`): `~` sorts before *everything* (even end-of-string / the empty
/// string), then end-of-string, then digits (weight 0), then letters (by ASCII),
/// then all other punctuation (ASCII + 256, so after letters).
fn dpkg_order(c: u8) -> i32 {
    if c.is_ascii_digit() {
        0
    } else if c.is_ascii_alphabetic() {
        c as i32
    } else if c == b'~' {
        -1
    } else if c != 0 {
        c as i32 + 256
    } else {
        0
    }
}

/// Compare one dpkg upstream-or-revision fragment, exactly like dpkg's
/// `verrevcmp`: alternating runs of non-digits (compared per-character via
/// [`dpkg_order`]) and digits (compared numerically, ignoring leading zeros).
fn dpkg_verrevcmp(a: &[u8], b: &[u8]) -> Ordering {
    let mut i = 0usize;
    let mut j = 0usize;
    while i < a.len() || j < b.len() {
        // Non-digit run: advance while either side is on a present non-digit.
        loop {
            let a_nd = i < a.len() && !a[i].is_ascii_digit();
            let b_nd = j < b.len() && !b[j].is_ascii_digit();
            if !(a_nd || b_nd) {
                break;
            }
            let ac = dpkg_order(if i < a.len() { a[i] } else { 0 });
            let bc = dpkg_order(if j < b.len() { b[j] } else { 0 });
            if ac != bc {
                return ac.cmp(&bc);
            }
            i += 1;
            j += 1;
        }
        // Digit run: leading zeros are insignificant.
        while i < a.len() && a[i] == b'0' {
            i += 1;
        }
        while j < b.len() && b[j] == b'0' {
            j += 1;
        }
        let mut first_diff = 0i32;
        while i < a.len() && a[i].is_ascii_digit() && j < b.len() && b[j].is_ascii_digit() {
            if first_diff == 0 {
                first_diff = a[i] as i32 - b[j] as i32;
            }
            i += 1;
            j += 1;
        }
        // A longer digit run is the larger number.
        if i < a.len() && a[i].is_ascii_digit() {
            return Ordering::Greater;
        }
        if j < b.len() && b[j].is_ascii_digit() {
            return Ordering::Less;
        }
        if first_diff != 0 {
            return first_diff.cmp(&0);
        }
    }
    Ordering::Equal
}

/// Split a dpkg version into `(epoch, upstream, revision)`.
/// `[epoch:]upstream[-revision]`: epoch is the numeric run before the first `:`
/// (absent => 0); revision is after the LAST `-` (absent => empty string, which
/// sorts before any present revision).
fn dpkg_split(v: &str) -> (u64, &str, &str) {
    let (epoch, rest) = match v.find(':') {
        Some(i) if i > 0 && v[..i].bytes().all(|c| c.is_ascii_digit()) => {
            (v[..i].parse::<u64>().unwrap_or(0), &v[i + 1..])
        }
        _ => (0, v),
    };
    let (upstream, revision) = match rest.rfind('-') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, ""),
    };
    (epoch, upstream, revision)
}

/// Reference dpkg version comparison (`dpkg --compare-versions a op b`):
/// compare epoch numerically, then upstream, then revision via [`dpkg_verrevcmp`].
pub fn dpkg_compare(a: &str, b: &str) -> Ordering {
    let (ea, ua, ra) = dpkg_split(a);
    let (eb, ub, rb) = dpkg_split(b);
    ea.cmp(&eb)
        .then_with(|| dpkg_verrevcmp(ua.as_bytes(), ub.as_bytes()))
        .then_with(|| dpkg_verrevcmp(ra.as_bytes(), rb.as_bytes()))
}

// ---------------------------------------------------------------------------
// rpm  (reference `rpmvercmp`)
// ---------------------------------------------------------------------------

fn strip_leading_zeros(s: &[u8]) -> &[u8] {
    let mut k = 0;
    while k < s.len() && s[k] == b'0' {
        k += 1;
    }
    &s[k..]
}

/// Reference rpm segment comparison (`rpmvercmp`): runs of alphanumerics
/// separated by any other character; `~` sorts before everything and `^` after;
/// numeric segments beat alpha segments and are compared as numbers.
fn rpmvercmp(a: &[u8], b: &[u8]) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let mut i = 0usize;
    let mut j = 0usize;
    loop {
        // Skip separators (anything that is not alphanumeric, `~`, or `^`).
        while i < a.len() && !a[i].is_ascii_alphanumeric() && a[i] != b'~' && a[i] != b'^' {
            i += 1;
        }
        while j < b.len() && !b[j].is_ascii_alphanumeric() && b[j] != b'~' && b[j] != b'^' {
            j += 1;
        }

        // Tilde: sorts before everything, including the empty string.
        let a_tilde = i < a.len() && a[i] == b'~';
        let b_tilde = j < b.len() && b[j] == b'~';
        if a_tilde || b_tilde {
            if !a_tilde {
                return Ordering::Greater;
            }
            if !b_tilde {
                return Ordering::Less;
            }
            i += 1;
            j += 1;
            continue;
        }

        // Caret: sorts after everything (a post-release marker).
        let a_caret = i < a.len() && a[i] == b'^';
        let b_caret = j < b.len() && b[j] == b'^';
        if a_caret || b_caret {
            if i >= a.len() {
                return Ordering::Less;
            }
            if j >= b.len() {
                return Ordering::Greater;
            }
            if !a_caret {
                return Ordering::Greater;
            }
            if !b_caret {
                return Ordering::Less;
            }
            i += 1;
            j += 1;
            continue;
        }

        if i >= a.len() || j >= b.len() {
            break;
        }

        let start_i = i;
        let start_j = j;
        let isnum = a[i].is_ascii_digit();
        if isnum {
            while i < a.len() && a[i].is_ascii_digit() {
                i += 1;
            }
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
        } else {
            while i < a.len() && a[i].is_ascii_alphabetic() {
                i += 1;
            }
            while j < b.len() && b[j].is_ascii_alphabetic() {
                j += 1;
            }
        }
        let seg_a = &a[start_i..i];
        let seg_b = &b[start_j..j];
        // `seg_a` is non-empty; if `seg_b` is empty the two segments are of
        // different type: a numeric segment beats an alpha one.
        if seg_b.is_empty() {
            return if isnum {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }
        let ord = if isnum {
            let sa = strip_leading_zeros(seg_a);
            let sb = strip_leading_zeros(seg_b);
            sa.len().cmp(&sb.len()).then_with(|| sa.cmp(sb))
        } else {
            seg_a.cmp(seg_b)
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    // One side ran out of segments; the side with a segment remaining is larger.
    match (i < a.len(), j < b.len()) {
        (false, false) => Ordering::Equal,
        (false, true) => Ordering::Less,
        (true, false) => Ordering::Greater,
        (true, true) => Ordering::Equal, // unreachable: loop only breaks when one ended
    }
}

fn rpm_split(v: &str) -> (u64, &str) {
    match v.find(':') {
        Some(i) if i > 0 && v[..i].bytes().all(|c| c.is_ascii_digit()) => {
            (v[..i].parse::<u64>().unwrap_or(0), &v[i + 1..])
        }
        _ => (0, v),
    }
}

/// Reference rpm version comparison: compare epoch numerically, then the
/// `version[-release]` remainder via [`rpmvercmp`] (with `-` treated as an
/// ordinary separator, so version and release compare as one segment stream).
pub fn rpm_compare(a: &str, b: &str) -> Ordering {
    let (ea, ra) = rpm_split(a);
    let (eb, rb) = rpm_split(b);
    ea.cmp(&eb)
        .then_with(|| rpmvercmp(ra.as_bytes(), rb.as_bytes()))
}

// ---------------------------------------------------------------------------
// semver  (SemVer 2.0 precedence)
// ---------------------------------------------------------------------------

#[derive(PartialEq, Eq)]
enum PreId {
    Num(u64),
    Text(String),
}

struct Semver {
    core: [u64; 3],
    pre: Vec<PreId>,
}

fn parse_semver(v: &str) -> Option<Semver> {
    let v = v.strip_prefix('v').unwrap_or(v);
    // Drop build metadata.
    let v = v.split('+').next().unwrap_or(v);
    let (core_str, pre_str) = match v.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (v, None),
    };
    let mut core = [0u64; 3];
    for (idx, part) in core_str.split('.').enumerate() {
        if idx >= 3 {
            return None;
        }
        core[idx] = part.parse::<u64>().ok()?;
    }
    let pre = match pre_str {
        None => Vec::new(),
        Some(p) => p
            .split('.')
            .map(|id| {
                if !id.is_empty() && id.bytes().all(|c| c.is_ascii_digit()) {
                    // Numeric identifiers must not have leading zeros; parse fails closed.
                    id.parse::<u64>().map(PreId::Num).ok()
                } else {
                    Some(PreId::Text(id.to_string()))
                }
            })
            .collect::<Option<Vec<_>>>()?,
    };
    Some(Semver { core, pre })
}

fn cmp_pre(a: &[PreId], b: &[PreId]) -> Ordering {
    // A version with a pre-release has LOWER precedence than one without.
    match (a.is_empty(), b.is_empty()) {
        (true, true) => return Ordering::Equal,
        (true, false) => return Ordering::Greater,
        (false, true) => return Ordering::Less,
        (false, false) => {}
    }
    for (x, y) in a.iter().zip(b.iter()) {
        let ord = match (x, y) {
            (PreId::Num(m), PreId::Num(n)) => m.cmp(n),
            (PreId::Text(m), PreId::Text(n)) => m.cmp(n),
            // Numeric identifiers always have lower precedence than alphanumeric.
            (PreId::Num(_), PreId::Text(_)) => Ordering::Less,
            (PreId::Text(_), PreId::Num(_)) => Ordering::Greater,
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    a.len().cmp(&b.len())
}

/// SemVer 2.0 precedence comparison. Returns `None` if either side is not a
/// parseable semantic version, so the matcher can fail closed rather than guess.
pub fn semver_compare(a: &str, b: &str) -> Option<Ordering> {
    let sa = parse_semver(a)?;
    let sb = parse_semver(b)?;
    Some(
        sa.core
            .cmp(&sb.core)
            .then_with(|| cmp_pre(&sa.pre, &sb.pre)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering::*;

    // --- dpkg reference cases (the subtle, correctness-critical algorithm) ---

    #[test]
    fn dpkg_numeric_ordering() {
        assert_eq!(dpkg_compare("1.0", "1.1"), Less);
        assert_eq!(dpkg_compare("1.1", "1.0"), Greater);
        assert_eq!(dpkg_compare("1.0", "1.0"), Equal);
    }

    #[test]
    fn dpkg_absent_revision_sorts_before_present() {
        // "2.0" (empty revision) < "2.0-1"
        assert_eq!(dpkg_compare("2.0", "2.0-1"), Less);
        assert_eq!(dpkg_compare("2.0-1", "2.0"), Greater);
    }

    #[test]
    fn dpkg_tilde_sorts_before_everything() {
        assert_eq!(dpkg_compare("1.0~rc1", "1.0"), Less);
        assert_eq!(dpkg_compare("1.0", "1.0~rc1"), Greater);
        assert_eq!(dpkg_compare("1.0~~", "1.0~"), Less);
        assert_eq!(dpkg_compare("1.0~beta", "1.0~rc"), Less); // b < r
    }

    #[test]
    fn dpkg_epoch_dominates() {
        assert_eq!(dpkg_compare("1:1.0", "2.0"), Greater);
        assert_eq!(dpkg_compare("2.0", "1:1.0"), Less);
        assert_eq!(dpkg_compare("1:1.0", "1:1.0"), Equal);
    }

    #[test]
    fn dpkg_ubuntu_style_upstream() {
        // The brief's tricky case: 3.0.2 upstream < 3.0.14 upstream regardless of
        // the ubuntu revision.
        assert_eq!(dpkg_compare("3.0.2-0ubuntu1.15", "3.0.14"), Less);
        assert_eq!(dpkg_compare("3.0.14", "3.0.2-0ubuntu1.15"), Greater);
        // Same upstream, revisions compared with the same algorithm.
        assert_eq!(dpkg_compare("3.0.2-0ubuntu1.15", "3.0.2-0ubuntu1.16"), Less);
    }

    #[test]
    fn dpkg_letters_before_punctuation() {
        // A letter (weight = ASCII) sorts before other punctuation (ASCII + 256).
        assert_eq!(dpkg_compare("1.0a", "1.0+"), Less);
    }

    #[test]
    fn dpkg_is_total_and_symmetric() {
        // Never panics on odd input; reversing the args reverses the ordering.
        let samples = ["", "0", "~", "1:2~3-4ubuntu5.6+", "abc-", "1.0.0"];
        for a in samples {
            for b in samples {
                assert_eq!(dpkg_compare(a, b), dpkg_compare(b, a).reverse());
            }
        }
    }

    // --- rpm reference cases ---

    #[test]
    fn rpm_basic_and_tilde_and_caret() {
        assert_eq!(rpm_compare("1.0", "1.1"), Less);
        assert_eq!(rpm_compare("1.0", "1.0.1"), Less);
        assert_eq!(rpm_compare("1.0~rc1", "1.0"), Less); // tilde before
        assert_eq!(rpm_compare("1.0", "1.0^git1"), Less); // caret after
        assert_eq!(rpm_compare("1.0-1", "1.0-2"), Less); // release compared
        assert_eq!(rpm_compare("1.0", "1.0"), Equal);
    }

    #[test]
    fn rpm_numeric_beats_alpha_and_epoch() {
        assert_eq!(rpm_compare("1.0", "1.a"), Greater); // number newer than letter
        assert_eq!(rpm_compare("1:1.0", "2.0"), Greater); // epoch dominates
        assert_eq!(rpm_compare("3.0.2-0.el8", "3.0.14-1.el8"), Less);
    }

    // --- semver cases ---

    #[test]
    fn semver_core_and_prerelease() {
        assert_eq!(semver_compare("1.2.3", "1.2.4"), Some(Less));
        assert_eq!(semver_compare("1.0.0", "2.0.0"), Some(Less));
        assert_eq!(semver_compare("1.0.0-alpha", "1.0.0"), Some(Less));
        assert_eq!(semver_compare("1.0.0-alpha.1", "1.0.0-alpha.2"), Some(Less));
        assert_eq!(semver_compare("1.0.0-alpha", "1.0.0-beta"), Some(Less));
        assert_eq!(semver_compare("1.2", "1.2.0"), Some(Equal));
    }

    #[test]
    fn semver_unparseable_fails_closed() {
        assert_eq!(semver_compare("not-a-version", "1.0.0"), None);
        assert_eq!(semver_compare("1.0.0", "1.2.x"), None); // non-numeric core
        assert_eq!(semver_compare("1.0.0.0", "1.0.0"), None); // too many core parts
    }
}
