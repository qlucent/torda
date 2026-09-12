//! Findings data contract — the canonical, explainable, deduped finding shape
//! the server's findings engine produces. Pure
//! types + serde; NO scoring or decision logic lives here (that is slice 1.4).
//! A source's severity label is retained in `Provenance` for audit but is never
//! a field the score reads — the engine recomputes `Score.R` from canonical inputs.
use serde::{Deserialize, Serialize};

/// How a detection was made; drives confidence ranking (authenticated wins).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DetectionMethod {
    Authenticated,
    Unauthenticated,
}

/// Exploit maturity for a vuln. The numeric weight used in scoring is the
/// engine's concern (slice 1.4), not part of this contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExploitMaturity {
    None,
    Poc,
    Functional,
    Weaponized,
    InTheWild,
}

/// VEX reachability status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VexStatus {
    Affected,
    NotAffected,
    Unknown,
}

/// Business criticality of the asset (v0 tiers; the weight mapping is slice 1.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Criticality {
    CrownJewel,
    High,
    Normal,
    Low,
}

/// SSVC-style decision the engine assigns. Thresholds live in slice 1.4.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Decision {
    Act,
    Attend,
    Track,
    Defer,
}

/// Lifecycle state of a finding. Defaults to `Open`;
/// `Suppressed` = VEX not_affected; `Reopened` = a closed finding's detection
/// reappeared (regression).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FindingState {
    #[default]
    Open,
    Suppressed,
    Reopened,
    Closed,
    Accepted,
}

/// Stable identity for dedup/correlation: one finding per
/// (asset, vuln, component, location).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Identity {
    pub asset_id: String,
    pub vuln_id: String,
    pub component: String,
    pub location: String,
}

/// One source's evidence for a finding. `reported_severity` is retained for
/// audit but NEVER used to score — the engine recomputes the canonical score.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Provenance {
    pub source: String,
    pub method: DetectionMethod,
    pub reported_severity: Option<String>,
    pub confidence: f32,
}

/// Enrichment feed values used as canonical scoring inputs (NVD/EPSS/KEV/VEX).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Enrichment {
    pub cvss_vector: Option<String>,
    pub cvss_env: Option<f32>,
    pub epss: Option<f32>,
    pub epss_pct: Option<f32>,
    pub kev: bool,
    pub exploit_maturity: ExploitMaturity,
    pub vex: VexStatus,
    /// The feed snapshot version these values came from (e.g.
    /// `"2026-09-12T00:00:00Z"`), stamped by a feed-store-backed
    /// [`crate`]-external `EnrichmentSource` so every score cites which feed
    /// scored it. `None` when the enrichment came from an unversioned source or
    /// no feed at all. `#[serde(default)]` keeps findings persisted before this
    /// field existed loadable, and it is NEVER read by the score — it is
    /// explainability provenance, exactly like `Provenance.reported_severity`.
    #[serde(default)]
    pub feed_version: Option<String>,
}

/// Asset-context inputs to scoring.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AssetContext {
    pub internet_facing: bool,
    pub criticality: Criticality,
    pub compensating_controls: bool,
}

/// The recomputed canonical risk score with its explainable inputs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Score {
    #[serde(rename = "R")]
    pub r: u8,
    pub explain: ScoreExplain,
}

/// Per-factor contributions, persisted so every score is auditable.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScoreExplain {
    pub sev: f32,
    pub likelihood: f32,
    pub exposure: f32,
    pub crit: f32,
    pub reach: f32,
}

/// A canonical, deduped, scored, decision-bearing finding.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub finding_id: String,
    pub identity: Identity,
    pub provenance: Vec<Provenance>,
    pub enrichment: Enrichment,
    pub asset_ctx: AssetContext,
    pub score: Score,
    pub decision: Decision,
    pub sla_hours: u32,
    pub remediation_key: String,
    #[serde(default)]
    pub status: FindingState,
    /// Lifecycle timestamps (epoch millis), stamped by the engine's `reconcile`
    /// from the batch's event time — deterministic, never a wall clock.
    /// `first_seen` = when the finding first opened (preserved across recurrence
    /// and reopen); `last_seen` = the most recent batch it was observed in;
    /// `closed_at` = when it was resolved (set where status becomes Closed; cleared
    /// on reopen). All optional + `#[serde(default)]` for backward compatibility
    /// with findings persisted before these existed.
    #[serde(default)]
    pub first_seen: Option<i64>,
    #[serde(default)]
    pub last_seen: Option<i64>,
    #[serde(default)]
    pub closed_at: Option<i64>,
}

/// Group-by-fix output: findings sharing a `remediation_key` collapse into one
/// item ops acts on. `risk` = max member `R`,
/// `closes` = member vuln_ids, `assets` = distinct member asset_ids.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationItem {
    pub remediation_key: String,
    pub risk: u8,
    pub closes: Vec<String>,
    pub assets: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json_str<T: Serialize>(v: &T) -> String {
        serde_json::to_string(v).unwrap()
    }

    #[test]
    fn enums_serialize_to_spec_strings() {
        assert_eq!(json_str(&Decision::Act), "\"ACT\"");
        assert_eq!(json_str(&Decision::Defer), "\"DEFER\"");
        assert_eq!(json_str(&ExploitMaturity::InTheWild), "\"in_the_wild\"");
        assert_eq!(json_str(&ExploitMaturity::Weaponized), "\"weaponized\"");
        assert_eq!(json_str(&ExploitMaturity::Poc), "\"poc\"");
        assert_eq!(json_str(&VexStatus::NotAffected), "\"not_affected\"");
        assert_eq!(json_str(&VexStatus::Affected), "\"affected\"");
        assert_eq!(
            json_str(&DetectionMethod::Authenticated),
            "\"authenticated\""
        );
        assert_eq!(
            json_str(&DetectionMethod::Unauthenticated),
            "\"unauthenticated\""
        );
        assert_eq!(json_str(&Criticality::CrownJewel), "\"crown_jewel\"");
    }

    #[test]
    fn provenance_keeps_null_reported_severity() {
        let p = Provenance {
            source: "torda".into(),
            method: DetectionMethod::Authenticated,
            reported_severity: None,
            confidence: 0.95,
        };
        let v: serde_json::Value = serde_json::from_str(&json_str(&p)).unwrap();
        assert!(
            v["reported_severity"].is_null(),
            "reported_severity must serialize as null"
        );
        assert_eq!(v["method"], "authenticated");
    }

    #[test]
    fn score_field_is_uppercase_r() {
        let s = Score {
            r: 91,
            explain: ScoreExplain {
                sev: 0.74,
                likelihood: 0.83,
                exposure: 1.4,
                crit: 1.5,
                reach: 1.0,
            },
        };
        let v: serde_json::Value = serde_json::from_str(&json_str(&s)).unwrap();
        assert_eq!(v["R"], 91);
        assert_eq!(v["explain"]["sev"], 0.74);
        assert!(v.get("r").is_none(), "must use \"R\", not \"r\"");
    }

    #[test]
    fn identity_round_trips() {
        let id = Identity {
            asset_id: "asset-1".into(),
            vuln_id: "CVE-2024-0001".into(),
            component: "openssl".into(),
            location: "/usr/lib".into(),
        };
        let back: Identity = serde_json::from_str(&json_str(&id)).unwrap();
        assert_eq!(back, id);
    }

    const CANONICAL_FINDING: &str = r#"{
      "finding_id": "11111111-1111-1111-1111-111111111111",
      "identity": {"asset_id":"asset-1","vuln_id":"CVE-2024-0001","component":"openssl","location":"/usr/lib"},
      "provenance": [
        {"source":"torda","method":"authenticated","reported_severity":null,"confidence":0.95},
        {"source":"nessus","method":"authenticated","reported_severity":"High","confidence":0.8},
        {"source":"network-scan","method":"unauthenticated","reported_severity":"Critical","confidence":0.5}
      ],
      "enrichment": {"cvss_vector":"CVSS:3.1/AV:N","cvss_env":7.4,"epss":0.83,"epss_pct":0.97,"kev":true,
                     "exploit_maturity":"weaponized","vex":"affected"},
      "asset_ctx": {"internet_facing":true,"criticality":"crown_jewel","compensating_controls":false},
      "score": {"R":91,"explain":{"sev":0.74,"likelihood":0.83,"exposure":1.4,"crit":1.5,"reach":1.0}},
      "decision": "ACT",
      "sla_hours": 48,
      "remediation_key": "upgrade:openssl>=3.0.14"
    }"#;

    #[test]
    fn deserializes_canonical_spec_finding() {
        let f: Finding = serde_json::from_str(CANONICAL_FINDING).unwrap();
        assert_eq!(f.finding_id, "11111111-1111-1111-1111-111111111111");
        assert_eq!(f.identity.component, "openssl");
        assert_eq!(f.provenance.len(), 3);
        assert_eq!(f.provenance[0].reported_severity, None);
        assert_eq!(f.provenance[1].reported_severity.as_deref(), Some("High"));
        assert_eq!(f.enrichment.exploit_maturity, ExploitMaturity::Weaponized);
        assert_eq!(f.enrichment.vex, VexStatus::Affected);
        assert!(f.enrichment.kev);
        assert_eq!(f.asset_ctx.criticality, Criticality::CrownJewel);
        assert_eq!(f.score.r, 91);
        assert_eq!(f.decision, Decision::Act);
        assert_eq!(f.sla_hours, 48);
        assert_eq!(f.remediation_key, "upgrade:openssl>=3.0.14");
    }

    #[test]
    fn finding_round_trips_through_json() {
        let f: Finding = serde_json::from_str(CANONICAL_FINDING).unwrap();
        let json = serde_json::to_string(&f).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(back, f);

        // Spot-check the re-serialized JSON uses the spec's exact keys/strings.
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["score"]["R"], 91);
        assert_eq!(v["decision"], "ACT");
        assert_eq!(v["asset_ctx"]["criticality"], "crown_jewel");
        assert_eq!(v["enrichment"]["exploit_maturity"], "weaponized");
    }

    #[test]
    fn remediation_item_round_trips() {
        let item = RemediationItem {
            remediation_key: "upgrade:openssl>=3.0.14".into(),
            risk: 91,
            closes: vec!["CVE-2024-0001".into(), "CVE-2024-0002".into()],
            assets: vec!["asset-1".into(), "asset-2".into()],
        };
        let back: RemediationItem =
            serde_json::from_str(&serde_json::to_string(&item).unwrap()).unwrap();
        assert_eq!(back, item);
        assert_eq!(back.closes.len(), 2);
    }

    #[test]
    fn identity_works_as_a_dedup_key() {
        use std::collections::HashSet;
        let a = Identity {
            asset_id: "asset-1".into(),
            vuln_id: "CVE-2024-0001".into(),
            component: "openssl".into(),
            location: "/usr/lib".into(),
        };
        let a_dup = a.clone();
        let b = Identity {
            asset_id: "asset-2".into(),
            vuln_id: "CVE-2024-0001".into(),
            component: "openssl".into(),
            location: "/usr/lib".into(),
        };
        let mut set = HashSet::new();
        set.insert(a);
        set.insert(a_dup); // same identity -> no new entry
        set.insert(b);
        assert_eq!(set.len(), 2, "equal identities collapse to one key");
    }

    #[test]
    fn finding_state_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&FindingState::Open).unwrap(),
            "\"open\""
        );
        assert_eq!(
            serde_json::to_string(&FindingState::Suppressed).unwrap(),
            "\"suppressed\""
        );
        assert_eq!(
            serde_json::to_string(&FindingState::Reopened).unwrap(),
            "\"reopened\""
        );
        assert_eq!(
            serde_json::to_string(&FindingState::Closed).unwrap(),
            "\"closed\""
        );
        assert_eq!(
            serde_json::to_string(&FindingState::Accepted).unwrap(),
            "\"accepted\""
        );
    }

    #[test]
    fn finding_state_defaults_to_open() {
        assert_eq!(FindingState::default(), FindingState::Open);
    }

    #[test]
    fn finding_without_status_deserializes_as_open() {
        // The canonical §3 JSON (no "status") must still parse — status defaults to Open.
        let f: Finding = serde_json::from_str(CANONICAL_FINDING).unwrap();
        assert_eq!(f.status, FindingState::Open);
    }

    #[test]
    fn finding_with_status_round_trips() {
        let mut f: Finding = serde_json::from_str(CANONICAL_FINDING).unwrap();
        f.status = FindingState::Suppressed;
        let back: Finding = serde_json::from_str(&serde_json::to_string(&f).unwrap()).unwrap();
        assert_eq!(back, f);
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&f).unwrap()).unwrap();
        assert_eq!(v["status"], "suppressed");
    }
}
