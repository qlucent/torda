//! The built-in v0 control set — a few concrete CIS-style checks over snapshot
//! tables. Each `check` returns true when COMPLIANT. Parameterized / user-authored
//! controls are slice P2b; these are fixed Rust functions.
use crate::control::Control;

/// SSH: root login must be disabled (`PermitRootLogin no`). Compliant iff that
/// exact setting is present.
fn sshd_root_login_disabled(rows: &[serde_json::Value]) -> bool {
    rows.iter()
        .any(|r| r["key"] == "PermitRootLogin" && r["value"] == "no")
}

/// The `telnet` package must not be installed. Compliant iff no row is named telnet.
fn telnet_not_installed(rows: &[serde_json::Value]) -> bool {
    !rows.iter().any(|r| r["name"] == "telnet")
}

/// Reads a snapshot value as an integer whether it arrives as a JSON number
/// (`365`) or a JSON string (`"365"`). Returns None for any other shape.
fn value_as_i64(v: &serde_json::Value) -> Option<i64> {
    v.as_i64()
        .or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok()))
}

/// Password max age must be set and <= 365 days. Compliant iff `PASS_MAX_DAYS`
/// is present and parses to <= 365; absent or unparseable -> not compliant.
fn password_max_days_ok(rows: &[serde_json::Value]) -> bool {
    rows.iter()
        .find(|r| r["key"] == "PASS_MAX_DAYS")
        .and_then(|r| value_as_i64(&r["value"]))
        .map(|days| days <= 365)
        .unwrap_or(false)
}

/// The built-in v0 control set. Each entry is a fixed check + the metadata a
/// finding needs (subject/location/weight/remediation_key).
pub fn builtin_controls() -> Vec<Control> {
    vec![
        Control {
            id: "sshd-root-login-disabled".into(),
            title: "SSH root login disabled".into(),
            table: "sshd_config".into(),
            subject: "sshd_config".into(),
            location: "/etc/ssh/sshd_config".into(),
            weight: 0.8,
            remediation_key: "set:PermitRootLogin=no".into(),
            check: sshd_root_login_disabled,
        },
        Control {
            id: "telnet-not-installed".into(),
            title: "telnet package not installed".into(),
            table: "packages".into(),
            subject: "telnet".into(),
            location: "package-manager".into(),
            weight: 0.6,
            remediation_key: "remove:telnet".into(),
            check: telnet_not_installed,
        },
        Control {
            id: "password-max-days".into(),
            title: "Password max age <= 365 days".into(),
            table: "login_defs".into(),
            subject: "login.defs".into(),
            location: "/etc/login.defs".into(),
            weight: 0.5,
            remediation_key: "set:PASS_MAX_DAYS<=365".into(),
            check: password_max_days_ok,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find(id: &str) -> Control {
        builtin_controls().into_iter().find(|c| c.id == id).unwrap()
    }

    #[test]
    fn builtin_set_has_expected_controls() {
        let ids: Vec<String> = builtin_controls().into_iter().map(|c| c.id).collect();
        assert_eq!(
            ids,
            vec![
                "sshd-root-login-disabled",
                "telnet-not-installed",
                "password-max-days"
            ]
        );
        // Every control carries a non-empty remediation key and a weight in (0,1].
        for c in builtin_controls() {
            assert!(!c.remediation_key.is_empty());
            assert!(c.weight > 0.0 && c.weight <= 1.0);
        }
    }

    #[test]
    fn sshd_root_login_check() {
        let c = find("sshd-root-login-disabled");
        assert_eq!(c.table, "sshd_config");
        assert!(
            (c.check)(&[serde_json::json!({"key":"PermitRootLogin","value":"no"})]),
            "no -> compliant"
        );
        assert!(
            !(c.check)(&[serde_json::json!({"key":"PermitRootLogin","value":"yes"})]),
            "yes -> fail"
        );
        assert!(
            !(c.check)(&[serde_json::json!({"key":"Port","value":"22"})]),
            "setting absent -> fail"
        );
    }

    #[test]
    fn telnet_not_installed_check() {
        let c = find("telnet-not-installed");
        assert_eq!(c.table, "packages");
        assert!(
            (c.check)(&[serde_json::json!({"name":"openssl","version":"3.0.2"})]),
            "no telnet -> compliant"
        );
        assert!(
            !(c.check)(&[serde_json::json!({"name":"telnet","version":"0.17"})]),
            "telnet present -> fail"
        );
    }

    #[test]
    fn password_max_days_check() {
        let c = find("password-max-days");
        assert_eq!(c.table, "login_defs");
        assert!(
            (c.check)(&[serde_json::json!({"key":"PASS_MAX_DAYS","value":"365"})]),
            "365 <= 365 -> compliant"
        );
        assert!(
            !(c.check)(&[serde_json::json!({"key":"PASS_MAX_DAYS","value":"99999"})]),
            "too large -> fail"
        );
        assert!(
            !(c.check)(&[serde_json::json!({"key":"OTHER","value":"1"})]),
            "setting absent -> fail"
        );
        assert!(
            (c.check)(&[serde_json::json!({"key":"PASS_MAX_DAYS","value":365})]),
            "numeric 365 <= 365 -> compliant"
        );
        assert!(
            !(c.check)(&[serde_json::json!({"key":"PASS_MAX_DAYS","value":"abc"})]),
            "unparseable value -> fail"
        );
    }
}
