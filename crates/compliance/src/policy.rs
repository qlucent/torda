//! Org policy: which frameworks to report and how to customize the control set.
//! A `ControlOverride` can disable a control or change its weight; `apply_overrides`
//! transforms the control list before evaluation. This is how an org tailors the
//! shipped controls to its own risk posture without touching check code. (Threshold
//! overrides — e.g. the max-days value — are out of scope; checks are fn pointers.)
use crate::control::Control;
use crate::framework::all_frameworks;

/// One org customization of a shipped control. `enabled: Some(false)` removes the
/// control; `weight: Some(w)` replaces its weight. `None` fields leave that aspect
/// as shipped. An override whose `control_id` matches no control is ignored.
#[derive(Clone, Debug, PartialEq)]
pub struct ControlOverride {
    pub control_id: String,
    pub enabled: Option<bool>,
    pub weight: Option<f32>,
}

/// An org's compliance policy: which frameworks to report findings against, and
/// how to customize the control set.
#[derive(Clone, Debug, PartialEq)]
pub struct Policy {
    pub frameworks: Vec<String>,
    pub overrides: Vec<ControlOverride>,
}

impl Policy {
    /// The shipped default: report against every framework, no control overrides.
    pub fn default_policy() -> Policy {
        Policy {
            frameworks: all_frameworks().into_iter().map(|p| p.framework).collect(),
            overrides: Vec::new(),
        }
    }
}

/// Applies the overrides to a control list: drops disabled controls and replaces
/// weights. Controls with no matching override pass through unchanged.
pub fn apply_overrides(controls: Vec<Control>, overrides: &[ControlOverride]) -> Vec<Control> {
    controls
        .into_iter()
        .filter_map(|mut c| {
            if let Some(o) = overrides.iter().find(|o| o.control_id == c.id) {
                if o.enabled == Some(false) {
                    return None;
                }
                if let Some(w) = o.weight {
                    c.weight = w;
                }
            }
            Some(c)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controls::builtin_controls;

    #[test]
    fn disable_drops_the_control() {
        let ov = vec![ControlOverride {
            control_id: "telnet-not-installed".into(),
            enabled: Some(false),
            weight: None,
        }];
        let out = apply_overrides(builtin_controls(), &ov);
        assert!(
            out.iter().all(|c| c.id != "telnet-not-installed"),
            "disabled control removed"
        );
        assert_eq!(out.len(), builtin_controls().len() - 1);
    }

    #[test]
    fn weight_override_changes_only_weight() {
        let ov = vec![ControlOverride {
            control_id: "telnet-not-installed".into(),
            enabled: None,
            weight: Some(0.95),
        }];
        let out = apply_overrides(builtin_controls(), &ov);
        let telnet = out.iter().find(|c| c.id == "telnet-not-installed").unwrap();
        assert_eq!(telnet.weight, 0.95);
        // Other controls are untouched.
        let orig_pw = builtin_controls()
            .into_iter()
            .find(|c| c.id == "password-max-days")
            .unwrap()
            .weight;
        let pw = out.iter().find(|c| c.id == "password-max-days").unwrap();
        assert_eq!(pw.weight, orig_pw);
    }

    #[test]
    fn unmatched_override_is_a_noop() {
        let ov = vec![ControlOverride {
            control_id: "no-such-control".into(),
            enabled: Some(false),
            weight: Some(0.1),
        }];
        let out = apply_overrides(builtin_controls(), &ov);
        let shape = |cs: &[Control]| {
            cs.iter()
                .map(|c| (c.id.clone(), c.weight))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            shape(&out),
            shape(&builtin_controls()),
            "unmatched override changes nothing (id+weight+order)"
        );
    }

    #[test]
    fn default_policy_reports_all_frameworks_no_overrides() {
        let p = Policy::default_policy();
        assert_eq!(p.frameworks.len(), 7);
        assert!(p.frameworks.contains(&"CIS".to_string()));
        assert!(p.overrides.is_empty());
    }
}
