//! Package inventory providers for the snapshot service. The OS-specific reads
//! are isolated in thin, cfg-gated providers; the parsing of each format is a
//! pure function so it can be unit-tested with fixtures on any platform. This
//! lives inside the substrate — the only door to the OS — never in a module.

/// One installed software package. `source` records which inventory it came
/// from (`dpkg`, `rpm`, `registry`) so provenance is preserved downstream.
#[derive(Clone, Debug, PartialEq)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub source: String,
}

impl Package {
    pub fn new(name: impl Into<String>, version: impl Into<String>, source: &str) -> Package {
        Package {
            name: name.into(),
            version: version.into(),
            source: source.to_string(),
        }
    }
}

/// Produces the installed-package list. One implementation per OS lives below;
/// the snapshot service depends only on this trait.
pub trait PackageProvider: Send + Sync {
    fn packages(&self) -> Vec<Package>;
}

/// Parses the dpkg `status` file (`/var/lib/dpkg/status`). Returns only entries
/// whose `Status:` line marks them currently installed.
pub fn parse_dpkg_status(contents: &str) -> Vec<Package> {
    let mut out = Vec::new();
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut installed = false;

    for line in contents.lines() {
        if line.trim().is_empty() {
            push_dpkg(&mut out, &mut name, &mut version, &mut installed);
        } else if let Some(v) = line.strip_prefix("Package:") {
            name = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Version:") {
            version = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Status:") {
            installed = v.split_whitespace().last() == Some("installed");
        }
    }
    // Flush the trailing paragraph (the file may not end with a blank line).
    push_dpkg(&mut out, &mut name, &mut version, &mut installed);
    out
}

fn push_dpkg(
    out: &mut Vec<Package>,
    name: &mut Option<String>,
    version: &mut Option<String>,
    installed: &mut bool,
) {
    if *installed {
        if let Some(n) = name.take() {
            out.push(Package::new(n, version.take().unwrap_or_default(), "dpkg"));
        }
    }
    *name = None;
    *version = None;
    *installed = false;
}

/// Parses `rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n'` output: one package
/// per line, name and version separated by a tab.
pub fn parse_rpm_qa(output: &str) -> Vec<Package> {
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim_end();
            let (name, version) = line.split_once('\t')?;
            let name = name.trim();
            if name.is_empty() {
                return None;
            }
            Some(Package::new(name, version.trim(), "rpm"))
        })
        .collect()
}

/// Parses `reg query <UninstallKey> /s` output. Each subkey is a block beginning
/// with an `HKEY_...` line; within it, `DisplayName` and `DisplayVersion` value
/// lines give the package. Blocks without a `DisplayName` are skipped.
pub fn parse_reg_uninstall(output: &str) -> Vec<Package> {
    let mut out = Vec::new();
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("HKEY_") {
            push_reg(&mut out, &mut name, &mut version);
        } else if let Some(v) = reg_value(trimmed, "DisplayName") {
            name = Some(v);
        } else if let Some(v) = reg_value(trimmed, "DisplayVersion") {
            version = Some(v);
        }
    }
    push_reg(&mut out, &mut name, &mut version);
    out
}

fn push_reg(out: &mut Vec<Package>, name: &mut Option<String>, version: &mut Option<String>) {
    if let Some(n) = name.take() {
        out.push(Package::new(
            n,
            version.take().unwrap_or_default(),
            "registry",
        ));
    }
    *name = None;
    *version = None;
}

/// Extracts the data from a `reg` value line of the form
/// `<value-name>    REG_SZ    <data>`. Returns None if `line` is a different value.
fn reg_value(line: &str, value_name: &str) -> Option<String> {
    let rest = line.strip_prefix(value_name)?;
    // The value name must be a WHOLE token: the next char must be whitespace, so
    // `DisplayName` does not also match `DisplayName_Localized` (a MUI-resource
    // value whose data is an `@dll,-id` indirect string, not a real app name —
    // matching it as a prefix captured "REG_SZ @C:\...,-id" as a junk package).
    if !rest.starts_with(char::is_whitespace) {
        return None;
    }
    let rest = rest.trim_start();
    // `rest` now starts with the type token (e.g. "REG_SZ"); the data is what
    // follows the first whitespace gap after it.
    let data = rest.split_once(char::is_whitespace)?.1.trim();
    if data.is_empty() {
        None
    } else {
        Some(data.to_string())
    }
}

/// Fallback provider: no package inventory (used on unsupported OSes and as a
/// test fake).
pub struct EmptyProvider;
impl PackageProvider for EmptyProvider {
    fn packages(&self) -> Vec<Package> {
        Vec::new()
    }
}

#[cfg(target_os = "linux")]
pub struct DpkgProvider;
#[cfg(target_os = "linux")]
impl PackageProvider for DpkgProvider {
    fn packages(&self) -> Vec<Package> {
        std::fs::read_to_string("/var/lib/dpkg/status")
            .map(|c| parse_dpkg_status(&c))
            .unwrap_or_default()
    }
}

#[cfg(target_os = "linux")]
pub struct RpmProvider;
#[cfg(target_os = "linux")]
impl PackageProvider for RpmProvider {
    fn packages(&self) -> Vec<Package> {
        std::process::Command::new("rpm")
            .args(["-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| parse_rpm_qa(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or_default()
    }
}

#[cfg(target_os = "windows")]
pub struct RegistryProvider;
#[cfg(target_os = "windows")]
impl PackageProvider for RegistryProvider {
    fn packages(&self) -> Vec<Package> {
        const KEYS: [&str; 2] = [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ];
        let mut pkgs = Vec::new();
        for key in KEYS {
            if let Some(out) = reg_query_s(key) {
                pkgs.extend(parse_reg_uninstall(&out));
            }
        }
        pkgs
    }
}

#[cfg(target_os = "windows")]
fn reg_query_s(key: &str) -> Option<String> {
    let out = std::process::Command::new("reg")
        .args(["query", key, "/s"])
        .output()
        .ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        None
    }
}

/// Selects the right provider for the host OS.
#[cfg(target_os = "linux")]
pub fn default_package_provider() -> Box<dyn PackageProvider> {
    if std::path::Path::new("/var/lib/dpkg/status").exists() {
        Box::new(DpkgProvider)
    } else {
        Box::new(RpmProvider)
    }
}

#[cfg(target_os = "windows")]
pub fn default_package_provider() -> Box<dyn PackageProvider> {
    Box::new(RegistryProvider)
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn default_package_provider() -> Box<dyn PackageProvider> {
    Box::new(EmptyProvider)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpkg_parser_keeps_installed_skips_others() {
        // Two installed packages and one deinstalled (config-files) entry.
        let fixture = "\
Package: openssl
Status: install ok installed
Version: 3.0.2-0ubuntu1.15

Package: removed-pkg
Status: deinstall ok config-files
Version: 1.0.0

Package: glibc
Status: install ok installed
Version: 2.39-0ubuntu8.3
";
        let pkgs = parse_dpkg_status(fixture);
        assert_eq!(pkgs.len(), 2, "only installed packages kept");
        assert_eq!(
            pkgs[0],
            Package::new("openssl", "3.0.2-0ubuntu1.15", "dpkg")
        );
        assert_eq!(pkgs[1], Package::new("glibc", "2.39-0ubuntu8.3", "dpkg"));
    }

    #[test]
    fn dpkg_parser_flushes_trailing_paragraph_without_blank_line() {
        // File does not end with a blank line — the last entry must still flush.
        let fixture = "Package: curl\nStatus: install ok installed\nVersion: 8.5.0";
        let pkgs = parse_dpkg_status(fixture);
        assert_eq!(pkgs, vec![Package::new("curl", "8.5.0", "dpkg")]);
    }

    #[test]
    fn dpkg_parser_empty_input_is_empty() {
        assert!(parse_dpkg_status("").is_empty());
    }

    #[test]
    fn rpm_parser_splits_name_and_version() {
        let fixture = "openssl\t3.0.7-18.el9\nglibc\t2.34-60.el9\n";
        let pkgs = parse_rpm_qa(fixture);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0], Package::new("openssl", "3.0.7-18.el9", "rpm"));
        assert_eq!(pkgs[1], Package::new("glibc", "2.34-60.el9", "rpm"));
    }

    #[test]
    fn rpm_parser_skips_blank_and_malformed_lines() {
        let fixture = "\n\nvalid\t1.0\nno-tab-here\n";
        let pkgs = parse_rpm_qa(fixture);
        assert_eq!(pkgs, vec![Package::new("valid", "1.0", "rpm")]);
    }

    #[test]
    fn reg_parser_pairs_displayname_and_version_per_block() {
        // Two subkeys with name+version, one with only a name, one empty block.
        let fixture = "\
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{AAA}
    DisplayName    REG_SZ    7-Zip 23.01
    DisplayVersion    REG_SZ    23.01

HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{BBB}
    DisplayName    REG_SZ    Some Tool
    Publisher    REG_SZ    Acme

HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{CCC}
    SystemComponent    REG_DWORD    0x1
";
        let pkgs = parse_reg_uninstall(fixture);
        assert_eq!(pkgs.len(), 2, "blocks without a DisplayName are skipped");
        assert_eq!(pkgs[0], Package::new("7-Zip 23.01", "23.01", "registry"));
        assert_eq!(pkgs[1], Package::new("Some Tool", "", "registry"));
    }

    #[test]
    fn reg_parser_empty_input_is_empty() {
        assert!(parse_reg_uninstall("").is_empty());
    }

    #[test]
    fn reg_parser_ignores_displayname_localized_mui_resource() {
        // Real-hardware regression: some system components carry a
        // `DisplayName_Localized` value whose data is an `@dll,-id` MUI-resource
        // indirect string, NOT a real app name. A prefix match on "DisplayName"
        // captured "REG_SZ  @C:\...,-id" as a junk package. The whole-token match
        // must skip `DisplayName_Localized` and fall through to the real
        // `DisplayName` in the same block.
        let fixture = "\
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{RDP}
    DisplayName_Localized    REG_EXPAND_SZ    @C:\\Windows\\System32\\mstsc.exe,-4000

HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{APP}
    DisplayName_Localized    REG_SZ    @C:\\Program Files\\Foo\\res.dll,-20000
    DisplayName    REG_SZ    Foo App
    DisplayVersion    REG_SZ    1.2.3
";
        let pkgs = parse_reg_uninstall(fixture);
        // The {RDP} block has ONLY a localized name -> skipped (no real DisplayName).
        // The {APP} block has both -> the real DisplayName wins, localized ignored.
        assert_eq!(pkgs, vec![Package::new("Foo App", "1.2.3", "registry")]);
    }

    #[test]
    fn dpkg_parser_excludes_not_installed_and_half_installed() {
        let fixture = "\
Package: purged
Status: purge ok not-installed
Version: 1.0

Package: broken
Status: install ok half-installed
Version: 2.0

Package: good
Status: install ok installed
Version: 3.0
";
        let pkgs = parse_dpkg_status(fixture);
        assert_eq!(pkgs, vec![Package::new("good", "3.0", "dpkg")]);
    }

    #[test]
    fn empty_provider_returns_nothing() {
        assert!(EmptyProvider.packages().is_empty());
    }

    #[test]
    fn default_provider_packages_are_well_formed() {
        // Tolerant: the list MAY be empty on a minimal host (no dpkg/rpm), but
        // any package returned must have a non-empty name and a known source.
        let pkgs = default_package_provider().packages();
        for p in &pkgs {
            assert!(!p.name.is_empty(), "package with empty name: {p:?}");
            assert!(
                matches!(p.source.as_str(), "dpkg" | "rpm" | "registry"),
                "unexpected source: {p:?}"
            );
        }
    }
}
