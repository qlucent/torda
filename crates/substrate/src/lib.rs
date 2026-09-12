//! Shared collection substrate.
//! P0 ships stub implementations so the workspace builds and runs on any
//! host. P1 replaces `StubBus` with an aya/eBPF bus behind `linux-ebpf`,
//! and `StubSnapshot` with real OS table providers — without touching any
//! module, because they depend only on the core traits.
mod etw;
pub mod files;
pub mod packages;
// Linux eBPF backend: only compiled on a Linux `--features linux-ebpf` build,
// where build.rs has produced the embedded kernel object. Task 2 fills the
// EbpfBus loader; this task provides the compiled object it embeds.
#[cfg(all(target_os = "linux", feature = "linux-ebpf"))]
mod ebpf;

use files::{default_file_provider, FileHashProvider, FileState};
use packages::{default_package_provider, Package, PackageProvider};
use std::fs;
use std::sync::Arc;
use torda_core::{EventBus, EventKind, Rows, SnapshotProvider, SubstrateEvent};

// ---------------- Event bus (stub) ----------------

pub struct StubBus {
    tx: tokio::sync::broadcast::Sender<SubstrateEvent>,
}

impl StubBus {
    pub fn new() -> Arc<Self> {
        let (tx, _rx) = tokio::sync::broadcast::channel(1024);
        Arc::new(Self { tx })
    }
}

impl EventBus for StubBus {
    fn publish(&self, ev: SubstrateEvent) {
        let _ = self.tx.send(ev); // ignore "no subscribers"
    }
    fn subscribe(&self, _kinds: &[EventKind]) -> tokio::sync::broadcast::Receiver<SubstrateEvent> {
        // Real impl filters by kind; stub forwards all.
        self.tx.subscribe()
    }
}

// ---------------- Snapshot provider (stub) ----------------

pub struct StubSnapshot {
    hostname: String,
    os: String,
    os_version: String,
    packages: Vec<Package>,
    files: Vec<FileState>,
}

impl StubSnapshot {
    pub fn new() -> Arc<Self> {
        Self::with_providers(default_package_provider(), default_file_provider())
    }

    /// Builds the snapshot reading packages from `provider` and files from the
    /// default file provider. Kept for callers/tests that only inject packages.
    pub fn with_provider(provider: Box<dyn PackageProvider>) -> Arc<Self> {
        Self::with_providers(provider, default_file_provider())
    }

    /// Builds the snapshot from both providers. The provider seam keeps OS access
    /// testable and lets tests inject deterministic package and file lists.
    pub fn with_providers(
        packages: Box<dyn PackageProvider>,
        files: Box<dyn FileHashProvider>,
    ) -> Arc<Self> {
        let hostname = read_hostname();
        let (os, os_version) = read_os_release();
        Arc::new(Self {
            hostname,
            os,
            os_version,
            packages: packages.packages(),
            files: files.files(),
        })
    }
}

impl SnapshotProvider for StubSnapshot {
    fn query(&self, table: &str) -> anyhow::Result<Rows> {
        let rows = match table {
            "os_version" => vec![serde_json::json!({
                "name": self.os,
                "version": self.os_version,
            })],
            "packages" => self
                .packages
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "name": p.name,
                        "version": p.version,
                        "source": p.source,
                        "libraries": p.libraries,
                    })
                })
                .collect(),
            "files" => self
                .files
                .iter()
                .map(|f| {
                    serde_json::json!({
                        "path": f.path,
                        "sha256": f.sha256,
                        "exists": f.exists,
                    })
                })
                .collect(),
            other => anyhow::bail!("unknown snapshot table: {other}"),
        };
        Ok(Rows(rows))
    }

    fn device(&self) -> torda_ocsf::Device {
        torda_ocsf::Device {
            hostname: self.hostname.clone(),
            os: self.os.clone(),
            os_version: self.os_version.clone(),
        }
    }
}

// ---------------- Platform substrate factory ----------------

/// The shared substrate for THIS host: an `EventBus` + a `SnapshotProvider`
/// selected for the build target (`#[cfg(target_os)]`). One codebase; each
/// per-OS binary compiles in only its backend. Modules above depend only on the
/// `torda-core` traits and are identical on every OS.
///
/// The `SnapshotProvider` is real: packages come from the OS inventory
/// (dpkg/rpm on Linux, the registry uninstall keys on Windows, via
/// `default_package_provider`) and `device()` reports the real hostname/OS. The
/// `EventBus` is the stub for now — real kernel-event backends (ETW on Windows,
/// eBPF on Linux, EndpointSecurity on macOS) land behind the `windows-etw` /
/// `linux-ebpf` / `macos-es` features in follow-up slices, dropping in at
/// [`select_event_bus`] without touching this type or any module.
pub struct Substrate {
    pub bus: Arc<dyn EventBus>,
    pub snapshot: Arc<dyn SnapshotProvider>,
    /// Which event-bus backend is live: `"etw"` when the real ETW session
    /// started, else `"stub"` (fallback / no backend feature). The agent banner
    /// reads this so it reports the actual bus rather than hardcoding "stub".
    pub bus_label: &'static str,
}

impl Substrate {
    /// Build the substrate for the current platform: the real cfg-selected
    /// `SnapshotProvider` + the `EventBus` backend (`StubBus` until a real
    /// backend feature is on).
    pub fn for_this_platform() -> Self {
        // snapshot: reuse the EXISTING real path — `StubSnapshot::new()` already
        // routes through `default_package_provider()` (cfg-selected real) + real
        // `device()`. It returns `Arc<StubSnapshot>`, coerced to the trait object.
        let snapshot: Arc<dyn SnapshotProvider> = StubSnapshot::new();
        // event bus: real backend selected by feature when available, else the
        // stub. `bus_label` records which one actually started.
        let (bus, bus_label) = select_event_bus();
        Self {
            bus,
            snapshot,
            bus_label,
        }
    }
}

/// Selects the `EventBus` for this platform. Real kernel-event backends drop in
/// here behind per-OS feature flags; the default build compiles in the stub bus,
/// so the host toolchain never needs a bpf/ETW/ES toolchain to build.
///
/// The Windows ETW backend is wired here now (behind `windows-etw`); it fails
/// soft to `StubBus` when the session can't be opened (e.g. non-elevated run).
/// The other per-OS backends drop in at this same seam:
/// - `#[cfg(all(target_os = "windows", feature = "windows-etw"))]` -> `EtwBus`
/// - `#[cfg(all(target_os = "linux",   feature = "linux-ebpf"))]`  -> `EbpfBus`
/// - `#[cfg(all(target_os = "macos",   feature = "macos-es"))]`    -> `EsBus`
fn select_event_bus() -> (Arc<dyn EventBus>, &'static str) {
    #[cfg(all(target_os = "windows", feature = "windows-etw"))]
    {
        match etw::EtwBus::try_start() {
            // `try_start` returns `Arc<EtwBus>`, coerced to the trait object.
            Ok(bus) => return (bus, "etw"),
            Err(e) => eprintln!(
                "etw: falling back to stub event bus ({e}) — run elevated for real events"
            ),
        }
    }
    #[cfg(all(target_os = "linux", feature = "linux-ebpf"))]
    {
        match ebpf::EbpfBus::try_start() {
            // `try_start` returns `Arc<EbpfBus>`, coerced to the trait object.
            Ok(bus) => return (bus, "ebpf"),
            Err(e) => eprintln!(
                "ebpf: falling back to stub event bus ({e}) — run as root for real events"
            ),
        }
    }
    // Default / feature-off / non-elevated / non-root fallback.
    // `StubBus::new()` returns `Arc<StubBus>`, coerced to the trait object.
    (StubBus::new(), "stub")
}

fn read_hostname() -> String {
    // Unix: /etc/hostname or $HOSTNAME. Windows: %COMPUTERNAME%.
    fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| env_nonempty("HOSTNAME"))
        .or_else(|| env_nonempty("COMPUTERNAME"))
        .unwrap_or_else(|| "unknown-host".to_string())
}

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

/// Reads OS name + version. The substrate is the only component allowed to
/// query the OS directly; P1 swaps these stubs for real table providers.
#[cfg(not(target_os = "windows"))]
fn read_os_release() -> (String, String) {
    let content = fs::read_to_string("/etc/os-release").unwrap_or_default();
    let mut name = "unknown".to_string();
    let mut version = "0".to_string();
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("NAME=") {
            name = v.trim_matches('"').to_string();
        } else if let Some(v) = line.strip_prefix("VERSION_ID=") {
            version = v.trim_matches('"').to_string();
        }
    }
    (name, version)
}

#[cfg(target_os = "windows")]
fn read_os_release() -> (String, String) {
    // Read ProductName + version from the registry. Called once at
    // construction (cached on the struct), never in a hot path.
    let name = reg_current_version("ProductName").unwrap_or_else(|| "Windows".to_string());
    let version = reg_current_version("DisplayVersion")
        .or_else(|| reg_current_version("CurrentBuild"))
        .unwrap_or_else(|| "0".to_string());
    (name, version)
}

/// Queries one value under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`.
#[cfg(target_os = "windows")]
fn reg_current_version(value: &str) -> Option<String> {
    use std::process::Command;
    let out = Command::new("reg")
        .args([
            "query",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "/v",
            value,
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    // Each value line looks like: "<name>    REG_SZ    <data>".
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with(value) {
            if let Some(idx) = line.find("REG_SZ") {
                let data = line[idx + "REG_SZ".len()..].trim();
                if !data.is_empty() {
                    return Some(data.to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packages::{EmptyProvider, Package, PackageProvider};
    use torda_core::SnapshotProvider;

    struct FakeProvider;
    impl PackageProvider for FakeProvider {
        fn packages(&self) -> Vec<Package> {
            vec![
                Package::new("openssl", "3.0.2", "fake"),
                Package::new("glibc", "2.39", "fake"),
            ]
        }
    }

    #[test]
    fn snapshot_serializes_packages_from_provider() {
        let s = StubSnapshot::with_provider(Box::new(FakeProvider));
        let rows = s.query("packages").unwrap().0;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["name"], "openssl");
        assert_eq!(rows[0]["version"], "3.0.2");
        assert_eq!(rows[0]["source"], "fake");
        assert_eq!(rows[1]["name"], "glibc");
        assert_eq!(rows[1]["version"], "2.39");
        assert_eq!(rows[1]["source"], "fake");
    }

    #[test]
    fn snapshot_os_table_and_unknown_table_error() {
        let s = StubSnapshot::with_provider(Box::new(EmptyProvider));
        assert_eq!(s.query("os_version").unwrap().0.len(), 1);
        assert!(
            s.query("does_not_exist").is_err(),
            "unknown table must error"
        );
    }

    #[test]
    fn snapshot_serves_files_table() {
        use crate::files::{FileState, StaticFileProvider};
        let s = StubSnapshot::with_providers(
            Box::new(EmptyProvider),
            Box::new(StaticFileProvider(vec![FileState::present(
                "/etc/passwd",
                "abcd",
            )])),
        );
        let rows = s.query("files").unwrap().0;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["path"], "/etc/passwd");
        assert_eq!(rows[0]["sha256"], "abcd");
        assert_eq!(rows[0]["exists"], true);
    }

    #[test]
    fn device_is_populated() {
        let s = StubSnapshot::with_provider(Box::new(EmptyProvider));
        let d = s.device();
        assert!(!d.hostname.is_empty());
        assert!(!d.os.is_empty());
        assert!(!d.os_version.is_empty());
    }

    #[test]
    fn for_this_platform_snapshot_is_real() {
        let sub = Substrate::for_this_platform();
        // The snapshot must reuse the real cfg-selected package provider.
        let rows = sub.snapshot.query("packages").expect("packages query ok").0;
        assert!(
            !rows.is_empty(),
            "expected real host packages (Windows registry uninstall keys on CI)"
        );
        // Rows look like real package records: a non-empty name is present.
        for r in &rows {
            let name = r["name"].as_str().unwrap_or("");
            assert!(!name.is_empty(), "package row missing name: {r:?}");
        }
        // device() is real: non-empty hostname and a resolved (non-stub) OS.
        let d = sub.snapshot.device();
        assert!(!d.hostname.is_empty(), "hostname must be populated");
        assert_ne!(d.hostname, "unknown-host", "hostname must resolve");
        assert!(!d.os.is_empty(), "os must be populated");
        assert_ne!(d.os.to_lowercase(), "unknown", "os must be detected");
    }

    #[test]
    fn for_this_platform_bus_is_usable() {
        let sub = Substrate::for_this_platform();
        // Smoke test the trait object: subscribe, publish, receive (StubBus).
        let mut rx = sub.bus.subscribe(&[EventKind::ProcessExec]);
        sub.bus.publish(SubstrateEvent {
            kind: EventKind::ProcessExec,
            ts: 0,
            fields: serde_json::json!({"pid": 1}),
        });
        let ev = rx.try_recv().expect("published event received");
        assert_eq!(ev.kind, EventKind::ProcessExec);
    }

    #[test]
    fn default_build_uses_stub_bus() {
        // On the default (no windows-etw) build, `select_event_bus` returns the
        // StubBus: publish/subscribe round-trips through the broadcast channel.
        let sub = Substrate::for_this_platform();
        let mut rx = sub.bus.subscribe(&[EventKind::ProcessExit]);
        sub.bus.publish(SubstrateEvent {
            kind: EventKind::ProcessExit,
            ts: 7,
            fields: serde_json::json!({"pid": 42}),
        });
        let ev = rx.try_recv().expect("stub bus delivers published event");
        assert_eq!(ev.kind, EventKind::ProcessExit);
        assert_eq!(ev.ts, 7);
        assert_eq!(ev.fields["pid"], 42);
    }

    #[test]
    fn substrate_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Substrate>();
        assert_send_sync::<Arc<dyn EventBus>>();
        assert_send_sync::<Arc<dyn SnapshotProvider>>();
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_os_fields_detected() {
        let d = StubSnapshot::with_provider(Box::new(EmptyProvider)).device();
        assert!(
            d.os.to_lowercase().contains("windows"),
            "os should be detected from the registry, got {:?}",
            d.os
        );
        assert_ne!(d.os_version, "0", "os_version should be detected");
        assert_ne!(
            d.hostname, "unknown-host",
            "hostname should resolve via COMPUTERNAME"
        );
    }
}
