//! File-monitor module (pure core) — the event-driven file-detection consumer.
//!
//! Both substrate backends (ETW and eBPF) already emit `EventKind::FileOpen`
//! and `EventKind::FileWrite`, but today nothing reads them: procmon, corr, and
//! netmon all drop file events via their kind guards. `torda-mod-filemon` is the
//! missing consumer — the direct file-domain analog of `torda-mod-procmon`
//! (process) and `torda-mod-netmon` (network): it will subscribe to the shared
//! bus and emit, never touch the OS itself, and never open a probe of its own.
//!
//! The pure core ([`FilePolicy`] + [`assess`]) is fully host-testable without
//! any runtime. [`FileMonModule`] wraps that core into a real `Module`: it
//! subscribes to `FileOpen`/`FileWrite` on the shared bus, runs the prefilter
//! FIRST, then `assess`, then emits one OCSF File System Activity (1001)
//! record for each considered event that actually TRIPPED a detection rule.
//! It reads only the bus and emits — it never touches the OS itself, and
//! never opens a probe of its own.
//!
//! # Relationship to `torda-mod-fim`
//! `torda-mod-fim` (already in the workspace) is the **snapshot/baseline**
//! file-integrity module: it diffs an expected-digest watchlist against the
//! `files` snapshot table. `torda-mod-filemon` is a different module with a
//! different job: it judges individual `FileOpen`/`FileWrite` *events* as they
//! happen, with no baseline and no digest. The two are complementary, not
//! duplicates, and this crate never touches `torda-mod-fim`.
//!
//! # Why a prefilter is load-bearing
//! Live measurements against the real substrate backends showed **412 ETW file
//! events in 3 seconds** and **114 `openat` events in 3 seconds**, nearly all
//! irrelevant system/application noise (temp files, browser caches, log
//! churn). A consumer with no filter would flood the bus, the emitter, and the
//! findings store. [`FilePolicy::considers`] is therefore the mandatory first
//! gate: it MUST run before any other work, on every event, full stop.
//!
//! # Emission policy: flagged-only (a DELIBERATE divergence from netmon/procmon)
//! `torda-mod-netmon` and `torda-mod-procmon` emit one envelope per event that
//! survives their prefilter, flagged or not — that's fine at network/process
//! event volumes. It is NOT fine here: a live elevated ETW run measured 412
//! file events in 3 seconds, and the default [`FilePolicy`] WATCHES
//! `\windows\system32\`, a directory Windows processes read from constantly.
//! "Emit everything considered" against that path would flood the
//! emitter/bus/findings store with a steady stream of Informational,
//! empty-`detections` envelopes for ordinary DLL reads — undercutting the
//! entire point of having a path filter in the first place.
//!
//! So `torda-mod-filemon` only emits when [`assess`] actually fires a rule
//! (`!assessment.hits.is_empty()`, equivalently `severity_id != 1`). This is
//! an honest tradeoff, not a free lunch: we lose benign-file-access
//! telemetry (no record at all of a considered-but-clean open/write) in
//! exchange for a signal-to-noise ratio a human or downstream engine can
//! actually use. If benign file-access telemetry is ever needed, it should
//! be a separate, explicitly volume-bounded/sampled path — not the default
//! behavior of this consumer.
//!
//! # Severity scheme
//! Values are re-exported from `torda_core::severity` — the single source of
//! truth shared by every module — never redeclared here:
//! `1 = Informational`, `3 = Medium`, `4 = High`. An assessment's
//! `severity_id` is the MAX over its rule hits, or `1` when nothing fired.
//!
//! # Honest limits (v0)
//! - **No file hashes, no content inspection.** The ruleset judges a path and
//!   an open/write flag only; it cannot tell a legitimate installer write from
//!   a malicious one to the same path.
//! - **No process reputation.** It does not know which process performed the
//!   operation, so it cannot distinguish `svchost.exe` from an unsigned
//!   binary writing to the same directory.
//! - **No baseline or diff.** It has no notion of "this file changed from what
//!   we expect" — that is `torda-mod-fim`'s job, not this module's.
//! - **Substring matching, not path normalization.** ETW yields NT-device
//!   paths (`\Device\HarddiskVolume3\Windows\System32\...`) while eBPF yields
//!   POSIX paths (`/etc/passwd`). Rather than attempt NT→DOS drive-letter
//!   normalization (deferred — it requires a live device-to-drive-letter
//!   mapping that can change across reboots), v0 matches on substrings that
//!   are valid in **both** path forms (e.g. `\windows\system32\`, `/etc/`).
//!   This is simple and correct for the common case, but it means a path that
//!   happens to contain a watched substring in an unexpected position (e.g.
//!   deep inside an unrelated directory name) can also match — a known,
//!   accepted false-positive source for a v0 substring filter.
//! - **Un-canonicalized paths are also an evasion surface (false-negative), not
//!   just a false-positive source.** Paths are matched as raw substrings, with
//!   no canonicalization: an attacker who controls the path can EVADE the
//!   ruleset in v0 by making it contain an `ignore` substring — e.g. a `..`
//!   traversal through an ignored dir (`/tmp/../etc/passwd`), a namespace path
//!   to the real target (`/proc/self/root/etc/shadow`), or (before this fix)
//!   an extension trick (`evil.log.dll` suppressing the whole ruleset via a
//!   mid-string `.log` match). Extension-style ignore entries (leading `.`)
//!   are now suffix-anchored with `ends_with` rather than `contains`, closing
//!   that specific bypass, but directory-substring evasion via `..`/symlink/
//!   namespace paths remains open until path canonicalization lands (deferred,
//!   alongside the NT->DOS normalization above). Treat the v0 policy as
//!   best-effort noise reduction, not an authorization boundary.

/// Severity constants — the single source of truth lives in `torda_core::severity`.
pub use torda_core::severity::{SEV_HIGH, SEV_INFORMATIONAL, SEV_MEDIUM};

// ---------------- Path policy (prefilter) ----------------

/// The cheap path prefilter every file event MUST pass through first.
///
/// `watch` lists substrings that make a path worth considering at all;
/// `ignore` lists substrings that drop it anyway (checked AFTER `watch`, so
/// ignore always wins over watch — noise suppression takes priority).
#[derive(Clone)]
pub struct FilePolicy {
    /// Only paths matching one of these substrings are CONSIDERED at all.
    /// Lowercased once at construction time (see [`FilePolicy::considers`]).
    pub watch: Vec<String>,
    /// Dropped even if they matched `watch` (noise). Checked AFTER `watch`.
    /// Lowercased once at construction time.
    pub ignore: Vec<String>,
}

impl FilePolicy {
    /// Build a policy, normalizing every entry (lowercased) so `considers()` is
    /// reliably case-insensitive no matter how the policy was constructed.
    ///
    /// This is the SAFE constructor and the ONLY normalization path: a
    /// hand-built `FilePolicy { watch, ignore }` literal (the fields stay
    /// `pub` for tests/flexibility) with mixed-case entries would silently
    /// lose case-insensitivity, since `considers()` only lowercases the
    /// incoming path, never the policy's own entries. Always prefer `new()`
    /// (or `Default`, which now goes through it) over a bare struct literal.
    pub fn new(watch: Vec<String>, ignore: Vec<String>) -> Self {
        FilePolicy {
            watch: watch.iter().map(|s| s.to_ascii_lowercase()).collect(),
            ignore: ignore.iter().map(|s| s.to_ascii_lowercase()).collect(),
        }
    }

    /// The cheap prefilter. MUST be called FIRST on every event, before any
    /// other work (assessment, envelope construction, emission).
    ///
    /// Case-insensitive substring match: `watch`/`ignore` are lowercased once
    /// at construction, and this function lowercases the incoming `path` once
    /// per call. A per-event `to_ascii_lowercase()` allocation is not free,
    /// but it is simple, obviously correct, and cheap relative to the I/O and
    /// emission work downstream that it exists to prevent — prioritizing
    /// correctness/clarity over micro-optimizing this one allocation.
    ///
    /// Returns `false` => drop the event immediately (watch-miss, or an
    /// ignore-hit that overrides a watch-hit).
    pub fn considers(&self, path: &str) -> bool {
        let path_lower = path.to_ascii_lowercase();
        let watched = self.watch.iter().any(|w| path_lower.contains(w.as_str()));
        if !watched {
            return false;
        }
        // Extension-style ignore entries (leading `.`, e.g. `.log`/`.etl`) are
        // anchored to the END of the path with `ends_with`, NOT `contains`:
        // an unanchored `.log` would also match mid-string in a path like
        // `evil.log.dll`, silently dropping a real threat under a watched
        // directory just because it embeds an ignored extension as a decoy.
        // Directory/substring ignore entries (no leading `.`) keep `contains`
        // since they are meant to match anywhere the directory appears.
        !self.ignore.iter().any(|i| {
            if i.starts_with('.') {
                path_lower.ends_with(i.as_str())
            } else {
                path_lower.contains(i.as_str())
            }
        })
    }
}

impl Default for FilePolicy {
    /// The shipped v0 default policy.
    ///
    /// `watch` substrings are chosen to be valid in BOTH the ETW NT-device
    /// path form and the eBPF POSIX path form — see the module doc's "Honest
    /// limits" section. No NT-device-to-drive-letter normalization is
    /// attempted; that is deferred.
    fn default() -> Self {
        let watch = [
            // Windows system/binary dirs
            "\\windows\\system32\\",
            "\\program files\\",
            // Windows persistence
            "\\start menu\\programs\\startup\\",
            "\\system32\\tasks\\",
            // Windows credential stores
            "\\system32\\config\\",
            "\\drivers\\etc\\hosts",
            // Linux system/binary dirs
            "/usr/bin/",
            "/usr/sbin/",
            "/bin/",
            "/sbin/",
            // Linux config/credentials
            "/etc/",
            ".ssh/",
            // Linux persistence
            "/etc/cron",
            "/etc/systemd/",
            "/etc/init.d/",
            "/etc/rc.local",
        ];
        let ignore = [
            // Temp dirs
            "\\appdata\\local\\temp\\",
            "/tmp/",
            "\\temp\\",
            // Browser/webview caches
            "\\ebwebview\\",
            "\\cache\\",
            // Log/trace churn
            "\\logfiles\\",
            ".etl",
            ".log",
            // Linux pseudo-filesystems
            "/proc/",
            "/sys/",
            "/dev/",
        ];
        FilePolicy::new(
            watch.iter().map(|s| s.to_string()).collect(),
            ignore.iter().map(|s| s.to_string()).collect(),
        )
    }
}

// ---------------- Ruleset (pure, deterministic, I/O-free) ----------------

/// One rule firing against a file event.
pub struct RuleHit {
    /// Stable rule identifier (e.g. `"write_to_system_dir"`).
    pub rule: &'static str,
    /// Human-readable rationale for this specific hit.
    pub reason: String,
}

/// The verdict for one file event: a MAX severity plus every rule that fired.
pub struct Assessment {
    /// `1 = Informational, 3 = Medium, 4 = High`. MAX over `hits`.
    pub severity_id: u8,
    pub hits: Vec<RuleHit>,
}

/// System/binary directories: a WRITE here is a strong tampering signal.
const SYSTEM_DIRS: &[&str] = &[
    "\\windows\\system32\\",
    "\\program files\\",
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
];

/// Startup/autorun/cron/systemd/init locations: a WRITE here is a persistence
/// signal.
const PERSISTENCE_LOCATIONS: &[&str] = &[
    "\\start menu\\programs\\startup\\",
    "\\system32\\tasks\\",
    "/etc/cron",
    "/etc/systemd/",
    "/etc/init.d/",
    "/etc/rc.local",
];

/// Sensitive config/credential directories: a WRITE here can plant/alter
/// trust material (SSH keys, hosts file, cron, credential store, etc).
const SENSITIVE_CONFIG_DIRS: &[&str] = &[
    "/etc/",
    ".ssh/",
    "\\system32\\config\\",
    "\\drivers\\etc\\hosts",
];

/// Specific credential/secret files: a READ of these is a credential-theft
/// signal (not tampering, since nothing was changed).
const SENSITIVE_READ_FILES: &[&str] = &[
    "/etc/shadow",
    ".ssh/id_",
    "\\system32\\config\\sam",
    "/etc/sudoers",
];

/// Severity for a given rule id. Keeps the scheme explicit and per-rule.
fn rule_severity(rule: &str) -> u8 {
    match rule {
        "write_to_system_dir" => SEV_HIGH,
        "write_to_persistence_location" => SEV_HIGH,
        "write_to_sensitive_config" => SEV_HIGH,
        "read_of_sensitive_file" => SEV_MEDIUM,
        _ => SEV_INFORMATIONAL,
    }
}

/// Assess a file event by path + write flag. PURE, deterministic, I/O-free.
/// `write` = `true` for `FileWrite`, `false` for `FileOpen`.
///
/// The caller MUST have already passed `policy.considers(path)` — this
/// function does no volume filtering of its own, only judgement.
///
/// A single path may fire more than one rule (e.g. a write to `/etc/cron.d/x`
/// is both `write_to_sensitive_config` and `write_to_persistence_location`) —
/// that is expected; every hit is kept, and `severity_id` is the MAX over all
/// of them.
pub fn assess(path: &str, write: bool) -> Assessment {
    // Single lowercase per call — see `FilePolicy::considers` for the same
    // cost/clarity tradeoff rationale.
    let path_lower = path.to_ascii_lowercase();
    let mut hits: Vec<RuleHit> = Vec::new();

    if write && SYSTEM_DIRS.iter().any(|p| path_lower.contains(p)) {
        hits.push(RuleHit {
            rule: "write_to_system_dir",
            reason: format!("write to a system/binary directory: {path}"),
        });
    }
    if write && PERSISTENCE_LOCATIONS.iter().any(|p| path_lower.contains(p)) {
        hits.push(RuleHit {
            rule: "write_to_persistence_location",
            reason: format!("write to a startup/autorun/cron/systemd/init location: {path}"),
        });
    }
    if write && SENSITIVE_CONFIG_DIRS.iter().any(|p| path_lower.contains(p)) {
        hits.push(RuleHit {
            rule: "write_to_sensitive_config",
            reason: format!("write to a sensitive config/credential path: {path}"),
        });
    }
    if !write && SENSITIVE_READ_FILES.iter().any(|p| path_lower.contains(p)) {
        hits.push(RuleHit {
            rule: "read_of_sensitive_file",
            reason: format!("read of a credential/secret file: {path}"),
        });
    }

    let severity_id = hits
        .iter()
        .map(|h| rule_severity(h.rule))
        .max()
        .unwrap_or(SEV_INFORMATIONAL);

    Assessment { severity_id, hits }
}

// ---------------- Module ----------------

/// Subscribes to `FileOpen`/`FileWrite` and emits one OCSF File System
/// Activity record for each event that survives [`FilePolicy::considers`]
/// AND trips at least one rule in [`assess`]. Considered-but-clean events
/// (empty `assessment.hits`) are dropped without emitting — see the module
/// doc's "Emission policy" section for why this diverges from netmon/procmon.
pub struct FileMonModule {
    ctx: Option<torda_core::ModuleCtx>,
    policy: FilePolicy,
    /// Signals the background task to stop; `true` == please exit.
    stop_tx: Option<tokio::sync::watch::Sender<bool>>,
    /// Handle to the bus-reading task, awaited (bounded) on `stop`.
    task: Option<tokio::task::JoinHandle<()>>,
}

impl FileMonModule {
    /// Builds a module with the shipped default [`FilePolicy`].
    pub fn new() -> Self {
        Self::with_policy(FilePolicy::default())
    }

    /// Builds a module with a caller-supplied policy (demos/tests that need a
    /// custom watch/ignore set).
    pub fn with_policy(policy: FilePolicy) -> Self {
        Self {
            ctx: None,
            policy,
            stop_tx: None,
            task: None,
        }
    }
}

impl Default for FileMonModule {
    fn default() -> Self {
        Self::new()
    }
}

/// Extracts the path from a `FileOpen`/`FileWrite` event and — if it survives
/// the prefilter AND `assess` actually fires a rule — emits its File System
/// Activity record.
///
/// ORDER MATTERS: the kind guard, then the path extraction, then
/// `policy.considers(path)` MUST run before any other work (assess, envelope
/// build, emit). The live substrate emits hundreds of file events per second,
/// nearly all noise; the filter is what keeps this consumer from flooding the
/// bus/emitter/findings store. A malformed event (missing/non-string `path`)
/// is SKIPPED — never a panic, never an emit.
///
/// A CONSIDERED event with zero detections is ALSO skipped — never emitted.
/// This is the flagged-only emission policy (see the module doc's "Emission
/// policy" section): file-event volume makes "emit everything considered"
/// untenable the way it is for netmon/procmon, so only flagged activity
/// produces a record here.
fn handle_event(
    ev: &torda_core::SubstrateEvent,
    policy: &FilePolicy,
    meta: &torda_ocsf::Metadata,
    device: &torda_ocsf::Device,
    emitter: &dyn torda_core::OcsfEmitter,
) {
    // Kind guard: the stub bus forwards every kind; only file events are ours.
    let write = match ev.kind {
        torda_core::EventKind::FileWrite => true,
        torda_core::EventKind::FileOpen => false,
        _ => return,
    };

    let path = match ev.fields.get("path").and_then(serde_json::Value::as_str) {
        Some(s) => s,
        None => return,
    };

    // THE FILTER RUNS FIRST — before assess, envelope build, or emit.
    if !policy.considers(path) {
        return;
    }

    let pid = ev.fields.get("pid").and_then(serde_json::Value::as_u64);
    let image = ev.fields.get("image").and_then(serde_json::Value::as_str);

    let a = assess(path, write);
    // FLAGGED-ONLY EMISSION: a considered event that trips no rule is
    // deliberately dropped here — see the module doc's "Emission policy"
    // section. This is the one point where filemon diverges from
    // netmon/procmon's "emit everything considered" contract.
    if a.hits.is_empty() {
        return;
    }
    let detections: Vec<serde_json::Value> = a
        .hits
        .iter()
        .map(|h| serde_json::json!({ "rule": h.rule, "reason": h.reason }))
        .collect();

    let mut env = torda_ocsf::OcsfEnvelope::new(
        torda_ocsf::class::FILE_SYSTEM_ACTIVITY,
        "File System Activity",
        meta.clone(),
        device.clone(),
        serde_json::json!({
            "file": { "path": path, "op": if write { "write" } else { "open" } },
            "pid": pid,
            "image": image,
            "detections": detections,
        }),
    );
    // OcsfEnvelope::new defaults severity_id to 1; override with our verdict.
    env.severity_id = a.severity_id;
    emitter.emit(env);
}

#[async_trait::async_trait]
impl torda_core::Module for FileMonModule {
    fn id(&self) -> torda_core::ModuleId {
        "filemon".to_string()
    }

    async fn init(&mut self, ctx: torda_core::ModuleCtx) -> anyhow::Result<()> {
        self.ctx = Some(ctx);
        Ok(())
    }

    async fn start(&mut self) -> anyhow::Result<()> {
        let ctx = self
            .ctx
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("filemon: init before start"))?;

        // Subscribe on the shared bus; capture only what the task needs (so it
        // owns no `ModuleCtx` reference and stays `'static`).
        let mut rx = ctx.bus.subscribe(&[
            torda_core::EventKind::FileOpen,
            torda_core::EventKind::FileWrite,
        ]);
        let meta = ctx.meta();
        let device = ctx.snapshot.device();
        let emitter = ctx.emitter.clone();
        // The policy lives for the life of the task; clone it in.
        let policy = self.policy.clone();

        let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stop_rx.changed() => {
                        if *stop_rx.borrow() {
                            break;
                        }
                    }
                    r = rx.recv() => match r {
                        Ok(ev) => handle_event(&ev, &policy, &meta, &device, emitter.as_ref()),
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue, // dropped events; keep reading
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,        // bus gone; exit
                    },
                }
            }
        });

        self.stop_tx = Some(stop_tx);
        self.task = Some(task);
        Ok(())
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(true); // wake the task's select! arm
        }
        if let Some(task) = self.task.take() {
            // Bounded join so stop never hangs the manager.
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), task).await;
        }
        Ok(())
    }

    fn health(&self) -> torda_core::ModuleHealth {
        torda_core::ModuleHealth {
            ok: self.ctx.is_some(),
            detail: "file monitor ready".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(a: &Assessment) -> Vec<&'static str> {
        a.hits.iter().map(|h| h.rule).collect()
    }

    // ---------- FilePolicy::considers ----------

    #[test]
    fn considers_watched_path_is_true() {
        let policy = FilePolicy::default();
        assert!(policy.considers("/etc/passwd"));
        assert!(policy.considers("C:\\Windows\\System32\\drivers\\evil.sys"));
    }

    #[test]
    fn considers_unwatched_path_is_false() {
        let policy = FilePolicy::default();
        assert!(!policy.considers("/home/user/notes.txt"));
        assert!(!policy.considers("\\users\\pkkar\\documents\\a.docx"));
    }

    #[test]
    fn considers_ignore_beats_watch_even_when_watch_would_match() {
        let policy = FilePolicy::default();
        // Deliberately overlapping paths: each contains a WATCH substring
        // ("/etc/", "\system32\config\") *and* an IGNORE substring ("/tmp/",
        // "\appdata\local\temp\"). If watch alone decided, these would pass —
        // proving ignore is checked after watch and overrides it.
        assert!(
            !policy.considers("/tmp/etc/passwd"),
            "watch-matching /etc/ must still be dropped by the /tmp/ ignore hit"
        );
        assert!(
            !policy.considers("C:\\Users\\bob\\AppData\\Local\\Temp\\System32\\Config\\sam"),
            "watch-matching \\system32\\config\\ must still be dropped by the temp-dir ignore hit"
        );
        // Plain temp/tmp noise (not otherwise watched at all) is dropped too.
        assert!(!policy.considers("/tmp/x"));
        assert!(!policy.considers("\\appdata\\local\\temp\\y"));
    }

    #[test]
    fn default_policy_ignores_our_own_etw_telemetry() {
        // A security agent must never flag its own telemetry. A live
        // elevated ETW run flagged the agent's OWN ETW session backing file
        // (real path observed live below) purely because the *demo* used a
        // deliberately-minimal custom policy. The DEFAULT policy already
        // ignores `\logfiles\` and `.etl` — pin that here so production
        // never regresses on it.
        let policy = FilePolicy::default();

        // The exact path observed live.
        assert!(
            !policy.considers(
                "\\Device\\HarddiskVolume3\\WINDOWS\\system32\\Logfiles\\WMI\\RtBackup\\EtwRTn4r1b-trace-Ut8lOPiKnn.etl"
            ),
            "must never flag our own ETW session backing file"
        );
        // A `.etl` elsewhere under system32 (not necessarily under LogFiles).
        assert!(
            !policy
                .considers("\\Device\\HarddiskVolume3\\WINDOWS\\system32\\Tasks\\trace-abc123.etl"),
            "must never flag a .etl file anywhere under system32"
        );
        // A bare \logfiles\ path (no .etl extension).
        assert!(
            !policy
                .considers("\\Device\\HarddiskVolume3\\WINDOWS\\system32\\LogFiles\\Sum\\Svc.log"),
            "must never flag anything under \\logfiles\\"
        );
    }

    #[test]
    fn considers_extension_ignore_is_suffix_anchored_not_substring() {
        let policy = FilePolicy::default();

        // `.log` appears MID-STRING (not as a true suffix) in this path — an
        // attacker naming a payload `evil.log.dll` must NOT get a free pass
        // out of the ruleset for a real threat under a watched system dir.
        assert!(
            policy.considers(r"\device\harddiskvolume3\windows\system32\evil.log.dll"),
            "a `.log` substring mid-path must not suppress consideration of a real payload"
        );

        // Regression guard: a genuine `.etl` suffix under `\logfiles\` must
        // still be dropped (both the directory ignore and the now-anchored
        // extension ignore agree here).
        assert!(
            !policy.considers(
                r"\device\harddiskvolume3\windows\system32\logfiles\wmi\rtbackup\etwrt-trace-xyz.etl"
            ),
            "a genuine .etl file under \\logfiles\\ must still be dropped"
        );

        // A plain file that genuinely ENDS IN `.log` under a watched dir must
        // still be dropped — the suffix anchor is not a regression for the
        // legitimate case, only for the mid-string bypass.
        assert!(
            !policy.considers(r"\windows\system32\foo.log"),
            "a path that genuinely ends in .log under a watched dir must still be dropped"
        );
    }

    #[test]
    fn considers_is_case_insensitive() {
        let policy = FilePolicy::default();
        assert!(policy.considers("/ETC/PASSWD"));
        assert!(policy.considers("\\WINDOWS\\SYSTEM32\\"));
    }

    #[test]
    fn new_normalizes_mixed_case_watch_and_ignore_entries() {
        // A policy hand-built via `new()` with MIXED-CASE watch/ignore entries
        // must still behave case-insensitively in both directions: a lowercase
        // path must match a mixed-case watch entry, and a lowercase ignore
        // entry must still override an uppercase path that matches watch.
        let policy = FilePolicy::new(
            vec!["/ETC/".to_string(), "\\Windows\\System32\\".to_string()],
            vec!["/TMP/".to_string()],
        );

        // Lowercase paths match the mixed-case watch entries.
        assert!(policy.considers("/etc/passwd"));
        assert!(policy.considers("c:\\windows\\system32\\evil.dll"));
        // Uppercase paths also match (both sides normalized).
        assert!(policy.considers("/ETC/PASSWD"));

        // The lowercase ignore entry still overrides a watch-matching,
        // differently-cased path.
        assert!(!policy.considers("/TMP/ETC/PASSWD"));
        assert!(!policy.considers("/tmp/etc/passwd"));
    }

    /// ~50 realistic noise paths taken from the live ETW/eBPF runs (temp dirs,
    /// browser/webview caches, log/trace churn, Linux pseudo-filesystems).
    /// Shared by the pure-`considers` test and the module-level volume test.
    fn noise_paths() -> &'static [&'static str] {
        &[
            // Windows temp dirs
            "C:\\Users\\pkkar\\AppData\\Local\\Temp\\tmp8F3A.tmp",
            "C:\\Users\\pkkar\\AppData\\Local\\Temp\\chrome_BITS_1a2b\\setup.exe",
            "C:\\Users\\pkkar\\AppData\\Local\\Temp\\{3F1A2B4C-1234-5678-9ABC-DEF012345678}\\a.dll",
            "\\Device\\HarddiskVolume3\\Users\\pkkar\\AppData\\Local\\Temp\\_MEI12345\\lib.pyd",
            "C:\\Windows\\Temp\\WER1234.tmp.mdmp",
            "C:\\Users\\pkkar\\AppData\\Local\\Temp\\nsz1122.tmp\\nsExec.dll",
            "C:\\Users\\pkkar\\AppData\\Local\\Temp\\jna-98765\\jna1234.dll",
            "C:\\Users\\pkkar\\AppData\\Local\\Temp\\pip-req-build-abc123\\setup.py",
            "C:\\Users\\pkkar\\AppData\\Local\\Temp\\vscode-typescript1\\tsserver.log",
            "C:\\Windows\\Temp\\SDIAG_1234\\report.xml",
            // Browser/webview caches
            "C:\\Users\\pkkar\\AppData\\Local\\Microsoft\\Edge\\User Data\\EBWebView\\Default\\Cache\\data_1",
            "C:\\Users\\pkkar\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\Cache_Data\\f_00012a",
            "C:\\Users\\pkkar\\AppData\\Local\\Microsoft\\Edge\\User Data\\EBWebView\\Default\\Code Cache\\js\\0001",
            "C:\\Users\\pkkar\\AppData\\Local\\Google\\Chrome\\User Data\\ShaderCache\\GPUCache\\data_2",
            "C:\\Users\\pkkar\\AppData\\Local\\Packages\\MicrosoftEdge\\EBWebView\\Cache\\entry_3",
            "C:\\Users\\pkkar\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\index",
            "C:\\Users\\pkkar\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cache\\data_3",
            "C:\\Users\\pkkar\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\abc.default\\cache2\\entries\\0A1B2C",
            "C:\\Users\\pkkar\\AppData\\Local\\Google\\Chrome\\User Data\\GrShaderCache\\GPUCache\\data_0",
            "C:\\Users\\pkkar\\AppData\\Local\\Microsoft\\Edge\\User Data\\EBWebView\\Default\\Cache\\data_2",
            // Log/trace churn
            "C:\\Windows\\System32\\LogFiles\\WMI\\RtBackup\\EtwRTEventLog-Application.etl",
            "C:\\Windows\\System32\\LogFiles\\Sum\\Svc.log",
            "C:\\ProgramData\\Microsoft\\Windows\\WER\\Temp\\WER1234.tmp.etl",
            "C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log",
            "C:\\Windows\\Panther\\setupact.log",
            "C:\\Windows\\Logs\\CBS\\CBS.log",
            "C:\\Windows\\Logs\\DISM\\dism.log",
            "C:\\Windows\\Logs\\MoSetup\\BlueBox.log",
            "C:\\Windows\\System32\\LogFiles\\Scm\\SCM-20260101-000000.etl",
            "C:\\Windows\\Logs\\NetSetup\\NetSetup.LOG",
            // Linux temp
            "/tmp/pip-install-abc123/pkg/setup.py",
            "/tmp/systemd-private-abc123-httpd.service-xyz/tmp/passwd",
            "/tmp/.X11-unix/X0",
            "/tmp/snap.rootfs_ABC123/etc/resolv.conf",
            "/tmp/vscode-typescript1/tsserver.log",
            // Linux pseudo-filesystems: /proc
            "/proc/1234/status",
            "/proc/1234/fd/3",
            "/proc/self/maps",
            "/proc/meminfo",
            "/proc/1234/cmdline",
            // Linux pseudo-filesystems: /sys
            "/sys/class/net/eth0/statistics/rx_bytes",
            "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq",
            "/sys/fs/cgroup/memory.max",
            "/sys/kernel/debug/tracing/trace_pipe",
            "/sys/block/sda/stat",
            // Linux pseudo-filesystems: /dev
            "/dev/null",
            "/dev/urandom",
            "/dev/pts/3",
            "/dev/shm/some_segment",
            "/dev/zero",
            // A few more mixed noise samples
            "C:\\Users\\pkkar\\AppData\\Local\\Temp\\2\\~DF1A2B.tmp",
            "C:\\Windows\\Temp\\MpCmdRun.log",
            "/tmp/kubelet-plugins/xyz.sock",
        ]
    }

    #[test]
    fn considers_zero_pass_on_realistic_noise_vector() {
        // NONE of these should pass `considers` — proving the filter actually
        // protects everything downstream.
        let noise = noise_paths();
        assert!(
            noise.len() >= 50,
            "expected >= 50 noise paths, got {}",
            noise.len()
        );
        let policy = FilePolicy::default();
        for path in noise {
            assert!(
                !policy.considers(path),
                "noise path incorrectly passed considers: {path}"
            );
        }
    }

    // ---------- assess: cross-OS same-rule payoff ----------

    #[test]
    fn assess_same_rule_fires_for_both_etw_and_ebpf_path_forms() {
        // ETW NT-device form.
        let etw = assess(
            "\\Device\\HarddiskVolume3\\Windows\\System32\\drivers\\evil.sys",
            true,
        );
        // eBPF POSIX form.
        let ebpf = assess("/usr/bin/evil", true);

        assert_eq!(rules(&etw), vec!["write_to_system_dir"]);
        assert_eq!(rules(&ebpf), vec!["write_to_system_dir"]);
        assert_eq!(etw.severity_id, SEV_HIGH);
        assert_eq!(ebpf.severity_id, SEV_HIGH);
    }

    // ---------- assess: each rule fires exactly on its inputs ----------

    #[test]
    fn assess_write_to_system_dir_is_high() {
        for path in [
            "C:\\Windows\\System32\\evil.dll",
            "C:\\Program Files\\Vendor\\app.exe",
            "/usr/bin/evil",
            "/usr/sbin/evil",
            "/bin/evil",
            "/sbin/evil",
        ] {
            let a = assess(path, true);
            assert_eq!(rules(&a), vec!["write_to_system_dir"], "path: {path}");
            assert_eq!(a.severity_id, SEV_HIGH, "path: {path}");
        }
    }

    #[test]
    fn assess_write_to_persistence_location_is_high() {
        for path in [
            "C:\\Users\\pkkar\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.lnk",
            "C:\\Windows\\System32\\Tasks\\EvilTask",
            "/etc/cron.d/evil",
            "/etc/systemd/system/evil.service",
            "/etc/init.d/evil",
            "/etc/rc.local",
        ] {
            let a = assess(path, true);
            assert!(rules(&a).contains(&"write_to_persistence_location"), "path: {path}");
            assert_eq!(a.severity_id, SEV_HIGH, "path: {path}");
        }
    }

    #[test]
    fn assess_write_to_sensitive_config_is_high() {
        let a = assess("/etc/passwd", true);
        assert_eq!(rules(&a), vec!["write_to_sensitive_config"]);
        assert_eq!(a.severity_id, SEV_HIGH);

        let b = assess("/home/user/.ssh/authorized_keys", true);
        assert_eq!(rules(&b), vec!["write_to_sensitive_config"]);
        assert_eq!(b.severity_id, SEV_HIGH);

        // These two are nested under \windows\system32\, so they ALSO match
        // the system-dir rule — both hits are correct and expected (a single
        // path firing more than one rule), so we assert containment rather
        // than an exact single-element vec here.
        let c = assess("C:\\Windows\\System32\\config\\SYSTEM", true);
        assert!(rules(&c).contains(&"write_to_sensitive_config"));
        assert!(rules(&c).contains(&"write_to_system_dir"));
        assert_eq!(c.severity_id, SEV_HIGH);

        let d = assess("C:\\Windows\\System32\\drivers\\etc\\hosts", true);
        assert!(rules(&d).contains(&"write_to_sensitive_config"));
        assert!(rules(&d).contains(&"write_to_system_dir"));
        assert_eq!(d.severity_id, SEV_HIGH);
    }

    #[test]
    fn assess_write_to_etc_cron_fires_both_persistence_and_sensitive_config() {
        // A write to /etc/cron.d/x is BOTH a persistence write (matches
        // "/etc/cron") AND a sensitive-config write (matches "/etc/") — both
        // hits are kept, and severity is the max (both High here, so still
        // High, but the point is BOTH rule names are present).
        let a = assess("/etc/cron.d/x", true);
        assert_eq!(
            rules(&a),
            vec!["write_to_persistence_location", "write_to_sensitive_config"]
        );
        assert_eq!(a.severity_id, SEV_HIGH);
    }

    #[test]
    fn assess_read_of_sensitive_file_is_medium() {
        for path in [
            "/etc/shadow",
            "/home/user/.ssh/id_rsa",
            "C:\\Windows\\System32\\config\\SAM",
            "/etc/sudoers",
        ] {
            let a = assess(path, false);
            assert_eq!(rules(&a), vec!["read_of_sensitive_file"], "path: {path}");
            assert_eq!(a.severity_id, SEV_MEDIUM, "path: {path}");
        }
    }

    #[test]
    fn assess_benign_watched_path_is_informational_no_hits() {
        // A read of a watched-but-non-sensitive path: no rule fires.
        let a = assess("/usr/bin/ls", false);
        assert_eq!(a.severity_id, SEV_INFORMATIONAL);
        assert!(a.hits.is_empty());
    }

    #[test]
    fn assess_write_vs_read_matters() {
        // WRITE to /etc/passwd -> write_to_sensitive_config (High).
        let write = assess("/etc/passwd", true);
        assert_eq!(rules(&write), vec!["write_to_sensitive_config"]);
        assert_eq!(write.severity_id, SEV_HIGH);

        // READ of /usr/bin/ls -> no hits at all.
        let read_benign = assess("/usr/bin/ls", false);
        assert!(read_benign.hits.is_empty());
        assert_eq!(read_benign.severity_id, SEV_INFORMATIONAL);

        // READ of /etc/shadow -> read_of_sensitive_file (Medium), NOT a write rule.
        let read_shadow = assess("/etc/shadow", false);
        assert_eq!(rules(&read_shadow), vec!["read_of_sensitive_file"]);
        assert_eq!(read_shadow.severity_id, SEV_MEDIUM);

        // The same shadow path as a WRITE fires the sensitive-config write
        // rule instead (it's under /etc/), never the read rule.
        let write_shadow = assess("/etc/shadow", true);
        assert_eq!(rules(&write_shadow), vec!["write_to_sensitive_config"]);
        assert_eq!(write_shadow.severity_id, SEV_HIGH);
    }

    #[test]
    fn assess_severity_is_max_over_hits() {
        // Confirms the MAX rule explicitly: two High hits and one path with
        // just the Medium read rule, checked against rule_severity directly.
        assert_eq!(rule_severity("write_to_system_dir"), SEV_HIGH);
        assert_eq!(rule_severity("write_to_persistence_location"), SEV_HIGH);
        assert_eq!(rule_severity("write_to_sensitive_config"), SEV_HIGH);
        assert_eq!(rule_severity("read_of_sensitive_file"), SEV_MEDIUM);

        let a = assess("/etc/cron.d/x", true);
        let max = a.hits.iter().map(|h| rule_severity(h.rule)).max().unwrap();
        assert_eq!(a.severity_id, max);
    }

    // ---------- end-to-end via StubBus + capturing emitter ----------

    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use torda_core::{
        EventBus, EventKind, Module, ModuleCtx, OcsfEmitter, ResourceBudget, ResourceGovernor,
        ResourceSampler, ResourceUsage, SubstrateEvent,
    };
    use torda_ocsf::{class, Device};
    use torda_substrate::StubBus;

    #[derive(Default)]
    struct CapturingEmitter {
        emitted: Mutex<Vec<torda_ocsf::OcsfEnvelope>>,
    }
    impl OcsfEmitter for CapturingEmitter {
        fn emit(&self, rec: torda_ocsf::OcsfEnvelope) {
            self.emitted.lock().unwrap().push(rec);
        }
    }

    struct TestSampler;
    impl ResourceSampler for TestSampler {
        fn sample(&self) -> ResourceUsage {
            ResourceUsage::ZERO
        }
    }

    // A minimal snapshot: filemon only calls `device()`.
    struct FakeSnapshot;
    impl torda_core::SnapshotProvider for FakeSnapshot {
        fn query(&self, table: &str) -> anyhow::Result<torda_core::Rows> {
            anyhow::bail!("no table {table}")
        }
        fn device(&self) -> Device {
            Device {
                hostname: "host-1".into(),
                os: "Test".into(),
                os_version: "1".into(),
            }
        }
    }

    fn file_event(kind: EventKind, fields: serde_json::Value) -> SubstrateEvent {
        SubstrateEvent {
            kind,
            ts: 0,
            fields,
        }
    }

    /// Builds a `ModuleCtx` around a StubBus + capturing emitter for the e2e tests.
    fn make_ctx(bus: Arc<StubBus>, emitter: Arc<CapturingEmitter>) -> ModuleCtx {
        ModuleCtx {
            bus,
            snapshot: Arc::new(FakeSnapshot),
            emitter,
            governor: Arc::new(ResourceGovernor::new(
                ResourceBudget::default(),
                Box::new(TestSampler),
            )),
            tenant_id: "t".into(),
            product: "torda".into(),
            version: "0".into(),
        }
    }

    /// Drives the module's background task until it has emitted at least `want`
    /// envelopes, or a bounded number of polls elapse (so a bug can't hang CI).
    async fn drain_until(emitter: &CapturingEmitter, want: usize) {
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(2)).await;
            if emitter.emitted.lock().unwrap().len() >= want {
                break;
            }
        }
    }

    #[tokio::test]
    async fn detection_write_to_sensitive_config_emits_one_high_envelope() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = FileMonModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap(); // subscribes before we publish

        bus.publish(file_event(
            EventKind::FileWrite,
            serde_json::json!({ "path": "/etc/passwd", "pid": 42, "image": "vim" }),
        ));

        drain_until(&emitter, 1).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(
            emitted.len(),
            1,
            "exactly one envelope for the watched sensitive write"
        );
        let env = &emitted[0];
        assert_eq!(env.class_uid, class::FILE_SYSTEM_ACTIVITY);
        assert_eq!(env.class_name, "File System Activity");
        assert_eq!(env.severity_id, SEV_HIGH);
        assert_eq!(env.data["file"]["path"], "/etc/passwd");
        assert_eq!(env.data["file"]["op"], "write");
        let rules: Vec<&str> = env.data["detections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["rule"].as_str().unwrap())
            .collect();
        assert!(
            rules.contains(&"write_to_sensitive_config"),
            "rules: {rules:?}"
        );
    }

    #[tokio::test]
    async fn benign_watched_path_emits_nothing() {
        // INVERTED expectation (was: "a considered-but-benign event still
        // emits one Informational envelope with empty detections"). A live
        // elevated ETW run showed that contract floods the emitter with a
        // steady stream of empty-`detections` records for ordinary DLL reads
        // under \windows\system32\ — so filemon now emits ONLY flagged
        // activity. A considered-but-clean event must emit ZERO envelopes.
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = FileMonModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // A considered-but-benign read: watched (under /usr/bin/) but no
        // rule fires for a read (only writes trip write_to_system_dir).
        bus.publish(file_event(
            EventKind::FileOpen,
            serde_json::json!({ "path": "/usr/bin/ls", "pid": 7, "image": "bash" }),
        ));

        // Trailing VALID, flagged event is a deterministic sync point: the
        // broadcast bus is ordered, so once THIS one is emitted we KNOW the
        // benign open above was already processed (and dropped).
        bus.publish(file_event(
            EventKind::FileWrite,
            serde_json::json!({ "path": "/etc/passwd", "pid": 999, "image": "sync" }),
        ));

        drain_until(&emitter, 1).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(
            emitted.len(),
            1,
            "the benign open must emit nothing; only the trailing flagged sync event emits"
        );
        assert_eq!(emitted[0].data["file"]["path"], "/etc/passwd");
    }

    #[tokio::test]
    async fn volume_burst_of_noise_emits_zero_envelopes() {
        // ⚠️ THE VOLUME TEST — the point of this slice. Publish ~50 realistic
        // NOISE paths (temp/cache/log/proc/sys — Task 1's noise vector) as a
        // mix of FileOpen/FileWrite events: the prefilter must drop every
        // single one, so the emitter/bus/findings store see ZERO envelopes
        // under real volume.
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = FileMonModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        let noise = noise_paths();
        assert!(
            noise.len() >= 50,
            "expected >= 50 noise paths, got {}",
            noise.len()
        );
        for (i, path) in noise.iter().enumerate() {
            let kind = if i % 2 == 0 {
                EventKind::FileOpen
            } else {
                EventKind::FileWrite
            };
            bus.publish(file_event(
                kind,
                serde_json::json!({ "path": path, "pid": i as u64, "image": "noisy" }),
            ));
        }

        // A trailing VALID, watched event is a deterministic sync point: the
        // broadcast bus is ordered, so once THIS one is emitted we KNOW every
        // noise event before it was already processed (and dropped).
        bus.publish(file_event(
            EventKind::FileWrite,
            serde_json::json!({ "path": "/etc/passwd", "pid": 999, "image": "sync" }),
        ));

        drain_until(&emitter, 1).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(
            emitted.len(),
            1,
            "ALL {} noise events must be filtered; only the trailing sync event emits",
            noise.len()
        );
        assert_eq!(emitted[0].data["file"]["path"], "/etc/passwd");
    }

    #[tokio::test]
    async fn missing_path_event_is_skipped_without_panic() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = FileMonModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // Missing `path` entirely — must be skipped, no panic.
        bus.publish(file_event(
            EventKind::FileWrite,
            serde_json::json!({ "pid": 1, "image": "x" }),
        ));
        // `path` present but the wrong type (a number, not a string) — must
        // also be skipped, no panic.
        bus.publish(file_event(
            EventKind::FileWrite,
            serde_json::json!({ "path": 12345, "pid": 2, "image": "x" }),
        ));
        // Trailing VALID event = ordered sync point.
        bus.publish(file_event(
            EventKind::FileWrite,
            serde_json::json!({ "path": "/etc/passwd", "pid": 3, "image": "sync" }),
        ));

        drain_until(&emitter, 1).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(
            emitted.len(),
            1,
            "malformed path events skipped; only the trailing valid event emitted"
        );
        assert_eq!(emitted[0].data["pid"], 3);
    }

    #[tokio::test]
    async fn non_file_event_is_dropped_by_kind_guard() {
        // The stub bus forwards ALL event kinds regardless of the subscribe
        // filter, so a `NetConnect` event still reaches filemon's receiver.
        // The module's own kind-match guard must drop it, even if it carried
        // a `path`-shaped field by coincidence.
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = FileMonModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        bus.publish(SubstrateEvent {
            kind: EventKind::NetConnect,
            ts: 0,
            fields: serde_json::json!({ "path": "/etc/passwd", "pid": 9 }),
        });
        bus.publish(file_event(
            EventKind::FileWrite,
            serde_json::json!({ "path": "/etc/passwd", "pid": 10, "image": "sync" }),
        ));

        drain_until(&emitter, 1).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(
            emitted.len(),
            1,
            "NetConnect dropped by the kind guard; only the write emitted"
        );
        assert_eq!(emitted[0].data["pid"], 10);
    }
}
