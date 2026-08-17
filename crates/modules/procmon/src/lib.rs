//! Process-monitor module — the first module that CONSUMES EventBus events.
//!
//! It subscribes to `ProcessExec` and `ProcessExit` on the shared substrate
//! bus, emits one OCSF Process Activity record per exec (flagging suspicious
//! execs via the pure ruleset [`assess`]), and correlates each exit back to its
//! exec by pid to compute a process lifetime and flag short-lived-suspicious
//! processes ([`assess_lifecycle`]). It reads only the bus and emits — it never
//! touches the OS. The substrate is the only door.
//!
//! # Severity scheme
//! We map a hit to a small numeric severity independent of any source label:
//! `1 = Informational`, `2 = Low`, `3 = Medium`, `4 = High`. An execution's
//! `severity_id` is the MAX over its rule hits, or `1` when nothing fired.
//!
//! # Honest limits
//! Today the ruleset only sees the process **image** (path or short comm name).
//! Command line, file hash, signer, and parent process are not available on the
//! stub bus and are deliberate follow-ups; a benign binary invoked from a
//! suspicious path, or a renamed LOLBin, will be judged on name/path alone.
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;
use torda_core::{EventKind, Module, ModuleCtx, ModuleHealth, ModuleId, SubstrateEvent};
use torda_ocsf::{class, Device, Metadata, OcsfEnvelope};

// ---------------- Severity scheme ----------------
//
// `SEV_INFORMATIONAL` — no rule fired — a routine execution.
// `SEV_MEDIUM` — dual-use / suspicious-location execution worth a human glance.
// `SEV_HIGH` — a COMBINED attacker signal — materially worse than either weak
// signal alone (e.g. a dual-use / LOLBin binary staged in a world-writable
// path). Reserved for correlated rules like `lolbin_in_suspicious_path`.
//
// Values live in `torda_core::severity` (the single source of truth shared by
// every module); re-exported here so `torda_mod_procmon::SEV_*` keeps working.
pub use torda_core::severity::{SEV_HIGH, SEV_INFORMATIONAL, SEV_MEDIUM};

/// A process whose total lifetime is below this many milliseconds is "short
/// lived". Combined with an already-suspicious image this is a weak evasion
/// signal (fire-and-exit tooling), surfaced by [`assess_lifecycle`].
pub const SHORT_LIVED_MS: i64 = 500;

// ---------------- Ruleset (pure, deterministic, I/O-free) ----------------

/// One rule firing against a process image.
pub struct RuleHit {
    /// Stable rule identifier (e.g. `"lolbin"`, `"suspicious_path"`).
    pub rule: &'static str,
    /// Human-readable rationale for this specific hit.
    pub reason: String,
}

/// The verdict for one process image: a MAX severity plus every rule that fired.
pub struct Assessment {
    /// `1 = Informational, 2 = Low, 3 = Medium, 4 = High`. MAX over `hits`.
    pub severity_id: u8,
    pub hits: Vec<RuleHit>,
}

/// Living-off-the-land / dual-use binaries, matched by BASENAME.
///
/// Rationale: these ship with the OS (or common toolchains) and are routinely
/// abused to download, decode, or execute payloads without dropping new files,
/// so an exec of one is worth surfacing even though it is often benign.
const LOLBINS: &[&str] = &[
    // Windows
    "powershell",
    "cmd",
    "wscript",
    "cscript",
    "mshta",
    "regsvr32",
    "rundll32",
    "certutil",
    "bitsadmin",
    "msbuild",
    // Linux
    "nc",
    "ncat",
    "socat",
    "xxd",
    "base64",
    "nmap",
    "wget",
    "curl",
];

/// Directory substrings (case-insensitive) that commonly stage attacker tooling.
///
/// Rationale: world-writable / user-download locations are the usual launch pad
/// for dropped payloads; execution FROM one of these is a weak-but-useful signal.
const SUSPICIOUS_PATHS: &[&str] = &[r"\temp\", r"\downloads\", "/tmp/", "/dev/shm/", "/var/tmp/"];

/// Reduces an image to a lowercased basename: strips the directory (last `\` or
/// `/`) and a trailing `.exe`. Pure; used for LOLBin matching.
fn basename(image: &str) -> String {
    let last = image.rsplit(['\\', '/']).next().unwrap_or(image);
    let lower = last.to_lowercase();
    lower
        .strip_suffix(".exe")
        .map(str::to_string)
        .unwrap_or(lower)
}

/// Severity for a given rule id. Keeps the scheme explicit and per-rule.
fn rule_severity(rule: &str) -> u8 {
    match rule {
        "lolbin" => SEV_MEDIUM,
        "suspicious_path" => SEV_MEDIUM,
        // Correlated signal: a LOLBin launched FROM a suspicious path is worse
        // than either weak signal on its own, so it earns a strictly HIGHER band.
        "lolbin_in_suspicious_path" => SEV_HIGH,
        // Lifecycle correlation: an already-suspicious image that exits quickly.
        "short_lived_suspicious" => SEV_MEDIUM,
        _ => SEV_INFORMATIONAL,
    }
}

/// Assess a process image (full path or short comm name). Pure + deterministic:
/// no I/O, no OS, no allocation beyond the returned hits.
pub fn assess(image: &str) -> Assessment {
    let mut hits: Vec<RuleHit> = Vec::new();

    // (a) LOLBin / dual-use by basename (case-insensitive, .exe-stripped).
    let base = basename(image);
    let is_lolbin = LOLBINS.contains(&base.as_str());
    if is_lolbin {
        hits.push(RuleHit {
            rule: "lolbin",
            reason: format!("'{base}' is a known living-off-the-land / dual-use binary"),
        });
    }

    // (b) Suspicious launch directory (case-insensitive substring).
    let lower = image.to_lowercase();
    let suspicious_dir = SUSPICIOUS_PATHS.iter().find(|p| lower.contains(**p));
    if let Some(pat) = suspicious_dir {
        hits.push(RuleHit {
            rule: "suspicious_path",
            reason: format!("image path contains suspicious directory '{pat}'"),
        });
    }

    // (c) Correlated HIGH signal: a LOLBin executing FROM a suspicious directory
    // (a dual-use payload staged in a world-writable / temp path) is materially
    // worse than either weak signal alone, so it fires its own HIGH-severity rule.
    // This gives the MAX-over-hits severity a genuinely differentiated band to
    // pick, rather than every rule collapsing to Medium.
    if is_lolbin {
        if let Some(pat) = suspicious_dir {
            hits.push(RuleHit {
                rule: "lolbin_in_suspicious_path",
                reason: format!(
                    "living-off-the-land binary '{base}' launched from suspicious directory '{pat}'"
                ),
            });
        }
    }

    let severity_id = hits
        .iter()
        .map(|h| rule_severity(h.rule))
        .max()
        .unwrap_or(SEV_INFORMATIONAL);

    Assessment { severity_id, hits }
}

/// Lifecycle rule: flag an already-suspicious process that exits quickly.
///
/// Pure + deterministic (no I/O, no OS). Fires `Some(short_lived_suspicious)` at
/// [`SEV_MEDIUM`] ONLY when BOTH hold:
/// 1. the image is already suspicious by name/path — `assess(image).severity_id
///    > SEV_INFORMATIONAL` — so a benign short-lived process never fires; and
/// 2. the process was short lived — `lifetime_ms < SHORT_LIVED_MS` (strict, so
///    the boundary value `SHORT_LIVED_MS` itself does NOT fire).
///
/// A benign short-lived process, or a long-lived suspicious one, returns `None`.
pub fn assess_lifecycle(image: &str, lifetime_ms: i64) -> Option<RuleHit> {
    if assess(image).severity_id > SEV_INFORMATIONAL && lifetime_ms < SHORT_LIVED_MS {
        Some(RuleHit {
            rule: "short_lived_suspicious",
            reason: format!(
                "suspicious image '{image}' exited after {lifetime_ms}ms (< {SHORT_LIVED_MS}ms)"
            ),
        })
    } else {
        None
    }
}

// ---------------- Module ----------------

/// Largest number of un-correlated execs we retain awaiting an exit. Bounds
/// memory on a busy host (or when exits are lost): at the cap the OLDEST pending
/// exec is evicted so the map can never grow without limit.
const MAX_PENDING: usize = 4096;

/// An exec we've seen but not yet matched to an exit. Task-local state, keyed by
/// pid; a later exit for the same pid correlates against it to derive lifetime.
struct PendingExec {
    /// The exec-time image — the honest image to attribute the exit to, and the
    /// one re-assessed for the lifecycle rule.
    image: String,
    /// Exec timestamp; `exit.ts - exec_ts` (clamped) is the lifetime.
    exec_ts: i64,
}

/// Subscribes to `ProcessExec` + `ProcessExit`, emits one OCSF Process Activity
/// record per exec (flagged by [`assess`]) and one per exit (correlated to its
/// exec by pid, flagged by [`assess_lifecycle`]).
#[derive(Default)]
pub struct ProcMonModule {
    ctx: Option<ModuleCtx>,
    /// Signals the background task to stop; `true` == please exit.
    stop_tx: Option<tokio::sync::watch::Sender<bool>>,
    /// Handle to the bus-reading task, awaited (bounded) on `stop`.
    task: Option<tokio::task::JoinHandle<()>>,
    /// Live size of the task-local `pending` map, mirrored for `health()`.
    pending_len: Arc<AtomicUsize>,
    /// Count of pending execs dropped by the cap, surfaced in `health()` — the
    /// bound is never silent.
    evicted: Arc<AtomicU64>,
}

impl ProcMonModule {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Routes a bus event to the exec or exit handler. The stub bus forwards ALL
/// kinds regardless of the subscribe filter, so any other kind is dropped here.
/// A malformed event is SKIPPED by the handlers — never a panic.
fn handle_event(
    ev: &SubstrateEvent,
    meta: &Metadata,
    device: &Device,
    emitter: &dyn torda_core::OcsfEmitter,
    pending: &mut HashMap<u32, PendingExec>,
    pending_len: &AtomicUsize,
    evicted: &AtomicU64,
) {
    match ev.kind {
        EventKind::ProcessExec => {
            handle_exec(ev, meta, device, emitter, pending, pending_len, evicted)
        }
        EventKind::ProcessExit => handle_exit(ev, meta, device, emitter, pending, pending_len),
        _ => {} // not ours; drop.
    }
}

/// Extracts `pid` + `image` from an exec and emits its Process Activity record,
/// then records the exec so a later exit can be correlated. A malformed event
/// (missing either field) is SKIPPED — no panic.
fn handle_exec(
    ev: &SubstrateEvent,
    meta: &Metadata,
    device: &Device,
    emitter: &dyn torda_core::OcsfEmitter,
    pending: &mut HashMap<u32, PendingExec>,
    pending_len: &AtomicUsize,
    evicted: &AtomicU64,
) {
    let pid = match ev.fields.get("pid").and_then(serde_json::Value::as_u64) {
        Some(p) => p,
        None => return,
    };
    let image = match ev.fields.get("image").and_then(serde_json::Value::as_str) {
        Some(s) => s,
        None => return,
    };

    // ---- exec emit: preserved byte-for-byte from the original handler ----
    let a = assess(image);
    let detections: Vec<serde_json::Value> = a
        .hits
        .iter()
        .map(|h| serde_json::json!({ "rule": h.rule, "reason": h.reason }))
        .collect();

    let mut env = OcsfEnvelope::new(
        class::PROCESS_ACTIVITY,
        "Process Activity",
        meta.clone(),
        device.clone(),
        serde_json::json!({
            "activity": "exec",
            "process": { "pid": pid, "image": image },
            "detections": detections,
        }),
    );
    // OcsfEnvelope::new defaults severity_id to 1; override with our verdict.
    env.severity_id = a.severity_id;
    emitter.emit(env);
    // ---- end preserved exec emit ----

    // Record the exec for later correlation. `insert` OVERWRITES any prior entry
    // for this pid (most-recent-exec-wins): on the ORDERED bus a pid is always
    // freed by an exit before it is reused, and even if an exit were lost the
    // stale entry is replaced here — so a reused pid can never mis-correlate.
    let key = pid as u32;
    if !pending.contains_key(&key) && pending.len() >= MAX_PENDING {
        // Bounded map: at the cap, evict the OLDEST (lowest exec_ts) pending
        // exec and count it — never a silent drop, never unbounded growth.
        if let Some(oldest) = pending
            .iter()
            .min_by_key(|(_, p)| p.exec_ts)
            .map(|(k, _)| *k)
        {
            pending.remove(&oldest);
            evicted.fetch_add(1, Ordering::Relaxed);
        }
    }
    pending.insert(
        key,
        PendingExec {
            image: image.to_string(),
            exec_ts: ev.ts,
        },
    );
    pending_len.store(pending.len(), Ordering::Relaxed);
}

/// Correlates an exit back to its exec by pid, computes the (clamped) lifetime,
/// runs [`assess_lifecycle`], and emits the exit Process Activity record. A
/// malformed event (missing pid or image) is SKIPPED — no panic.
fn handle_exit(
    ev: &SubstrateEvent,
    meta: &Metadata,
    device: &Device,
    emitter: &dyn torda_core::OcsfEmitter,
    pending: &mut HashMap<u32, PendingExec>,
    pending_len: &AtomicUsize,
) {
    let pid = match ev.fields.get("pid").and_then(serde_json::Value::as_u64) {
        Some(p) => p,
        None => return,
    };
    let exit_image = match ev.fields.get("image").and_then(serde_json::Value::as_str) {
        Some(s) => s,
        None => return,
    };

    let key = pid as u32;
    let (image, lifetime_ms, lifecycle_hit, exec_severity) = match pending.remove(&key) {
        Some(p) => {
            // Correlated. Clamp non-negative: clock jitter or event reordering
            // must never yield a negative lifetime.
            let lifetime_ms = (ev.ts - p.exec_ts).max(0);
            let hit = assess_lifecycle(&p.image, lifetime_ms);
            let exec_sev = assess(&p.image).severity_id;
            (p.image, serde_json::json!(lifetime_ms), hit, exec_sev)
        }
        None => {
            // Uncorrelated: no exec on record. We do NOT guess a lifetime —
            // `null` is the honest answer, and no lifecycle rule can fire
            // without one. Severity is assessed from the exit image alone.
            (
                exit_image.to_string(),
                serde_json::Value::Null,
                None,
                assess(exit_image).severity_id,
            )
        }
    };
    pending_len.store(pending.len(), Ordering::Relaxed);

    let mut detections: Vec<serde_json::Value> = Vec::new();
    let lifecycle_severity = match &lifecycle_hit {
        Some(h) => {
            detections.push(serde_json::json!({ "rule": h.rule, "reason": h.reason }));
            rule_severity(h.rule)
        }
        None => SEV_INFORMATIONAL,
    };

    let mut env = OcsfEnvelope::new(
        class::PROCESS_ACTIVITY,
        "Process Activity",
        meta.clone(),
        device.clone(),
        serde_json::json!({
            "activity": "exit",
            "process": { "pid": pid, "image": image },
            "lifetime_ms": lifetime_ms,
            "detections": detections,
        }),
    );
    // Severity is the MAX of the exec-time verdict and the lifecycle verdict.
    env.severity_id = exec_severity.max(lifecycle_severity);
    emitter.emit(env);
}

#[async_trait]
impl Module for ProcMonModule {
    fn id(&self) -> ModuleId {
        "procmon".to_string()
    }

    async fn init(&mut self, ctx: ModuleCtx) -> anyhow::Result<()> {
        self.ctx = Some(ctx);
        Ok(())
    }

    async fn start(&mut self) -> anyhow::Result<()> {
        let ctx = self
            .ctx
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("procmon: init before start"))?;

        // Subscribe on the shared bus; capture only what the task needs (so it
        // owns no `ModuleCtx` reference and stays `'static`).
        let mut rx = ctx
            .bus
            .subscribe(&[EventKind::ProcessExec, EventKind::ProcessExit]);
        let meta = ctx.meta();
        let device = ctx.snapshot.device();
        let emitter = ctx.emitter.clone();
        let pending_len = self.pending_len.clone();
        let evicted = self.evicted.clone();

        let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            // Correlation state is TASK-LOCAL: this single task processes every
            // event serially, so the map needs no Mutex. Only the two counters
            // are shared (atomically) with `health()`.
            let mut pending: HashMap<u32, PendingExec> = HashMap::new();
            loop {
                tokio::select! {
                    _ = stop_rx.changed() => {
                        if *stop_rx.borrow() {
                            break;
                        }
                    }
                    r = rx.recv() => match r {
                        Ok(ev) => handle_event(
                            &ev, &meta, &device, emitter.as_ref(),
                            &mut pending, &pending_len, &evicted,
                        ),
                        Err(RecvError::Lagged(_)) => continue, // dropped events; keep reading
                        Err(RecvError::Closed) => break,        // bus gone; exit
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
            let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        }
        Ok(())
    }

    fn health(&self) -> ModuleHealth {
        let pending = self.pending_len.load(Ordering::Relaxed);
        let evicted = self.evicted.load(Ordering::Relaxed);
        ModuleHealth {
            ok: self.ctx.is_some(),
            detail: format!("process monitor ready; {pending} pending, {evicted} evicted"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use torda_core::{
        EventBus, OcsfEmitter, ResourceBudget, ResourceGovernor, ResourceSampler, ResourceUsage,
    };
    use torda_substrate::StubBus;

    // ---------- pure ruleset tests ----------

    fn rules(a: &Assessment) -> Vec<&'static str> {
        a.hits.iter().map(|h| h.rule).collect()
    }

    #[test]
    fn assess_windows_powershell_full_path_is_lolbin_medium() {
        let a = assess(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
        assert_eq!(a.severity_id, SEV_MEDIUM);
        assert_eq!(rules(&a), vec!["lolbin"]);
    }

    #[test]
    fn assess_tmp_path_is_suspicious_path_medium() {
        let a = assess("/tmp/evil");
        assert_eq!(a.severity_id, SEV_MEDIUM);
        assert_eq!(rules(&a), vec!["suspicious_path"]);
    }

    #[test]
    fn assess_is_case_insensitive_and_strips_exe() {
        let a = assess("powershell.EXE");
        assert_eq!(a.severity_id, SEV_MEDIUM);
        assert_eq!(rules(&a), vec!["lolbin"]);
    }

    #[test]
    fn assess_short_comm_name_is_lolbin() {
        let a = assess("nc");
        assert_eq!(a.severity_id, SEV_MEDIUM);
        assert_eq!(rules(&a), vec!["lolbin"]);
    }

    #[test]
    fn assess_benign_binary_is_informational_no_hits() {
        let a = assess("/usr/bin/echo");
        assert_eq!(a.severity_id, SEV_INFORMATIONAL);
        assert!(a.hits.is_empty());
    }

    #[test]
    fn assess_lolbin_in_suspicious_path_hits_all_three_max_is_high() {
        // powershell (lolbin) launched from a Temp dir (suspicious_path) ALSO fires
        // the correlated `lolbin_in_suspicious_path` rule. Three hits with DIFFERING
        // per-rule severities (Medium, Medium, High); the reported severity is the
        // strict MAX = High — proving max(a, b) is genuinely > either Medium.
        let a = assess(r"C:\Users\me\AppData\Local\Temp\powershell.exe");
        assert_eq!(a.severity_id, SEV_HIGH);
        assert_ne!(a.severity_id, SEV_MEDIUM);
        assert_eq!(
            rules(&a),
            vec!["lolbin", "suspicious_path", "lolbin_in_suspicious_path"]
        );
    }

    #[test]
    fn assess_severity_is_strict_max_over_differing_rule_severities() {
        // A single image (`/tmp/nc`) matches THREE rules with DIFFERENT per-rule
        // severities: lolbin=Medium(3), suspicious_path=Medium(3),
        // lolbin_in_suspicious_path=High(4). The verdict must be the strict MAX
        // (High), not any lower matched hit — this is what makes "MAX" testable
        // (before the HIGH rule existed, every rule was Medium so MAX == any).
        assert_eq!(rule_severity("lolbin"), SEV_MEDIUM);
        assert_eq!(rule_severity("suspicious_path"), SEV_MEDIUM);
        assert_eq!(rule_severity("lolbin_in_suspicious_path"), SEV_HIGH);

        let a = assess("/tmp/nc");
        assert_eq!(
            rules(&a),
            vec!["lolbin", "suspicious_path", "lolbin_in_suspicious_path"]
        );
        let max = a.hits.iter().map(|h| rule_severity(h.rule)).max().unwrap();
        assert_eq!(a.severity_id, SEV_HIGH);
        assert_eq!(a.severity_id, max, "severity is the max over all hits");
        assert_ne!(
            a.severity_id, SEV_MEDIUM,
            "max differs from the lower Medium hits"
        );
    }

    // ---------- pure assess_lifecycle tests ----------

    #[test]
    fn lifecycle_short_lived_lolbin_fires_medium() {
        // Suspicious image (nc == lolbin) that exits in 4ms → the rule fires.
        let hit = assess_lifecycle("nc", 4).expect("short-lived lolbin must fire");
        assert_eq!(hit.rule, "short_lived_suspicious");
        assert_eq!(rule_severity(hit.rule), SEV_MEDIUM);
        // Non-vacuous: the underlying image really is suspicious on its own.
        assert!(assess("nc").severity_id > SEV_INFORMATIONAL);
    }

    #[test]
    fn lifecycle_short_lived_benign_does_not_fire() {
        // Benign image, even though it is short-lived, must NOT fire: the first
        // predicate (image already suspicious) is false.
        assert_eq!(assess("/usr/bin/echo").severity_id, SEV_INFORMATIONAL);
        assert!(assess_lifecycle("/usr/bin/echo", 4).is_none());
    }

    #[test]
    fn lifecycle_long_lived_lolbin_does_not_fire() {
        // Suspicious image, but long-lived (60s) → the lifetime predicate is
        // false, so the rule must NOT fire.
        assert!(assess("nc").severity_id > SEV_INFORMATIONAL);
        assert!(assess_lifecycle("nc", 60_000).is_none());
    }

    #[test]
    fn lifecycle_boundary_is_strict_less_than() {
        // Just below the threshold fires; AT and ABOVE it does not (strict `<`).
        assert!(assess_lifecycle("nc", SHORT_LIVED_MS - 1).is_some());
        assert!(assess_lifecycle("nc", SHORT_LIVED_MS).is_none());
        assert!(assess_lifecycle("nc", SHORT_LIVED_MS + 1).is_none());
    }

    // ---------- end-to-end via StubBus + capturing emitter ----------

    #[derive(Default)]
    struct CapturingEmitter {
        emitted: Mutex<Vec<OcsfEnvelope>>,
    }
    impl OcsfEmitter for CapturingEmitter {
        fn emit(&self, rec: OcsfEnvelope) {
            self.emitted.lock().unwrap().push(rec);
        }
    }

    struct TestSampler;
    impl ResourceSampler for TestSampler {
        fn sample(&self) -> ResourceUsage {
            ResourceUsage::ZERO
        }
    }

    // A minimal snapshot: procmon only calls `device()`.
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

    fn exec_event(fields: serde_json::Value) -> SubstrateEvent {
        SubstrateEvent {
            kind: EventKind::ProcessExec,
            ts: 0,
            fields,
        }
    }

    fn exec_event_ts(ts: i64, fields: serde_json::Value) -> SubstrateEvent {
        SubstrateEvent {
            kind: EventKind::ProcessExec,
            ts,
            fields,
        }
    }

    fn exit_event(ts: i64, fields: serde_json::Value) -> SubstrateEvent {
        SubstrateEvent {
            kind: EventKind::ProcessExit,
            ts,
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
    async fn subscribe_assess_emit_flags_suspicious_and_skips_malformed() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let ctx = make_ctx(bus.clone(), emitter.clone());

        let mut m = ProcMonModule::new();
        m.init(ctx).await.unwrap();
        m.start().await.unwrap(); // subscribes before we publish

        bus.publish(exec_event(
            serde_json::json!({ "pid": 123, "image": "/usr/bin/echo" }),
        ));
        bus.publish(exec_event(
            serde_json::json!({ "pid": 200, "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" }),
        ));
        bus.publish(exec_event(
            serde_json::json!({ "pid": 300, "image": "/tmp/evil" }),
        ));
        // Malformed: no `image` — must be skipped, no panic, no envelope.
        bus.publish(exec_event(serde_json::json!({ "pid": 1 })));

        // Let the background task drain the broadcast channel.
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(2)).await;
            if emitter.emitted.lock().unwrap().len() >= 3 {
                break;
            }
        }
        m.stop().await.unwrap(); // clean shutdown

        let emitted = emitter.emitted.lock().unwrap();
        // Exactly one envelope per VALID event; malformed produced none.
        assert_eq!(
            emitted.len(),
            3,
            "one emit per valid exec, malformed skipped"
        );
        for env in emitted.iter() {
            assert_eq!(env.class_uid, class::PROCESS_ACTIVITY);
            assert_eq!(env.class_name, "Process Activity");
            assert_eq!(env.data["activity"], "exec");
        }

        let by_pid = |pid: u64| -> &OcsfEnvelope {
            emitted
                .iter()
                .find(|e| e.data["process"]["pid"] == pid)
                .expect("envelope for pid")
        };

        // Benign echo: Informational, no detections.
        let echo = by_pid(123);
        assert_eq!(echo.severity_id, SEV_INFORMATIONAL);
        assert_eq!(echo.data["detections"].as_array().unwrap().len(), 0);

        // powershell: Medium, lolbin detection.
        let ps = by_pid(200);
        assert_eq!(ps.severity_id, SEV_MEDIUM);
        let ps_rules: Vec<&str> = ps.data["detections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["rule"].as_str().unwrap())
            .collect();
        assert_eq!(ps_rules, vec!["lolbin"]);

        // /tmp/evil: Medium, suspicious_path detection.
        let evil = by_pid(300);
        assert_eq!(evil.severity_id, SEV_MEDIUM);
        let evil_rules: Vec<&str> = evil.data["detections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["rule"].as_str().unwrap())
            .collect();
        assert_eq!(evil_rules, vec!["suspicious_path"]);
    }

    #[tokio::test]
    async fn missing_pid_event_is_skipped_like_missing_image() {
        // A ProcessExec carrying an `image` but NO `pid` is malformed and MUST be
        // skipped — the same safety branch as the missing-`image` case in the e2e
        // above. This pins down the previously-untested missing-pid path.
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = ProcMonModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // Malformed (no pid) — must produce nothing.
        bus.publish(exec_event(serde_json::json!({ "image": "/usr/bin/echo" })));
        // A trailing VALID exec is a deterministic sync point: the broadcast bus is
        // ordered, so once THIS one is emitted we KNOW the malformed one before it
        // was already processed (and dropped).
        bus.publish(exec_event(
            serde_json::json!({ "pid": 7, "image": "/tmp/nc" }),
        ));

        drain_until(&emitter, 1).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(
            emitted.len(),
            1,
            "missing-pid event skipped; only the valid exec emitted"
        );
        assert_eq!(emitted[0].data["process"]["pid"], 7);
    }

    #[tokio::test]
    async fn non_process_exec_event_is_dropped_by_kind_guard() {
        // The stub bus forwards ALL event kinds regardless of the subscribe filter,
        // so a `FileOpen` event still reaches procmon's receiver. The module's own
        // `kind != ProcessExec` guard must drop it — even though its fields look like
        // a perfectly well-formed exec (pid + image present). This proves the guard.
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = ProcMonModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // Non-exec kind with well-formed exec-looking fields: must be dropped.
        bus.publish(SubstrateEvent {
            kind: EventKind::FileOpen,
            ts: 0,
            fields: serde_json::json!({ "pid": 9, "image": "/bin/x" }),
        });
        // Trailing VALID exec = ordered sync point (see missing-pid test).
        bus.publish(exec_event(
            serde_json::json!({ "pid": 10, "image": "/usr/bin/echo" }),
        ));

        drain_until(&emitter, 1).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(
            emitted.len(),
            1,
            "FileOpen dropped by the kind guard; only the exec emitted"
        );
        assert_eq!(emitted[0].data["process"]["pid"], 10);
    }

    // ---------- end-to-end lifecycle correlation (exec ↔ exit) ----------

    /// Longer-running drain for tests that publish many events; bounded so a bug
    /// cannot hang CI.
    async fn wait_until(emitter: &CapturingEmitter, want: usize) {
        for _ in 0..2000 {
            if emitter.emitted.lock().unwrap().len() >= want {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    #[tokio::test]
    async fn correlated_suspicious_exit_emits_lifetime_and_lifecycle_detection() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = ProcMonModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // exec(200, /tmp/nc) then exit(200) 4ms later: short-lived + suspicious.
        bus.publish(exec_event_ts(
            1000,
            serde_json::json!({ "pid": 200, "image": "/tmp/nc" }),
        ));
        bus.publish(exit_event(
            1004,
            serde_json::json!({ "pid": 200, "image": "/tmp/nc" }),
        ));

        drain_until(&emitter, 2).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(emitted.len(), 2, "one exec + one exit envelope");

        let exec = emitted
            .iter()
            .find(|e| e.data["activity"] == "exec")
            .expect("exec env");
        // Exec path unchanged: /tmp/nc is High today.
        assert_eq!(exec.severity_id, SEV_HIGH);
        assert_eq!(exec.data["process"]["pid"], 200);

        let exit = emitted
            .iter()
            .find(|e| e.data["activity"] == "exit")
            .expect("exit env");
        assert_eq!(exit.class_uid, class::PROCESS_ACTIVITY);
        assert_eq!(exit.data["process"]["pid"], 200);
        assert_eq!(exit.data["process"]["image"], "/tmp/nc");
        // lifetime_ms is a non-negative JSON number.
        let lt = exit.data["lifetime_ms"]
            .as_i64()
            .expect("lifetime is a number");
        assert_eq!(lt, 4);
        assert!(lt >= 0);
        // Detections include the lifecycle rule.
        let rules: Vec<&str> = exit.data["detections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["rule"].as_str().unwrap())
            .collect();
        assert!(
            rules.contains(&"short_lived_suspicious"),
            "lifecycle rule present"
        );
        // severity = MAX(exec High, lifecycle Medium) = High.
        assert_eq!(exit.severity_id, SEV_HIGH);
    }

    #[tokio::test]
    async fn uncorrelated_exit_has_null_lifetime_and_no_lifecycle_detection() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = ProcMonModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // Exit for a pid we never saw exec: honest null lifetime, no guess.
        bus.publish(exit_event(
            500,
            serde_json::json!({ "pid": 999, "image": "/tmp/nc" }),
        ));

        drain_until(&emitter, 1).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(emitted.len(), 1, "exactly one uncorrelated exit envelope");
        let exit = &emitted[0];
        assert_eq!(exit.data["activity"], "exit");
        assert_eq!(exit.data["process"]["pid"], 999);
        // lifetime_ms is JSON null — we never invent a lifetime.
        assert!(
            exit.data["lifetime_ms"].is_null(),
            "uncorrelated lifetime is null"
        );
        // No lifecycle detection can fire without a lifetime.
        assert_eq!(exit.data["detections"].as_array().unwrap().len(), 0);
        // Severity is the exit image's own verdict (/tmp/nc == High).
        assert_eq!(exit.severity_id, SEV_HIGH);
    }

    #[tokio::test]
    async fn benign_short_lived_pair_reports_lifetime_but_no_lifecycle_detection() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = ProcMonModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // Benign echo, short-lived: lifetime is reported but the rule stays quiet.
        bus.publish(exec_event_ts(
            10,
            serde_json::json!({ "pid": 42, "image": "/usr/bin/echo" }),
        ));
        bus.publish(exit_event(
            13,
            serde_json::json!({ "pid": 42, "image": "/usr/bin/echo" }),
        ));

        drain_until(&emitter, 2).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(emitted.len(), 2);
        let exit = emitted
            .iter()
            .find(|e| e.data["activity"] == "exit")
            .expect("exit env");
        assert_eq!(
            exit.data["lifetime_ms"].as_i64().unwrap(),
            3,
            "lifetime reported"
        );
        assert_eq!(
            exit.data["detections"].as_array().unwrap().len(),
            0,
            "benign short-lived does NOT fire the lifecycle rule"
        );
        assert_eq!(exit.severity_id, SEV_INFORMATIONAL);
    }

    #[tokio::test]
    async fn negative_delta_lifetime_is_clamped_to_zero() {
        // Exit timestamp BEFORE exec (clock jitter / reorder): lifetime clamps to
        // 0, never negative — and 0 < SHORT_LIVED_MS so the suspicious rule fires.
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = ProcMonModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        bus.publish(exec_event_ts(
            1000,
            serde_json::json!({ "pid": 7, "image": "/tmp/nc" }),
        ));
        bus.publish(exit_event(
            900,
            serde_json::json!({ "pid": 7, "image": "/tmp/nc" }),
        ));

        drain_until(&emitter, 2).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        let exit = emitted
            .iter()
            .find(|e| e.data["activity"] == "exit")
            .expect("exit env");
        assert_eq!(
            exit.data["lifetime_ms"].as_i64().unwrap(),
            0,
            "clamped to zero, never negative"
        );
    }

    #[tokio::test]
    async fn malformed_exit_without_pid_is_skipped() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = ProcMonModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // Malformed exit (no pid) → skipped, no panic, no envelope.
        bus.publish(exit_event(5, serde_json::json!({ "image": "/tmp/nc" })));
        // Ordered sync point: a valid exec after it proves the malformed exit was
        // already processed (and dropped).
        bus.publish(exec_event(
            serde_json::json!({ "pid": 11, "image": "/usr/bin/echo" }),
        ));

        drain_until(&emitter, 1).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(
            emitted.len(),
            1,
            "malformed exit skipped; only the exec emitted"
        );
        assert_eq!(emitted[0].data["activity"], "exec");
        assert_eq!(emitted[0].data["process"]["pid"], 11);
    }

    #[tokio::test]
    async fn pid_reuse_correlates_each_exit_to_its_own_exec() {
        // Same pid reused: exec A (/tmp/nc) / exit A / exec B (/usr/bin/echo) /
        // exit B. On the ordered bus each exit must correlate to the exec that
        // immediately preceded it — the overwrite-on-exec makes this safe.
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = ProcMonModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        bus.publish(exec_event_ts(
            0,
            serde_json::json!({ "pid": 50, "image": "/tmp/nc" }),
        ));
        bus.publish(exit_event(
            4,
            serde_json::json!({ "pid": 50, "image": "/tmp/nc" }),
        ));
        bus.publish(exec_event_ts(
            10,
            serde_json::json!({ "pid": 50, "image": "/usr/bin/echo" }),
        ));
        bus.publish(exit_event(
            13,
            serde_json::json!({ "pid": 50, "image": "/usr/bin/echo" }),
        ));

        wait_until(&emitter, 4).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        let exits: Vec<&OcsfEnvelope> = emitted
            .iter()
            .filter(|e| e.data["activity"] == "exit")
            .collect();
        assert_eq!(exits.len(), 2, "two exit envelopes");

        // First exit correlates to the suspicious /tmp/nc exec → lifecycle fires.
        let first = exits[0];
        assert_eq!(first.data["process"]["image"], "/tmp/nc");
        assert_eq!(first.data["lifetime_ms"].as_i64().unwrap(), 4);
        assert_eq!(first.severity_id, SEV_HIGH);
        let first_rules: Vec<&str> = first.data["detections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["rule"].as_str().unwrap())
            .collect();
        assert!(first_rules.contains(&"short_lived_suspicious"));

        // Second exit correlates to the benign echo exec → no lifecycle, Info.
        let second = exits[1];
        assert_eq!(second.data["process"]["image"], "/usr/bin/echo");
        assert_eq!(second.data["lifetime_ms"].as_i64().unwrap(), 3);
        assert_eq!(second.severity_id, SEV_INFORMATIONAL);
        assert_eq!(second.data["detections"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn pending_map_is_bounded_and_evicts_oldest() {
        // Insert MAX_PENDING+1 execs (distinct pids, increasing ts). The map is
        // capped at MAX_PENDING, so the OLDEST (lowest ts, pid 1) is evicted and
        // the eviction counter is surfaced in health(). A later exit of that
        // evicted pid is therefore uncorrelated (null lifetime).
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = ProcMonModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        let total = MAX_PENDING + 1;
        let mut published = 0usize;
        // Pace publishes so the bounded broadcast channel (cap 1024) never lags
        // and drops execs — we need every one to actually be inserted.
        while published < total {
            let end = (published + 400).min(total);
            for i in published..end {
                let pid = (i as u64) + 1; // pid 1..=total; ts i so pid 1 is oldest
                bus.publish(exec_event_ts(
                    i as i64,
                    serde_json::json!({ "pid": pid, "image": "/usr/bin/echo" }),
                ));
            }
            published = end;
            wait_until(&emitter, published).await;
        }
        // All execs processed.
        assert_eq!(emitter.emitted.lock().unwrap().len(), total);

        // Eviction happened and is visible in health, with the map at the cap.
        let h = m.health();
        assert!(
            h.detail.contains(&format!("{MAX_PENDING} pending")),
            "map held at cap: {}",
            h.detail
        );
        assert!(
            !h.detail.contains("0 evicted"),
            "some eviction occurred: {}",
            h.detail
        );
        assert!(h.detail.contains("evicted"));

        // Exit of the evicted pid (1) → uncorrelated, honest null lifetime.
        bus.publish(exit_event(
            9_000,
            serde_json::json!({ "pid": 1u64, "image": "/usr/bin/echo" }),
        ));
        wait_until(&emitter, total + 1).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(emitted.len(), total + 1);
        let exit = emitted.last().unwrap();
        assert_eq!(exit.data["activity"], "exit");
        assert_eq!(exit.data["process"]["pid"], 1);
        assert!(
            exit.data["lifetime_ms"].is_null(),
            "evicted pid exit is uncorrelated (null)"
        );
    }
}
