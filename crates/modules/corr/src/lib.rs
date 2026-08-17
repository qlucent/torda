//! Correlation module — the FIRST cross-sensor module.
//!
//! `torda-mod-procmon` (process) and `torda-mod-netmon` (network) each watch one
//! sensor and emit their own OCSF records independently. This module JOINS them
//! by pid to surface an **attack chain**: a suspicious process that then makes a
//! suspicious network connection. It subscribes to `ProcessExec` / `ProcessExit`
//! / `NetConnect` on the shared substrate bus, maintains a bounded
//! pid → process-context map from the exec stream, and on each `NetConnect`
//! looks the pid up, re-uses BOTH single-sensor rulesets
//! ([`torda_mod_procmon::assess`] + [`torda_mod_netmon::assess`]), and emits ONE
//! `CORRELATED_ACTIVITY` (9002) record. It reads only the bus and emits — it
//! never touches the OS, and it never re-implements either module's ruleset.
//!
//! # Correlated rule
//! `suspicious_process_suspicious_connection` fires **IFF BOTH** halves are
//! suspicious — the process verdict AND the connection verdict are each above
//! Informational (an AND, never an OR, never either-alone). When it fires the
//! record is [`SEV_HIGH`]; otherwise the record's severity is the MAX of the two
//! independent verdicts. procmon/netmon still emit their own records — this is a
//! DISTINCT class 9002 record, not a duplicate.
//!
//! # Honest limits
//! The join is by pid alone, on the ordered stub bus: an exec must be seen
//! before the connection to attribute it. A `NetConnect` for a pid with no prior
//! exec (or one already evicted by the cap) is emitted `attributed: false` with
//! a connection-only verdict — never guessed.
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast::error::RecvError;
use torda_core::severity::{SEV_HIGH, SEV_INFORMATIONAL};
use torda_core::{EventKind, Module, ModuleCtx, ModuleHealth, ModuleId, SubstrateEvent};
use torda_ocsf::{class, Device, Metadata, OcsfEnvelope};

/// Stable identifier of the process↔connection correlated rule.
const CORRELATED_RULE: &str = "suspicious_process_suspicious_connection";

/// Stable identifier of the process↔file-write correlated rule — the file
/// analog of [`CORRELATED_RULE`]. Fires IFF BOTH halves are suspicious: the
/// pid's cached exec verdict AND the file-write verdict
/// ([`torda_mod_filemon::assess`]). Same strict-AND contract as the connection
/// rule; the record is a DISTINCT class 9002 chain record.
const CORRELATED_FILE_RULE: &str = "suspicious_process_suspicious_file_write";

/// Stable identifier of the TRIPLE chain rule — the dropper-then-C2 attack
/// chain. Fires when ONE pid produced BOTH a suspicious file-write (that already
/// satisfied [`CORRELATED_FILE_RULE`]) AND a suspicious connection (that already
/// satisfied [`CORRELATED_RULE`]) within [`CHAIN_WINDOW`]. It is a CONJUNCTION of
/// the two EXISTING correlated verdicts — no signal is re-assessed here — emitted
/// as its own DISTINCT class 9002 record at [`SEV_HIGH`], additive to (never a
/// replacement for) the two component records which still fire independently.
const CORRELATED_CHAIN_RULE: &str = "suspicious_process_wrote_file_and_connected";

/// Stable identifier of the EXFIL chain rule — the data-exfiltration analog of
/// [`CORRELATED_CHAIN_RULE`]. Fires when ONE attributed pid produced BOTH a
/// suspicious sensitive-file READ (a `FileOpen` whose path trips filemon's
/// `read_of_sensitive_file` verdict under [`torda_mod_filemon::FilePolicy`], the
/// `write=false` path) AND a suspicious connection (that already satisfied
/// [`CORRELATED_RULE`]) within [`CHAIN_WINDOW`]. It is a CONJUNCTION of the read
/// verdict and the EXISTING connect verdict — emitted as its own DISTINCT class
/// 9002 record at [`SEV_HIGH`], additive to and fully independent of the write
/// triple (a pid that reads-sensitive AND writes-suspicious AND connects may fire
/// BOTH). The connect half requires a suspicious process, so this chain — like the
/// triple — is never built from a benign process.
const CORRELATED_EXFIL_RULE: &str = "suspicious_process_read_sensitive_and_connected";

/// The rule id filemon fires (and corr re-judges) for a sensitive-file READ. Kept
/// as a const so the `FileOpen` re-judge checks the SAME string filemon emits.
const READ_OF_SENSITIVE_FILE_RULE: &str = "read_of_sensitive_file";

/// Largest number of live process contexts we retain. Bounds memory on a busy
/// host (or when exits are lost): at the cap the OLDEST (lowest exec_ts) context
/// is evicted so the map can never grow without limit.
const MAX_TRACKED: usize = 4096;

/// How long an un-attributed `NetConnect` waits in the pending buffer for its
/// `ProcessExec` to arrive on the (separately drained) EVENTS ring before it is
/// flushed `attributed: false`. On the real eBPF substrate process and network
/// events are drained by different threads, so a connect can be processed BEFORE
/// its exec; buffering for this grace window makes correlation order-independent.
const GRACE: Duration = Duration::from_millis(250);

/// How long a just-exited pid's context is retained in `recently_exited` so a
/// LATE cross-ring event can still attribute to it. The high-volume
/// `sys_enter_openat` FILE_EVENTS ring is delivered to corr AFTER the EVENTS
/// ring, so a short-lived writer's `FileWrite` can be PROCESSED after its
/// `ProcessExit` has already evicted the live context — the write then misses
/// the live `map` and the pre-exec pending buffer cannot rescue it (the exec
/// already came and went). Retaining the exited context for this window closes
/// that gap. Chosen generous enough to cover FILE-ring delivery lag under load,
/// yet FAR below the Linux pid-recycle time, so a reused pid can never
/// mis-attribute the previous process's context within the window.
const EXITED_RETENTION: Duration = Duration::from_secs(1);

/// Largest number of recently-exited contexts retained. Bounds memory on a host
/// with high exit churn exactly as [`MAX_TRACKED`] bounds the live map: at the
/// cap the OLDEST (earliest `Instant`) retained context is evicted so
/// `recently_exited` can never grow without limit.
const MAX_RECENTLY_EXITED: usize = 4096;

/// Largest number of un-attributed connects held awaiting their exec. Bounds
/// memory the same way `MAX_TRACKED` bounds the context map: at the cap the
/// OLDEST pending connect (min `buffered_at`) is evicted and counted.
const MAX_PENDING_CONNECTS: usize = 4096;

/// Largest number of un-attributed file-writes held awaiting their exec — the
/// file analog of [`MAX_PENDING_CONNECTS`]. At the cap the OLDEST pending
/// file-write (min `buffered_at`) is evicted and counted.
const MAX_PENDING_FILE_WRITES: usize = 4096;

/// Largest number of un-attributed sensitive-file READS held awaiting their exec
/// — the read analog of [`MAX_PENDING_FILE_WRITES`]. At the cap the OLDEST pending
/// read (min `buffered_at`) is evicted and counted. Only reads that already
/// tripped `read_of_sensitive_file` are ever buffered, so this stays tiny.
const MAX_PENDING_FILE_READS: usize = 4096;

/// How close in time a pid's suspicious file-write half and suspicious connect
/// half must be for the TRIPLE [`CORRELATED_CHAIN_RULE`] to fire. Deliberately
/// LONGER than [`GRACE`]'s 250ms cross-ring window (which solves a different
/// problem — buffering a signal until its exec is drained): a dropper writes its
/// payload and then beacons out SECONDS later, so the two component findings for
/// one pid can be a few seconds apart yet still be one attack chain. A half older
/// than this window is too stale to chain (and is purged on the grace tick).
const CHAIN_WINDOW: Duration = Duration::from_secs(5);

/// Largest number of live per-pid chain trackers retained, bounding memory on a
/// busy host exactly as [`MAX_TRACKED`] bounds the context map: at the cap the
/// OLDEST entry (by the older of its two half-stamps) is evicted and counted so
/// the chain map can never grow without limit.
const MAX_CHAIN_TRACKED: usize = 4096;

/// A `NetConnect` seen before any `ProcessExec` for its pid: held for [`GRACE`]
/// so its exec can still correlate it (order-independent join). If the exec
/// arrives it is emitted `attributed: true`; otherwise it flushes
/// `attributed: false` on the grace timer or on stop. Task-local, keyed by pid.
struct PendingConnect {
    /// The connect-time comm — the name used only if this flushes un-attributed.
    image: String,
    /// Connection destination address (for the netmon verdict + record).
    daddr: String,
    /// Connection destination port (for the netmon verdict + record).
    dport: u16,
    /// The connect event's real protocol, preserved so the buffered emit paths
    /// (exec-drain, grace-flush, shutdown-flush) keep the same fidelity as the
    /// immediate path instead of hardcoding "tcp".
    proto: String,
    /// When it entered the buffer; drives the grace flush and oldest-eviction.
    buffered_at: Instant,
}

/// A `FileWrite` seen before any `ProcessExec` for its pid — the file analog of
/// [`PendingConnect`]. Held for [`GRACE`] so its exec can still correlate it
/// (order-independent join). If the exec arrives it is emitted
/// `attributed: true`; otherwise it flushes `attributed: false` on the grace
/// timer or on stop. Task-local, keyed by pid.
struct PendingFileWrite {
    /// The write-time image — the name used only if this flushes un-attributed.
    image: String,
    /// The written path. Already passed `FilePolicy::considers` before it was
    /// buffered, so the later filemon verdict + record use it directly.
    path: String,
    /// When it entered the buffer; drives the grace flush and oldest-eviction.
    buffered_at: Instant,
}

/// A sensitive-file `FileOpen` (read) seen before any `ProcessExec` for its pid —
/// the read analog of [`PendingFileWrite`]. Held for [`GRACE`] so its exec can
/// still attribute it (order-independent join). UNLIKE a pending write, a pending
/// read emits NO component record: corr does not re-emit filemon's read record, it
/// only feeds the EXFIL chain — so an over-grace read that never gets an exec is
/// simply forgotten (nothing to flush), never emitted un-attributed. Only reads
/// that already tripped `read_of_sensitive_file` are buffered here. Task-local,
/// keyed by pid.
struct PendingFileRead {
    /// The read path. Already `considers`'d AND confirmed a sensitive read before
    /// buffering, so the exec-drain re-judge re-confirms it deterministically.
    path: String,
    /// When it entered the buffer; drives the grace purge and oldest-eviction.
    buffered_at: Instant,
}

/// The exec-time verdict for a pid, captured from [`torda_mod_procmon::assess`] so a
/// later `NetConnect` on the same pid can be attributed back to the process that
/// opened it. Task-local state, keyed by pid.
struct ProcContext {
    /// The exec-time image — the honest process identity to attribute a
    /// connection to.
    image: String,
    /// The process verdict at exec time (MAX over procmon's hits). Drives the
    /// correlated-rule AND-test and the fallback severity.
    exec_severity: u8,
    /// The process's detections as ready-to-emit `{rule, reason}` objects,
    /// captured at exec time. Preserved in full (with reasons) so the correlated
    /// record is explainable — never re-derived, never lossy.
    exec_detections: Vec<serde_json::Value>,
    /// Exec timestamp; the oldest context is the eviction victim at the cap.
    exec_ts: i64,
}

/// The suspicious-file-write half of a pid's chain: captured ONLY when the file
/// component rule ([`CORRELATED_FILE_RULE`]) actually fired for an attributed,
/// suspicious write, so an un-attributed or benign write can never enter the
/// chain. Holds exactly what [`emit_correlated_chain`] needs to reconstruct the
/// `file` block + file detection set — never re-derived, never re-assessed.
struct ChainFileHalf {
    /// The suspicious written path (the `file.path` of the triple record).
    path: String,
    /// The file detections as ready-to-emit `{rule, reason}` objects, captured
    /// from the component emit so the triple is explainable without re-assessing.
    detections: Vec<serde_json::Value>,
    /// When this half was recorded; drives the [`CHAIN_WINDOW`] join + purge +
    /// oldest-eviction.
    stamp: Instant,
}

/// The suspicious sensitive-file-READ half of a pid's chain: captured ONLY when a
/// `FileOpen` for an ATTRIBUTED pid tripped filemon's `read_of_sensitive_file`
/// verdict (the `write=false` path), so an un-attributed or non-sensitive read can
/// never enter the chain. The read analog of [`ChainFileHalf`]; holds exactly what
/// [`emit_correlated_exfil`] needs to reconstruct the `file` block + read detection
/// set — never re-derived at emit time, never re-assessed.
struct ChainReadHalf {
    /// The sensitive read path (the `file.path` of the exfil record).
    path: String,
    /// The read detections as ready-to-emit `{rule, reason}` objects, captured
    /// from the re-judge so the exfil record is explainable without re-assessing.
    detections: Vec<serde_json::Value>,
    /// When this half was recorded; drives the [`CHAIN_WINDOW`] join + purge +
    /// oldest-eviction.
    stamp: Instant,
}

/// The suspicious-connect half of a pid's chain — the network analog of
/// [`ChainFileHalf`], captured ONLY when the connect component rule
/// ([`CORRELATED_RULE`]) actually fired for an attributed, suspicious connect.
struct ChainConnHalf {
    /// Connection destination address (the `connection.daddr` of the triple).
    daddr: String,
    /// Connection destination port (the `connection.dport` of the triple).
    dport: u16,
    /// Connection protocol, preserved at the fidelity of the component emit.
    proto: String,
    /// The connection detections as ready-to-emit `{rule, reason}` objects.
    detections: Vec<serde_json::Value>,
    /// When this half was recorded; drives the join + purge + oldest-eviction.
    stamp: Instant,
}

/// A pid's TRIPLE-chain tracker: the most-recent suspicious file-write half and
/// the most-recent suspicious connect half, plus a `fired` de-dup flag. The
/// triple fires the FIRST time BOTH halves are present within [`CHAIN_WINDOW`];
/// `fired` then blocks any re-fire (a pid that writes N× and connects M× emits
/// ONE triple, not N×M) until the entry is purged (both halves aged past the
/// window) or the pid exits. Task-local, keyed by pid. Both halves are `Option`
/// because they arrive independently and in either order.
#[derive(Default)]
struct ChainState {
    /// Most-recent suspicious file-write half, or `None` until one fires.
    file: Option<ChainFileHalf>,
    /// Most-recent suspicious sensitive-read half, or `None` until one fires.
    /// Drives the EXFIL chain alongside `conn`, independently of `file`.
    read: Option<ChainReadHalf>,
    /// Most-recent suspicious connect half, or `None` until one fires. Shared by
    /// BOTH chains — it completes the write triple (with `file`) AND the exfil
    /// chain (with `read`).
    conn: Option<ChainConnHalf>,
    /// Set once the WRITE TRIPLE has fired for this pid → never fires twice per
    /// chain.
    fired: bool,
    /// Set once the EXFIL chain has fired for this pid → never fires twice per
    /// chain. Independent of `fired` so a pid that both writes+connects AND
    /// reads+connects emits one triple AND one exfil, each exactly once.
    exfil_fired: bool,
}

impl ChainState {
    /// The entry's age for oldest-eviction: the EARLIEST of its (up to three)
    /// half-stamps (the oldest = when this chain first began). An entry with no
    /// half (transient) is treated as newest.
    fn oldest_stamp(&self) -> Instant {
        let mut oldest: Option<Instant> = None;
        for s in [
            self.file.as_ref().map(|f| f.stamp),
            self.read.as_ref().map(|r| r.stamp),
            self.conn.as_ref().map(|c| c.stamp),
        ]
        .into_iter()
        .flatten()
        {
            oldest = Some(oldest.map_or(s, |o| o.min(s)));
        }
        oldest.unwrap_or_else(Instant::now)
    }

    /// True once ALL present halves have aged past [`CHAIN_WINDOW`] (or it holds no
    /// halves): the entry can no longer form a valid chain of EITHER kind and is
    /// purged.
    fn is_expired(&self) -> bool {
        let file_old = self
            .file
            .as_ref()
            .is_none_or(|f| f.stamp.elapsed() >= CHAIN_WINDOW);
        let read_old = self
            .read
            .as_ref()
            .is_none_or(|r| r.stamp.elapsed() >= CHAIN_WINDOW);
        let conn_old = self
            .conn
            .as_ref()
            .is_none_or(|c| c.stamp.elapsed() >= CHAIN_WINDOW);
        file_old && read_old && conn_old
    }
}

/// Subscribes to `ProcessExec` + `ProcessExit` + `NetConnect`, maintains the
/// bounded pid → [`ProcContext`] map from the process stream, and emits one
/// `CORRELATED_ACTIVITY` record per `NetConnect` (joined by pid).
#[derive(Default)]
pub struct CorrModule {
    ctx: Option<ModuleCtx>,
    /// Signals the background task to stop; `true` == please exit.
    stop_tx: Option<tokio::sync::watch::Sender<bool>>,
    /// Handle to the bus-reading task, awaited (bounded) on `stop`.
    task: Option<tokio::task::JoinHandle<()>>,
    /// Live size of the task-local context map, mirrored for `health()`.
    tracked_len: Arc<AtomicUsize>,
    /// Count of contexts dropped by the cap, surfaced in `health()` — the bound
    /// is never silent.
    evicted: Arc<AtomicU64>,
    /// Live size of the task-local pending-connect buffer, mirrored for
    /// `health()`.
    pending_len: Arc<AtomicUsize>,
    /// Count of pending connects dropped by the `MAX_PENDING_CONNECTS` cap,
    /// surfaced in `health()` — the pending bound is never silent either.
    pending_evicted: Arc<AtomicU64>,
    /// Live size of the task-local pending-file-write buffer, mirrored for
    /// `health()`.
    file_pending_len: Arc<AtomicUsize>,
    /// Count of pending file-writes dropped by the `MAX_PENDING_FILE_WRITES`
    /// cap, surfaced in `health()` — the file pending bound is never silent.
    file_pending_evicted: Arc<AtomicU64>,
    /// Live size of the task-local pending-file-read buffer, mirrored for
    /// `health()`.
    read_pending_len: Arc<AtomicUsize>,
    /// Count of pending sensitive-reads dropped by the `MAX_PENDING_FILE_READS`
    /// cap, surfaced in `health()` — the read pending bound is never silent.
    read_pending_evicted: Arc<AtomicU64>,
    /// Live size of the task-local per-pid chain tracker, mirrored for
    /// `health()`.
    chain_len: Arc<AtomicUsize>,
    /// Count of chain entries dropped by the `MAX_CHAIN_TRACKED` cap, surfaced in
    /// `health()` — the chain bound is never silent either.
    chain_evicted: Arc<AtomicU64>,
}

impl CorrModule {
    pub fn new() -> Self {
        Self::default()
    }

    /// Test-only seam: start with a caller-chosen grace duration instead of
    /// the real [`GRACE`] constant, so a test can disable the grace-flush
    /// timer's *effect* (by making it huge) without touching production
    /// behavior — `start()` always calls [`Self::start_internal`] with the
    /// real `GRACE`. This exists ONLY to make
    /// `pending_buffer_is_bounded_and_counts_evictions` deterministic: with a
    /// huge grace the interval still ticks, but its expiry filter can never
    /// match during the test, so the buffer fill can never race the flush.
    #[cfg(test)]
    async fn start_with_grace(&mut self, grace: Duration) -> anyhow::Result<()> {
        self.start_internal(grace).await
    }

    /// Shared start logic behind both `start()` (real `GRACE`) and the
    /// test-only `start_with_grace` (custom grace). Spawns the task-local
    /// event loop that owns `map`/`pending` and drains the bus.
    async fn start_internal(&mut self, grace: Duration) -> anyhow::Result<()> {
        let ctx = self
            .ctx
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("corr: init before start"))?;

        // Subscribe on the shared bus; capture only what the task needs (so it
        // owns no `ModuleCtx` reference and stays `'static`).
        let mut rx = ctx.bus.subscribe(&[
            EventKind::ProcessExec,
            EventKind::ProcessExit,
            EventKind::NetConnect,
            EventKind::FileWrite,
            EventKind::FileOpen,
        ]);
        let meta = ctx.meta();
        let device = ctx.snapshot.device();
        let emitter = ctx.emitter.clone();
        let tracked_len = self.tracked_len.clone();
        let evicted = self.evicted.clone();
        let pending_len = self.pending_len.clone();
        let pending_evicted = self.pending_evicted.clone();
        let file_pending_len = self.file_pending_len.clone();
        let file_pending_evicted = self.file_pending_evicted.clone();
        let read_pending_len = self.read_pending_len.clone();
        let read_pending_evicted = self.read_pending_evicted.clone();
        let chain_len = self.chain_len.clone();
        let chain_evicted = self.chain_evicted.clone();

        let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            // Correlation state is TASK-LOCAL: this single task processes every
            // event serially, so neither map needs a Mutex. Only the counters
            // are shared (atomically) with `health()`.
            let mut map: HashMap<u32, ProcContext> = HashMap::new();
            // Connects seen before their exec, awaiting correlation for GRACE.
            // Keyed by pid, holding ALL of that pid's pre-exec connects (FIFO) so
            // a pid that opens ≥2 connects before its exec loses none.
            let mut pending: HashMap<u32, Vec<PendingConnect>> = HashMap::new();
            // File-writes seen before their exec, awaiting correlation for GRACE —
            // the file analog of `pending`, keyed by pid, holding ALL of that
            // pid's pre-exec writes (FIFO) so none is lost.
            let mut file_pending: HashMap<u32, Vec<PendingFileWrite>> = HashMap::new();
            // Sensitive reads seen before their exec, awaiting attribution for
            // GRACE — the read analog of `file_pending`. Keyed by pid, holding ALL
            // of that pid's pre-exec sensitive reads (FIFO). Unlike writes these
            // are never flushed un-attributed (reads emit no component) — an
            // over-grace read is just forgotten on the grace tick.
            let mut read_pending: HashMap<u32, Vec<PendingFileRead>> = HashMap::new();
            // Contexts of pids that have EXITED, retained for `EXITED_RETENTION`
            // so a LATE cross-ring event (a FILE_EVENTS-ring write delivered after
            // the pid's exit was already processed) can still attribute to the
            // process that made it. Keyed by pid → (context, exit instant).
            // Bounded by `MAX_RECENTLY_EXITED` (oldest-evict) and grace-purged.
            let mut recently_exited: HashMap<u32, (ProcContext, Instant)> = HashMap::new();
            // The TRIPLE-chain tracker: per-pid, holds the most-recent suspicious
            // file-write half and suspicious connect half plus a `fired` de-dup
            // flag. Populated ONLY by the two existing correlated paths when their
            // component rule actually fired, so nothing un-attributed or benign
            // ever enters it. Bounded by `MAX_CHAIN_TRACKED` (oldest-evict) and
            // purged on the grace tick once both halves age past `CHAIN_WINDOW`.
            let mut chain: HashMap<u32, ChainState> = HashMap::new();
            // The prefilter gate for file events, built ONCE for the task's life
            // (not per-event): only writes filemon itself would consider enter the
            // join. Matches filemon's contract AND keeps benign/high-volume writes
            // out of the correlation buffer.
            let file_policy = torda_mod_filemon::FilePolicy::default();
            // Backstop that flushes over-grace pending connects even with no more
            // bus traffic. First tick fires immediately (nothing pending — fine).
            let mut flush = tokio::time::interval(grace / 2);
            loop {
                tokio::select! {
                    _ = stop_rx.changed() => {
                        if *stop_rx.borrow() {
                            // Stop-flush: nothing is lost on shutdown. Every
                            // still-buffered connect is emitted un-attributed
                            // (its exec never came) BEFORE we break. Shared
                            // helper — see the `Closed` arm below for the
                            // symmetric bus-gone case.
                            flush_pending_on_shutdown(
                                &mut pending, &meta, &device, emitter.as_ref(), &pending_len,
                            );
                            flush_file_pending_on_shutdown(
                                &mut file_pending, &meta, &device, emitter.as_ref(), &file_pending_len,
                            );
                            break;
                        }
                    }
                    _ = flush.tick() => {
                        // Grace flush: within each pid's Vec, any connect whose exec
                        // never arrived within the grace window is emitted
                        // un-attributed and REMOVED (so it can never also emit
                        // elsewhere → exactly-once); the rest stay. A pid whose Vec
                        // becomes empty is dropped (no empty-Vec leak). Emit in
                        // buffered (FIFO) order.
                        let mut drained_pids: Vec<u32> = Vec::new();
                        for (pid, vec) in pending.iter_mut() {
                            let mut i = 0;
                            while i < vec.len() {
                                if vec[i].buffered_at.elapsed() >= grace {
                                    let pc = vec.remove(i);
                                    emit_correlated(
                                        &meta, &device, emitter.as_ref(),
                                        *pid as u64, false, &pc.image, SEV_INFORMATIONAL,
                                        &[], &pc.daddr, pc.dport, &pc.proto,
                                    );
                                } else {
                                    i += 1;
                                }
                            }
                            if vec.is_empty() {
                                drained_pids.push(*pid);
                            }
                        }
                        for pid in drained_pids {
                            pending.remove(&pid);
                        }
                        pending_len.store(pending_total(&pending), Ordering::Relaxed);

                        // Same grace flush for file-writes: any pid's write whose
                        // exec never arrived within the window is emitted
                        // un-attributed and REMOVED (exactly-once); the rest stay.
                        let mut drained_file_pids: Vec<u32> = Vec::new();
                        for (pid, vec) in file_pending.iter_mut() {
                            let mut i = 0;
                            while i < vec.len() {
                                if vec[i].buffered_at.elapsed() >= grace {
                                    let pfw = vec.remove(i);
                                    emit_correlated_file(
                                        &meta, &device, emitter.as_ref(),
                                        *pid as u64, false, &pfw.image, SEV_INFORMATIONAL,
                                        &[], &pfw.path,
                                    );
                                } else {
                                    i += 1;
                                }
                            }
                            if vec.is_empty() {
                                drained_file_pids.push(*pid);
                            }
                        }
                        for pid in drained_file_pids {
                            file_pending.remove(&pid);
                        }
                        file_pending_len.store(file_pending_total(&file_pending), Ordering::Relaxed);

                        // Grace PURGE for sensitive reads: any pid's read whose exec
                        // never arrived within the window is FORGOTTEN (reads emit no
                        // component, so there is nothing to flush un-attributed — the
                        // read simply can no longer attribute and is dropped). A pid
                        // whose Vec becomes empty is removed (no empty-Vec leak).
                        let mut drained_read_pids: Vec<u32> = Vec::new();
                        for (pid, vec) in read_pending.iter_mut() {
                            vec.retain(|pfr| pfr.buffered_at.elapsed() < grace);
                            if vec.is_empty() {
                                drained_read_pids.push(*pid);
                            }
                        }
                        for pid in drained_read_pids {
                            read_pending.remove(&pid);
                        }
                        read_pending_len.store(read_pending_total(&read_pending), Ordering::Relaxed);

                        // Purge recently-exited contexts past the retention window
                        // (mirrors the pending grace flush; keeps the map small
                        // under exit churn). These hold no un-emitted findings —
                        // they are only attribution helpers — so a purge emits
                        // nothing, it just forgets a context too old to attribute.
                        let mut expired_pids: Vec<u32> = Vec::new();
                        for (pid, (_, stamp)) in recently_exited.iter() {
                            if stamp.elapsed() >= EXITED_RETENTION {
                                expired_pids.push(*pid);
                            }
                        }
                        for pid in expired_pids {
                            recently_exited.remove(&pid);
                        }

                        // Purge chain entries whose BOTH halves have aged past
                        // `CHAIN_WINDOW` (or that hold no halves): they can no
                        // longer form a valid chain. A purge emits nothing — the
                        // halves were already emitted as their component records.
                        // Purging also RESETS `fired`, so a fresh write+connect in
                        // a NEW window can legitimately chain again (exactly-once is
                        // per chain/window, not per pid forever).
                        let mut expired_chain_pids: Vec<u32> = Vec::new();
                        for (pid, cs) in chain.iter() {
                            if cs.is_expired() {
                                expired_chain_pids.push(*pid);
                            }
                        }
                        for pid in expired_chain_pids {
                            chain.remove(&pid);
                        }
                        chain_len.store(chain.len(), Ordering::Relaxed);
                    }
                    r = rx.recv() => match r {
                        Ok(ev) => handle_event(
                            &ev, &meta, &device, emitter.as_ref(),
                            &file_policy, &mut map, &mut pending, &mut file_pending,
                            &mut read_pending, &mut recently_exited, &mut chain,
                            &tracked_len, &evicted, &pending_len, &pending_evicted,
                            &file_pending_len, &file_pending_evicted,
                            &read_pending_len, &read_pending_evicted,
                            &chain_len, &chain_evicted,
                        ),
                        Err(RecvError::Lagged(_)) => continue, // dropped events; keep reading
                        Err(RecvError::Closed) => {
                            // Bus gone (all senders dropped): symmetric with the
                            // explicit-stop arm above — no-loss holds on EITHER
                            // shutdown path. Reuses the SAME flush helper, so the
                            // emit logic is not duplicated between the two arms.
                            flush_pending_on_shutdown(
                                &mut pending, &meta, &device, emitter.as_ref(), &pending_len,
                            );
                            flush_file_pending_on_shutdown(
                                &mut file_pending, &meta, &device, emitter.as_ref(), &file_pending_len,
                            );
                            break;
                        }
                    },
                }
            }
        });

        self.stop_tx = Some(stop_tx);
        self.task = Some(task);
        Ok(())
    }
}

/// Routes a bus event to the process-context or correlation handler. The stub
/// bus forwards ALL kinds regardless of the subscribe filter, so any other kind
/// (e.g. `FileOpen`) is dropped here. A malformed event is SKIPPED by the
/// handlers — never a panic.
#[allow(clippy::too_many_arguments)]
fn handle_event(
    ev: &SubstrateEvent,
    meta: &Metadata,
    device: &Device,
    emitter: &dyn torda_core::OcsfEmitter,
    file_policy: &torda_mod_filemon::FilePolicy,
    map: &mut HashMap<u32, ProcContext>,
    pending: &mut HashMap<u32, Vec<PendingConnect>>,
    file_pending: &mut HashMap<u32, Vec<PendingFileWrite>>,
    read_pending: &mut HashMap<u32, Vec<PendingFileRead>>,
    recently_exited: &mut HashMap<u32, (ProcContext, Instant)>,
    chain: &mut HashMap<u32, ChainState>,
    tracked_len: &AtomicUsize,
    evicted: &AtomicU64,
    pending_len: &AtomicUsize,
    pending_evicted: &AtomicU64,
    file_pending_len: &AtomicUsize,
    file_pending_evicted: &AtomicU64,
    read_pending_len: &AtomicUsize,
    read_pending_evicted: &AtomicU64,
    chain_len: &AtomicUsize,
    chain_evicted: &AtomicU64,
) {
    match ev.kind {
        EventKind::ProcessExec => handle_exec(
            ev,
            meta,
            device,
            emitter,
            map,
            pending,
            file_pending,
            read_pending,
            recently_exited,
            chain,
            tracked_len,
            evicted,
            pending_len,
            file_pending_len,
            read_pending_len,
            chain_len,
            chain_evicted,
        ),
        EventKind::ProcessExit => handle_exit(ev, map, recently_exited, tracked_len),
        EventKind::NetConnect => handle_connect(
            ev,
            meta,
            device,
            emitter,
            map,
            pending,
            recently_exited,
            chain,
            pending_len,
            pending_evicted,
            chain_len,
            chain_evicted,
        ),
        EventKind::FileWrite => handle_file_write(
            ev,
            meta,
            device,
            emitter,
            file_policy,
            map,
            file_pending,
            recently_exited,
            chain,
            file_pending_len,
            file_pending_evicted,
            chain_len,
            chain_evicted,
        ),
        EventKind::FileOpen => handle_file_open(
            ev,
            meta,
            device,
            emitter,
            file_policy,
            map,
            read_pending,
            recently_exited,
            chain,
            read_pending_len,
            read_pending_evicted,
            chain_len,
            chain_evicted,
        ),
        _ => {} // not ours; drop.
    }
}

/// Builds the correlated record for ONE connect and emits it — the SINGLE emit
/// path shared by all four callers (immediate-attributed, exec-drain, grace
/// flush, stop flush). It re-uses [`torda_mod_netmon::assess`] and the strict-AND
/// [`CORRELATED_RULE`]; the caller supplies the process side (attributed flag,
/// image, exec verdict, exec detections) already resolved. The `data` shape is
/// identical regardless of caller — the rule/emit logic lives here ONCE.
///
/// Returns `Some(conn_detections)` IFF the strict-AND [`CORRELATED_RULE`] fired
/// (both halves suspicious), and `None` otherwise. This is the TRIPLE-chain seam:
/// the attributed callers feed a `Some` return into the per-pid chain tracker (an
/// un-attributed grace/stop flush always returns `None` — its process half is
/// Informational — so an un-attributed half can NEVER enter the chain). The
/// returned detections are the ones already computed here, never re-assessed.
#[allow(clippy::too_many_arguments)]
fn emit_correlated(
    meta: &Metadata,
    device: &Device,
    emitter: &dyn torda_core::OcsfEmitter,
    pid: u64,
    attributed: bool,
    proc_image: &str,
    exec_severity: u8,
    proc_detections: &[serde_json::Value],
    daddr: &str,
    dport: u16,
    proto: &str,
) -> Option<Vec<serde_json::Value>> {
    // REUSE netmon's ruleset — never re-implemented here.
    let net = torda_mod_netmon::assess(daddr, dport);
    let conn_detections: Vec<serde_json::Value> = net
        .hits
        .iter()
        .map(|h| serde_json::json!({ "rule": h.rule, "reason": h.reason }))
        .collect();

    // Correlated rule: fires IFF BOTH halves are suspicious (AND, not OR).
    let mut top_detections: Vec<serde_json::Value> = Vec::new();
    let fired = exec_severity > SEV_INFORMATIONAL && net.severity_id > SEV_INFORMATIONAL;
    let severity = if fired {
        top_detections.push(serde_json::json!({
            "rule": CORRELATED_RULE,
            "reason": format!(
                "suspicious process '{proc_image}' made a suspicious connection to {daddr}:{dport}"
            ),
        }));
        SEV_HIGH
    } else {
        exec_severity.max(net.severity_id)
    };

    let mut env = OcsfEnvelope::new(
        class::CORRELATED_ACTIVITY,
        "Correlated Activity",
        meta.clone(),
        device.clone(),
        serde_json::json!({
            "activity": "process_network",
            "process": {
                "pid": pid,
                "image": proc_image,
                "detections": proc_detections,
                "attributed": attributed,
            },
            "connection": {
                "daddr": daddr,
                "dport": dport,
                "proto": proto,
                "detections": conn_detections.clone(),
            },
            "detections": top_detections,
        }),
    );
    // OcsfEnvelope::new defaults severity_id to 1; override with our verdict.
    env.severity_id = severity;
    emitter.emit(env);
    // Feed the chain ONLY when the component rule actually fired.
    fired.then_some(conn_detections)
}

/// Builds the correlated record for ONE file-write and emits it — the file
/// analog of [`emit_correlated`], the SINGLE emit path shared by all four
/// callers (immediate-attributed, exec-drain, grace flush, stop flush). It
/// re-uses [`torda_mod_filemon::assess`] and the strict-AND [`CORRELATED_FILE_RULE`];
/// the caller supplies the process side already resolved. The `data` carries a
/// `file` block where [`emit_correlated`] carries a `connection` block. The
/// caller MUST have already passed the path through `FilePolicy::considers`
/// (filemon's contract — `assess` does no volume filtering of its own).
///
/// Returns `Some(file_detections)` IFF the strict-AND [`CORRELATED_FILE_RULE`]
/// fired (both halves suspicious), and `None` otherwise — the file analog of
/// [`emit_correlated`]'s TRIPLE-chain seam, so only attributed, suspicious writes
/// ever feed the chain tracker.
#[allow(clippy::too_many_arguments)]
fn emit_correlated_file(
    meta: &Metadata,
    device: &Device,
    emitter: &dyn torda_core::OcsfEmitter,
    pid: u64,
    attributed: bool,
    proc_image: &str,
    exec_severity: u8,
    proc_detections: &[serde_json::Value],
    path: &str,
) -> Option<Vec<serde_json::Value>> {
    // REUSE filemon's ruleset — never re-implemented here.
    let file = torda_mod_filemon::assess(path, true);
    let file_detections: Vec<serde_json::Value> = file
        .hits
        .iter()
        .map(|h| serde_json::json!({ "rule": h.rule, "reason": h.reason }))
        .collect();

    // Correlated rule: fires IFF BOTH halves are suspicious (AND, not OR).
    let mut top_detections: Vec<serde_json::Value> = Vec::new();
    let fired = exec_severity > SEV_INFORMATIONAL && file.severity_id > SEV_INFORMATIONAL;
    let severity = if fired {
        top_detections.push(serde_json::json!({
            "rule": CORRELATED_FILE_RULE,
            "reason": format!(
                "suspicious process '{proc_image}' made a suspicious write to {path}"
            ),
        }));
        SEV_HIGH
    } else {
        exec_severity.max(file.severity_id)
    };

    let mut env = OcsfEnvelope::new(
        class::CORRELATED_ACTIVITY,
        "Correlated Activity",
        meta.clone(),
        device.clone(),
        serde_json::json!({
            "activity": "process_file",
            "process": {
                "pid": pid,
                "image": proc_image,
                "detections": proc_detections,
                "attributed": attributed,
            },
            "file": {
                "path": path,
                "op": "write",
                "detections": file_detections.clone(),
            },
            "detections": top_detections,
        }),
    );
    // OcsfEnvelope::new defaults severity_id to 1; override with our verdict.
    env.severity_id = severity;
    emitter.emit(env);
    // Feed the chain ONLY when the component rule actually fired.
    fired.then_some(file_detections)
}

/// Emits the TRIPLE [`CORRELATED_CHAIN_RULE`] record — the dropper-then-C2 chain.
/// A shape-parallel sibling of [`emit_correlated`]/[`emit_correlated_file`]
/// (same shared metadata/device/emitter plumbing, same class 9002, same
/// `{rule, reason}` detection style), but it carries BOTH a `file` block AND a
/// `connection` block AND all THREE detection sets (process, file, connection)
/// plus the top-level [`CORRELATED_CHAIN_RULE`] detection. It NEVER re-assesses:
/// every detection set here was already computed by the two component paths and
/// is passed straight through. Always [`SEV_HIGH`] and always attributed — the
/// caller only reaches this after BOTH component rules fired for the same pid.
#[allow(clippy::too_many_arguments)]
fn emit_correlated_chain(
    meta: &Metadata,
    device: &Device,
    emitter: &dyn torda_core::OcsfEmitter,
    pid: u64,
    proc_image: &str,
    proc_detections: &[serde_json::Value],
    file_path: &str,
    file_detections: &[serde_json::Value],
    daddr: &str,
    dport: u16,
    proto: &str,
    conn_detections: &[serde_json::Value],
) {
    let top_detections = vec![serde_json::json!({
        "rule": CORRELATED_CHAIN_RULE,
        "reason": format!(
            "suspicious process '{proc_image}' wrote to {file_path} and connected to {daddr}:{dport}"
        ),
    })];

    let mut env = OcsfEnvelope::new(
        class::CORRELATED_ACTIVITY,
        "Correlated Activity",
        meta.clone(),
        device.clone(),
        serde_json::json!({
            "activity": "process_file_network",
            "process": {
                "pid": pid,
                "image": proc_image,
                "detections": proc_detections,
                "attributed": true,
            },
            "file": {
                "path": file_path,
                "op": "write",
                "detections": file_detections,
            },
            "connection": {
                "daddr": daddr,
                "dport": dport,
                "proto": proto,
                "detections": conn_detections,
            },
            "detections": top_detections,
        }),
    );
    // The triple is an escalation over either component → always SEV_HIGH.
    env.severity_id = SEV_HIGH;
    emitter.emit(env);
}

/// Emits the EXFIL [`CORRELATED_EXFIL_RULE`] record — the read-sensitive-then-C2
/// data-exfiltration chain. The read analog of [`emit_correlated_chain`]: same
/// class 9002, same `{rule, reason}` detection style, same `process`/`file`/
/// `connection` block shape (so the ingest edge_key `{image}->{daddr}:{dport}`
/// is byte-for-byte the triple's), but the `file` block carries the READ path
/// (`op: "read"`) and the top-level `detections` is the UNION of the read
/// component detection + the connect component detections PLUS the
/// [`CORRELATED_EXFIL_RULE`] entry — self-contained, because corr never emits a
/// standalone read component (filemon already does). It NEVER re-assesses: both
/// detection sets were computed by the read re-judge and the connect component and
/// are passed straight through. Always [`SEV_HIGH`] and always attributed — the
/// caller only reaches this after BOTH the read verdict and the connect component
/// rule fired for the same pid.
#[allow(clippy::too_many_arguments)]
fn emit_correlated_exfil(
    meta: &Metadata,
    device: &Device,
    emitter: &dyn torda_core::OcsfEmitter,
    pid: u64,
    proc_image: &str,
    proc_detections: &[serde_json::Value],
    file_path: &str,
    read_detections: &[serde_json::Value],
    daddr: &str,
    dport: u16,
    proto: &str,
    conn_detections: &[serde_json::Value],
) {
    // Top-level detections: the read component + the connect component + the exfil
    // rule itself, so the single record explains the whole chain without needing
    // the (never-emitted) read component alongside it.
    let mut top_detections: Vec<serde_json::Value> = Vec::new();
    top_detections.extend(read_detections.iter().cloned());
    top_detections.extend(conn_detections.iter().cloned());
    top_detections.push(serde_json::json!({
        "rule": CORRELATED_EXFIL_RULE,
        "reason": format!(
            "suspicious process '{proc_image}' read sensitive file {file_path} and connected to {daddr}:{dport}"
        ),
    }));

    let mut env = OcsfEnvelope::new(
        class::CORRELATED_ACTIVITY,
        "Correlated Activity",
        meta.clone(),
        device.clone(),
        serde_json::json!({
            "activity": "process_file_network",
            "process": {
                "pid": pid,
                "image": proc_image,
                "detections": proc_detections,
                "attributed": true,
            },
            "file": {
                "path": file_path,
                "op": "read",
                "detections": read_detections,
            },
            "connection": {
                "daddr": daddr,
                "dport": dport,
                "proto": proto,
                "detections": conn_detections,
            },
            "detections": top_detections,
        }),
    );
    // The exfil chain is an escalation over either component → always SEV_HIGH.
    env.severity_id = SEV_HIGH;
    emitter.emit(env);
}

/// The read+connect JOIN + de-dup for the EXFIL chain — the read analog of
/// [`maybe_fire_chain`]. If the entry now holds BOTH a `read` half and a `conn`
/// half, they are within [`CHAIN_WINDOW`] of each other, and it has not already
/// `exfil_fired`, emit ONE exfil record and latch `exfil_fired`. Order-independent
/// (whichever of read/connect arrives second completes the chain). Independent of
/// the write triple's `fired` flag, so a pid can fire both chains. No lock is held
/// — the chain map is task-local — so the `emitter.emit` inside is safe.
fn maybe_fire_exfil(
    entry: &mut ChainState,
    meta: &Metadata,
    device: &Device,
    emitter: &dyn torda_core::OcsfEmitter,
    pid: u64,
    proc_image: &str,
    proc_detections: &[serde_json::Value],
) {
    if entry.exfil_fired {
        return;
    }
    let within = match (&entry.read, &entry.conn) {
        (Some(r), Some(c)) => r.stamp.elapsed() < CHAIN_WINDOW && c.stamp.elapsed() < CHAIN_WINDOW,
        _ => false,
    };
    if !within {
        return;
    }
    let read = entry.read.as_ref().unwrap();
    let conn = entry.conn.as_ref().unwrap();
    emit_correlated_exfil(
        meta,
        device,
        emitter,
        pid,
        proc_image,
        proc_detections,
        &read.path,
        &read.detections,
        &conn.daddr,
        conn.dport,
        &conn.proto,
        &conn.detections,
    );
    entry.exfil_fired = true;
}

/// Records the just-confirmed suspicious sensitive-READ half into the pid's chain
/// tracker, then fires the EXFIL chain IFF a suspicious connect half is ALSO
/// present within [`CHAIN_WINDOW`] and the exfil chain has not already fired — the
/// read analog of [`record_file_and_maybe_chain`]. Called ONLY after the read was
/// attributed AND re-judged to trip `read_of_sensitive_file`, so nothing
/// un-attributed or non-sensitive ever enters the chain.
#[allow(clippy::too_many_arguments)]
fn record_read_and_maybe_exfil(
    chain: &mut HashMap<u32, ChainState>,
    meta: &Metadata,
    device: &Device,
    emitter: &dyn torda_core::OcsfEmitter,
    pid: u64,
    proc_image: &str,
    proc_detections: &[serde_json::Value],
    path: &str,
    read_detections: Vec<serde_json::Value>,
    chain_len: &AtomicUsize,
    chain_evicted: &AtomicU64,
) {
    let key = pid as u32;
    if !chain.contains_key(&key) && chain.len() >= MAX_CHAIN_TRACKED {
        evict_oldest_chain(chain, chain_evicted);
    }
    let entry = chain.entry(key).or_default();
    entry.read = Some(ChainReadHalf {
        path: path.to_string(),
        detections: read_detections,
        stamp: Instant::now(),
    });
    maybe_fire_exfil(
        entry,
        meta,
        device,
        emitter,
        pid,
        proc_image,
        proc_detections,
    );
    chain_len.store(chain.len(), Ordering::Relaxed);
}

/// Re-judges a `FileOpen` path with filemon's `write=false` ruleset and returns
/// the ready-to-emit read `{rule, reason}` detections IFF `read_of_sensitive_file`
/// fired, else `None`. Mirrors how the write path re-judges via [`torda_mod_filemon::assess`]
/// — never trusting any incoming severity label, always recomputing the verdict.
/// The caller MUST have already passed the path through `FilePolicy::considers`.
fn judge_read(path: &str) -> Option<Vec<serde_json::Value>> {
    let a = torda_mod_filemon::assess(path, false);
    if a.hits.iter().any(|h| h.rule == READ_OF_SENSITIVE_FILE_RULE) {
        Some(
            a.hits
                .iter()
                .map(|h| serde_json::json!({ "rule": h.rule, "reason": h.reason }))
                .collect(),
        )
    } else {
        None
    }
}

/// Records the just-fired suspicious-CONNECT half into the pid's chain tracker,
/// then fires the TRIPLE [`CORRELATED_CHAIN_RULE`] IFF a suspicious file-write
/// half is ALSO present, stamped within [`CHAIN_WINDOW`], and the chain has not
/// already fired. Called ONLY from the attributed connect paths, and ONLY when
/// [`emit_correlated`] reported its component rule fired (so an un-attributed or
/// benign half never reaches here). The `fired` flag makes this exactly-once per
/// chain: a pid that connects M× after writing emits ONE triple, not M.
#[allow(clippy::too_many_arguments)]
fn record_connect_and_maybe_chain(
    chain: &mut HashMap<u32, ChainState>,
    meta: &Metadata,
    device: &Device,
    emitter: &dyn torda_core::OcsfEmitter,
    pid: u64,
    proc_image: &str,
    proc_detections: &[serde_json::Value],
    daddr: &str,
    dport: u16,
    proto: &str,
    conn_detections: Vec<serde_json::Value>,
    chain_len: &AtomicUsize,
    chain_evicted: &AtomicU64,
) {
    let key = pid as u32;
    // Bounded map: evict the oldest entry before inserting a genuinely NEW pid.
    if !chain.contains_key(&key) && chain.len() >= MAX_CHAIN_TRACKED {
        evict_oldest_chain(chain, chain_evicted);
    }
    let entry = chain.entry(key).or_default();
    entry.conn = Some(ChainConnHalf {
        daddr: daddr.to_string(),
        dport,
        proto: proto.to_string(),
        detections: conn_detections,
        stamp: Instant::now(),
    });
    // The connect half is shared: it may complete the WRITE TRIPLE (with a `file`
    // half) AND/OR the EXFIL chain (with a `read` half). Attempt both; each has
    // its own `fired` latch, so a pid with all three halves emits one triple AND
    // one exfil, each exactly once.
    maybe_fire_chain(
        entry,
        meta,
        device,
        emitter,
        pid,
        proc_image,
        proc_detections,
    );
    maybe_fire_exfil(
        entry,
        meta,
        device,
        emitter,
        pid,
        proc_image,
        proc_detections,
    );
    chain_len.store(chain.len(), Ordering::Relaxed);
}

/// Records the just-fired suspicious-FILE-WRITE half into the pid's chain
/// tracker, then fires the triple IFF a suspicious connect half is ALSO present
/// within [`CHAIN_WINDOW`] and the chain has not already fired — the file analog
/// of [`record_connect_and_maybe_chain`].
#[allow(clippy::too_many_arguments)]
fn record_file_and_maybe_chain(
    chain: &mut HashMap<u32, ChainState>,
    meta: &Metadata,
    device: &Device,
    emitter: &dyn torda_core::OcsfEmitter,
    pid: u64,
    proc_image: &str,
    proc_detections: &[serde_json::Value],
    path: &str,
    file_detections: Vec<serde_json::Value>,
    chain_len: &AtomicUsize,
    chain_evicted: &AtomicU64,
) {
    let key = pid as u32;
    if !chain.contains_key(&key) && chain.len() >= MAX_CHAIN_TRACKED {
        evict_oldest_chain(chain, chain_evicted);
    }
    let entry = chain.entry(key).or_default();
    entry.file = Some(ChainFileHalf {
        path: path.to_string(),
        detections: file_detections,
        stamp: Instant::now(),
    });
    maybe_fire_chain(
        entry,
        meta,
        device,
        emitter,
        pid,
        proc_image,
        proc_detections,
    );
    chain_len.store(chain.len(), Ordering::Relaxed);
}

/// The join + de-dup, shared by both record helpers: if the entry now holds BOTH
/// halves, they are within [`CHAIN_WINDOW`] of each other, and it has not already
/// `fired`, emit ONE triple and latch `fired`. Order-independent (whichever half
/// arrives second completes the chain). No lock is held — the chain map is
/// task-local — so the `emitter.emit` inside is safe.
fn maybe_fire_chain(
    entry: &mut ChainState,
    meta: &Metadata,
    device: &Device,
    emitter: &dyn torda_core::OcsfEmitter,
    pid: u64,
    proc_image: &str,
    proc_detections: &[serde_json::Value],
) {
    if entry.fired {
        return;
    }
    // Both halves present AND the complementary half is still inside the window
    // (its `elapsed()` measured from the half just recorded ~now → the two stamps
    // are within CHAIN_WINDOW of each other).
    let within = match (&entry.file, &entry.conn) {
        (Some(f), Some(c)) => f.stamp.elapsed() < CHAIN_WINDOW && c.stamp.elapsed() < CHAIN_WINDOW,
        _ => false,
    };
    if !within {
        return;
    }
    let file = entry.file.as_ref().unwrap();
    let conn = entry.conn.as_ref().unwrap();
    emit_correlated_chain(
        meta,
        device,
        emitter,
        pid,
        proc_image,
        proc_detections,
        &file.path,
        &file.detections,
        &conn.daddr,
        conn.dport,
        &conn.proto,
        &conn.detections,
    );
    entry.fired = true;
}

/// Evicts the OLDEST chain entry (by the earlier of its two half-stamps) and
/// counts it, bounding the chain map exactly as the other bounded maps are
/// bounded — never a silent drop, never unbounded growth.
fn evict_oldest_chain(chain: &mut HashMap<u32, ChainState>, chain_evicted: &AtomicU64) {
    if let Some(victim) = chain
        .iter()
        .min_by_key(|(_, cs)| cs.oldest_stamp())
        .map(|(k, _)| *k)
    {
        chain.remove(&victim);
        chain_evicted.fetch_add(1, Ordering::Relaxed);
    }
}

/// Shared shutdown drain used by BOTH shutdown paths: the explicit-stop arm
/// (`stop_rx`) and the bus-closed arm (`RecvError::Closed`). Flushes every
/// still-buffered connect `attributed: false` through the SAME
/// [`emit_correlated`] used everywhere else, so neither shutdown reason loses
/// a buffered connect and the emit logic is never duplicated between the two
/// `select!` arms.
fn flush_pending_on_shutdown(
    pending: &mut HashMap<u32, Vec<PendingConnect>>,
    meta: &Metadata,
    device: &Device,
    emitter: &dyn torda_core::OcsfEmitter,
    pending_len: &AtomicUsize,
) {
    // Drain EVERY pid's Vec — every buffered connect flushes un-attributed, so
    // no-loss holds even when a pid buffered multiple pre-exec connects.
    for (pid, vec) in pending.drain() {
        for pc in vec {
            emit_correlated(
                meta,
                device,
                emitter,
                pid as u64,
                false,
                &pc.image,
                SEV_INFORMATIONAL,
                &[],
                &pc.daddr,
                pc.dport,
                &pc.proto,
            );
        }
    }
    pending_len.store(0, Ordering::Relaxed);
}

/// File analog of [`flush_pending_on_shutdown`]: flushes every still-buffered
/// file-write `attributed: false` through the SAME [`emit_correlated_file`] used
/// everywhere else, so neither shutdown reason loses a buffered write.
fn flush_file_pending_on_shutdown(
    file_pending: &mut HashMap<u32, Vec<PendingFileWrite>>,
    meta: &Metadata,
    device: &Device,
    emitter: &dyn torda_core::OcsfEmitter,
    file_pending_len: &AtomicUsize,
) {
    for (pid, vec) in file_pending.drain() {
        for pfw in vec {
            emit_correlated_file(
                meta,
                device,
                emitter,
                pid as u64,
                false,
                &pfw.image,
                SEV_INFORMATIONAL,
                &[],
                &pfw.path,
            );
        }
    }
    file_pending_len.store(0, Ordering::Relaxed);
}

/// Total number of buffered connects across all pids' Vecs — the value mirrored
/// into `health()`'s pending count and compared against `MAX_PENDING_CONNECTS`.
fn pending_total(pending: &HashMap<u32, Vec<PendingConnect>>) -> usize {
    pending.values().map(Vec::len).sum()
}

/// Total number of buffered file-writes across all pids' Vecs — the file analog
/// of [`pending_total`], compared against `MAX_PENDING_FILE_WRITES`.
fn file_pending_total(file_pending: &HashMap<u32, Vec<PendingFileWrite>>) -> usize {
    file_pending.values().map(Vec::len).sum()
}

/// Total number of buffered sensitive reads across all pids' Vecs — the read
/// analog of [`file_pending_total`], compared against `MAX_PENDING_FILE_READS`.
fn read_pending_total(read_pending: &HashMap<u32, Vec<PendingFileRead>>) -> usize {
    read_pending.values().map(Vec::len).sum()
}

/// Evicts the GLOBALLY oldest buffered connect (min `buffered_at` across ALL
/// pids' Vecs) and counts it, bounding the TOTAL number of buffered connects.
/// A pid whose Vec becomes empty is dropped (no empty-Vec leak).
fn evict_oldest_pending(
    pending: &mut HashMap<u32, Vec<PendingConnect>>,
    pending_evicted: &AtomicU64,
) {
    let mut victim: Option<(u32, usize, Instant)> = None;
    for (pid, vec) in pending.iter() {
        for (idx, pc) in vec.iter().enumerate() {
            let older = match victim {
                Some((_, _, t)) => pc.buffered_at < t,
                None => true,
            };
            if older {
                victim = Some((*pid, idx, pc.buffered_at));
            }
        }
    }
    if let Some((pid, idx, _)) = victim {
        if let Some(vec) = pending.get_mut(&pid) {
            vec.remove(idx);
            if vec.is_empty() {
                pending.remove(&pid);
            }
        }
        pending_evicted.fetch_add(1, Ordering::Relaxed);
    }
}

/// File analog of [`evict_oldest_pending`]: evicts the GLOBALLY oldest buffered
/// file-write (min `buffered_at` across all pids' Vecs) and counts it, bounding
/// the TOTAL number of buffered file-writes. A pid whose Vec becomes empty is
/// dropped (no empty-Vec leak).
fn evict_oldest_file_pending(
    file_pending: &mut HashMap<u32, Vec<PendingFileWrite>>,
    file_pending_evicted: &AtomicU64,
) {
    let mut victim: Option<(u32, usize, Instant)> = None;
    for (pid, vec) in file_pending.iter() {
        for (idx, pfw) in vec.iter().enumerate() {
            let older = match victim {
                Some((_, _, t)) => pfw.buffered_at < t,
                None => true,
            };
            if older {
                victim = Some((*pid, idx, pfw.buffered_at));
            }
        }
    }
    if let Some((pid, idx, _)) = victim {
        if let Some(vec) = file_pending.get_mut(&pid) {
            vec.remove(idx);
            if vec.is_empty() {
                file_pending.remove(&pid);
            }
        }
        file_pending_evicted.fetch_add(1, Ordering::Relaxed);
    }
}

/// Read analog of [`evict_oldest_file_pending`]: evicts the GLOBALLY oldest
/// buffered sensitive read (min `buffered_at` across all pids' Vecs) and counts
/// it, bounding the TOTAL number of buffered reads. A pid whose Vec becomes empty
/// is dropped (no empty-Vec leak).
fn evict_oldest_read_pending(
    read_pending: &mut HashMap<u32, Vec<PendingFileRead>>,
    read_pending_evicted: &AtomicU64,
) {
    let mut victim: Option<(u32, usize, Instant)> = None;
    for (pid, vec) in read_pending.iter() {
        for (idx, pfr) in vec.iter().enumerate() {
            let older = match victim {
                Some((_, _, t)) => pfr.buffered_at < t,
                None => true,
            };
            if older {
                victim = Some((*pid, idx, pfr.buffered_at));
            }
        }
    }
    if let Some((pid, idx, _)) = victim {
        if let Some(vec) = read_pending.get_mut(&pid) {
            vec.remove(idx);
            if vec.is_empty() {
                read_pending.remove(&pid);
            }
        }
        read_pending_evicted.fetch_add(1, Ordering::Relaxed);
    }
}

/// Records/refreshes the process context for an exec's pid, reusing
/// [`torda_mod_procmon::assess`] for the verdict. Missing pid/image → skipped.
/// THEN drains any connect buffered for this pid: its exec has now arrived, so
/// it is emitted `attributed: true` — THIS is the order-independent fix.
#[allow(clippy::too_many_arguments)]
fn handle_exec(
    ev: &SubstrateEvent,
    meta: &Metadata,
    device: &Device,
    emitter: &dyn torda_core::OcsfEmitter,
    map: &mut HashMap<u32, ProcContext>,
    pending: &mut HashMap<u32, Vec<PendingConnect>>,
    file_pending: &mut HashMap<u32, Vec<PendingFileWrite>>,
    read_pending: &mut HashMap<u32, Vec<PendingFileRead>>,
    recently_exited: &mut HashMap<u32, (ProcContext, Instant)>,
    chain: &mut HashMap<u32, ChainState>,
    tracked_len: &AtomicUsize,
    evicted: &AtomicU64,
    pending_len: &AtomicUsize,
    file_pending_len: &AtomicUsize,
    read_pending_len: &AtomicUsize,
    chain_len: &AtomicUsize,
    chain_evicted: &AtomicU64,
) {
    let pid = match ev.fields.get("pid").and_then(serde_json::Value::as_u64) {
        Some(p) => p,
        None => return,
    };
    let image = match ev.fields.get("image").and_then(serde_json::Value::as_str) {
        Some(s) => s,
        None => return,
    };

    // REUSE procmon's ruleset — never re-implemented here.
    let a = torda_mod_procmon::assess(image);
    let exec_detections: Vec<serde_json::Value> = a
        .hits
        .iter()
        .map(|h| serde_json::json!({ "rule": h.rule, "reason": h.reason }))
        .collect();

    let key = pid as u32;
    // PID REUSE: a new exec for this pid supersedes any retained exited context.
    // Drop it so a lagging event for the OLD (now-gone) process can never
    // mis-attribute to — or steal the identity of — this fresh process.
    recently_exited.remove(&key);
    // Symmetric pid-reuse reset for the chain tracker. Unlike the pre-fix code the
    // chain is NOT dropped on exit (so a short-lived process's post-exit half can
    // still complete its chain); pid reuse is instead handled HERE — a fresh exec
    // supersedes any half-built chain from the OLD process that held this pid.
    // Cleared BEFORE the pending drains below so THIS exec's own drained halves
    // survive.
    if chain.remove(&key).is_some() {
        chain_len.store(chain.len(), Ordering::Relaxed);
    }
    // Bounded map: at the cap (and only when inserting a NEW pid), evict the
    // OLDEST context and count it — never a silent drop, never unbounded growth.
    if !map.contains_key(&key) && map.len() >= MAX_TRACKED {
        if let Some(oldest) = map.iter().min_by_key(|(_, c)| c.exec_ts).map(|(k, _)| *k) {
            map.remove(&oldest);
            evicted.fetch_add(1, Ordering::Relaxed);
        }
    }
    // `insert` OVERWRITES any prior entry for this pid (most-recent-exec-wins):
    // on the ordered bus a pid is freed by an exit before reuse, and even if an
    // exit were lost the stale context is replaced here.
    map.insert(
        key,
        ProcContext {
            image: image.to_string(),
            exec_severity: a.severity_id,
            exec_detections: exec_detections.clone(),
            exec_ts: ev.ts,
        },
    );
    tracked_len.store(map.len(), Ordering::Relaxed);

    // THE FIX: connects for this pid may have been drained from the NET_EVENTS
    // ring BEFORE this exec. If so, its exec has now arrived — emit EACH buffered
    // connect correlated (attributed: true) in buffered (FIFO) order using the
    // SAME rule logic as the immediate path. The whole Vec is removed here so
    // none can also flush → exactly-once, and no pre-exec connect is lost.
    if let Some(vec) = pending.remove(&key) {
        for pc in vec {
            if let Some(conn_detections) = emit_correlated(
                meta,
                device,
                emitter,
                pid,
                true,
                image,
                a.severity_id,
                &exec_detections,
                &pc.daddr,
                pc.dport,
                &pc.proto,
            ) {
                // Component connect rule fired for this now-attributed connect →
                // feed the chain (a buffered write drained just below, or an
                // earlier one, may complete the triple).
                record_connect_and_maybe_chain(
                    chain,
                    meta,
                    device,
                    emitter,
                    pid,
                    image,
                    &exec_detections,
                    &pc.daddr,
                    pc.dport,
                    &pc.proto,
                    conn_detections,
                    chain_len,
                    chain_evicted,
                );
            }
        }
        pending_len.store(pending_total(pending), Ordering::Relaxed);
    }

    // Same order-independent fix for file-writes: writes for this pid may have
    // been drained from the FILE_EVENTS ring BEFORE this exec. Emit EACH buffered
    // write correlated (attributed: true) in buffered (FIFO) order, removing the
    // whole Vec so none can also flush → exactly-once, no pre-exec write lost.
    if let Some(vec) = file_pending.remove(&key) {
        for pfw in vec {
            if let Some(file_detections) = emit_correlated_file(
                meta,
                device,
                emitter,
                pid,
                true,
                image,
                a.severity_id,
                &exec_detections,
                &pfw.path,
            ) {
                // Component file rule fired → feed the chain; a connect drained
                // just above may complete the triple (order-independent).
                record_file_and_maybe_chain(
                    chain,
                    meta,
                    device,
                    emitter,
                    pid,
                    image,
                    &exec_detections,
                    &pfw.path,
                    file_detections,
                    chain_len,
                    chain_evicted,
                );
            }
        }
        file_pending_len.store(file_pending_total(file_pending), Ordering::Relaxed);
    }

    // Same order-independent fix for sensitive reads: reads for this pid may have
    // been drained from the FILE_EVENTS ring BEFORE this exec. Re-judge EACH
    // buffered read (deterministic; it already passed `considers` + a sensitive
    // verdict at buffer time) and record its half attributed to THIS exec, removing
    // the whole Vec so none can also purge on the grace tick. A read records no
    // component — it only feeds the exfil chain, which a connect drained above may
    // now complete (order-independent).
    if let Some(vec) = read_pending.remove(&key) {
        for pfr in vec {
            if let Some(read_detections) = judge_read(&pfr.path) {
                record_read_and_maybe_exfil(
                    chain,
                    meta,
                    device,
                    emitter,
                    pid,
                    image,
                    &exec_detections,
                    &pfr.path,
                    read_detections,
                    chain_len,
                    chain_evicted,
                );
            }
        }
        read_pending_len.store(read_pending_total(read_pending), Ordering::Relaxed);
    }
}

/// Removes an exited pid's context from the LIVE map, but instead of dropping it
/// MOVES it into `recently_exited` stamped `Instant::now()`, so a LATE cross-ring
/// event (a FILE_EVENTS-ring write processed after this exit) can still attribute
/// to it for [`EXITED_RETENTION`]. Bounded: at the [`MAX_RECENTLY_EXITED`] cap the
/// OLDEST-by-instant retained context is evicted first (never unbounded, never a
/// panic). Missing pid, or a pid the live map never held → nothing to stash. Any
/// connect/write still buffered for the pid is LEFT in `pending`/`file_pending`:
/// a late exec (rare) still wins, otherwise it flushes un-attributed on
/// grace/stop.
fn handle_exit(
    ev: &SubstrateEvent,
    map: &mut HashMap<u32, ProcContext>,
    recently_exited: &mut HashMap<u32, (ProcContext, Instant)>,
    tracked_len: &AtomicUsize,
) {
    let pid = match ev.fields.get("pid").and_then(serde_json::Value::as_u64) {
        Some(p) => p,
        None => return,
    };
    let key = pid as u32;
    // The chain tracker is INTENTIONALLY NOT dropped on exit. A short-lived
    // process (the dropper the triple exists to catch) exits BETWEEN its two
    // cross-ring halves; the second half arrives via `recently_exited` AFTER this
    // exit, so dropping the chain now would lose the join (proven live: only the
    // one curl whose halves both landed before its exit chained). The chain is
    // bounded + window-purged on the grace tick, and reset on pid re-exec in
    // `handle_exec` — symmetric with how `recently_exited` handles pid reuse.
    if let Some(ctx) = map.remove(&key) {
        // Bounded retention: at the cap (and only when stashing a pid NOT already
        // retained) evict the oldest-by-instant entry first, so the map can never
        // grow past `MAX_RECENTLY_EXITED`.
        if !recently_exited.contains_key(&key) && recently_exited.len() >= MAX_RECENTLY_EXITED {
            if let Some(oldest) = recently_exited
                .iter()
                .min_by_key(|(_, (_, t))| *t)
                .map(|(k, _)| *k)
            {
                recently_exited.remove(&oldest);
            }
        }
        recently_exited.insert(key, (ctx, Instant::now()));
    }
    tracked_len.store(map.len(), Ordering::Relaxed);
}

/// The JOIN. If the pid is already known, emits ONE correlated record
/// immediately (the unchanged attributed path). If NOT — the exec may simply not
/// have been drained yet — the connect is BUFFERED for [`GRACE`] so its exec can
/// still correlate it (order-independent). Missing/unparseable pid/daddr/dport →
/// skipped (no panic, no emit, no buffer).
#[allow(clippy::too_many_arguments)]
fn handle_connect(
    ev: &SubstrateEvent,
    meta: &Metadata,
    device: &Device,
    emitter: &dyn torda_core::OcsfEmitter,
    map: &HashMap<u32, ProcContext>,
    pending: &mut HashMap<u32, Vec<PendingConnect>>,
    recently_exited: &HashMap<u32, (ProcContext, Instant)>,
    chain: &mut HashMap<u32, ChainState>,
    pending_len: &AtomicUsize,
    pending_evicted: &AtomicU64,
    chain_len: &AtomicUsize,
    chain_evicted: &AtomicU64,
) {
    let pid = match ev.fields.get("pid").and_then(serde_json::Value::as_u64) {
        Some(p) => p,
        None => return,
    };
    let daddr = match ev.fields.get("daddr").and_then(serde_json::Value::as_str) {
        Some(s) => s,
        None => return,
    };
    let dport: u16 = match ev
        .fields
        .get("dport")
        .and_then(serde_json::Value::as_u64)
        .and_then(|p| p.try_into().ok())
    {
        Some(p) => p,
        None => return,
    };
    // `image` (the connect-time comm) is only needed to name an UN-attributed
    // process; default to "unknown" if absent. `proto` defaults to "tcp".
    let connect_image = ev
        .fields
        .get("image")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let proto = ev
        .fields
        .get("proto")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("tcp");

    let key = pid as u32;
    match map.get(&key) {
        // pid found → emit the correlated record IMMEDIATELY (unchanged path).
        Some(c) => {
            if let Some(conn_detections) = emit_correlated(
                meta,
                device,
                emitter,
                pid,
                true,
                &c.image,
                c.exec_severity,
                &c.exec_detections,
                daddr,
                dport,
                proto,
            ) {
                record_connect_and_maybe_chain(
                    chain,
                    meta,
                    device,
                    emitter,
                    pid,
                    &c.image,
                    &c.exec_detections,
                    daddr,
                    dport,
                    proto,
                    conn_detections,
                    chain_len,
                    chain_evicted,
                );
            }
        }
        // pid not found LIVE → it may be a LATE cross-ring event for a process
        // that has ALREADY exited (its exit evicted the live context before this
        // connect was processed). If we still hold that pid's context within the
        // retention window, attribute IMMEDIATELY — byte-identical to the live-hit
        // arm above — instead of buffering (the exec already came and went, so no
        // future exec would ever drain a buffered connect here).
        None if recently_exited
            .get(&key)
            .is_some_and(|(_, stamp)| stamp.elapsed() < EXITED_RETENTION) =>
        {
            let (c, _) = &recently_exited[&key];
            if let Some(conn_detections) = emit_correlated(
                meta,
                device,
                emitter,
                pid,
                true,
                &c.image,
                c.exec_severity,
                &c.exec_detections,
                daddr,
                dport,
                proto,
            ) {
                record_connect_and_maybe_chain(
                    chain,
                    meta,
                    device,
                    emitter,
                    pid,
                    &c.image,
                    &c.exec_detections,
                    daddr,
                    dport,
                    proto,
                    conn_detections,
                    chain_len,
                    chain_evicted,
                );
            }
        }
        // pid not found → do NOT emit; buffer and wait for the exec (GRACE).
        // ALL of a pid's pre-exec connects are retained (append to its Vec) so a
        // second connect never overwrites the first — no silent detection loss.
        None => {
            // Bounded buffer: cap the TOTAL buffered connects across all pids. If
            // a new buffer would exceed the cap, evict the GLOBALLY oldest connect
            // and count it — never a silent drop, never over the cap.
            if pending_total(pending) >= MAX_PENDING_CONNECTS {
                evict_oldest_pending(pending, pending_evicted);
            }
            pending.entry(key).or_default().push(PendingConnect {
                image: connect_image.to_string(),
                daddr: daddr.to_string(),
                dport,
                proto: proto.to_string(),
                buffered_at: Instant::now(),
            });
            pending_len.store(pending_total(pending), Ordering::Relaxed);
        }
    }
}

/// The FILE JOIN — the file analog of [`handle_connect`]. Runs the mandatory
/// [`FilePolicy::considers`](torda_mod_filemon::FilePolicy::considers) prefilter
/// FIRST (matches filemon's contract AND keeps benign, high-volume writes out of
/// the correlation buffer). If the pid is already known, emits ONE correlated
/// record immediately (attributed). If NOT — the exec may simply not have been
/// drained yet — the write is BUFFERED for [`GRACE`] so its exec can still
/// correlate it (order-independent). Missing/unparseable pid/path, or a path the
/// policy does not consider → skipped (no panic, no emit, no buffer).
#[allow(clippy::too_many_arguments)]
fn handle_file_write(
    ev: &SubstrateEvent,
    meta: &Metadata,
    device: &Device,
    emitter: &dyn torda_core::OcsfEmitter,
    file_policy: &torda_mod_filemon::FilePolicy,
    map: &HashMap<u32, ProcContext>,
    file_pending: &mut HashMap<u32, Vec<PendingFileWrite>>,
    recently_exited: &HashMap<u32, (ProcContext, Instant)>,
    chain: &mut HashMap<u32, ChainState>,
    file_pending_len: &AtomicUsize,
    file_pending_evicted: &AtomicU64,
    chain_len: &AtomicUsize,
    chain_evicted: &AtomicU64,
) {
    let pid = match ev.fields.get("pid").and_then(serde_json::Value::as_u64) {
        Some(p) => p,
        None => return,
    };
    let path = match ev.fields.get("path").and_then(serde_json::Value::as_str) {
        Some(s) => s,
        None => return,
    };

    // THE PREFILTER RUNS FIRST — before the join, the assess, or any buffer.
    // `assess` assumes the caller already gated on `considers`, and file events
    // are HIGH volume: only writes filemon itself would consider may enter here.
    if !file_policy.considers(path) {
        return;
    }

    // `image` (the write-time comm) is only needed to name an UN-attributed
    // process; default to "unknown" if absent.
    let write_image = ev
        .fields
        .get("image")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");

    let key = pid as u32;
    match map.get(&key) {
        // pid found → emit the correlated record IMMEDIATELY (attributed).
        Some(c) => {
            if let Some(file_detections) = emit_correlated_file(
                meta,
                device,
                emitter,
                pid,
                true,
                &c.image,
                c.exec_severity,
                &c.exec_detections,
                path,
            ) {
                record_file_and_maybe_chain(
                    chain,
                    meta,
                    device,
                    emitter,
                    pid,
                    &c.image,
                    &c.exec_detections,
                    path,
                    file_detections,
                    chain_len,
                    chain_evicted,
                );
            }
        }
        // pid not found LIVE → it may be a LATE cross-ring event for a process
        // that has ALREADY exited. This is the short-lived-writer (dropper) case:
        // the high-volume FILE_EVENTS ring lags, so the write is processed AFTER
        // the pid's exit evicted the live context. If we still hold that context
        // within the retention window, attribute IMMEDIATELY — byte-identical to
        // the live-hit arm above — instead of buffering (the exec already came and
        // went, so no future exec would ever drain a buffered write here).
        None if recently_exited
            .get(&key)
            .is_some_and(|(_, stamp)| stamp.elapsed() < EXITED_RETENTION) =>
        {
            let (c, _) = &recently_exited[&key];
            if let Some(file_detections) = emit_correlated_file(
                meta,
                device,
                emitter,
                pid,
                true,
                &c.image,
                c.exec_severity,
                &c.exec_detections,
                path,
            ) {
                record_file_and_maybe_chain(
                    chain,
                    meta,
                    device,
                    emitter,
                    pid,
                    &c.image,
                    &c.exec_detections,
                    path,
                    file_detections,
                    chain_len,
                    chain_evicted,
                );
            }
        }
        // pid not found → do NOT emit; buffer and wait for the exec (GRACE).
        // ALL of a pid's pre-exec writes are retained (append to its Vec).
        None => {
            // Bounded buffer: cap the TOTAL buffered writes across all pids. If a
            // new buffer would exceed the cap, evict the GLOBALLY oldest write and
            // count it — never a silent drop, never over the cap.
            if file_pending_total(file_pending) >= MAX_PENDING_FILE_WRITES {
                evict_oldest_file_pending(file_pending, file_pending_evicted);
            }
            file_pending.entry(key).or_default().push(PendingFileWrite {
                image: write_image.to_string(),
                path: path.to_string(),
                buffered_at: Instant::now(),
            });
            file_pending_len.store(file_pending_total(file_pending), Ordering::Relaxed);
        }
    }
}

/// The READ JOIN — the read analog of [`handle_file_write`], feeding the EXFIL
/// chain. Runs the mandatory [`FilePolicy::considers`](torda_mod_filemon::FilePolicy::considers)
/// prefilter FIRST, then re-judges the path with the `write=false` ruleset
/// ([`judge_read`]); a path that does NOT trip `read_of_sensitive_file` is dropped
/// here and never buffered (unlike the write path, a non-suspicious read has no
/// component to emit, so there is no reason to keep it). For a confirmed sensitive
/// read: if the pid is known (live or recently-exited within retention) its read
/// half is recorded IMMEDIATELY, attributed; otherwise the read is BUFFERED for
/// [`GRACE`] so its exec can still attribute it (order-independent). Records/emits
/// NO component record of its own — filemon already emits the read record; corr
/// only completes the exfil chain. Missing/unparseable pid/path, a path the policy
/// does not consider, or a non-sensitive read → skipped (no panic, no emit, no
/// buffer).
#[allow(clippy::too_many_arguments)]
fn handle_file_open(
    ev: &SubstrateEvent,
    meta: &Metadata,
    device: &Device,
    emitter: &dyn torda_core::OcsfEmitter,
    file_policy: &torda_mod_filemon::FilePolicy,
    map: &HashMap<u32, ProcContext>,
    read_pending: &mut HashMap<u32, Vec<PendingFileRead>>,
    recently_exited: &HashMap<u32, (ProcContext, Instant)>,
    chain: &mut HashMap<u32, ChainState>,
    read_pending_len: &AtomicUsize,
    read_pending_evicted: &AtomicU64,
    chain_len: &AtomicUsize,
    chain_evicted: &AtomicU64,
) {
    let pid = match ev.fields.get("pid").and_then(serde_json::Value::as_u64) {
        Some(p) => p,
        None => return,
    };
    let path = match ev.fields.get("path").and_then(serde_json::Value::as_str) {
        Some(s) => s,
        None => return,
    };

    // THE PREFILTER RUNS FIRST — before the join, the assess, or any buffer.
    if !file_policy.considers(path) {
        return;
    }
    // Re-judge with the `write=false` ruleset; only a genuine sensitive read
    // proceeds. Recomputed here, never trusting any incoming severity label.
    let read_detections = match judge_read(path) {
        Some(d) => d,
        None => return,
    };

    let key = pid as u32;
    match map.get(&key) {
        // pid found LIVE → record the read half IMMEDIATELY (attributed).
        Some(c) => {
            record_read_and_maybe_exfil(
                chain,
                meta,
                device,
                emitter,
                pid,
                &c.image,
                &c.exec_detections,
                path,
                read_detections,
                chain_len,
                chain_evicted,
            );
        }
        // pid not found LIVE → it may be a LATE cross-ring event for a process that
        // has ALREADY exited (the short-lived-reader case: the high-volume
        // FILE_EVENTS ring lags, so the read is processed AFTER the pid's exit
        // evicted the live context). If we still hold that context within the
        // retention window, attribute IMMEDIATELY instead of buffering (the exec
        // already came and went, so no future exec would ever drain it).
        None if recently_exited
            .get(&key)
            .is_some_and(|(_, stamp)| stamp.elapsed() < EXITED_RETENTION) =>
        {
            let (c, _) = &recently_exited[&key];
            record_read_and_maybe_exfil(
                chain,
                meta,
                device,
                emitter,
                pid,
                &c.image,
                &c.exec_detections,
                path,
                read_detections,
                chain_len,
                chain_evicted,
            );
        }
        // pid not found → do NOT record; buffer and wait for the exec (GRACE).
        // ALL of a pid's pre-exec sensitive reads are retained (append to its Vec).
        None => {
            // Bounded buffer: cap the TOTAL buffered reads across all pids. If a new
            // buffer would exceed the cap, evict the GLOBALLY oldest read and count
            // it — never a silent drop, never over the cap.
            if read_pending_total(read_pending) >= MAX_PENDING_FILE_READS {
                evict_oldest_read_pending(read_pending, read_pending_evicted);
            }
            read_pending.entry(key).or_default().push(PendingFileRead {
                path: path.to_string(),
                buffered_at: Instant::now(),
            });
            read_pending_len.store(read_pending_total(read_pending), Ordering::Relaxed);
        }
    }
}

#[async_trait]
impl Module for CorrModule {
    fn id(&self) -> ModuleId {
        "corr".to_string()
    }

    async fn init(&mut self, ctx: ModuleCtx) -> anyhow::Result<()> {
        self.ctx = Some(ctx);
        Ok(())
    }

    async fn start(&mut self) -> anyhow::Result<()> {
        // Production entry point: always the real GRACE constant.
        self.start_internal(GRACE).await
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
        let tracked = self.tracked_len.load(Ordering::Relaxed);
        let evicted = self.evicted.load(Ordering::Relaxed);
        let pending = self.pending_len.load(Ordering::Relaxed);
        let pending_evicted = self.pending_evicted.load(Ordering::Relaxed);
        let file_pending = self.file_pending_len.load(Ordering::Relaxed);
        let file_pending_evicted = self.file_pending_evicted.load(Ordering::Relaxed);
        let read_pending = self.read_pending_len.load(Ordering::Relaxed);
        let read_pending_evicted = self.read_pending_evicted.load(Ordering::Relaxed);
        let chain = self.chain_len.load(Ordering::Relaxed);
        let chain_evicted = self.chain_evicted.load(Ordering::Relaxed);
        ModuleHealth {
            ok: self.ctx.is_some(),
            detail: format!(
                "correlation ready; {tracked} tracked, {evicted} evicted, \
                 {pending} pending, {pending_evicted} pending-evictions, \
                 {file_pending} file-pending, {file_pending_evicted} file-pending-evictions, \
                 {read_pending} read-pending, {read_pending_evicted} read-pending-evictions, \
                 {chain} chain, {chain_evicted} chain-evictions"
            ),
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

    // ---------- capturing harness (mirrors procmon/netmon) ----------

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

    fn exec_event(ts: i64, fields: serde_json::Value) -> SubstrateEvent {
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
    fn net_event(ts: i64, fields: serde_json::Value) -> SubstrateEvent {
        SubstrateEvent {
            kind: EventKind::NetConnect,
            ts,
            fields,
        }
    }
    fn file_write_event(ts: i64, fields: serde_json::Value) -> SubstrateEvent {
        SubstrateEvent {
            kind: EventKind::FileWrite,
            ts,
            fields,
        }
    }
    fn file_open_event(ts: i64, fields: serde_json::Value) -> SubstrateEvent {
        SubstrateEvent {
            kind: EventKind::FileOpen,
            ts,
            fields,
        }
    }

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

    /// Bounded drain: wait until at least `want` envelopes are captured.
    async fn wait_until(emitter: &CapturingEmitter, want: usize) {
        for _ in 0..2000 {
            if emitter.emitted.lock().unwrap().len() >= want {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    /// Parse a `{n} {name}` field out of the `health()` detail string.
    fn health_field(detail: &str, name: &str) -> usize {
        for part in detail.split([';', ',']) {
            let part = part.trim();
            if let Some(num) = part.strip_suffix(&format!(" {name}")) {
                return num.trim().parse().unwrap();
            }
        }
        panic!("field '{name}' not found in health detail '{detail}'");
    }

    /// Bounded barrier: wait until exactly `want` connects sit in the pending
    /// buffer — an ordered sync point that does NOT rely on the wall-clock grace
    /// timer (it settles in milliseconds, long before the 250ms grace).
    async fn wait_pending(m: &CorrModule, want: usize) {
        for _ in 0..2000 {
            if health_field(&m.health().detail, "pending") == want {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    /// Bounded barrier: wait until the live tracked-context count reaches `want`
    /// — an ordered sync point on the process stream (exec raises it, exit lowers
    /// it) that does NOT rely on the wall-clock grace timer.
    async fn wait_tracked(m: &CorrModule, want: usize) {
        for _ in 0..2000 {
            if health_field(&m.health().detail, "tracked") == want {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    /// Bounded barrier: wait until the per-pid chain tracker holds `want` entries
    /// — an ordered sync point for the READ half, which records a chain entry but
    /// emits NO record of its own (so `wait_until` cannot observe it).
    async fn wait_chain(m: &CorrModule, want: usize) {
        for _ in 0..2000 {
            if health_field(&m.health().detail, "chain") == want {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    /// Bounded barrier: wait until the task has ABSORBED `want` connects — each is
    /// either still buffered (`pending`) or was evicted at the cap
    /// (`pending-evictions`). Lets the bounded-buffer test pace past the 1024
    /// channel cap without an emit-based sync point.
    async fn wait_absorbed(m: &CorrModule, want: usize) {
        for _ in 0..5000 {
            let d = m.health().detail;
            if health_field(&d, "pending") + health_field(&d, "pending-evictions") >= want {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    /// Bounded barrier: wait until the task has ABSORBED `want` file-writes —
    /// each is either still buffered (`file-pending`) or was evicted at the cap
    /// (`file-pending-evictions`). File analog of [`wait_absorbed`].
    async fn wait_file_absorbed(m: &CorrModule, want: usize) {
        for _ in 0..5000 {
            let d = m.health().detail;
            if health_field(&d, "file-pending") + health_field(&d, "file-pending-evictions") >= want
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    /// Collect the rule names from a `detections` JSON array.
    fn rule_names(detections: &serde_json::Value) -> Vec<String> {
        detections
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["rule"].as_str().unwrap().to_string())
            .collect()
    }

    // ---------- 1. the attack chain ----------

    #[tokio::test]
    async fn attack_chain_suspicious_process_then_suspicious_connection_is_high() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // exec /tmp/nc (procmon: lolbin) THEN connect to a public C2 port (netmon:
        // suspicious_port_to_external). Both halves suspicious → correlated High.
        bus.publish(exec_event(
            1,
            serde_json::json!({ "pid": 7, "image": "/tmp/nc" }),
        ));
        bus.publish(net_event(
            2,
            serde_json::json!({ "pid": 7, "image": "nc", "daddr": "203.0.113.1", "dport": 4444 }),
        ));

        wait_until(&emitter, 1).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        // Exactly one 9002 (the NetConnect); the exec emitted none.
        assert_eq!(emitted.len(), 1, "one correlated record per NetConnect");
        let r = &emitted[0];
        assert_eq!(r.class_uid, class::CORRELATED_ACTIVITY);
        assert_eq!(r.class_name, "Correlated Activity");
        assert_eq!(r.data["activity"], "process_network");
        // Verdict: correlated High.
        assert_eq!(r.severity_id, SEV_HIGH);
        // Top-level correlated rule present.
        assert!(rule_names(&r.data["detections"]).contains(&CORRELATED_RULE.to_string()));
        // Process side: attributed, carries the process detection.
        assert_eq!(r.data["process"]["attributed"], true);
        assert_eq!(r.data["process"]["pid"], 7);
        assert_eq!(r.data["process"]["image"], "/tmp/nc");
        assert!(rule_names(&r.data["process"]["detections"]).contains(&"lolbin".to_string()));
        // Connection side: carries the external-port detection.
        assert!(rule_names(&r.data["connection"]["detections"])
            .contains(&"suspicious_port_to_external".to_string()));
        assert_eq!(r.data["connection"]["daddr"], "203.0.113.1");
        assert_eq!(r.data["connection"]["dport"], 4444);
    }

    // ---------- 2. benign process + suspicious connection: no correlated rule ----------

    #[tokio::test]
    async fn benign_process_suspicious_connection_does_not_fire_correlated_rule() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // Benign echo, then a suspicious external connection. Process half is
        // Informational, so the AND-rule cannot fire.
        bus.publish(exec_event(
            1,
            serde_json::json!({ "pid": 8, "image": "/usr/bin/echo" }),
        ));
        bus.publish(net_event(
            2,
            serde_json::json!({ "pid": 8, "image": "echo", "daddr": "203.0.113.1", "dport": 4444 }),
        ));

        wait_until(&emitter, 1).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(emitted.len(), 1);
        let r = &emitted[0];
        // Severity is the CONNECTION's own verdict (netmon: external C2 = High),
        // NOT the correlated-High-with-that-rule.
        let net_sev = torda_mod_netmon::assess("203.0.113.1", 4444).severity_id;
        assert_eq!(r.severity_id, net_sev);
        // The correlated rule is ABSENT.
        assert!(!rule_names(&r.data["detections"]).contains(&CORRELATED_RULE.to_string()));
        assert_eq!(r.data["detections"].as_array().unwrap().len(), 0);
        assert_eq!(r.data["process"]["attributed"], true);
    }

    // ---------- 3. suspicious process + benign connection: no correlated rule ----------

    #[tokio::test]
    async fn suspicious_process_benign_connection_does_not_fire_correlated_rule() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // Suspicious /tmp/nc, then a benign external connection (443). Connection
        // half is Informational, so the AND-rule cannot fire.
        bus.publish(exec_event(
            1,
            serde_json::json!({ "pid": 9, "image": "/tmp/nc" }),
        ));
        bus.publish(net_event(
            2,
            serde_json::json!({ "pid": 9, "image": "nc", "daddr": "93.184.216.34", "dport": 443 }),
        ));

        wait_until(&emitter, 1).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(emitted.len(), 1);
        let r = &emitted[0];
        // Severity falls back to the PROCESS's exec verdict (connection is Info).
        let exec_sev = torda_mod_procmon::assess("/tmp/nc").severity_id;
        assert_eq!(r.severity_id, exec_sev);
        assert!(
            exec_sev > SEV_INFORMATIONAL,
            "process half really is suspicious"
        );
        // The correlated rule is ABSENT.
        assert!(!rule_names(&r.data["detections"]).contains(&CORRELATED_RULE.to_string()));
        // Connection produced no detections.
        assert_eq!(
            r.data["connection"]["detections"].as_array().unwrap().len(),
            0
        );
    }

    // ---------- 4. unknown pid: unattributed, connection-only verdict ----------

    #[tokio::test]
    async fn unknown_pid_is_unattributed_with_connection_only_verdict() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // NetConnect with no prior exec for this pid. It now BUFFERS (its exec
        // might still arrive); with no exec it flushes un-attributed on stop.
        bus.publish(net_event(
            1,
            serde_json::json!({ "pid": 555, "image": "mystery", "daddr": "203.0.113.1", "dport": 4444 }),
        ));

        wait_pending(&m, 1).await; // buffered, no immediate emit
        m.stop().await.unwrap(); // stop-flush emits it un-attributed

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(emitted.len(), 1);
        let r = &emitted[0];
        assert_eq!(r.data["process"]["attributed"], false);
        // Attributed to the connect comm, no process detections, Informational.
        assert_eq!(r.data["process"]["image"], "mystery");
        assert_eq!(r.data["process"]["detections"].as_array().unwrap().len(), 0);
        // Connection-only verdict = netmon's (external C2 = High); correlated rule
        // absent because the process half is Informational.
        assert_eq!(
            r.severity_id,
            torda_mod_netmon::assess("203.0.113.1", 4444).severity_id
        );
        assert!(!rule_names(&r.data["detections"]).contains(&CORRELATED_RULE.to_string()));
    }

    // ---------- 5a. malformed NetConnect skipped; FileOpen dropped by kind guard ----------

    #[tokio::test]
    async fn malformed_connect_skipped_and_fileopen_dropped_by_kind_guard() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // Malformed NetConnect (no daddr) → skipped, no panic, no emit.
        bus.publish(net_event(
            1,
            serde_json::json!({ "pid": 1, "image": "x", "dport": 4444 }),
        ));
        // FileOpen with exec/connect-looking fields → dropped by the kind guard.
        bus.publish(SubstrateEvent {
            kind: EventKind::FileOpen,
            ts: 2,
            fields: serde_json::json!({ "pid": 2, "image": "/tmp/nc", "daddr": "203.0.113.1", "dport": 4444 }),
        });
        // Trailing VALID chain = ordered sync point: once THIS emits, the two
        // above were already processed (and dropped).
        bus.publish(exec_event(
            3,
            serde_json::json!({ "pid": 3, "image": "/tmp/nc" }),
        ));
        bus.publish(net_event(
            4,
            serde_json::json!({ "pid": 3, "image": "nc", "daddr": "203.0.113.1", "dport": 4444 }),
        ));

        wait_until(&emitter, 1).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(emitted.len(), 1, "only the valid chain emitted a 9002");
        assert_eq!(emitted[0].data["process"]["pid"], 3);
        assert_eq!(emitted[0].severity_id, SEV_HIGH);
    }

    // ---------- 5b. bounded map evicts and counts in health ----------

    #[tokio::test]
    async fn tracked_map_is_bounded_and_evicts_oldest() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // Insert MAX_TRACKED+1 execs (distinct pids, increasing ts so pid 1 is
        // oldest). Execs emit nothing, so we pace with an interleaved NetConnect
        // per batch as an ordered sync point (keeps in-flight < the 1024 channel
        // cap and confirms the batch was processed before continuing).
        let total = MAX_TRACKED + 1;
        let mut published = 0usize;
        let mut netconnects = 0usize;
        while published < total {
            let end = (published + 400).min(total);
            for i in published..end {
                let pid = (i as u64) + 1; // pid 1..=total; ts i so pid 1 is oldest
                bus.publish(exec_event(
                    i as i64,
                    serde_json::json!({ "pid": pid, "image": "/usr/bin/echo" }),
                ));
            }
            published = end;
            // Sync point: one benign NetConnect, wait for its 9002.
            netconnects += 1;
            bus.publish(net_event(
                (published as i64) + 1_000_000,
                serde_json::json!({ "pid": 1u64, "image": "echo", "daddr": "93.184.216.34", "dport": 443 }),
            ));
            wait_until(&emitter, netconnects).await;
        }

        // Eviction happened and is visible in health, map held at the cap.
        let h = m.health();
        m.stop().await.unwrap();
        assert!(
            h.detail.contains(&format!("{MAX_TRACKED} tracked")),
            "map at cap: {}",
            h.detail
        );
        assert!(
            !h.detail.contains("0 evicted"),
            "some eviction occurred: {}",
            h.detail
        );
    }

    // ---------- 6. exactly one 9002 per NetConnect; exec/exit emit none ----------

    #[tokio::test]
    async fn only_netconnect_emits_and_exactly_once_each() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // Two execs + one exit emit NO 9002; the two NetConnects emit exactly one
        // each → total 2.
        bus.publish(exec_event(
            1,
            serde_json::json!({ "pid": 10, "image": "/tmp/nc" }),
        ));
        bus.publish(exec_event(
            2,
            serde_json::json!({ "pid": 11, "image": "/usr/bin/echo" }),
        ));
        bus.publish(exit_event(3, serde_json::json!({ "pid": 10 })));
        bus.publish(net_event(
            4,
            serde_json::json!({ "pid": 11, "image": "echo", "daddr": "203.0.113.1", "dport": 4444 }),
        ));
        // pid 10 exited into recently_exited; this connect arrives WITHIN
        // EXITED_RETENTION, so the cross-ring recently-exited fallback attributes
        // it to /tmp/nc IMMEDIATELY (no buffering) — /tmp/nc + external C2 port →
        // correlated High. (Before the recently-exited fix this connect missed the
        // evicted context and flushed un-attributed; that was the bug.)
        bus.publish(net_event(
            5,
            serde_json::json!({ "pid": 10, "image": "nc", "daddr": "203.0.113.1", "dport": 4444 }),
        ));

        wait_until(&emitter, 2).await; // both connects emit immediately
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(
            emitted.len(),
            2,
            "one 9002 per NetConnect; exec/exit emit none"
        );
        for r in emitted.iter() {
            assert_eq!(r.class_uid, class::CORRELATED_ACTIVITY);
            assert_eq!(r.data["activity"], "process_network");
        }
        // pid 11 attributed (benign echo → correlated rule absent).
        let c11 = emitted
            .iter()
            .find(|e| e.data["process"]["pid"] == 11)
            .unwrap();
        assert_eq!(c11.data["process"]["attributed"], true);
        assert!(!rule_names(&c11.data["detections"]).contains(&CORRELATED_RULE.to_string()));
        // pid 10 exited but the connect landed within retention → attributed to
        // the exited context (/tmp/nc), correlated High with the strict-AND rule.
        let c10 = emitted
            .iter()
            .find(|e| e.data["process"]["pid"] == 10)
            .unwrap();
        assert_eq!(c10.data["process"]["attributed"], true);
        assert_eq!(c10.data["process"]["image"], "/tmp/nc");
        assert_eq!(c10.severity_id, SEV_HIGH);
        assert!(rule_names(&c10.data["detections"]).contains(&CORRELATED_RULE.to_string()));
    }

    // ---------- 7. THE FIX: connect BEFORE exec still correlates (order-independent) ----------

    #[tokio::test]
    async fn connect_before_exec_still_correlates_high() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // On the real substrate the NET_EVENTS ring can be drained before the
        // EVENTS ring, so the connect arrives FIRST. It must still correlate once
        // the exec lands. (This case is MISSED on `main`.)
        bus.publish(net_event(
            1,
            serde_json::json!({ "pid": 7, "image": "nc", "daddr": "203.0.113.1", "dport": 4444 }),
        ));
        bus.publish(exec_event(
            2,
            serde_json::json!({ "pid": 7, "image": "/tmp/nc" }),
        ));

        // The exec-drain emits synchronously when the exec is processed.
        wait_until(&emitter, 1).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(
            emitted.len(),
            1,
            "exactly one correlated record for the reordered pair"
        );
        let r = &emitted[0];
        assert_eq!(r.class_uid, class::CORRELATED_ACTIVITY);
        // Correlated High, with the strict-AND rule, attributed to the EXEC image.
        assert_eq!(r.severity_id, SEV_HIGH);
        assert!(rule_names(&r.data["detections"]).contains(&CORRELATED_RULE.to_string()));
        assert_eq!(r.data["process"]["attributed"], true);
        assert_eq!(r.data["process"]["pid"], 7);
        assert_eq!(r.data["process"]["image"], "/tmp/nc");
        assert!(rule_names(&r.data["process"]["detections"]).contains(&"lolbin".to_string()));
        assert_eq!(r.data["connection"]["daddr"], "203.0.113.1");
        assert_eq!(r.data["connection"]["dport"], 4444);
    }

    // ---------- 8. exec-first is still an IMMEDIATE, single emit (unchanged path) ----------

    #[tokio::test]
    async fn exec_first_connect_is_immediate_and_single() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        bus.publish(exec_event(
            1,
            serde_json::json!({ "pid": 21, "image": "/tmp/nc" }),
        ));
        bus.publish(net_event(
            2,
            serde_json::json!({ "pid": 21, "image": "nc", "daddr": "203.0.113.1", "dport": 4444 }),
        ));

        // Emitted immediately by the found-path — nothing buffered.
        wait_until(&emitter, 1).await;
        assert_eq!(
            health_field(&m.health().detail, "pending"),
            0,
            "nothing buffered"
        );
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0].severity_id, SEV_HIGH);
        assert_eq!(emitted[0].data["process"]["attributed"], true);
    }

    // ---------- 9. exactly-once: a drained connect is NOT re-emitted by flush/stop ----------

    #[tokio::test]
    async fn buffered_connect_drained_by_exec_is_not_re_emitted() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // Connect buffers, its exec drains it (one emit). A later grace tick and
        // the stop-flush must NOT emit it again.
        bus.publish(net_event(
            1,
            serde_json::json!({ "pid": 33, "image": "nc", "daddr": "203.0.113.1", "dport": 4444 }),
        ));
        bus.publish(exec_event(
            2,
            serde_json::json!({ "pid": 33, "image": "/tmp/nc" }),
        ));
        wait_until(&emitter, 1).await;

        // Wait comfortably past the grace window so the interval backstop has run.
        for _ in 0..400 {
            tokio::time::sleep(Duration::from_millis(1)).await;
            assert_eq!(
                emitter.emitted.lock().unwrap().len(),
                1,
                "no double-emit after grace"
            );
        }
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(
            emitted.len(),
            1,
            "exactly one 9002 for the drained connect across the whole run"
        );
        assert_eq!(emitted[0].data["process"]["attributed"], true);
    }

    // ---------- 10. grace backstop: no-exec connect flushes un-attributed BEFORE stop ----------

    #[tokio::test]
    async fn buffered_connect_flushes_unattributed_after_grace() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // No exec ever arrives. The interval backstop must flush it after GRACE —
        // with NO stop() call (proving the timer path, bounded so it can't hang).
        bus.publish(net_event(
            1,
            serde_json::json!({ "pid": 44, "image": "mystery", "daddr": "203.0.113.1", "dport": 4444 }),
        ));

        wait_until(&emitter, 1).await; // grace flush emits within ~GRACE
        {
            let emitted = emitter.emitted.lock().unwrap();
            assert_eq!(
                emitted.len(),
                1,
                "flushed by the grace backstop before stop"
            );
            assert_eq!(emitted[0].data["process"]["attributed"], false);
            assert_eq!(emitted[0].data["process"]["image"], "mystery");
        }
        m.stop().await.unwrap();
        // Stop must not re-emit the already-flushed connect.
        assert_eq!(emitter.emitted.lock().unwrap().len(), 1);
    }

    // ---------- 11. pending buffer is bounded and counts cap evictions ----------

    #[tokio::test]
    async fn pending_buffer_is_bounded_and_counts_evictions() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        // Deterministic seam (test-only, `#[cfg(test)]`): start with a grace
        // duration far longer than this test can possibly run, instead of the
        // real 250ms `GRACE`. Production always uses `start()` → real `GRACE`;
        // this test alone needs the grace-flush timer's *effect* disabled so
        // the fill below can never race it. Without this seam, a slow host
        // could let the periodic grace-flush (which ticks every `GRACE/2`)
        // drain the oldest buffered connects mid-fill, making both the
        // `pending_evicted > 0` assertion and `wait_absorbed` flaky (the
        // eviction path might never fire, or absorption might stall). With
        // the timer's expiry check unreachable, the ONLY way pending count is
        // ever reduced is the `MAX_PENDING_CONNECTS` cap eviction itself — so
        // the assertions below are still non-vacuous: if the cap were
        // removed, `pending` would just grow past it and `pending-evictions`
        // would stay 0, and this test would fail.
        m.start_with_grace(Duration::from_secs(3600)).await.unwrap();

        // Publish MAX_PENDING_CONNECTS+1 un-attributed connects (distinct pids) in
        // batches under the 1024 channel cap, syncing on the absorbed count so the
        // receiver never lags. Crossing the cap must evict-oldest and count it.
        let total = MAX_PENDING_CONNECTS + 1;
        let mut published = 0usize;
        while published < total {
            let end = (published + 512).min(total);
            for i in published..end {
                let pid = (i as u64) + 1; // pid 1..=total; ts i so pid 1 is oldest
                bus.publish(net_event(
                    i as i64,
                    serde_json::json!({ "pid": pid, "image": "nc", "daddr": "203.0.113.1", "dport": 4444 }),
                ));
            }
            published = end;
            wait_absorbed(&m, published).await;
        }

        // Cap eviction happened and is visible in health — nothing panicked.
        let h = m.health();
        m.stop().await.unwrap();
        assert!(
            health_field(&h.detail, "pending-evictions") > 0,
            "pending buffer evicted at the cap: {}",
            h.detail
        );
        assert!(
            health_field(&h.detail, "pending") <= MAX_PENDING_CONNECTS,
            "pending never exceeds the cap: {}",
            h.detail
        );
    }

    // ---------- 12. THE FIX: ≥2 same-pid connects BEFORE exec ALL correlate ----------

    #[tokio::test]
    async fn multiple_connects_same_pid_before_exec_all_correlate() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // TWO NetConnects for the SAME pid=7 to DIFFERENT destinations, BOTH
        // BEFORE the exec is drained. With the single-slot map this dropped the
        // first (overwrite). With the per-pid Vec, BOTH must be retained and then
        // correlated when the exec lands — exactly TWO 9002 records, one per dest.
        bus.publish(net_event(
            1,
            serde_json::json!({ "pid": 7, "image": "nc", "daddr": "203.0.113.1", "dport": 4444 }),
        ));
        bus.publish(net_event(
            2,
            serde_json::json!({ "pid": 7, "image": "nc", "daddr": "203.0.113.9", "dport": 4444 }),
        ));
        bus.publish(exec_event(
            3,
            serde_json::json!({ "pid": 7, "image": "/tmp/nc" }),
        ));

        wait_until(&emitter, 2).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        // BOTH pre-exec connects emit — NOT one (no overwrite loss).
        assert_eq!(
            emitted.len(),
            2,
            "both pre-exec connects for pid 7 emit correlated"
        );
        for r in emitted.iter() {
            assert_eq!(r.class_uid, class::CORRELATED_ACTIVITY);
            assert_eq!(r.data["process"]["pid"], 7);
            assert_eq!(r.data["process"]["attributed"], true);
            assert_eq!(r.data["process"]["image"], "/tmp/nc");
            // Both halves suspicious → correlated High with the strict-AND rule.
            assert_eq!(r.severity_id, SEV_HIGH);
            assert!(rule_names(&r.data["detections"]).contains(&CORRELATED_RULE.to_string()));
        }
        // Each destination is represented exactly once.
        let mut daddrs: Vec<String> = emitted
            .iter()
            .map(|r| r.data["connection"]["daddr"].as_str().unwrap().to_string())
            .collect();
        daddrs.sort();
        assert_eq!(
            daddrs,
            vec!["203.0.113.1".to_string(), "203.0.113.9".to_string()]
        );
    }

    // ---------- 13. no-loss on flush: ≥2 same-pid connects, NO exec, ALL flush ----------

    #[tokio::test]
    async fn multiple_connects_same_pid_no_exec_all_flush_unattributed() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // Two connects for the same pid, NO exec ever. Both buffer; the stop-flush
        // must emit BOTH un-attributed (no loss). Also proves the buffered path
        // preserves the connect's real `proto` (here "udp"), not a hardcoded "tcp".
        bus.publish(net_event(
            1,
            serde_json::json!({ "pid": 7, "image": "a", "daddr": "203.0.113.1", "dport": 4444, "proto": "udp" }),
        ));
        bus.publish(net_event(
            2,
            serde_json::json!({ "pid": 7, "image": "b", "daddr": "203.0.113.9", "dport": 4444, "proto": "udp" }),
        ));

        wait_pending(&m, 2).await; // BOTH buffered (2 total), not 1
        m.stop().await.unwrap(); // stop-flush emits both un-attributed

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(
            emitted.len(),
            2,
            "both buffered connects flush on stop (no loss)"
        );
        for r in emitted.iter() {
            assert_eq!(r.data["process"]["pid"], 7);
            assert_eq!(r.data["process"]["attributed"], false);
            // proto preserved from the buffered connect, not hardcoded "tcp".
            assert_eq!(r.data["connection"]["proto"], "udp");
        }
        let mut daddrs: Vec<String> = emitted
            .iter()
            .map(|r| r.data["connection"]["daddr"].as_str().unwrap().to_string())
            .collect();
        daddrs.sort();
        assert_eq!(
            daddrs,
            vec!["203.0.113.1".to_string(), "203.0.113.9".to_string()]
        );
    }

    // ==================== FILE-WRITE CORRELATION ====================

    // ---------- F1. the file attack chain: suspicious proc + suspicious write ----------

    #[tokio::test]
    async fn attack_chain_suspicious_process_then_suspicious_file_write_is_high() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // exec /tmp/nc (procmon: lolbin) THEN write to /etc/passwd (filemon:
        // write_to_sensitive_config). Both halves suspicious → correlated High.
        bus.publish(exec_event(
            1,
            serde_json::json!({ "pid": 7, "image": "/tmp/nc" }),
        ));
        bus.publish(file_write_event(
            2,
            serde_json::json!({ "pid": 7, "image": "nc", "path": "/etc/passwd" }),
        ));

        wait_until(&emitter, 1).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(emitted.len(), 1, "one correlated record per FileWrite");
        let r = &emitted[0];
        assert_eq!(r.class_uid, class::CORRELATED_ACTIVITY);
        assert_eq!(r.class_name, "Correlated Activity");
        assert_eq!(r.data["activity"], "process_file");
        // Verdict: correlated High.
        assert_eq!(r.severity_id, SEV_HIGH);
        // Top-level correlated file rule present.
        assert!(rule_names(&r.data["detections"]).contains(&CORRELATED_FILE_RULE.to_string()));
        // Process side: attributed to the EXEC image, carries the process detection.
        assert_eq!(r.data["process"]["attributed"], true);
        assert_eq!(r.data["process"]["pid"], 7);
        assert_eq!(r.data["process"]["image"], "/tmp/nc");
        assert!(rule_names(&r.data["process"]["detections"]).contains(&"lolbin".to_string()));
        // File side: carries the sensitive-config write detection.
        assert_eq!(r.data["file"]["path"], "/etc/passwd");
        assert_eq!(r.data["file"]["op"], "write");
        assert!(rule_names(&r.data["file"]["detections"])
            .contains(&"write_to_sensitive_config".to_string()));
    }

    // ---------- F2. AND contract: benign process + suspicious write does NOT fire ----------

    #[tokio::test]
    async fn benign_process_suspicious_file_write_does_not_fire_correlated_rule() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // Benign echo, then a suspicious write to /etc/passwd. Process half is
        // Informational, so the AND-rule cannot fire — record emits at the file
        // verdict's severity, WITHOUT the correlated rule.
        bus.publish(exec_event(
            1,
            serde_json::json!({ "pid": 8, "image": "/usr/bin/echo" }),
        ));
        bus.publish(file_write_event(
            2,
            serde_json::json!({ "pid": 8, "image": "echo", "path": "/etc/passwd" }),
        ));

        wait_until(&emitter, 1).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(emitted.len(), 1);
        let r = &emitted[0];
        // Severity is the FILE's own verdict (filemon: sensitive config = High),
        // NOT correlated-High-with-that-rule.
        let file_sev = torda_mod_filemon::assess("/etc/passwd", true).severity_id;
        assert_eq!(r.severity_id, file_sev);
        // The correlated rule is ABSENT.
        assert!(!rule_names(&r.data["detections"]).contains(&CORRELATED_FILE_RULE.to_string()));
        assert_eq!(r.data["detections"].as_array().unwrap().len(), 0);
        assert_eq!(r.data["process"]["attributed"], true);
    }

    // ---------- F3. prefilter: an ignored path produces NO correlation attempt ----------

    #[tokio::test]
    async fn ignored_path_write_is_dropped_by_considers_prefilter() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // Suspicious process, but the write is to /tmp/x — dropped by the
        // `FilePolicy::considers` prefilter, so it never enters the join (no
        // emit, no buffer). The trailing WATCHED write is a sync point.
        bus.publish(exec_event(
            1,
            serde_json::json!({ "pid": 9, "image": "/tmp/nc" }),
        ));
        bus.publish(file_write_event(
            2,
            serde_json::json!({ "pid": 9, "image": "nc", "path": "/tmp/x" }),
        ));
        // Trailing VALID chain = ordered sync point: once THIS emits, the /tmp/x
        // write above was already processed (and dropped by considers).
        bus.publish(file_write_event(
            3,
            serde_json::json!({ "pid": 9, "image": "nc", "path": "/etc/passwd" }),
        ));

        wait_until(&emitter, 1).await;
        // Nothing was buffered by the ignored write.
        assert_eq!(health_field(&m.health().detail, "file-pending"), 0);
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(
            emitted.len(),
            1,
            "only the watched write correlated; /tmp/x dropped"
        );
        assert_eq!(emitted[0].data["file"]["path"], "/etc/passwd");
        assert_eq!(emitted[0].severity_id, SEV_HIGH);
    }

    // ---------- F4. order-independence: write BEFORE exec still correlates ----------

    #[tokio::test]
    async fn file_write_before_exec_still_correlates_high() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // On the real substrate the FILE_EVENTS ring can be drained before the
        // EVENTS ring, so the write arrives FIRST. It must still correlate once
        // the exec lands.
        bus.publish(file_write_event(
            1,
            serde_json::json!({ "pid": 7, "image": "nc", "path": "/etc/passwd" }),
        ));
        bus.publish(exec_event(
            2,
            serde_json::json!({ "pid": 7, "image": "/tmp/nc" }),
        ));

        // The exec-drain emits synchronously when the exec is processed.
        wait_until(&emitter, 1).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(
            emitted.len(),
            1,
            "exactly one correlated record for the reordered pair"
        );
        let r = &emitted[0];
        assert_eq!(r.class_uid, class::CORRELATED_ACTIVITY);
        assert_eq!(r.severity_id, SEV_HIGH);
        assert!(rule_names(&r.data["detections"]).contains(&CORRELATED_FILE_RULE.to_string()));
        assert_eq!(r.data["process"]["attributed"], true);
        assert_eq!(r.data["process"]["image"], "/tmp/nc");
        assert!(rule_names(&r.data["process"]["detections"]).contains(&"lolbin".to_string()));
        assert_eq!(r.data["file"]["path"], "/etc/passwd");
    }

    // ---------- F5. grace/stop flush: a write whose exec never arrives is un-attributed ----------

    #[tokio::test]
    async fn file_write_without_exec_flushes_unattributed() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // No exec for this pid. The write BUFFERS; with no exec it flushes
        // un-attributed with a FILE-ONLY verdict (the process half is never
        // guessed). Proven via the grace backstop (no stop() first).
        bus.publish(file_write_event(
            1,
            serde_json::json!({ "pid": 44, "image": "mystery", "path": "/etc/passwd" }),
        ));

        wait_until(&emitter, 1).await; // grace flush emits within ~GRACE
        {
            let emitted = emitter.emitted.lock().unwrap();
            assert_eq!(
                emitted.len(),
                1,
                "flushed by the grace backstop before stop"
            );
            let r = &emitted[0];
            assert_eq!(r.data["process"]["attributed"], false);
            assert_eq!(r.data["process"]["image"], "mystery");
            assert_eq!(r.data["process"]["detections"].as_array().unwrap().len(), 0);
            // File-only verdict = filemon's (sensitive config = High); correlated
            // rule absent because the process half is Informational.
            assert_eq!(
                r.severity_id,
                torda_mod_filemon::assess("/etc/passwd", true).severity_id
            );
            assert!(!rule_names(&r.data["detections"]).contains(&CORRELATED_FILE_RULE.to_string()));
            assert_eq!(r.data["file"]["path"], "/etc/passwd");
        }
        m.stop().await.unwrap();
        // Stop must not re-emit the already-flushed write.
        assert_eq!(emitter.emitted.lock().unwrap().len(), 1);
    }

    // ---------- F6. file pending buffer is bounded and counts cap evictions ----------

    #[tokio::test]
    async fn file_pending_buffer_is_bounded_and_counts_evictions() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        // Same deterministic seam as the connect bounded test: a huge grace makes
        // the grace-flush timer's expiry check unreachable, so the ONLY way the
        // file pending count is ever reduced is the `MAX_PENDING_FILE_WRITES` cap
        // eviction itself — keeping the assertions below non-vacuous.
        m.start_with_grace(Duration::from_secs(3600)).await.unwrap();

        // Publish MAX_PENDING_FILE_WRITES+1 un-attributed watched writes (distinct
        // pids) in batches under the 1024 channel cap, syncing on the absorbed
        // count. Crossing the cap must evict-oldest and count it.
        let total = MAX_PENDING_FILE_WRITES + 1;
        let mut published = 0usize;
        while published < total {
            let end = (published + 512).min(total);
            for i in published..end {
                let pid = (i as u64) + 1; // pid 1..=total; ts i so pid 1 is oldest
                bus.publish(file_write_event(
                    i as i64,
                    serde_json::json!({ "pid": pid, "image": "nc", "path": "/etc/passwd" }),
                ));
            }
            published = end;
            wait_file_absorbed(&m, published).await;
        }

        // Cap eviction happened and is visible in health — nothing panicked.
        let h = m.health();
        m.stop().await.unwrap();
        assert!(
            health_field(&h.detail, "file-pending-evictions") > 0,
            "file pending buffer evicted at the cap: {}",
            h.detail
        );
        assert!(
            health_field(&h.detail, "file-pending") <= MAX_PENDING_FILE_WRITES,
            "file pending never exceeds the cap: {}",
            h.detail
        );
    }

    // ---------- F7. exactly-once: a drained write is NOT re-emitted by flush/stop ----------

    #[tokio::test]
    async fn buffered_file_write_drained_by_exec_is_not_re_emitted() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // Write buffers, its exec drains it (one emit). A later grace tick and the
        // stop-flush must NOT emit it again.
        bus.publish(file_write_event(
            1,
            serde_json::json!({ "pid": 33, "image": "nc", "path": "/etc/passwd" }),
        ));
        bus.publish(exec_event(
            2,
            serde_json::json!({ "pid": 33, "image": "/tmp/nc" }),
        ));
        wait_until(&emitter, 1).await;

        // Wait comfortably past the grace window so the interval backstop has run.
        for _ in 0..400 {
            tokio::time::sleep(Duration::from_millis(1)).await;
            assert_eq!(
                emitter.emitted.lock().unwrap().len(),
                1,
                "no double-emit after grace"
            );
        }
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(
            emitted.len(),
            1,
            "exactly one 9002 for the drained write across the whole run"
        );
        assert_eq!(emitted[0].data["process"]["attributed"], true);
        assert_eq!(emitted[0].severity_id, SEV_HIGH);
    }

    // ==================== RECENTLY-EXITED ATTRIBUTION ====================

    // ---------- R1. THE REGRESSION: exec → exit → (lagged) write STILL attributes ----------

    #[tokio::test]
    async fn file_write_after_exit_within_retention_attributes_high() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // The short-lived-writer (dropper) ordering the live eBPF checkpoint
        // caught: exec, then exit (which evicts the LIVE context), then — LATE,
        // because the high-volume FILE_EVENTS ring lags — the write for the SAME
        // pid. On `main` the write misses the live map AND cannot be rescued by the
        // pre-exec buffer (the exec already came and went), so it flushed
        // un-attributed. With recently-exited retention it MUST attribute.
        bus.publish(exec_event(
            1,
            serde_json::json!({ "pid": 7, "image": "/tmp/nc" }),
        ));
        bus.publish(exit_event(2, serde_json::json!({ "pid": 7 })));
        bus.publish(file_write_event(
            3,
            serde_json::json!({ "pid": 7, "image": "nc", "path": "/etc/passwd" }),
        ));

        // The recently-exited fallback emits synchronously when the write is
        // processed (no buffering, no grace wait).
        wait_until(&emitter, 1).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(
            emitted.len(),
            1,
            "exactly one correlated record for the post-exit write"
        );
        let r = &emitted[0];
        assert_eq!(r.class_uid, class::CORRELATED_ACTIVITY);
        assert_eq!(r.data["activity"], "process_file");
        // Attributed to the EXITED process's context, correlated High with the rule.
        assert_eq!(r.severity_id, SEV_HIGH);
        assert!(rule_names(&r.data["detections"]).contains(&CORRELATED_FILE_RULE.to_string()));
        assert_eq!(r.data["process"]["attributed"], true);
        assert_eq!(r.data["process"]["pid"], 7);
        assert_eq!(r.data["process"]["image"], "/tmp/nc");
        assert!(rule_names(&r.data["process"]["detections"]).contains(&"lolbin".to_string()));
        assert_eq!(r.data["file"]["path"], "/etc/passwd");
    }

    // ---------- R2. symmetric connect case: exec → exit → (lagged) connect attributes ----------

    #[tokio::test]
    async fn connect_after_exit_within_retention_attributes_high() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // Same recently-exited attribution for the network ring: exec, exit, then a
        // lagged NetConnect for the exited pid must still correlate.
        bus.publish(exec_event(
            1,
            serde_json::json!({ "pid": 7, "image": "/tmp/nc" }),
        ));
        bus.publish(exit_event(2, serde_json::json!({ "pid": 7 })));
        bus.publish(net_event(
            3,
            serde_json::json!({ "pid": 7, "image": "nc", "daddr": "203.0.113.1", "dport": 4444 }),
        ));

        wait_until(&emitter, 1).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(
            emitted.len(),
            1,
            "exactly one correlated record for the post-exit connect"
        );
        let r = &emitted[0];
        assert_eq!(r.data["activity"], "process_network");
        assert_eq!(r.severity_id, SEV_HIGH);
        assert!(rule_names(&r.data["detections"]).contains(&CORRELATED_RULE.to_string()));
        assert_eq!(r.data["process"]["attributed"], true);
        assert_eq!(r.data["process"]["pid"], 7);
        assert_eq!(r.data["process"]["image"], "/tmp/nc");
        assert_eq!(r.data["connection"]["daddr"], "203.0.113.1");
        assert_eq!(r.data["connection"]["dport"], 4444);
    }

    // ---------- R3. retention bound: a write PAST the window is NOT attributed ----------

    #[tokio::test]
    async fn file_write_after_retention_is_unattributed() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // exec then exit stashes the context in recently_exited, stamped now.
        bus.publish(exec_event(
            1,
            serde_json::json!({ "pid": 7, "image": "/tmp/nc" }),
        ));
        wait_tracked(&m, 1).await; // exec processed (context live)
        bus.publish(exit_event(2, serde_json::json!({ "pid": 7 })));
        wait_tracked(&m, 0).await; // exit processed (context now recently-exited)

        // Advance PAST the retention window. Once elapsed exceeds EXITED_RETENTION
        // the fallback can no longer fire (and the grace tick purges the entry), so
        // the late write must fall through to buffering and flush un-attributed.
        tokio::time::sleep(EXITED_RETENTION + Duration::from_millis(150)).await;

        bus.publish(file_write_event(
            3,
            serde_json::json!({ "pid": 7, "image": "nc", "path": "/etc/passwd" }),
        ));

        wait_until(&emitter, 1).await; // buffered, then grace-flushed un-attributed
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(emitted.len(), 1, "one record, flushed un-attributed");
        let r = &emitted[0];
        // Retention expired → NOT attributed; file-only verdict, no correlated rule.
        assert_eq!(r.data["process"]["attributed"], false);
        assert_eq!(r.data["process"]["image"], "nc");
        assert!(!rule_names(&r.data["detections"]).contains(&CORRELATED_FILE_RULE.to_string()));
        assert_eq!(r.data["file"]["path"], "/etc/passwd");
    }

    // ---------- R4. pid reuse: a reused pid attributes to the NEW image, never the old ----------

    #[tokio::test]
    async fn pid_reuse_attributes_to_new_image_not_the_exited_one() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // pid 7 runs imgA (/tmp/nc) and exits, then the SAME pid is reused by imgB
        // (/tmp/curl) which also exits. Both are lolbins (suspicious). A lagged
        // write for pid 7 must attribute to imgB — the re-exec cleared imgA from
        // recently_exited so the stale context can never win, and imgB's own exit
        // re-stashed the current context.
        bus.publish(exec_event(
            1,
            serde_json::json!({ "pid": 7, "image": "/tmp/nc" }),
        ));
        wait_tracked(&m, 1).await;
        bus.publish(exit_event(2, serde_json::json!({ "pid": 7 })));
        wait_tracked(&m, 0).await;
        bus.publish(exec_event(
            3,
            serde_json::json!({ "pid": 7, "image": "/tmp/curl" }),
        ));
        wait_tracked(&m, 1).await;
        bus.publish(exit_event(4, serde_json::json!({ "pid": 7 })));
        wait_tracked(&m, 0).await;
        bus.publish(file_write_event(
            5,
            serde_json::json!({ "pid": 7, "image": "curl", "path": "/etc/passwd" }),
        ));

        wait_until(&emitter, 1).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(emitted.len(), 1, "exactly one correlated record");
        let r = &emitted[0];
        assert_eq!(r.data["process"]["attributed"], true);
        assert_eq!(r.data["process"]["pid"], 7);
        // Attributed to the REUSED image, never the earlier exited one.
        assert_eq!(r.data["process"]["image"], "/tmp/curl");
        assert_ne!(r.data["process"]["image"], "/tmp/nc");
        assert_eq!(r.severity_id, SEV_HIGH);
        assert!(rule_names(&r.data["detections"]).contains(&CORRELATED_FILE_RULE.to_string()));
    }

    // ==================== TRIPLE CHAIN (write + connect) ====================

    /// Count the WRITE-TRIPLE records among a captured batch. The exfil record
    /// SHARES the `process_file_network` activity, so this disambiguates by the
    /// unique top-level rule [`CORRELATED_CHAIN_RULE`] — symmetric with `exfils()`
    /// — instead of matching the activity alone (which would over-match the exfil).
    fn triples(emitted: &[OcsfEnvelope]) -> Vec<&OcsfEnvelope> {
        emitted
            .iter()
            .filter(|e| {
                e.data["activity"] == "process_file_network"
                    && rule_names(&e.data["detections"])
                        .contains(&CORRELATED_CHAIN_RULE.to_string())
            })
            .collect()
    }

    /// Full assertions on a single triple record: SEV_HIGH, both blocks, all three
    /// detection sets, and the top-level chain rule.
    fn assert_valid_triple(r: &OcsfEnvelope) {
        assert_eq!(r.class_uid, class::CORRELATED_ACTIVITY);
        assert_eq!(r.class_name, "Correlated Activity");
        assert_eq!(r.data["activity"], "process_file_network");
        assert_eq!(r.severity_id, SEV_HIGH);
        // Top-level chain rule present.
        assert!(rule_names(&r.data["detections"]).contains(&CORRELATED_CHAIN_RULE.to_string()));
        // Process block: attributed + carries the process detection set.
        assert_eq!(r.data["process"]["attributed"], true);
        assert_eq!(r.data["process"]["pid"], 7);
        assert_eq!(r.data["process"]["image"], "/tmp/nc");
        assert!(rule_names(&r.data["process"]["detections"]).contains(&"lolbin".to_string()));
        // File block: carries the sensitive-config write detection.
        assert_eq!(r.data["file"]["path"], "/etc/passwd");
        assert_eq!(r.data["file"]["op"], "write");
        assert!(rule_names(&r.data["file"]["detections"])
            .contains(&"write_to_sensitive_config".to_string()));
        // Connection block: carries the external-port detection.
        assert_eq!(r.data["connection"]["daddr"], "203.0.113.1");
        assert_eq!(r.data["connection"]["dport"], 4444);
        assert!(rule_names(&r.data["connection"]["detections"])
            .contains(&"suspicious_port_to_external".to_string()));
    }

    // ---------- T1. suspicious WRITE then suspicious CONNECT → ONE triple + 2 components ----------

    #[tokio::test]
    async fn triple_chain_write_then_connect_fires_once_with_all_three() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // One pid: exec (lolbin) → suspicious write (/etc/passwd) → suspicious
        // connect (external C2). The write emits the file component, the connect
        // emits the connect component AND completes the triple → 3 records total.
        bus.publish(exec_event(
            1,
            serde_json::json!({ "pid": 7, "image": "/tmp/nc" }),
        ));
        bus.publish(file_write_event(
            2,
            serde_json::json!({ "pid": 7, "image": "nc", "path": "/etc/passwd" }),
        ));
        bus.publish(net_event(
            3,
            serde_json::json!({ "pid": 7, "image": "nc", "daddr": "203.0.113.1", "dport": 4444 }),
        ));

        wait_until(&emitter, 3).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(
            emitted.len(),
            3,
            "file component + connect component + triple"
        );
        // Exactly one triple, fully formed.
        let t = triples(&emitted);
        assert_eq!(t.len(), 1, "exactly one triple");
        assert_valid_triple(t[0]);
        // The two component records STILL emit independently (additive).
        let has_file_component = emitted.iter().any(|e| {
            e.data["activity"] == "process_file"
                && rule_names(&e.data["detections"]).contains(&CORRELATED_FILE_RULE.to_string())
        });
        let has_conn_component = emitted.iter().any(|e| {
            e.data["activity"] == "process_network"
                && rule_names(&e.data["detections"]).contains(&CORRELATED_RULE.to_string())
        });
        assert!(has_file_component, "file component still fires");
        assert!(has_conn_component, "connect component still fires");
    }

    // ---------- T1b (regression): a SHORT-LIVED pid whose EXIT lands BETWEEN its
    // two cross-ring halves STILL chains — the dropper case the triple exists to
    // catch. The connect records its half, the pid then EXITS, and the write
    // arrives late (attributed via `recently_exited`). Pre-fix, `handle_exit`
    // dropped the chain entry between the halves, so only the two components fired
    // and never the triple — the live eBPF run proved this (only 1 of 5 short-lived
    // curls chained). With the exit-drop removed (chain survives the window; pid
    // reuse handled on re-exec) all halves join: this asserts the third record. ----------
    #[tokio::test]
    async fn triple_chain_survives_exit_between_halves() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // pid 7: exec (lolbin) → suspicious connect (connect component + conn half)
        // → EXIT (context moves to recently_exited; the chain half must NOT drop)
        // → suspicious write, attributed via recently_exited (file component AND
        // completes the triple). 3 records: connect comp, file comp, triple.
        bus.publish(exec_event(
            1,
            serde_json::json!({ "pid": 7, "image": "/tmp/nc" }),
        ));
        bus.publish(net_event(
            2,
            serde_json::json!({ "pid": 7, "image": "nc", "daddr": "203.0.113.1", "dport": 4444 }),
        ));
        bus.publish(exit_event(3, serde_json::json!({ "pid": 7 })));
        bus.publish(file_write_event(
            4,
            serde_json::json!({ "pid": 7, "image": "nc", "path": "/etc/passwd" }),
        ));

        wait_until(&emitter, 3).await; // connect component + file component + triple
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        let t = triples(&emitted);
        assert_eq!(
            t.len(),
            1,
            "the triple must survive the exit landing between its two halves"
        );
        assert_valid_triple(t[0]);
    }

    // ---------- T2. order-independent: suspicious CONNECT then suspicious WRITE → same triple ----------

    #[tokio::test]
    async fn triple_chain_connect_then_write_is_order_independent() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // Same pid, halves reversed: connect first (connect component), then write
        // (file component AND completes the triple). Conjunction is order-independent.
        bus.publish(exec_event(
            1,
            serde_json::json!({ "pid": 7, "image": "/tmp/nc" }),
        ));
        bus.publish(net_event(
            2,
            serde_json::json!({ "pid": 7, "image": "nc", "daddr": "203.0.113.1", "dport": 4444 }),
        ));
        bus.publish(file_write_event(
            3,
            serde_json::json!({ "pid": 7, "image": "nc", "path": "/etc/passwd" }),
        ));

        wait_until(&emitter, 3).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(emitted.len(), 3);
        let t = triples(&emitted);
        assert_eq!(t.len(), 1, "exactly one triple regardless of half order");
        assert_valid_triple(t[0]);
    }

    // ---------- T3. only ONE half present → NO triple ----------

    #[tokio::test]
    async fn triple_chain_only_write_does_not_fire() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // A suspicious write but NO connect for the pid → the file component fires,
        // the triple does NOT (conjunction needs both halves).
        bus.publish(exec_event(
            1,
            serde_json::json!({ "pid": 7, "image": "/tmp/nc" }),
        ));
        bus.publish(file_write_event(
            2,
            serde_json::json!({ "pid": 7, "image": "nc", "path": "/etc/passwd" }),
        ));

        wait_until(&emitter, 1).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(emitted.len(), 1, "only the file component");
        assert!(triples(&emitted).is_empty(), "no triple from one half");
    }

    #[tokio::test]
    async fn triple_chain_only_connect_does_not_fire() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // A suspicious connect but NO write for the pid → connect component fires,
        // the triple does NOT.
        bus.publish(exec_event(
            1,
            serde_json::json!({ "pid": 7, "image": "/tmp/nc" }),
        ));
        bus.publish(net_event(
            2,
            serde_json::json!({ "pid": 7, "image": "nc", "daddr": "203.0.113.1", "dport": 4444 }),
        ));

        wait_until(&emitter, 1).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(emitted.len(), 1, "only the connect component");
        assert!(triples(&emitted).is_empty(), "no triple from one half");
    }

    // ---------- T4. halves > CHAIN_WINDOW apart → NO triple ----------

    #[tokio::test]
    async fn triple_chain_halves_outside_window_do_not_fire() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // Suspicious write, then a suspicious connect for the SAME pid but stamped
        // MORE than CHAIN_WINDOW later. Both component rules fire, but the halves
        // are too far apart to be one attack chain → no triple. (The stale file
        // half is also purged by the grace tick once it ages past the window.)
        bus.publish(exec_event(
            1,
            serde_json::json!({ "pid": 7, "image": "/tmp/nc" }),
        ));
        bus.publish(file_write_event(
            2,
            serde_json::json!({ "pid": 7, "image": "nc", "path": "/etc/passwd" }),
        ));
        wait_until(&emitter, 1).await; // file component + file half recorded

        // Real elapsed time past the 5s window (there is no CHAIN_WINDOW test seam;
        // this half deliberately ages out).
        tokio::time::sleep(CHAIN_WINDOW + Duration::from_millis(300)).await;

        bus.publish(net_event(
            3,
            serde_json::json!({ "pid": 7, "image": "nc", "daddr": "203.0.113.1", "dport": 4444 }),
        ));
        wait_until(&emitter, 2).await; // connect component
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(emitted.len(), 2, "two components, no triple");
        assert!(
            triples(&emitted).is_empty(),
            "halves outside the window never chain"
        );
    }

    // ---------- T5. churn: many writes+connects for one pid → EXACTLY ONE triple ----------

    #[tokio::test]
    async fn triple_chain_churn_fires_exactly_once() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // One pid writes and connects repeatedly within the window. The FIRST
        // completed pair fires the triple; `fired` blocks every later pair — one
        // triple, not N×M. Emissions: 3 file comps + 3 connect comps + 1 triple = 7.
        bus.publish(exec_event(
            1,
            serde_json::json!({ "pid": 7, "image": "/tmp/nc" }),
        ));
        for i in 0..3u32 {
            bus.publish(file_write_event(
                (2 + i * 2) as i64,
                serde_json::json!({ "pid": 7, "image": "nc", "path": "/etc/passwd" }),
            ));
            bus.publish(net_event(
                (3 + i * 2) as i64,
                serde_json::json!({ "pid": 7, "image": "nc", "daddr": "203.0.113.1", "dport": 4444 }),
            ));
        }

        wait_until(&emitter, 7).await;
        // Nothing more should arrive; confirm it stays at 7 across a few ticks.
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(1)).await;
            assert!(
                emitter.emitted.lock().unwrap().len() <= 7,
                "no extra triples"
            );
        }
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(emitted.len(), 7, "6 components + 1 triple");
        assert_eq!(
            triples(&emitted).len(),
            1,
            "exactly one triple across the churn (fired de-dup)"
        );
    }

    // ---------- T6. honest: a non-suspicious process never enters the chain ----------

    #[tokio::test]
    async fn triple_chain_benign_process_never_chains() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // A BENIGN process writes to a sensitive path AND connects to an external
        // C2 port. Both signals are suspicious on their own, but neither COMPONENT
        // rule fires (the process half is Informational → strict-AND fails), so
        // neither half is ever recorded → NO triple. This is the honesty invariant:
        // the chain is built only from genuine attributed component findings.
        bus.publish(exec_event(
            1,
            serde_json::json!({ "pid": 8, "image": "/usr/bin/echo" }),
        ));
        bus.publish(file_write_event(
            2,
            serde_json::json!({ "pid": 8, "image": "echo", "path": "/etc/passwd" }),
        ));
        bus.publish(net_event(
            3,
            serde_json::json!({ "pid": 8, "image": "echo", "daddr": "203.0.113.1", "dport": 4444 }),
        ));

        wait_until(&emitter, 2).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(emitted.len(), 2, "two components at their own verdicts");
        // Neither component carries the strict-AND rule (benign process).
        for r in emitted.iter() {
            assert!(!rule_names(&r.data["detections"]).contains(&CORRELATED_RULE.to_string()));
            assert!(!rule_names(&r.data["detections"]).contains(&CORRELATED_FILE_RULE.to_string()));
        }
        assert!(
            triples(&emitted).is_empty(),
            "a benign process never chains, even with both suspicious signals"
        );
    }

    // ---------- T7. the chain map is bounded and evicts the oldest ----------

    #[tokio::test]
    async fn chain_map_is_bounded_and_evicts_oldest() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        // Huge grace disables the grace-tick purge (and its CHAIN_WINDOW purge) for
        // the test's life, so the ONLY way a chain entry leaves the map is the
        // MAX_CHAIN_TRACKED cap eviction — keeping the assertions non-vacuous.
        m.start_with_grace(Duration::from_secs(3600)).await.unwrap();

        // MAX_CHAIN_TRACKED+1 distinct pids each do a suspicious exec + suspicious
        // connect → each records a CONN-only chain half (no write → no triple, entry
        // retained). Crossing the cap must evict-oldest and count it. Batched under
        // the 1024 channel cap, synced on the emit count (one connect component per
        // pid).
        let total = MAX_CHAIN_TRACKED + 1;
        let mut published = 0usize;
        while published < total {
            let end = (published + 256).min(total);
            for i in published..end {
                let pid = (i as u64) + 1; // pid 1..=total; ts i so pid 1 is oldest
                bus.publish(exec_event(
                    i as i64,
                    serde_json::json!({ "pid": pid, "image": "/tmp/nc" }),
                ));
                bus.publish(net_event(
                    i as i64,
                    serde_json::json!({ "pid": pid, "image": "nc", "daddr": "203.0.113.1", "dport": 4444 }),
                ));
            }
            published = end;
            wait_until(&emitter, published).await; // one connect component per pid
        }

        let h = m.health();
        m.stop().await.unwrap();
        assert!(
            health_field(&h.detail, "chain-evictions") > 0,
            "chain map evicted at the cap: {}",
            h.detail
        );
        assert!(
            health_field(&h.detail, "chain") <= MAX_CHAIN_TRACKED,
            "chain never exceeds the cap: {}",
            h.detail
        );
    }

    // ==================== EXFIL CHAIN (read-sensitive + connect) ====================

    /// The exfil record shares the triple's `process_file_network` activity, so it
    /// is isolated by its unique top-level rule [`CORRELATED_EXFIL_RULE`] — this
    /// keeps it distinct from the write triple even when a pid fires both.
    fn exfils(emitted: &[OcsfEnvelope]) -> Vec<&OcsfEnvelope> {
        emitted
            .iter()
            .filter(|e| {
                e.data["activity"] == "process_file_network"
                    && rule_names(&e.data["detections"])
                        .contains(&CORRELATED_EXFIL_RULE.to_string())
            })
            .collect()
    }

    /// Full assertions on a single exfil record: SEV_HIGH, all three blocks, the
    /// union detection set, and the top-level exfil rule.
    fn assert_valid_exfil(r: &OcsfEnvelope) {
        assert_eq!(r.class_uid, class::CORRELATED_ACTIVITY);
        assert_eq!(r.class_name, "Correlated Activity");
        assert_eq!(r.data["activity"], "process_file_network");
        assert_eq!(r.severity_id, SEV_HIGH);
        // Process block: attributed + carries the process detection set.
        assert_eq!(r.data["process"]["attributed"], true);
        assert_eq!(r.data["process"]["pid"], 7);
        assert_eq!(r.data["process"]["image"], "/tmp/nc");
        assert!(rule_names(&r.data["process"]["detections"]).contains(&"lolbin".to_string()));
        // File block: the sensitive READ path, op "read".
        assert_eq!(r.data["file"]["path"], "/etc/shadow");
        assert_eq!(r.data["file"]["op"], "read");
        assert!(rule_names(&r.data["file"]["detections"])
            .contains(&"read_of_sensitive_file".to_string()));
        // Connection block: carries the external-port detection (edge_key fields).
        assert_eq!(r.data["connection"]["daddr"], "203.0.113.1");
        assert_eq!(r.data["connection"]["dport"], 4444);
        assert!(rule_names(&r.data["connection"]["detections"])
            .contains(&"suspicious_port_to_external".to_string()));
        // Top-level detections = union of the read + connect component detections
        // PLUS the exfil rule.
        let top = rule_names(&r.data["detections"]);
        assert!(top.contains(&CORRELATED_EXFIL_RULE.to_string()));
        assert!(top.contains(&"read_of_sensitive_file".to_string()));
        assert!(top.contains(&"suspicious_port_to_external".to_string()));
    }

    // ---------- E1. sensitive READ then suspicious CONNECT within window → ONE exfil ----------

    #[tokio::test]
    async fn exfil_chain_fires_on_read_sensitive_then_connect_within_window() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // One pid: exec (lolbin) → sensitive read (/etc/shadow) → suspicious connect
        // (external C2). The read records its half (NO record of its own), the
        // connect emits the connect component AND completes the exfil chain → 2
        // records total (connect component + exfil).
        bus.publish(exec_event(
            1,
            serde_json::json!({ "pid": 7, "image": "/tmp/nc" }),
        ));
        bus.publish(file_open_event(
            2,
            serde_json::json!({ "pid": 7, "image": "nc", "path": "/etc/shadow" }),
        ));
        bus.publish(net_event(
            3,
            serde_json::json!({ "pid": 7, "image": "nc", "daddr": "203.0.113.1", "dport": 4444 }),
        ));

        wait_until(&emitter, 2).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(
            emitted.len(),
            2,
            "connect component + exfil (read emits none)"
        );
        let e = exfils(&emitted);
        assert_eq!(e.len(), 1, "exactly one exfil record");
        assert_valid_exfil(e[0]);
        // The connect component STILL emits independently (additive).
        let has_conn_component = emitted.iter().any(|r| {
            r.data["activity"] == "process_network"
                && rule_names(&r.data["detections"]).contains(&CORRELATED_RULE.to_string())
        });
        assert!(has_conn_component, "connect component still fires");
        // No write triple fired (no write happened).
        assert!(
            !emitted
                .iter()
                .any(|r| rule_names(&r.data["detections"])
                    .contains(&CORRELATED_CHAIN_RULE.to_string())),
            "no write triple without a write"
        );
    }

    // ---------- E2. read but NO connect → no exfil ----------

    #[tokio::test]
    async fn read_sensitive_without_connect_does_not_fire_exfil() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // Sensitive read but NO connect for the pid → the read half is recorded (a
        // chain entry appears) but the exfil conjunction needs the connect half, so
        // nothing is emitted. Synced on the chain-tracker count (the read emits no
        // record, so `wait_until` cannot observe it).
        bus.publish(exec_event(
            1,
            serde_json::json!({ "pid": 7, "image": "/tmp/nc" }),
        ));
        bus.publish(file_open_event(
            2,
            serde_json::json!({ "pid": 7, "image": "nc", "path": "/etc/shadow" }),
        ));

        wait_chain(&m, 1).await; // read half recorded → one chain entry
                                 // The read half really landed: the chain tracker holds exactly one entry
                                 // (this pid's read half). Proven independently of the zero-emit assertion
                                 // below, so E2 can't pass vacuously (e.g. if the read were silently dropped).
        assert_eq!(
            health_field(&m.health().detail, "chain"),
            1,
            "the sensitive-read half was recorded in the chain tracker"
        );
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(emitted.len(), 0, "a read with no connect emits nothing");
        assert!(exfils(&emitted).is_empty(), "no exfil from one half");
    }

    // ---------- E3. write triple is UNAFFECTED by the read half ----------

    #[tokio::test]
    async fn write_triple_unaffected_by_the_read_half() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // A pid that WRITES-suspicious + connects (no sensitive read) still fires
        // the write triple exactly as before and NO exfil — the read half is purely
        // additive.
        bus.publish(exec_event(
            1,
            serde_json::json!({ "pid": 7, "image": "/tmp/nc" }),
        ));
        bus.publish(file_write_event(
            2,
            serde_json::json!({ "pid": 7, "image": "nc", "path": "/etc/passwd" }),
        ));
        bus.publish(net_event(
            3,
            serde_json::json!({ "pid": 7, "image": "nc", "daddr": "203.0.113.1", "dport": 4444 }),
        ));

        wait_until(&emitter, 3).await;
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(
            emitted.len(),
            3,
            "file component + connect component + triple"
        );
        let t = triples(&emitted);
        assert_eq!(t.len(), 1, "the write triple still fires");
        assert_valid_triple(t[0]);
        assert!(
            exfils(&emitted).is_empty(),
            "no exfil fires without a sensitive read"
        );
    }

    // ---------- E4. pid reuse (re-exec) clears the read half ----------

    #[tokio::test]
    async fn exfil_pid_reuse_resets() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // pid 7 execs, reads sensitive (read half recorded), then RE-EXECS (pid
        // reuse) which clears the half, then connects. The connect emits its
        // component but the read half is gone → NO exfil.
        bus.publish(exec_event(
            1,
            serde_json::json!({ "pid": 7, "image": "/tmp/nc" }),
        ));
        bus.publish(file_open_event(
            2,
            serde_json::json!({ "pid": 7, "image": "nc", "path": "/etc/shadow" }),
        ));
        wait_chain(&m, 1).await; // first read half recorded
                                 // Re-exec of the SAME pid supersedes the old process → chain entry cleared.
        bus.publish(exec_event(
            3,
            serde_json::json!({ "pid": 7, "image": "/tmp/nc" }),
        ));
        bus.publish(net_event(
            4,
            serde_json::json!({ "pid": 7, "image": "nc", "daddr": "203.0.113.1", "dport": 4444 }),
        ));

        wait_until(&emitter, 1).await; // the connect component
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(emitted.len(), 1, "only the connect component after re-exec");
        assert!(
            exfils(&emitted).is_empty(),
            "the read half was cleared on pid reuse → no exfil"
        );
    }

    // ---------- E5. churn: many reads + one connect → EXACTLY ONE exfil ----------

    #[tokio::test]
    async fn exfil_fires_exactly_once_across_repeated_reads() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // One pid reads sensitive repeatedly (each overwrites the read half, none
        // emits) then connects once (fires the exfil). Further reads after the fire
        // re-record the half but `exfil_fired` blocks any re-fire → exactly one
        // exfil. Emissions: 1 connect component + 1 exfil = 2.
        bus.publish(exec_event(
            1,
            serde_json::json!({ "pid": 7, "image": "/tmp/nc" }),
        ));
        for i in 0..3i64 {
            bus.publish(file_open_event(
                2 + i,
                serde_json::json!({ "pid": 7, "image": "nc", "path": "/etc/shadow" }),
            ));
        }
        bus.publish(net_event(
            5,
            serde_json::json!({ "pid": 7, "image": "nc", "daddr": "203.0.113.1", "dport": 4444 }),
        ));
        // Two more reads AFTER the connect — must NOT produce a second exfil.
        for i in 0..2i64 {
            bus.publish(file_open_event(
                6 + i,
                serde_json::json!({ "pid": 7, "image": "nc", "path": "/etc/shadow" }),
            ));
        }

        wait_until(&emitter, 2).await; // connect component + the single exfil
                                       // Confirm it stays at 2 across a few ticks (no second exfil from the
                                       // post-connect reads).
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(1)).await;
            assert!(emitter.emitted.lock().unwrap().len() <= 2, "no extra exfil");
        }
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(emitted.len(), 2, "one connect component + one exfil");
        assert_eq!(
            exfils(&emitted).len(),
            1,
            "exactly one exfil across the repeated reads (exfil_fired de-dup)"
        );
        assert_valid_exfil(exfils(&emitted)[0]);
    }

    // ---------- E6. BOTH chains fire: one pid writes + reads + connects → 1 triple AND 1 exfil ----------

    #[tokio::test]
    async fn write_read_and_connect_fires_both_chains_each_exactly_once() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // One attributed pid does ALL THREE within CHAIN_WINDOW: a suspicious WRITE
        // (/etc/passwd), a sensitive READ (/etc/shadow), then a suspicious CONNECT
        // (external C2). The connect completes BOTH chains. Because the two latches
        // (`fired` vs `exfil_fired`) are independent, this fires EXACTLY ONE write
        // triple AND EXACTLY ONE exfil. Emissions: file component + connect
        // component + triple + exfil = 4.
        bus.publish(exec_event(
            1,
            serde_json::json!({ "pid": 7, "image": "/tmp/nc" }),
        ));
        bus.publish(file_write_event(
            2,
            serde_json::json!({ "pid": 7, "image": "nc", "path": "/etc/passwd" }),
        ));
        bus.publish(file_open_event(
            3,
            serde_json::json!({ "pid": 7, "image": "nc", "path": "/etc/shadow" }),
        ));
        bus.publish(net_event(
            4,
            serde_json::json!({ "pid": 7, "image": "nc", "daddr": "203.0.113.1", "dport": 4444 }),
        ));

        wait_until(&emitter, 4).await;
        // Confirm it stays at 4 (neither chain re-fires).
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(1)).await;
            assert!(
                emitter.emitted.lock().unwrap().len() <= 4,
                "no chain re-fires"
            );
        }
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(
            emitted.len(),
            4,
            "file component + connect component + triple + exfil"
        );
        let t = triples(&emitted);
        assert_eq!(t.len(), 1, "exactly one write triple");
        assert_valid_triple(t[0]);
        let e = exfils(&emitted);
        assert_eq!(e.len(), 1, "exactly one exfil");
        assert_valid_exfil(e[0]);
    }

    // ---------- E7. considered-but-NON-sensitive read + connect → no exfil ----------

    #[tokio::test]
    async fn non_sensitive_considered_read_with_connect_does_not_fire_exfil() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // /etc/hosts PASSES `FilePolicy::considers` (the "/etc/" watch substring)
        // but is NOT one of filemon's SENSITIVE_READ_FILES, so `judge_read` returns
        // None → no read half is recorded. The suspicious connect still emits its
        // component, but with no read half the exfil conjunction cannot fire.
        bus.publish(exec_event(
            1,
            serde_json::json!({ "pid": 7, "image": "/tmp/nc" }),
        ));
        bus.publish(file_open_event(
            2,
            serde_json::json!({ "pid": 7, "image": "nc", "path": "/etc/hosts" }),
        ));
        bus.publish(net_event(
            3,
            serde_json::json!({ "pid": 7, "image": "nc", "daddr": "203.0.113.1", "dport": 4444 }),
        ));

        wait_until(&emitter, 1).await; // the connect component only
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(emitted.len(), 1, "only the connect component");
        assert!(
            exfils(&emitted).is_empty(),
            "a non-sensitive considered read never records a read half → no exfil"
        );
    }

    // ---------- E8. sensitive read and connect > CHAIN_WINDOW apart → no exfil ----------

    #[tokio::test]
    async fn read_and_connect_outside_window_do_not_fire_exfil() {
        let emitter = Arc::new(CapturingEmitter::default());
        let bus = StubBus::new();
        let mut m = CorrModule::new();
        m.init(make_ctx(bus.clone(), emitter.clone()))
            .await
            .unwrap();
        m.start().await.unwrap();

        // Sensitive read, then a suspicious connect for the SAME pid stamped MORE
        // than CHAIN_WINDOW later. The read half is recorded but ages out (and is
        // purged on the grace tick) before the connect arrives → the connect emits
        // its component but the exfil never joins.
        bus.publish(exec_event(
            1,
            serde_json::json!({ "pid": 7, "image": "/tmp/nc" }),
        ));
        bus.publish(file_open_event(
            2,
            serde_json::json!({ "pid": 7, "image": "nc", "path": "/etc/shadow" }),
        ));
        wait_chain(&m, 1).await; // read half recorded

        // Real elapsed time past the 5s window (there is no CHAIN_WINDOW test seam).
        tokio::time::sleep(CHAIN_WINDOW + Duration::from_millis(300)).await;

        bus.publish(net_event(
            3,
            serde_json::json!({ "pid": 7, "image": "nc", "daddr": "203.0.113.1", "dport": 4444 }),
        ));
        wait_until(&emitter, 1).await; // connect component
        m.stop().await.unwrap();

        let emitted = emitter.emitted.lock().unwrap();
        assert_eq!(emitted.len(), 1, "connect component only, no exfil");
        assert!(
            exfils(&emitted).is_empty(),
            "halves outside the window never chain"
        );
    }
}
