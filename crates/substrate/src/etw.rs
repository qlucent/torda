//! Windows ETW event backend (behind the `windows-etw` feature).
//!
//! ETW is the Windows counterpart to the eBPF bus on Linux and the
//! EndpointSecurity bus on macOS: one kernel-event source that publishes onto
//! the shared [`EventBus`], which every module subscribes to. It drops into
//! [`crate::select_event_bus`] fail-soft — if the real ETW session can't be
//! opened (most commonly because the agent is not running elevated), the
//! factory logs and falls back to `StubBus`, so a non-elevated run still works.
//!
//! This module has two layers:
//! - [`process_event`]: a PURE mapping from already-extracted provider fields to
//!   a [`SubstrateEvent`]. It has NO ferrisetw/ETW types, so it compiles and is
//!   unit-tested on every host and build (including the default no-feature one).
//! - [`EtwBus`] (feature+cfg gated): the broadcast plumbing plus `try_start()`,
//!   which Task 2 fills with the real ferrisetw session + record extraction.

use serde_json::{Map, Value};
use torda_core::{EventKind, SubstrateEvent};

/// Map extracted process-event fields to a [`SubstrateEvent`].
///
/// PURE: takes no ETW/ferrisetw types, only plain scalars already pulled out of
/// a provider record, so it is unit-tested with fixtures on any host/build.
///
/// `fields` shape: an object always carrying `pid` (u32) and `image` (string).
/// `ppid` and `cmdline` are OMITTED entirely when `None` (rather than serialized
/// as JSON `null`), so downstream consumers can treat "key absent" as "provider
/// did not expose this field".
// Scaffolding: exercised by unit tests now and by the ETW consumer in Task 2;
// unused in the non-test default/feature build until the session is wired.
#[allow(dead_code)]
pub(crate) fn process_event(
    kind: EventKind,
    ts: i64,
    pid: u32,
    image: &str,
    ppid: Option<u32>,
    cmdline: Option<&str>,
) -> SubstrateEvent {
    let mut fields = Map::new();
    fields.insert("pid".to_string(), Value::from(pid));
    fields.insert("image".to_string(), Value::from(image));
    if let Some(ppid) = ppid {
        fields.insert("ppid".to_string(), Value::from(ppid));
    }
    if let Some(cmdline) = cmdline {
        fields.insert("cmdline".to_string(), Value::from(cmdline));
    }
    SubstrateEvent {
        kind,
        ts,
        fields: Value::Object(fields),
    }
}

/// Map an outbound-connect observation to a [`SubstrateEvent`] (`NetConnect`).
///
/// PURE: takes only plain scalars (no aya/eBPF types), so it compiles and is
/// unit-tested on every host/build, including the default no-feature Windows one.
///
/// Byte-order contract (the crux): `daddr_be` and `dport_be` arrive in NETWORK
/// (big-endian) order exactly as the kernel copied them out of the user
/// `sockaddr_in`. This mapper converts them to human/host form:
/// - `daddr` → a dotted-quad string (`Ipv4Addr`), so `0x0100007F` (127.0.0.1 in
///   network order) renders as `"127.0.0.1"`.
/// - `dport` → a HOST-order `u16` (`u16::from_be`), so net-order `0x5000`
///   becomes `80`.
///
/// `fields` shape: `{ pid, image, daddr, dport, proto }`. `proto` is always
/// `"tcp"` in v0 (the `connect(2)` intent sensor does not yet distinguish the
/// socket type).
// Scaffolding: exercised by unit tests + the eBPF drain path (behind the Linux
// `linux-ebpf` feature); unused on the default Windows build.
#[allow(dead_code)]
pub(crate) fn net_event(
    ts: i64,
    pid: u32,
    comm: &str,
    daddr_be: u32,
    dport_be: u16,
) -> SubstrateEvent {
    let daddr = std::net::Ipv4Addr::from(u32::from_be(daddr_be)).to_string();
    let dport = u16::from_be(dport_be);

    let mut fields = Map::new();
    fields.insert("pid".to_string(), Value::from(pid));
    fields.insert("image".to_string(), Value::from(comm));
    fields.insert("daddr".to_string(), Value::from(daddr));
    fields.insert("dport".to_string(), Value::from(dport));
    fields.insert("proto".to_string(), Value::from("tcp"));
    SubstrateEvent {
        kind: EventKind::NetConnect,
        ts,
        fields: Value::Object(fields),
    }
}

/// Map a file open/create (or write) observation to a [`SubstrateEvent`].
///
/// PURE: takes only plain scalars (no ferrisetw/ETW/aya types), so it compiles
/// and is unit-tested on every host/build. This is the FIRST file sensor on
/// either OS and the shared analogue of [`net_event`]: a future eBPF file
/// write-hook reuses it unchanged (hence the `write` param, even though the ETW
/// Kernel-File `Create` sensor only ever calls it with `write = false`).
///
/// `kind` is [`EventKind::FileWrite`] when `write`, else [`EventKind::FileOpen`].
/// `fields` shape: `{ pid, image, path, op }` where `op` is `"write"|"open"`,
/// plus `bytes` when `bytes` is `Some(n)` (omitted entirely, not `null`, when
/// `None`).
///
/// `image` may be BLANK on backends (like the ETW Kernel-File record) that do
/// not carry the initiating process image on the file event; a blank image is
/// honest, not fabricated — consumers correlate by `pid`.
///
/// `bytes` is the number of bytes written for a byte-level write observation
/// (e.g. the ETW Kernel-File Write event's `IOSize`); `None`/omitted for
/// open/create-intent events that carry no byte count.
// Scaffolding: exercised by unit tests + the ETW Kernel-File path (behind the
// `windows-etw` feature) and a future eBPF file hook; unused on the default build.
#[allow(dead_code)]
pub(crate) fn file_event(
    ts: i64,
    pid: u32,
    image: &str,
    path: &str,
    write: bool,
    bytes: Option<u64>,
) -> SubstrateEvent {
    let kind = if write {
        EventKind::FileWrite
    } else {
        EventKind::FileOpen
    };
    let op = if write { "write" } else { "open" };

    let mut fields = Map::new();
    fields.insert("pid".to_string(), Value::from(pid));
    fields.insert("image".to_string(), Value::from(image));
    fields.insert("path".to_string(), Value::from(path));
    fields.insert("op".to_string(), Value::from(op));
    if let Some(n) = bytes {
        fields.insert("bytes".to_string(), Value::from(n));
    }
    SubstrateEvent {
        kind,
        ts,
        fields: Value::Object(fields),
    }
}

/// Maximum number of live `FileObject -> path` correlations the [`FileNameCache`]
/// holds. Kernel-File is a HIGH-VOLUME provider, so the cache MUST be bounded:
/// past this many concurrently-tracked files, the OLDEST insertion is evicted
/// (FIFO) so memory can never grow without limit even if Cleanup/Close events
/// (the natural lifecycle eviction) are dropped or never observed.
const FILE_CACHE_CAP: usize = 8192;

/// Upper bound on `FileNameCache::order`'s length. `insert` compacts the deque
/// (dedup-keeping-last: dropping stale tokens whose key is no longer in `map`,
/// AND collapsing duplicate tokens for a key that's still live down to its
/// single most-recent occurrence) whenever it grows past this, so
/// `order.len() <= FILE_CACHE_ORDER_CAP` holds unconditionally — see the
/// compaction note on [`FileNameCache::insert`].
const FILE_CACHE_ORDER_CAP: usize = 2 * FILE_CACHE_CAP;

/// Bounded `FileObject (u64) -> path (String)` correlation map for the ETW
/// Kernel-File sensor.
///
/// WHY it exists: the Kernel-File **Write** event (id 16) carries a byte count
/// (`IOSize`) and a `FileObject` pointer but NO `FileName`. The **Create** event
/// (id 12) carries BOTH `FileObject` AND `FileName`. To attach a path to a
/// byte-level write we must remember, per open file object, the path we saw at
/// Create time. This structure is that memory.
///
/// DESIGN (bound + FIFO eviction + stale-skip):
/// - A `HashMap<u64, String>` holds the live `FileObject -> path` mappings.
/// - A `VecDeque<u64>` records INSERTION ORDER for FIFO eviction. When the map
///   is at [`FILE_CACHE_CAP`] and a brand-new `FileObject` is inserted, we evict
///   the oldest still-live key first, so `len()` NEVER exceeds the cap — this is
///   the memory-leak guard for the case where Cleanup/Close (`remove`) is missed.
/// - `remove` (the correct lifecycle eviction, on Cleanup/Close) deletes only
///   from the `HashMap`; the key may linger in the deque. Eviction therefore
///   POPS from the deque SKIPPING any key no longer present in the map (a
///   "stale" entry), so a removed-then-reinserted or already-removed object
///   never causes a wrong eviction.
/// - The deque genuinely self-cleans, but NOT via the eviction path alone: on
///   a host that stays well under [`FILE_CACHE_CAP`] concurrently-open files,
///   `map.len()` never reaches the cap, so the eviction loop above never runs
///   and stale tokens would otherwise accumulate in `order` forever (one per
///   `remove`d file, unbounded over process lifetime). Worse, a REFRESHED
///   live key (an unconditional `push_back` on every `insert`, even when the
///   key already exists) also grows `order` without bound if never compacted
///   — e.g. ETW drops a Cleanup/Close under load, Windows recycles the same
///   `FileObject` pointer, and the resulting Create re-`insert`s the same
///   still-live key repeatedly. To close BOTH leaks, `insert` additionally
///   COMPACTS `order` whenever `order.len()` exceeds [`FILE_CACHE_ORDER_CAP`]:
///   it dedups-keeping-last, dropping every token whose key is no longer in
///   `map` AND collapsing every duplicate token for a still-live key down to
///   its single most-recent occurrence. This bounds `order` independently of
///   the FIFO eviction path, and unconditionally — regardless of whether the
///   churn is remove-driven or refresh-driven.
///
/// The invariants `len() <= FILE_CACHE_CAP` and `order.len() <=
/// FILE_CACHE_ORDER_CAP` hold unconditionally and are unit tested. This type
/// is std-only (`HashMap` + `VecDeque`) and NOT feature-gated, so its tests
/// run on every host.
// Scaffolding: exercised by unit tests now and by the ETW Kernel-File consumer
// (behind `windows-etw`); unused in the non-test default build until the feature
// is enabled — hence the `dead_code` allow, matching the mappers above.
#[allow(dead_code)]
pub(crate) struct FileNameCache {
    map: std::collections::HashMap<u64, String>,
    // Insertion order for FIFO eviction. May contain keys already removed from
    // `map` (stale) or duplicate tokens for a key that was refreshed; eviction
    // skips stale ones. `insert` compacts this deque (dedup-keeping-last) once
    // it exceeds `FILE_CACHE_ORDER_CAP`, so `order.len() <= FILE_CACHE_ORDER_CAP`
    // always — see the compaction note on `insert`.
    order: std::collections::VecDeque<u64>,
}

#[allow(dead_code)]
impl FileNameCache {
    fn new() -> Self {
        Self {
            map: std::collections::HashMap::new(),
            order: std::collections::VecDeque::new(),
        }
    }

    /// Insert or refresh `fo -> path`. If `fo` is NEW and the map is at
    /// [`FILE_CACHE_CAP`], evict the oldest live entry FIRST (FIFO, skipping
    /// stale deque keys) so the map never exceeds the cap. Refreshing an
    /// existing `fo` updates its path in place and appends a fresh order token
    /// (the older duplicate becomes stale and is skipped at eviction).
    ///
    /// COMPACTION (bounds `order` independently of the map cap, and
    /// unconditionally): under normal operation a host stays well under
    /// `FILE_CACHE_CAP` concurrently-open files, so `map.len()` never reaches
    /// the cap and the FIFO eviction loop above never runs — every `remove`d
    /// key would then leave a permanently stale token in `order`, growing it
    /// without bound over the process lifetime. Worse, refreshing the SAME
    /// still-live key over and over (this method always `push_back`s, even
    /// when `fo` already exists) also grows `order` without bound if left
    /// uncompacted — a real scenario: ETW drops a Cleanup/Close under load,
    /// Windows recycles the `FileObject` pointer, and the next Create
    /// `insert`s that same still-live key again. A `retain`-only compaction
    /// (keep every token whose key is still in `map`) closes the first leak
    /// but NOT the second, since every duplicate token of a live key also
    /// counts as "live". To close both, once `order.len()` exceeds
    /// [`FILE_CACHE_ORDER_CAP`] we compact by DEDUP-KEEPING-LAST: walk `order`
    /// back-to-front, keep a token only the first time (i.e. most recent) its
    /// key is seen AND only if that key is still in `map`, then reverse back
    /// to front-to-back order. After compaction `order.len() == map.len() <=
    /// FILE_CACHE_CAP` — each live key appears in `order` EXACTLY once — so
    /// `order` never exceeds `FILE_CACHE_ORDER_CAP` before the *next*
    /// compaction, i.e. `order.len() <= FILE_CACHE_ORDER_CAP` holds
    /// unconditionally, regardless of whether the growth was remove-driven or
    /// refresh-driven. Amortized O(1) per insert (an O(n) compaction at most
    /// once per `FILE_CACHE_CAP` net inserts).
    fn insert(&mut self, fo: u64, path: String) {
        let is_new = !self.map.contains_key(&fo);
        if is_new && self.map.len() >= FILE_CACHE_CAP {
            // Evict the oldest STILL-LIVE key; skip stale deque entries whose
            // key was already removed (or superseded) from the map.
            while let Some(old) = self.order.pop_front() {
                if self.map.remove(&old).is_some() {
                    break;
                }
            }
        }
        self.map.insert(fo, path);
        self.order.push_back(fo);

        if self.order.len() > FILE_CACHE_ORDER_CAP {
            // Dedup-keeping-last: walk from the BACK, keep a token only if its
            // key is still live AND not already kept (so each live key appears
            // once, at its most-recent position). Then restore front-to-back
            // order. This makes order.len() == map.len() after compaction,
            // bounding `order` unconditionally even under repeated refresh of
            // a live key (duplicate tokens from refreshes are collapsed, not
            // just tokens left behind by `remove`).
            let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
            let mut kept: Vec<u64> = Vec::with_capacity(self.map.len());
            for &fo in self.order.iter().rev() {
                if self.map.contains_key(&fo) && seen.insert(fo) {
                    kept.push(fo);
                }
            }
            kept.reverse();
            self.order = kept.into();
        }
    }

    /// Look up a path by `FileObject`, returning an OWNED clone so the caller can
    /// drop the lock guard before using it (see the locking discipline in
    /// `handle_file_record`).
    fn get(&self, fo: u64) -> Option<String> {
        self.map.get(&fo).cloned()
    }

    /// Remove the mapping for `fo` on Cleanup/Close — the correct lifecycle
    /// eviction. Only the `HashMap` entry is dropped; the deque token (if any)
    /// is left stale and skipped at the next eviction.
    fn remove(&mut self, fo: u64) {
        self.map.remove(&fo);
    }

    /// Number of live mappings. Invariant: `len() <= FILE_CACHE_CAP` always.
    fn len(&self) -> usize {
        self.map.len()
    }

    /// Test-only accessor for the raw `order` deque length, used to pin the
    /// `order.len() <= FILE_CACHE_ORDER_CAP` bound. Not part of the public API.
    #[cfg(test)]
    fn order_len(&self) -> usize {
        self.order.len()
    }
}

/// NtCreateFile `CreateDisposition` values. The ETW Kernel-File Create event packs the disposition in the
/// HIGH byte of `CreateOptions` (`create_options >> 24`); the low 24 bits are the CreateOptions flags.
// Scaffolding: read by `is_write_create` below and exercised by unit tests on every host/build; the only
// production caller (`handle_file_record`) lives behind the `windows-etw` feature, so these are unused in
// the non-test default build.
#[allow(dead_code)]
const FILE_SUPERSEDE: u32 = 0;
#[allow(dead_code)]
const FILE_OPEN: u32 = 1;
#[allow(dead_code)]
const FILE_CREATE: u32 = 2;
#[allow(dead_code)]
const FILE_OPEN_IF: u32 = 3;
#[allow(dead_code)]
const FILE_OVERWRITE: u32 = 4;
#[allow(dead_code)]
const FILE_OVERWRITE_IF: u32 = 5;

/// True if the Create event's `CreateOptions` denotes WRITE intent — i.e. the file is created or
/// overwritten (SUPERSEDE/CREATE/OPEN_IF/OVERWRITE/OVERWRITE_IF). A plain `FILE_OPEN` (open existing) or an
/// unrecognized disposition → false (read; conservative default).
///
/// LIMITATION (honest): the Create event carries NO DesiredAccess mask, so opening an EXISTING file FOR
/// WRITE (disposition `FILE_OPEN` + write access) is NOT distinguished from a read open — deferred to the
/// Kernel-File event-16 (byte-level Write) slice.
/// ASSUMPTION: the disposition-in-high-byte packing — confirmed by the elevated live capture (Task 3).
// Scaffolding: exercised by unit tests now and by the ETW consumer (behind `windows-etw`); unused in the
// non-test default build until the feature is enabled.
#[allow(dead_code)]
pub(crate) fn is_write_create(create_options: u32) -> bool {
    matches!(
        (create_options >> 24) & 0xFF,
        FILE_SUPERSEDE | FILE_CREATE | FILE_OPEN_IF | FILE_OVERWRITE | FILE_OVERWRITE_IF
    )
}

// ------------------- EtwBus (Windows + feature only) -------------------

#[cfg(all(target_os = "windows", feature = "windows-etw"))]
mod bus {
    use super::*;
    use std::sync::Arc;
    use std::thread::JoinHandle;
    use torda_core::EventBus;

    use ferrisetw::parser::Parser;
    use ferrisetw::provider::Provider;
    use ferrisetw::trace::{TraceTrait, UserTrace};
    use ferrisetw::{EventRecord, SchemaLocator};

    /// `Microsoft-Windows-Kernel-Process` provider GUID. Emits process/thread/
    /// image lifecycle events; we subscribe and keep only the process ones.
    const KERNEL_PROCESS_GUID: &str = "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716";

    // Kernel-Process manifest event IDs used to tell process start from stop.
    // These match the WINEVENT opcodes Start(1)/Stop(2) on this provider.
    // (Assumption confirmed by the elevated Task 3 capture: id 1 => start, id 2
    // => stop. Thread/image events carry other ids and are skipped.)
    const EVENT_ID_PROCESS_START: u16 = 1;
    const EVENT_ID_PROCESS_STOP: u16 = 2;

    /// `Microsoft-Windows-Kernel-Network` provider GUID. Emits TCP/UDP,
    /// IPv4/IPv6 send/recv/connect/disconnect events; we subscribe and keep
    /// ONLY the outbound IPv4 TCP connect (see `EVENT_ID_TCP_CONNECT_V4`).
    const KERNEL_NETWORK_GUID: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";

    // Kernel-Network manifest event id for an OUTBOUND IPv4 TCP connect attempt:
    // id 12, "TCPv4: Connection attempted between <daddr>:<dport> and
    // <saddr>:<sport>." This is the connect(2)-intent analogue of the Linux
    // eBPF sensor (the SYN we send), NOT data xmit/recv (10/11), NOT the inbound
    // "established" (15), NOT IPv6 (28) or UDP. Its manifest template exposes
    // `PID` (UInt32), `daddr` (UInt32, out win:IPv4), `saddr`, `dport` (UInt16,
    // out win:Port), `sport`, and connection metadata. `daddr`/`dport` are the
    // REMOTE destination we are connecting to (%4:%6 in the message). Everything
    // else on this provider is skipped.
    // (Assumption confirmed by the elevated Task 3 capture: id 12 => outbound
    // IPv4 TCP connect; the destination is `daddr`/`dport`.)
    const EVENT_ID_TCP_CONNECT_V4: u16 = 12;

    /// `Microsoft-Windows-Kernel-File` provider GUID. Emits file create/open,
    /// read/write, delete/rename, etc.; we subscribe and keep ONLY the create/
    /// open event (see `EVENT_ID_FILE_CREATE`). This is the first file sensor on
    /// either OS.
    const KERNEL_FILE_GUID: &str = "EDD08927-9CC4-4E65-B970-C2560FB5C289";

    // Kernel-File manifest event id 12 = "Create": a file open/create. Its
    // template carries `FileName` (`win:UnicodeString`) directly in BOTH schema
    // versions, so `try_parse::<String>("FileName")` is version-agnostic (no
    // branch on schema version). PID is NOT in the template — it lives in the
    // ETW event header, read via `record.process_id()`.
    //
    // NOTE: event 12 is HIGH VOLUME (every file open on the box). This slice
    // does NO substrate-side path filtering — that is deferred; we publish every
    // create as `FileOpen` and let downstream modules decide.
    const EVENT_ID_FILE_CREATE: u16 = 12;

    // Kernel-File manifest event id 13 = "Cleanup" and id 14 = "Close": the
    // lifecycle END of a file object. Both carry `FileObject` (`win:Pointer`)
    // and `FileKey` but no `FileName`. We map neither to an event; we use them
    // ONLY to remove the `FileObject -> path` correlation from the cache (the
    // correct lifecycle eviction), so a reused `FileObject` value can't be
    // mis-correlated to a stale path.
    const EVENT_ID_FILE_CLEANUP: u16 = 13;
    const EVENT_ID_FILE_CLOSE: u16 = 14;

    // Kernel-File manifest event id 16 = "Write": a REAL byte-level write to an
    // (already-open) file. Its template carries `ByteOffset` (u64),
    // `FileObject` (`win:Pointer`), `FileKey`, `IOSize` (`win:UInt32` = bytes
    // written), and `IOFlags` — but NO `FileName`. The path is recovered by
    // correlating `FileObject` against the Create (id 12) we cached. A write to
    // a file whose Create we never observed (e.g. opened before our session
    // started) is DROPPED, not guessed — honest reporting.
    const EVENT_ID_FILE_WRITE: u16 = 16;

    /// The Windows ETW-backed event bus. The background consumer thread pushes
    /// mapped records onto the broadcast channel; modules subscribe via the
    /// shared [`EventBus`] trait. Dropping the bus stops the trace and joins the
    /// consumer (see the `Drop` impl).
    pub struct EtwBus {
        tx: tokio::sync::broadcast::Sender<SubstrateEvent>,
        // The live ferrisetw session. `Option` so `Drop` can `take()` it and
        // call the consuming `stop()`. Owning it here means the bus controls
        // teardown (rather than relying on ferrisetw's own `Drop`).
        trace: Option<UserTrace>,
        // The background thread running the blocking `ProcessTrace` pump. Joined
        // in `Drop` after the trace is stopped, so nothing leaks or detaches.
        consumer: Option<JoinHandle<()>>,
    }

    impl EtwBus {
        /// Start the ETW session + consumer and return a live bus.
        ///
        /// Returns `Err` when the session can't be opened (e.g. the process is
        /// NOT elevated: `StartTraceW` returns `ERROR_ACCESS_DENIED`) so
        /// [`crate::select_event_bus`] falls back to `StubBus`, fail-soft.
        ///
        /// Non-hanging: `TraceBuilder::start()` runs `StartTraceW` /
        /// `EnableTraceEx2` / `OpenTraceW` and returns promptly with the result;
        /// only the `ProcessTrace` pump blocks, and that runs on the spawned
        /// consumer thread — never on the caller. So a start failure surfaces as
        /// an immediate `Err` here, and a success returns without blocking.
        pub fn try_start() -> anyhow::Result<Arc<Self>> {
            let (tx, _rx) = tokio::sync::broadcast::channel(1024);

            // Each callback owns its own clone of the sender.
            let cb_tx = tx.clone();
            let process_provider = Provider::by_guid(KERNEL_PROCESS_GUID)
                .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
                    handle_record(record, locator, &cb_tx);
                })
                .build();

            // Kernel-Network on the SAME session: outbound IPv4 TCP connects are
            // mapped to `NetConnect` (the same shape the Linux eBPF backend
            // emits) so `torda-mod-netmon` runs unchanged on Windows.
            let cb_tx2 = tx.clone();
            let network_provider = Provider::by_guid(KERNEL_NETWORK_GUID)
                .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
                    handle_net_record(record, locator, &cb_tx2);
                })
                .build();

            // Kernel-File on the SAME session: file create/open events are
            // mapped to `FileOpen` via the shared `file_event` mapper, and
            // byte-level Write events (id 16) to `FileWrite` by correlating the
            // write's `FileObject` against the path we cached at Create time.
            // The Kernel-File record carries no initiating image, so `image` is
            // "". The bounded `FileNameCache` is the correlation memory; the
            // callback closure owns a clone of the `Arc` and lives as long as
            // the trace (no need to store it on `EtwBus`).
            let file_cache = Arc::new(std::sync::Mutex::new(FileNameCache::new()));
            let cb_tx3 = tx.clone();
            let cb_cache = file_cache.clone();
            let file_provider = Provider::by_guid(KERNEL_FILE_GUID)
                .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
                    handle_file_record(record, locator, &cb_tx3, &cb_cache);
                })
                .build();

            // start() is non-blocking; the Err path here is the fail-soft seam.
            // All three providers ride ONE session: fail-soft AS A UNIT — if the
            // session can't start (e.g. non-elevated), we return `Err` and
            // `select_event_bus` falls back to `StubBus`. One session, one Drop.
            let (trace, trace_handle) = UserTrace::new()
                .enable(process_provider)
                .enable(network_provider)
                .enable(file_provider)
                .start()
                .map_err(|e| {
                    anyhow::anyhow!(
                        "failed to start ETW Kernel-Process + Kernel-Network + Kernel-File \
                         session (run elevated for real events): {e:?}"
                    )
                })?;

            // Pump events on a background thread. `process_from_handle` blocks
            // until the session is stopped (from `Drop` below).
            let consumer = std::thread::Builder::new()
                .name("etw-consumer".to_string())
                .spawn(move || {
                    if let Err(e) = UserTrace::process_from_handle(trace_handle) {
                        eprintln!("etw: consumer pump exited: {e:?}");
                    }
                })
                .map_err(|e| anyhow::anyhow!("failed to spawn ETW consumer thread: {e}"))?;

            Ok(Arc::new(Self {
                tx,
                trace: Some(trace),
                consumer: Some(consumer),
            }))
        }
    }

    /// Map ONE raw ETW record to a [`SubstrateEvent`] and publish it.
    ///
    /// Panic-free: a missing/unparsable required field or a schema-lookup miss is
    /// logged and the event is SKIPPED — every extraction goes through `match`/
    /// `.ok()`, never `unwrap()`. Optional fields absent from this schema version
    /// map to `None` (the pure [`process_event`] then omits them).
    fn handle_record(
        record: &EventRecord,
        locator: &SchemaLocator,
        tx: &tokio::sync::broadcast::Sender<SubstrateEvent>,
    ) {
        // Start vs stop from the Kernel-Process event id; skip everything else
        // (thread start/stop, image load, etc.).
        let kind = match record.event_id() {
            EVENT_ID_PROCESS_START => EventKind::ProcessExec,
            EVENT_ID_PROCESS_STOP => EventKind::ProcessExit,
            _ => return,
        };

        let schema = match locator.event_schema(record) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("etw: schema lookup failed, skipping event: {e:?}");
                return;
            }
        };
        let parser = Parser::create(record, &schema);

        // PID is required. If it can't be parsed, skip (never panic).
        let pid: u32 = match parser.try_parse("ProcessID") {
            Ok(p) => p,
            Err(e) => {
                eprintln!("etw: unparsable ProcessID, skipping event: {e:?}");
                return;
            }
        };
        // ImageName is required for a useful event.
        let image: String = match parser.try_parse("ImageName") {
            Ok(s) => s,
            Err(e) => {
                eprintln!("etw: unparsable ImageName for pid {pid}, skipping: {e:?}");
                return;
            }
        };
        // Optional: not every schema version exposes these. Absent -> None.
        let ppid: Option<u32> = parser.try_parse("ParentProcessID").ok();
        let cmdline: Option<String> = parser.try_parse("CommandLine").ok();

        // Use the record's own timestamp (raw EventHeader.TimeStamp, i64). The
        // pure mapper builds the envelope; publishing ignores "no subscribers".
        let ev = process_event(
            kind,
            record.raw_timestamp(),
            pid,
            &image,
            ppid,
            cmdline.as_deref(),
        );
        let _ = tx.send(ev);
    }

    /// Map ONE raw Kernel-Network record to a [`SubstrateEvent`] (`NetConnect`)
    /// and publish it. Mirrors [`handle_record`]'s panic-free style.
    ///
    /// Only the OUTBOUND IPv4 TCP connect (`EVENT_ID_TCP_CONNECT_V4`) is mapped;
    /// every other Kernel-Network event (data xmit/recv, established, close,
    /// IPv6, UDP, ...) is SKIPPED. Any missing/unparsable required field is
    /// logged and the event is skipped — never `unwrap()`.
    ///
    /// Byte-order contract (the crux, cannot be observed without elevation):
    /// the manifest declares `daddr` as `win:UInt32`/out `win:IPv4` and `dport`
    /// as `win:UInt16`/out `win:Port`; the kernel writes both in NETWORK
    /// (big-endian) octet order into the record. ferrisetw's primitive parse
    /// reads the raw property bytes with `from_ne_bytes` (native = little-endian
    /// on every Windows target: x86/x64/ARM64), so `try_parse::<u32>("daddr")`
    /// yields the network-order value in the SAME representation the Linux eBPF
    /// backend passes (e.g. `0x0100007F` for 127.0.0.1), and likewise
    /// `try_parse::<u16>("dport")` yields `0x5000` for port 80. We therefore
    /// feed these values DIRECTLY into `net_event` as `daddr_be`/`dport_be`
    /// (network order) and let that shared mapper do the `from_be` conversion —
    /// no duplicated mapping, identical output to eBPF.
    /// (Assumption confirmed by the elevated Task 3 capture: `daddr`/`dport`
    /// arrive network-order and this parse renders the correct dotted-quad/port.)
    ///
    /// Image/process name: the Kernel-Network connect template exposes no image
    /// or process-name field (only `PID` and the address tuple), so we pass an
    /// empty `image`. This is honest — netmon keys its verdict on `daddr`/`dport`
    /// and correlates by `pid`; a blank image is acceptable, not a fabricated one.
    fn handle_net_record(
        record: &EventRecord,
        locator: &SchemaLocator,
        tx: &tokio::sync::broadcast::Sender<SubstrateEvent>,
    ) {
        // Only the outbound IPv4 TCP connect attempt; skip all other network
        // events (send/recv/established/close/retransmit, IPv6, UDP, ...).
        if record.event_id() != EVENT_ID_TCP_CONNECT_V4 {
            return;
        }

        let schema = match locator.event_schema(record) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("etw: net schema lookup failed, skipping event: {e:?}");
                return;
            }
        };
        let parser = Parser::create(record, &schema);

        // PID is required for correlation. If it can't be parsed, skip.
        let pid: u32 = match parser.try_parse("PID") {
            Ok(p) => p,
            Err(e) => {
                eprintln!("etw: net event unparsable PID, skipping: {e:?}");
                return;
            }
        };
        // Destination address (network order, see byte-order contract above).
        let daddr_be: u32 = match parser.try_parse("daddr") {
            Ok(a) => a,
            Err(e) => {
                eprintln!("etw: net event unparsable daddr for pid {pid}, skipping: {e:?}");
                return;
            }
        };
        // Destination port (network order, see byte-order contract above).
        let dport_be: u16 = match parser.try_parse("dport") {
            Ok(p) => p,
            Err(e) => {
                eprintln!("etw: net event unparsable dport for pid {pid}, skipping: {e:?}");
                return;
            }
        };

        // Reuse the shared pure mapper (also used by the eBPF drain path). No
        // image on this provider -> "". `net_event` converts network -> host.
        let ev = net_event(record.raw_timestamp(), pid, "", daddr_be, dport_be);
        let _ = tx.send(ev);
    }

    /// Map ONE raw Kernel-File record to a [`SubstrateEvent`] (`FileWrite` or
    /// `FileOpen`) and publish it, maintaining the `FileObject -> path`
    /// correlation cache. Mirrors [`handle_net_record`]'s panic-free style.
    ///
    /// Dispatch on `record.event_id()`:
    /// - **12 (Create):** map to `FileOpen`/`FileWrite` (write-intent from the
    ///   CreateDisposition; see [`is_write_create`]) EXACTLY as before, AND
    ///   cache `FileObject -> path` so a later byte-level Write can recover the
    ///   path. High volume; no substrate-side path filtering (deferred).
    /// - **13 (Cleanup) / 14 (Close):** the file object's lifecycle end — emit
    ///   NOTHING; `remove` the `FileObject` from the cache (correct lifecycle
    ///   eviction, so a reused pointer can't be mis-correlated).
    /// - **16 (Write):** a REAL byte-level write. The event has NO `FileName`,
    ///   so recover the path by looking `FileObject` up in the cache. If the
    ///   path is UNKNOWN (no observed Create — e.g. the file was opened before
    ///   our session started) the write is DROPPED, not guessed. If known, emit
    ///   `FileWrite` carrying `IOSize` as the byte count.
    /// - any other id → skip.
    ///
    /// Any missing/unparsable required field is skipped — never `unwrap()`.
    /// PID comes from the ETW event HEADER (`record.process_id()`), NOT the
    /// template. The Kernel-File record carries no initiating image, so `image`
    /// is passed as "" (honest blank, see [`file_event`]).
    ///
    /// LOCKING DISCIPLINE (crux of the stateful design): the `cache` mutex is
    /// held ONLY for the O(1) map op, NEVER across `tx.send()` or parsing. The
    /// Write path locks, clones the path out (`get` returns an owned `String`),
    /// DROPS the guard, THEN builds and sends. The Create path computes `path`
    /// first, then locks only to insert. The lock is POISON-TOLERANT
    /// (`Err(p) => p.into_inner()`), so one anomaly can never wedge the file
    /// sensor with a panicking callback.
    ///
    /// ASSUMPTIONS (runtime-confirmed at the elevated Task 3): (1) a `FileObject`
    /// value is STABLE and matches between a Create (12) and the subsequent
    /// Write (16) for the same open, so it is a valid correlation key; (2) the
    /// `try_parse` types below (`u64` for `FileObject`, `u32` for `IOSize`)
    /// decode the right bytes at runtime.
    ///
    /// SCOPE: Write (16) only. Read byte-events (15), Delete/Rename, and
    /// FileKey-based name resolution are DEFERRED. Session-start enumeration of
    /// already-open files (which would let us path pre-existing writes) is also
    /// deferred; such writes are honestly dropped.
    fn handle_file_record(
        record: &EventRecord,
        locator: &SchemaLocator,
        tx: &tokio::sync::broadcast::Sender<SubstrateEvent>,
        cache: &std::sync::Mutex<FileNameCache>,
    ) {
        match record.event_id() {
            EVENT_ID_FILE_CREATE => {
                handle_file_create(record, locator, tx, cache);
            }
            EVENT_ID_FILE_CLEANUP | EVENT_ID_FILE_CLOSE => {
                // Lifecycle end: drop the correlation, emit nothing. FileObject
                // is a `win:Pointer` -> parse as u64 (64-bit host). If it won't
                // parse, there is nothing to evict — just return.
                let schema = match locator.event_schema(record) {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let parser = Parser::create(record, &schema);
                let fo: u64 = match parser.try_parse("FileObject") {
                    Ok(f) => f,
                    Err(_) => return,
                };
                let mut c = match cache.lock() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                c.remove(fo);
            }
            EVENT_ID_FILE_WRITE => {
                handle_file_write(record, locator, tx, cache);
            }
            _ => (),
        }
    }

    /// Handle a Kernel-File **Create** (id 12): emit the open/create event
    /// (byte-unchanged from the pre-cache behaviour) and additionally cache the
    /// `FileObject -> path` correlation for later byte-level writes.
    fn handle_file_create(
        record: &EventRecord,
        locator: &SchemaLocator,
        tx: &tokio::sync::broadcast::Sender<SubstrateEvent>,
        cache: &std::sync::Mutex<FileNameCache>,
    ) {
        let schema = match locator.event_schema(record) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("etw: file schema lookup failed, skipping event: {e:?}");
                return;
            }
        };
        let parser = Parser::create(record, &schema);

        // PID is in the event HEADER, not the template.
        let pid: u32 = record.process_id();

        // FileName (UnicodeString) is required for a useful event. If it can't
        // be parsed, skip (never panic).
        let path: String = match parser.try_parse("FileName") {
            Ok(p) => p,
            Err(e) => {
                eprintln!("etw: file event unparsable FileName for pid {pid}, skipping: {e:?}");
                return;
            }
        };
        // An empty path carries no signal; skip it too.
        if path.is_empty() {
            return;
        }

        // CreateOptions carries the write-intent signal in its high byte (the
        // CreateDisposition; see `is_write_create`). Absent/unparsable ->
        // `None` -> `write = false` (FileOpen), the SAFE conservative default:
        // a raw `0` would decode to disposition 0 = FILE_SUPERSEDE = write,
        // which is the WRONG fallback, so we deliberately do not default the
        // int to 0 before deciding.
        let create_options: Option<u32> = parser.try_parse("CreateOptions").ok();
        let write = create_options.map(is_write_create).unwrap_or(false);

        // Cache the FileObject -> path correlation for a later byte-level Write
        // (id 16, which has no FileName). FileObject is a `win:Pointer` -> u64
        // on a 64-bit host. If it won't parse, DON'T fail the create emit — just
        // skip the insert (that file's writes will be dropped as unknown-path).
        // Compute `path` first, then hold the lock ONLY for the O(1) insert,
        // never across the send below.
        if let Ok(fo) = parser.try_parse::<u64>("FileObject") {
            let mut c = match cache.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            c.insert(fo, path.clone());
        }

        // Reuse the shared pure mapper (also used by a future eBPF file hook).
        // No image on this provider -> "". Byte-unchanged: create/open intent
        // carries no byte count -> `None`.
        let ev = file_event(record.raw_timestamp(), pid, "", &path, write, None);
        let _ = tx.send(ev);
    }

    /// Handle a Kernel-File **Write** (id 16): recover the path from the cache by
    /// `FileObject` and, if known, emit a `FileWrite` carrying `IOSize` bytes. A
    /// write to a file whose Create we never saw is DROPPED (no pathless write).
    fn handle_file_write(
        record: &EventRecord,
        locator: &SchemaLocator,
        tx: &tokio::sync::broadcast::Sender<SubstrateEvent>,
        cache: &std::sync::Mutex<FileNameCache>,
    ) {
        let schema = match locator.event_schema(record) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("etw: file write schema lookup failed, skipping event: {e:?}");
                return;
            }
        };
        let parser = Parser::create(record, &schema);

        // PID is in the event HEADER, not the template.
        let pid: u32 = record.process_id();

        // FileObject is a `win:Pointer` -> u64 (64-bit host); the correlation
        // key. Unparsable -> skip.
        let fo: u64 = match parser.try_parse("FileObject") {
            Ok(f) => f,
            Err(e) => {
                eprintln!("etw: file write unparsable FileObject for pid {pid}, skipping: {e:?}");
                return;
            }
        };
        // IOSize is `win:UInt32` = the number of bytes written. Unparsable ->
        // skip.
        let io_size: u32 = match parser.try_parse("IOSize") {
            Ok(n) => n,
            Err(e) => {
                eprintln!("etw: file write unparsable IOSize for pid {pid}, skipping: {e:?}");
                return;
            }
        };

        // Look up the path under the lock, clone it out, then DROP the guard
        // BEFORE building/sending the event — the lock never spans `tx.send`.
        let path = {
            let c = match cache.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            c.get(fo)
        };

        // Unknown path (no observed Create) -> DROP; we do NOT emit a pathless
        // write. Honest: we only report writes to files whose open we saw.
        let path = match path {
            Some(p) => p,
            None => return,
        };

        let ev = file_event(
            record.raw_timestamp(),
            pid,
            "",
            &path,
            true,
            Some(io_size as u64),
        );
        let _ = tx.send(ev);
    }

    impl Drop for EtwBus {
        fn drop(&mut self) {
            // Stop the trace FIRST: this unblocks `ProcessTrace` on the consumer
            // thread, so the subsequent join is bounded. Errors are ignored (we
            // must not panic in Drop).
            if let Some(trace) = self.trace.take() {
                let _ = trace.stop();
            }
            // Now join the consumer thread — no leaked session, no detached
            // thread. A panic in the thread is swallowed (never re-raised here).
            if let Some(consumer) = self.consumer.take() {
                let _ = consumer.join();
            }
        }
    }

    impl EventBus for EtwBus {
        fn publish(&self, ev: SubstrateEvent) {
            let _ = self.tx.send(ev); // ignore "no subscribers"
        }
        fn subscribe(
            &self,
            _kinds: &[EventKind],
        ) -> tokio::sync::broadcast::Receiver<SubstrateEvent> {
            // Real impl filters by kind; forwards all for now (like StubBus).
            self.tx.subscribe()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::time::{Duration, Instant};

        /// Non-elevated hosts cannot open a Kernel-Process ETW session:
        /// `StartTraceW` returns `ERROR_ACCESS_DENIED`, so `try_start` must
        /// return `Err` (never panic, never hang). The elevated Task 3 run
        /// confirms the `Ok` path (real session + captured events).
        #[test]
        fn try_start_is_fail_soft_when_not_elevated() {
            let start = Instant::now();
            let res = EtwBus::try_start();
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "try_start must return promptly, not hang"
            );
            // If a host DID allow it (elevated / Performance Log Users), tear the
            // session down cleanly rather than failing the assertion.
            match res {
                Ok(bus) => {
                    // Exercises Drop (stop + join) with a live session.
                    drop(bus);
                }
                Err(_) => { /* expected non-elevated: fail-soft Err */ }
            }
        }

        /// Whatever `try_start` does, the platform factory always yields a
        /// USABLE bus: non-elevated it falls back to `StubBus` (`bus_label ==
        /// "stub"`), without panic and promptly.
        #[test]
        fn for_this_platform_falls_back_to_stub_when_not_elevated() {
            let start = Instant::now();
            let sub = crate::Substrate::for_this_platform();
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "for_this_platform must return promptly"
            );
            assert_eq!(
                sub.bus_label, "stub",
                "non-elevated run must fall back to the stub bus"
            );
            // Usable: subscribe, publish, receive round-trips.
            let mut rx = sub.bus.subscribe(&[EventKind::ProcessExec]);
            sub.bus.publish(SubstrateEvent {
                kind: EventKind::ProcessExec,
                ts: 1,
                fields: serde_json::json!({ "pid": 1 }),
            });
            let ev = rx.try_recv().expect("stub fallback delivers events");
            assert_eq!(ev.kind, EventKind::ProcessExec);
        }
    }
}

#[cfg(all(target_os = "windows", feature = "windows-etw"))]
pub(crate) use bus::EtwBus;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_event_maps_exec_and_exit() {
        // Exec with full fields.
        let ev = process_event(
            EventKind::ProcessExec,
            123,
            4242,
            "C:\\Windows\\System32\\cmd.exe",
            Some(1000),
            Some("cmd /c echo"),
        );
        assert_eq!(ev.kind, EventKind::ProcessExec);
        assert_eq!(ev.ts, 123);
        assert_eq!(ev.fields["pid"], 4242);
        assert_eq!(ev.fields["image"], "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(ev.fields["ppid"], 1000);
        assert_eq!(ev.fields["cmdline"], "cmd /c echo");

        // Exit case.
        let ev = process_event(
            EventKind::ProcessExit,
            456,
            4242,
            "C:\\Windows\\System32\\cmd.exe",
            Some(1000),
            None,
        );
        assert_eq!(ev.kind, EventKind::ProcessExit);
        assert_eq!(ev.ts, 456);
        assert_eq!(ev.fields["pid"], 4242);
    }

    #[test]
    fn process_event_omits_none_ppid_and_cmdline() {
        let ev = process_event(EventKind::ProcessExec, 7, 99, "C:\\a.exe", None, None);
        assert_eq!(ev.fields["pid"], 99);
        assert_eq!(ev.fields["image"], "C:\\a.exe");
        // None fields are OMITTED, not serialized as null.
        let obj = ev.fields.as_object().expect("fields is an object");
        assert!(
            !obj.contains_key("ppid"),
            "ppid key must be omitted when None"
        );
        assert!(
            !obj.contains_key("cmdline"),
            "cmdline key must be omitted when None"
        );
        assert!(ev.fields.get("ppid").is_none());
        assert!(ev.fields.get("cmdline").is_none());
    }

    /// `net_event` converts the kernel's NETWORK-order address/port into a
    /// dotted-quad string and a HOST-order port, tagging the event `NetConnect`.
    #[test]
    fn net_event_converts_byte_order() {
        // daddr = 127.0.0.1 in network order (0x0100007F as read little-endian
        // from the user sockaddr); dport = 80 in network order (0x5000).
        let ev = net_event(123, 4242, "curl", 0x0100_007F, 0x5000);
        assert_eq!(ev.kind, EventKind::NetConnect);
        assert_eq!(ev.ts, 123);
        assert_eq!(ev.fields["pid"], 4242);
        assert_eq!(ev.fields["image"], "curl");
        assert_eq!(ev.fields["daddr"], "127.0.0.1");
        assert_eq!(ev.fields["dport"], 80); // host order
        assert_eq!(ev.fields["proto"], "tcp");

        // A different address/port to guard against accidental symmetry.
        // 8.8.4.4 in network order = 0x04040808 (LE read); port 443 = 0xBB01.
        let ev = net_event(1, 1, "x", 0x0404_0808, 0xBB01);
        assert_eq!(ev.fields["daddr"], "8.8.4.4");
        assert_eq!(ev.fields["dport"], 443);
    }

    /// `file_event` maps a file open/create (`write = false`) to a `FileOpen`
    /// event carrying `{ pid, image, path, op: "open" }`, with a blank image on
    /// the ETW file record. This is the mapping proof; the live Kernel-File
    /// capture is Task 3.
    #[test]
    fn file_event_maps_open() {
        let ev = file_event(123, 4242, "", "C:\\Users\\x\\a.tmp", false, None);
        assert_eq!(ev.kind, EventKind::FileOpen);
        assert_eq!(ev.ts, 123);
        assert_eq!(ev.fields["pid"], 4242);
        assert_eq!(ev.fields["path"], "C:\\Users\\x\\a.tmp");
        assert_eq!(ev.fields["op"], "open");
        assert_eq!(ev.fields["image"], ""); // blank image on the ETW file record
        assert!(ev.fields.get("bytes").is_none()); // omitted, not null, when bytes = None
    }

    /// `file_event` with `write = true` and `bytes = Some(n)` maps to a
    /// `FileWrite` event carrying `op: "write"` and `bytes: n`; with
    /// `bytes = None` the `bytes` key is omitted entirely (proves omission,
    /// not just the open-event case above).
    #[test]
    fn file_event_carries_bytes() {
        let ev = file_event(1, 7, "", "/etc/x", true, Some(4096));
        assert_eq!(ev.kind, EventKind::FileWrite);
        assert_eq!(ev.fields["op"], "write");
        assert_eq!(ev.fields["bytes"], 4096);

        let ev = file_event(1, 7, "", "/etc/x", true, None);
        assert_eq!(ev.kind, EventKind::FileWrite);
        assert_eq!(ev.fields["op"], "write");
        assert!(ev.fields.get("bytes").is_none());
    }

    /// `is_write_create` decodes the CreateDisposition from the HIGH byte of
    /// `CreateOptions`: a plain `FILE_OPEN` (open existing) or an unrecognized
    /// disposition is NOT write intent (conservative false); SUPERSEDE/CREATE/
    /// OPEN_IF/OVERWRITE/OVERWRITE_IF all are. The low-byte CreateOptions flags
    /// must never affect the result (mask is high-byte-only).
    #[test]
    fn is_write_create_decodes_disposition() {
        // A plain read open is NOT write intent.
        assert!(!is_write_create(FILE_OPEN << 24));

        // Every create/overwrite disposition IS write intent.
        assert!(is_write_create(FILE_SUPERSEDE << 24));
        assert!(is_write_create(FILE_CREATE << 24));
        assert!(is_write_create(FILE_OPEN_IF << 24));
        assert!(is_write_create(FILE_OVERWRITE << 24));
        assert!(is_write_create(FILE_OVERWRITE_IF << 24));

        // A garbage/unrecognized disposition -> conservative false.
        assert!(!is_write_create(0xEE << 24));

        // Low-byte CreateOptions flags must NOT affect the result.
        assert!(!is_write_create((FILE_OPEN << 24) | 0x0000_1234));
        assert!(is_write_create((FILE_CREATE << 24) | 0x00FF_FFFF));
    }

    /// Basic insert/get/remove round-trip: a cached `FileObject -> path` is
    /// retrievable, and after `remove` (the Cleanup/Close lifecycle eviction)
    /// the lookup misses.
    #[test]
    fn file_name_cache_insert_get_remove() {
        let mut cache = FileNameCache::new();
        cache.insert(0xDEAD_BEEF, "C:\\Users\\x\\a.tmp".to_string());
        assert_eq!(
            cache.get(0xDEAD_BEEF).as_deref(),
            Some("C:\\Users\\x\\a.tmp")
        );
        assert_eq!(cache.len(), 1);

        cache.remove(0xDEAD_BEEF);
        assert_eq!(cache.get(0xDEAD_BEEF), None);
        assert_eq!(cache.len(), 0);
    }

    /// The cache is BOUNDED: flooding it with far more DISTINCT FileObjects than
    /// the cap and NEVER removing (simulating missed Cleanup/Close) must leave
    /// `len()` pinned at exactly `FILE_CACHE_CAP` — no unbounded growth/leak.
    /// The oldest inserted is FIFO-evicted (get None); a recent one survives.
    #[test]
    fn file_name_cache_is_bounded_under_flood() {
        let mut cache = FileNameCache::new();
        let n = FILE_CACHE_CAP as u64 + 1000;
        for fo in 0..n {
            cache.insert(fo, format!("C:\\f\\{fo}"));
            // Never exceeds the cap at ANY point during the flood.
            assert!(cache.len() <= FILE_CACHE_CAP);
        }
        assert_eq!(cache.len(), FILE_CACHE_CAP);

        // The oldest (fo = 0) was FIFO-evicted long ago.
        assert_eq!(cache.get(0), None);
        // A recently inserted FileObject is still present.
        let recent = n - 1;
        assert_eq!(
            cache.get(recent).as_deref(),
            Some(format!("C:\\f\\{recent}").as_str())
        );
    }

    /// Exact FIFO boundary: fill to CAP, then insert ONE more new key — the
    /// first-inserted key is evicted, the newest is present, and `len()` stays
    /// at CAP.
    #[test]
    fn file_name_cache_fifo_eviction() {
        let mut cache = FileNameCache::new();
        for fo in 0..FILE_CACHE_CAP as u64 {
            cache.insert(fo, format!("p{fo}"));
        }
        assert_eq!(cache.len(), FILE_CACHE_CAP);

        // One more NEW key evicts the oldest (fo = 0), FIFO.
        let newest = FILE_CACHE_CAP as u64;
        cache.insert(newest, "new".to_string());
        assert_eq!(cache.len(), FILE_CACHE_CAP);
        assert_eq!(cache.get(0), None, "oldest key evicted");
        assert_eq!(cache.get(newest).as_deref(), Some("new"));
        // A non-oldest key inserted before the flood boundary survives.
        assert_eq!(cache.get(1).as_deref(), Some("p1"));
    }

    /// Regression for the unbounded `order` leak: on a host that stays well
    /// under `FILE_CACHE_CAP` concurrently-open files, `map.len()` never
    /// reaches the cap, so the FIFO eviction loop in `insert` never runs and
    /// never drains stale `order` tokens left behind by `remove`. Interleave
    /// many rounds of insert-then-remove BELOW the map cap — far more total
    /// inserts than `FILE_CACHE_ORDER_CAP` — and assert both `len()` (the map)
    /// stays tiny AND `order_len()` never exceeds `FILE_CACHE_ORDER_CAP`.
    /// Without the `insert`-time compaction this test fails: `order` would
    /// grow to `FILE_CACHE_ORDER_CAP * 4` (one token per insert, never
    /// reclaimed) while `map.len()` stays at 0 or 1.
    #[test]
    fn file_name_cache_order_bounded_under_remove_churn() {
        let mut cache = FileNameCache::new();
        let rounds = FILE_CACHE_ORDER_CAP * 4;
        for fo in 0..rounds as u64 {
            cache.insert(fo, format!("C:\\churn\\{fo}"));
            cache.remove(fo);

            // The map never grows beyond a single live entry (well under the cap).
            assert!(cache.len() <= 1);
            // The order deque never grows without bound, regardless of churn.
            assert!(
                cache.order_len() <= FILE_CACHE_ORDER_CAP,
                "order deque leaked: order_len={} > cap={} at fo={fo}",
                cache.order_len(),
                FILE_CACHE_ORDER_CAP
            );
        }
        assert_eq!(cache.len(), 0);
        assert!(cache.order_len() <= FILE_CACHE_ORDER_CAP);
    }

    /// Regression for the SECOND `order` leak variant: refreshing the SAME
    /// already-live key over and over (no `remove` in between) must not grow
    /// `order` without bound. `insert` unconditionally `push_back`s a token
    /// even when the key already exists, so a `retain`-only compaction (which
    /// keeps every token whose key is still in `map`) never reclaims these
    /// duplicates — they're all "live". This is the real ETW scenario: a
    /// dropped Cleanup/Close leaves a key live in `map`, Windows recycles the
    /// `FileObject` pointer, and the next Create re-`insert`s that same key.
    /// Pre-fix (retain-only compaction) this test FAILS: `order_len()` grows
    /// to `FILE_CACHE_ORDER_CAP * 4` while `map.len()` stays at 1. Post-fix
    /// (dedup-keeping-last compaction) `order_len()` stays `<=
    /// FILE_CACHE_ORDER_CAP` throughout, and `map.len()` is always 1.
    #[test]
    fn file_name_cache_order_bounded_under_live_key_refresh() {
        let mut cache = FileNameCache::new();
        let rounds = FILE_CACHE_ORDER_CAP * 4;
        for i in 0..rounds {
            cache.insert(7u64, format!("/p/{i}"));
            assert!(
                cache.order_len() <= FILE_CACHE_ORDER_CAP,
                "order deque leaked on live-key refresh: order_len={} > cap={} at i={i}",
                cache.order_len(),
                FILE_CACHE_ORDER_CAP
            );
        }
        assert_eq!(cache.len(), 1);
        assert!(cache.order_len() <= FILE_CACHE_ORDER_CAP);
        // The most recent write wins.
        assert_eq!(
            cache.get(7).as_deref(),
            Some(format!("/p/{}", rounds - 1).as_str())
        );
    }

    /// Mixed variant: one hammered live key interleaved with distinct-key
    /// churn (insert-then-remove, well under the map cap). Exercises both
    /// leak sources at once — duplicate tokens from the refreshed key AND
    /// stale tokens from the removed churn keys — and asserts `order` stays
    /// bounded throughout.
    #[test]
    fn file_name_cache_order_bounded_under_mixed_refresh_and_churn() {
        let mut cache = FileNameCache::new();
        let rounds = FILE_CACHE_ORDER_CAP * 4;
        for i in 0..rounds as u64 {
            // Hammer the same live key every iteration (refresh, never removed).
            cache.insert(42u64, format!("/hot/{i}"));
            // Distinct-key churn: insert then immediately remove.
            cache.insert(1_000_000 + i, format!("/churn/{i}"));
            cache.remove(1_000_000 + i);

            assert!(
                cache.order_len() <= FILE_CACHE_ORDER_CAP,
                "order deque leaked under mixed churn: order_len={} > cap={} at i={i}",
                cache.order_len(),
                FILE_CACHE_ORDER_CAP
            );
            // Only the hammered key stays live.
            assert_eq!(cache.len(), 1);
        }
        assert!(cache.order_len() <= FILE_CACHE_ORDER_CAP);
        assert_eq!(cache.len(), 1);
    }
}
