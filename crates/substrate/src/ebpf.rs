//! Linux eBPF event backend (behind the `linux-ebpf` feature, Linux only).
//!
//! eBPF is the Linux counterpart to the ETW bus on Windows: one kernel-event
//! source that publishes onto the shared [`crate::EventBus`]. [`EbpfBus`] loads
//! the embedded BPF object below, attaches BOTH the `sched_process_exec` and
//! `sched_process_exit` tracepoints, drains the shared ring buffer on a
//! background thread, and republishes each record as a [`SubstrateEvent`]
//! (`ProcessExec` / `ProcessExit`). It is fail-soft like `EtwBus`: when it cannot load
//! (most commonly because the agent is NOT root / lacks `CAP_BPF`, so the BPF
//! syscalls return `EPERM`), [`crate::select_event_bus`] logs and falls back to
//! `StubBus`, so a non-root run still works.
//!
//! The compiled kernel object is produced by `build.rs` (it compiles
//! `crates/substrate-ebpf` to `bpfel-unknown-none` and stages it at
//! `$OUT_DIR/substrate-ebpf.o`) and embedded here so the loader gets it via a
//! plain `&[u8]` with no runtime file dependency.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aya::maps::{MapData, RingBuf};
use aya::programs::TracePoint;
use aya::Ebpf;
use tokio::sync::broadcast;
use torda_core::{EventBus, EventKind, SubstrateEvent};
use torda_substrate_ebpf_common::{
    FileEvent, NetEvent, ProcEvent, KIND_CONNECT, KIND_EXEC, KIND_EXIT, KIND_OPEN, PATH_CAP,
};

use crate::etw::{file_event, net_event, process_event};

/// The compiled BPF object (staged by `build.rs`) containing ALL the tracepoint
/// programs (the two process ones, the connect one, and the openat file one).
/// [`EbpfBus::try_start`] feeds these bytes to [`aya::Ebpf::load`], which loads
/// every program in the object.
pub(crate) static PROC_EXEC_OBJ: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/substrate-ebpf.o"));

/// Category of the process tracepoints (both live under
/// `/sys/kernel/tracing/events/sched/`).
const TP_CATEGORY: &str = "sched";
/// The exec tracepoint name (`sched/sched_process_exec`). aya also keys the
/// program by its `#[tracepoint]` fn name, which matches — so this doubles as
/// the program name for the exec handler.
const EXEC_TP_NAME: &str = "sched_process_exec";
/// The exit tracepoint name (`sched/sched_process_exit`); likewise doubles as
/// the exit handler's program name.
const EXIT_TP_NAME: &str = "sched_process_exit";
/// Category of the network-connect tracepoint (`syscalls/sys_enter_connect`) —
/// a DIFFERENT category from the process tracepoints, hence the generalized
/// `attach_tracepoint(category, name)`.
const CONNECT_TP_CATEGORY: &str = "syscalls";
/// The connect tracepoint name (`syscalls/sys_enter_connect`); doubles as the
/// connect handler's program name.
const CONNECT_TP_NAME: &str = "sys_enter_connect";
/// Category of the file-open tracepoint (`syscalls/sys_enter_openat`) — the same
/// `syscalls` category as the connect one.
const OPENAT_TP_CATEGORY: &str = "syscalls";
/// The openat tracepoint name (`syscalls/sys_enter_openat`); doubles as the
/// openat handler's program name.
const OPENAT_TP_NAME: &str = "sys_enter_openat";
/// The `#[map]` static name — the ring buffer shared by both process programs.
const MAP_NAME: &str = "EVENTS";
/// The `#[map]` static name for the SEPARATE network-connect ring buffer.
const NET_MAP_NAME: &str = "NET_EVENTS";
/// The `#[map]` static name for the SEPARATE file-open ring buffer.
const FILE_MAP_NAME: &str = "FILE_EVENTS";

/// Idle wait between ring-buffer drains. Bounds both CPU (no hard busy-spin when
/// idle) and the [`Drop`] join latency (a stop flag is checked once per cycle).
const POLL_IDLE: Duration = Duration::from_millis(100);

/// The Linux eBPF-backed event bus. A background thread drains the kernel ring
/// buffer and pushes mapped records onto the broadcast channel; modules
/// subscribe via the shared [`EventBus`] trait. Dropping the bus stops and joins
/// the poll thread, then drops the [`Ebpf`] handle (which detaches the program).
pub struct EbpfBus {
    tx: broadcast::Sender<SubstrateEvent>,
    /// Set on `Drop` to stop BOTH poll threads.
    stop: Arc<AtomicBool>,
    /// The process ring-buffer (`EVENTS`) drain thread; joined (bounded) in `Drop`.
    poller: Option<JoinHandle<()>>,
    /// The network ring-buffer (`NET_EVENTS`) drain thread; joined (bounded) in
    /// `Drop`. A SEPARATE thread from `poller` since each ring is drained
    /// independently.
    net_poller: Option<JoinHandle<()>>,
    /// The file ring-buffer (`FILE_EVENTS`) drain thread; joined (bounded) in
    /// `Drop`. A SEPARATE thread from `poller`/`net_poller` since each ring is
    /// drained independently.
    file_poller: Option<JoinHandle<()>>,
    /// The loaded+attached BPF object. Kept alive ONLY for its lifetime — while
    /// it lives the tracepoint stays attached; dropping it detaches the program.
    /// Never touched after construction, hence the leading underscore.
    _ebpf: Ebpf,
}

impl EbpfBus {
    /// Load [`PROC_EXEC_OBJ`], attach BOTH the `sched_process_exec` and
    /// `sched_process_exit` tracepoints, open the ring buffer, and spawn the
    /// drain thread.
    ///
    /// Returns `Err` when the load/attach fails — most importantly a NON-root
    /// run, where the BPF syscalls (`BPF_MAP_CREATE` / `BPF_PROG_LOAD`) return
    /// `EPERM` — so [`crate::select_event_bus`] falls back to `StubBus`,
    /// fail-soft. Only the `Ok` (real-capture) path requires root/`CAP_BPF`.
    ///
    /// Non-hanging: every step here (`load`, `TracePoint::load`, `attach`, ring
    /// open) returns promptly with a `Result`; the only long-lived work is the
    /// drain loop, which runs on the spawned thread — never on the caller. A
    /// failure surfaces as an immediate `Err`; success returns right after the
    /// attach, before the first event.
    pub fn try_start() -> anyhow::Result<Arc<Self>> {
        // Load the object: creates the maps and prepares the programs. On a
        // non-root host this is where `EPERM` first surfaces (map/prog syscalls
        // are privileged), which is exactly the fail-soft seam.
        let mut ebpf = Ebpf::load(PROC_EXEC_OBJ).map_err(|e| {
            anyhow::anyhow!("failed to load eBPF object (run as root / grant CAP_BPF): {e}")
        })?;

        // Load + attach BOTH tracepoint programs (they live in the same object,
        // already loaded above). A failure to load or attach EITHER surfaces as
        // an `Err` here → fail-soft fallback to `StubBus`. Scoped so the
        // `&mut Ebpf` borrow ends before we take the map out below.
        {
            attach_tracepoint(&mut ebpf, TP_CATEGORY, EXEC_TP_NAME)?;
            attach_tracepoint(&mut ebpf, TP_CATEGORY, EXIT_TP_NAME)?;
            // The network sensor: a DIFFERENT tracepoint category (`syscalls`).
            // Attaching as a unit — a failure here fails the whole start
            // (fail-soft → `StubBus`), same as the process tracepoints.
            attach_tracepoint(&mut ebpf, CONNECT_TP_CATEGORY, CONNECT_TP_NAME)?;
            // The file sensor: the `syscalls` category again. Attached as part of
            // the same unit — a failure here fails the whole start (fail-soft →
            // `StubBus`), like the process and connect tracepoints.
            attach_tracepoint(&mut ebpf, OPENAT_TP_CATEGORY, OPENAT_TP_NAME)?;
        }

        // Take the process ring-buffer map OUT of the object so we own it
        // (`Send`) and can move it into the drain thread. The program keeps its
        // own kernel reference to the map (bound at load time), so this does not
        // detach it.
        let map = ebpf
            .take_map(MAP_NAME)
            .ok_or_else(|| anyhow::anyhow!("ring-buffer map `{MAP_NAME}` not found in object"))?;
        let mut ring: RingBuf<MapData> = RingBuf::try_from(map)
            .map_err(|e| anyhow::anyhow!("map `{MAP_NAME}` is not a ring buffer: {e}"))?;

        // Likewise take the SEPARATE network ring-buffer map for its own thread.
        let net_map = ebpf.take_map(NET_MAP_NAME).ok_or_else(|| {
            anyhow::anyhow!("ring-buffer map `{NET_MAP_NAME}` not found in object")
        })?;
        let mut net_ring: RingBuf<MapData> = RingBuf::try_from(net_map)
            .map_err(|e| anyhow::anyhow!("map `{NET_MAP_NAME}` is not a ring buffer: {e}"))?;

        // Likewise take the SEPARATE file ring-buffer map for its own thread.
        let file_map = ebpf.take_map(FILE_MAP_NAME).ok_or_else(|| {
            anyhow::anyhow!("ring-buffer map `{FILE_MAP_NAME}` not found in object")
        })?;
        let mut file_ring: RingBuf<MapData> = RingBuf::try_from(file_map)
            .map_err(|e| anyhow::anyhow!("map `{FILE_MAP_NAME}` is not a ring buffer: {e}"))?;

        let (tx, _rx) = broadcast::channel(1024);
        let stop = Arc::new(AtomicBool::new(false));

        // Process drain thread. Started ONLY after a successful attach, so a
        // load/attach failure never spawns a thread. It maps each record with
        // `map_record` (ProcEvent → ProcessExec/ProcessExit).
        let poll_tx = tx.clone();
        let poll_stop = stop.clone();
        let poller = std::thread::Builder::new()
            .name("ebpf-ringbuf".to_string())
            .spawn(move || drain_loop(&mut ring, &poll_tx, &poll_stop, map_record))
            .map_err(|e| anyhow::anyhow!("failed to spawn eBPF ring-buffer thread: {e}"))?;

        // Network drain thread: a SECOND thread draining `NET_EVENTS` with
        // `map_net_record` (NetEvent → NetConnect). Shares the same stop flag and
        // broadcast channel; both are joined in `Drop`.
        let net_tx = tx.clone();
        let net_stop = stop.clone();
        let net_poller = std::thread::Builder::new()
            .name("ebpf-net-ringbuf".to_string())
            .spawn(move || drain_loop(&mut net_ring, &net_tx, &net_stop, map_net_record))
            .map_err(|e| anyhow::anyhow!("failed to spawn eBPF net ring-buffer thread: {e}"))?;

        // File drain thread: a THIRD thread draining `FILE_EVENTS` with
        // `map_file_record` (FileEvent → FileOpen). Shares the same stop flag and
        // broadcast channel; all three are joined in `Drop`.
        let file_tx = tx.clone();
        let file_stop = stop.clone();
        let file_poller = std::thread::Builder::new()
            .name("ebpf-file-ringbuf".to_string())
            .spawn(move || drain_loop(&mut file_ring, &file_tx, &file_stop, map_file_record))
            .map_err(|e| anyhow::anyhow!("failed to spawn eBPF file ring-buffer thread: {e}"))?;

        Ok(Arc::new(Self {
            tx,
            stop,
            poller: Some(poller),
            net_poller: Some(net_poller),
            file_poller: Some(file_poller),
            _ebpf: ebpf,
        }))
    }
}

/// Get the program named `name` out of the loaded object, load it into the
/// kernel, and attach it to the `<category>/<name>` tracepoint. The
/// `#[tracepoint]` fn name, the program key, and the tracepoint name all
/// coincide, so `name` serves all three; `category` selects the tracepoint group
/// (`sched` for the process tracepoints, `syscalls` for the connect and openat
/// ones). Any
/// failure (program missing, wrong type, load/attach EPERM) returns `Err` — the
/// caller propagates it, so a failed attach of ANY tracepoint fails the whole
/// start (fail-soft → `StubBus`).
fn attach_tracepoint(ebpf: &mut Ebpf, category: &str, name: &str) -> anyhow::Result<()> {
    let program: &mut TracePoint = ebpf
        .program_mut(name)
        .ok_or_else(|| anyhow::anyhow!("eBPF program `{name}` not found in object"))?
        .try_into()
        .map_err(|e| anyhow::anyhow!("program `{name}` is not a tracepoint: {e}"))?;
    program
        .load()
        .map_err(|e| anyhow::anyhow!("failed to load tracepoint `{name}` (need root): {e}"))?;
    program
        .attach(category, name)
        .map_err(|e| anyhow::anyhow!("failed to attach `{category}/{name}`: {e}"))?;
    Ok(())
}

/// Drain a ring buffer until asked to stop, mapping each raw record with `map`.
///
/// Generic over the mapper so ONE loop serves both rings: the process thread
/// passes [`map_record`] (`EVENTS` → ProcessExec/ProcessExit) and the network
/// thread passes [`map_net_record`] (`NET_EVENTS` → NetConnect).
///
/// Not a hard busy-spin: it drains everything currently available, and only when
/// the buffer is empty sleeps [`POLL_IDLE`] before re-checking. The stop flag is
/// read once per cycle, so [`Drop`]'s join is bounded by ~[`POLL_IDLE`].
fn drain_loop(
    ring: &mut RingBuf<MapData>,
    tx: &broadcast::Sender<SubstrateEvent>,
    stop: &AtomicBool,
    map: fn(&[u8]) -> Option<SubstrateEvent>,
) {
    while !stop.load(Ordering::Relaxed) {
        let mut drained_any = false;
        // `next()` is non-blocking: `Some` while records remain, else `None`.
        while let Some(item) = ring.next() {
            drained_any = true;
            // Panic-free: a short/malformed record is skipped, never unwrapped.
            if let Some(ev) = map(&item) {
                let _ = tx.send(ev); // ignore "no subscribers"
            }
            // `item` drops here, advancing the consumer position.
        }
        if !drained_any {
            std::thread::sleep(POLL_IDLE);
        }
    }
}

/// Map one raw ring-buffer record to a [`SubstrateEvent`], reusing the pure
/// [`process_event`] mapper shared with the ETW backend.
///
/// Returns `None` (skip, never panic) for a truncated/malformed record OR an
/// unrecognized `kind`. Notes on the mapped fields:
/// - `kind` (the leading `u32`) selects the event: `KIND_EXEC` → `ProcessExec`,
///   `KIND_EXIT` → `ProcessExit`; any other value is skipped (`None`).
/// - `image` is the Linux task **comm** (`bpf_get_current_comm`, up to 16 bytes,
///   NUL-trimmed): the SHORT process name, NOT a full executable path.
/// - `ts` is a wall-clock timestamp taken at read time (ms since the UNIX
///   epoch). The kernel record carries no timestamp field, so this is the drain
///   time, not the exact exec/exit time.
/// - `ppid` is `Some(ppid)` when non-zero, else `None`; the kernel program
///   currently emits `0` (CO-RE parent lookup is deferred), so it is normally
///   omitted. `cmdline` is always `None` (not collected by these tracepoints).
fn map_record(bytes: &[u8]) -> Option<SubstrateEvent> {
    if bytes.len() < core::mem::size_of::<ProcEvent>() {
        return None;
    }
    // Read the fixed `#[repr(C)]` fields at their canonical offsets (the shared
    // `ProcEvent` layout is the single source of truth for both sides). `kind`
    // is the leading field, so pid/ppid/comm each sit 4 bytes further along.
    let kind_off = core::mem::offset_of!(ProcEvent, kind);
    let pid_off = core::mem::offset_of!(ProcEvent, pid);
    let ppid_off = core::mem::offset_of!(ProcEvent, ppid);
    let comm_off = core::mem::offset_of!(ProcEvent, comm);

    let kind_raw = u32::from_ne_bytes(bytes.get(kind_off..kind_off + 4)?.try_into().ok()?);
    // Unknown discriminant → skip (forward-compatible with future kinds).
    let kind = match kind_raw {
        KIND_EXEC => EventKind::ProcessExec,
        KIND_EXIT => EventKind::ProcessExit,
        _ => return None,
    };

    let pid = u32::from_ne_bytes(bytes.get(pid_off..pid_off + 4)?.try_into().ok()?);
    let ppid = u32::from_ne_bytes(bytes.get(ppid_off..ppid_off + 4)?.try_into().ok()?);
    let comm = bytes.get(comm_off..comm_off + 16)?;

    let image = comm_to_image(comm);
    let ppid_opt = if ppid > 0 { Some(ppid) } else { None };
    Some(process_event(kind, now_ms(), pid, &image, ppid_opt, None))
}

/// `AF_INET` (IPv4). The kernel program already drops non-AF_INET, but the
/// userspace mapper re-checks defensively so a stray record can never mislabel.
const AF_INET: u16 = 2;

/// Map one raw `NET_EVENTS` record to a [`SubstrateEvent`] (`NetConnect`),
/// reusing the pure [`net_event`] mapper for the byte-order conversion.
///
/// Returns `None` (skip, never panic) for a truncated/malformed record, an
/// unrecognized `kind`, or (defensively) a non-AF_INET family. Field reads use
/// `.get(..)?` + `try_into().ok()?` at the canonical [`NetEvent`] offsets (the
/// shared `#[repr(C)]` layout is the single source of truth for both sides), so
/// a short buffer short-circuits instead of panicking.
///
/// `daddr`/`dport` are read with native-endian `from_ne_bytes` — this recovers
/// the SAME u32/u16 values the kernel wrote (kernel `bpfel` and userspace are
/// both little-endian); those values are still in NETWORK order and are handed
/// to [`net_event`], which does the network→host conversion.
fn map_net_record(bytes: &[u8]) -> Option<SubstrateEvent> {
    if bytes.len() < core::mem::size_of::<NetEvent>() {
        return None;
    }
    let kind_off = core::mem::offset_of!(NetEvent, kind);
    let pid_off = core::mem::offset_of!(NetEvent, pid);
    let daddr_off = core::mem::offset_of!(NetEvent, daddr);
    let dport_off = core::mem::offset_of!(NetEvent, dport);
    let family_off = core::mem::offset_of!(NetEvent, family);
    let comm_off = core::mem::offset_of!(NetEvent, comm);

    let kind_raw = u32::from_ne_bytes(bytes.get(kind_off..kind_off + 4)?.try_into().ok()?);
    // Only the connect kind is understood in v0; anything else → skip.
    if kind_raw != KIND_CONNECT {
        return None;
    }
    // Defensive: userspace only ever emits IPv4 records (kernel drops the rest).
    let family = u16::from_ne_bytes(bytes.get(family_off..family_off + 2)?.try_into().ok()?);
    if family != AF_INET {
        return None;
    }

    let pid = u32::from_ne_bytes(bytes.get(pid_off..pid_off + 4)?.try_into().ok()?);
    let daddr_be = u32::from_ne_bytes(bytes.get(daddr_off..daddr_off + 4)?.try_into().ok()?);
    let dport_be = u16::from_ne_bytes(bytes.get(dport_off..dport_off + 2)?.try_into().ok()?);
    let comm = bytes.get(comm_off..comm_off + 16)?;

    let image = comm_to_image(comm);
    Some(net_event(now_ms(), pid, &image, daddr_be, dport_be))
}

/// openat access-mode + creation flags (Linux asm-generic UAPI — x86_64/aarch64/etc.).
const O_ACCMODE: u32 = 0o3;
const O_WRONLY: u32 = 0o1;
const O_RDWR: u32 = 0o2;
const O_CREAT: u32 = 0o100; // 0x40
const O_TRUNC: u32 = 0o1000; // 0x200

/// A "write intent" open = opened for writing (WRONLY/RDWR) or creating/truncating.
/// Read-only opens (O_RDONLY with no create/trunc) are NOT write intent.
/// NB: these flag VALUES are the asm-generic UAPI ones (correct for x86_64/aarch64,
/// the arches we build/run); a few arches (alpha/sparc/mips) renumber O_CREAT — out of scope.
fn is_write_open(flags: u32) -> bool {
    let acc = flags & O_ACCMODE;
    acc == O_WRONLY || acc == O_RDWR || (flags & O_CREAT) != 0 || (flags & O_TRUNC) != 0
}

/// Map one raw `FILE_EVENTS` record to a [`SubstrateEvent`] (`FileOpen`/`FileWrite`),
/// reusing the pure [`file_event`] mapper shared with the ETW backend.
///
/// Returns `None` (skip, never panic) for a truncated/malformed record, an
/// unrecognized `kind`, or an empty path. Field reads use `.get(..)?` +
/// `try_into().ok()?` at the canonical [`FileEvent`] offsets (the shared
/// `#[repr(C)]` layout is the single source of truth for both sides), so a short
/// buffer short-circuits instead of panicking.
///
/// - `kind` (the leading `u32`): only [`KIND_OPEN`] is understood in v0; any
///   other value is skipped.
/// - `image` is the Linux task **comm** (up to 16 bytes, NUL-trimmed).
/// - `path` is the `openat` filename: the [`PATH_CAP`]-byte buffer decoded to a
///   `String` at the first NUL (lossy UTF-8). It is TRUNCATED to ≤255 chars
///   in-kernel; an empty path → skip.
/// - `write` is decoded from the raw `openat` `flags` via [`is_write_open`]: a
///   write-intent open (WRONLY/RDWR/CREAT/TRUNC) emits `FileWrite`; a read-only
///   open emits `FileOpen`.
fn map_file_record(bytes: &[u8]) -> Option<SubstrateEvent> {
    if bytes.len() < core::mem::size_of::<FileEvent>() {
        return None;
    }
    let kind_off = core::mem::offset_of!(FileEvent, kind);
    let pid_off = core::mem::offset_of!(FileEvent, pid);
    let flags_off = core::mem::offset_of!(FileEvent, flags);
    let comm_off = core::mem::offset_of!(FileEvent, comm);
    let path_off = core::mem::offset_of!(FileEvent, path);

    let kind_raw = u32::from_ne_bytes(bytes.get(kind_off..kind_off + 4)?.try_into().ok()?);
    // Only the open kind is understood in v0; anything else → skip.
    if kind_raw != KIND_OPEN {
        return None;
    }

    let pid = u32::from_ne_bytes(bytes.get(pid_off..pid_off + 4)?.try_into().ok()?);
    let flags = u32::from_ne_bytes(bytes.get(flags_off..flags_off + 4)?.try_into().ok()?);
    let comm = bytes.get(comm_off..comm_off + 16)?;
    let path_bytes = bytes.get(path_off..path_off + PATH_CAP)?;

    let image = comm_to_image(comm);
    // Decode the NUL-terminated path buffer at the first NUL (lossy UTF-8).
    let end = path_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(path_bytes.len());
    let path = String::from_utf8_lossy(&path_bytes[..end]).into_owned();
    // An empty path carries no signal (and never comes from a real openat) → skip.
    if path.is_empty() {
        return None;
    }
    Some(file_event(
        now_ms(),
        pid,
        &image,
        &path,
        is_write_open(flags),
        None,
    ))
}

/// Decode the NUL-padded 16-byte task comm into a `String` (lossy UTF-8, trimmed
/// at the first NUL). This is the short process name, not a path.
fn comm_to_image(comm: &[u8]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..end]).into_owned()
}

/// Wall-clock milliseconds since the UNIX epoch, taken at drain time.
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl Drop for EbpfBus {
    fn drop(&mut self) {
        // Signal BOTH drain threads to stop, then join them (each bounded by
        // ~POLL_IDLE since it checks the flag once per cycle). Errors are ignored
        // — never panic in Drop. The `_ebpf` field auto-drops AFTER this returns,
        // detaching all the tracepoint programs.
        self.stop.store(true, Ordering::Relaxed);
        if let Some(poller) = self.poller.take() {
            let _ = poller.join();
        }
        if let Some(net_poller) = self.net_poller.take() {
            let _ = net_poller.join();
        }
        if let Some(file_poller) = self.file_poller.take() {
            let _ = file_poller.join();
        }
    }
}

impl EventBus for EbpfBus {
    fn publish(&self, ev: SubstrateEvent) {
        let _ = self.tx.send(ev); // ignore "no subscribers"
    }
    fn subscribe(&self, _kinds: &[EventKind]) -> broadcast::Receiver<SubstrateEvent> {
        // Real impl would filter by kind; forwards all for now (like StubBus).
        self.tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// Build a synthetic `ProcEvent` byte buffer: `kind` + `pid` + `ppid` +
    /// 16-byte `comm` (`#[repr(C)]`, native-endian), matching the shared layout.
    fn make_record(kind: u32, pid: u32, ppid: u32, comm: &[u8]) -> [u8; 28] {
        // 4 (kind) + 4 (pid) + 4 (ppid) + 16 (comm) = 28 bytes.
        let mut buf = [0u8; 28];
        buf[0..4].copy_from_slice(&kind.to_ne_bytes());
        buf[4..8].copy_from_slice(&pid.to_ne_bytes());
        buf[8..12].copy_from_slice(&ppid.to_ne_bytes());
        let n = comm.len().min(16);
        buf[12..12 + n].copy_from_slice(&comm[..n]);
        buf
    }

    /// The `kind` discriminant selects the event: `KIND_EXEC` → `ProcessExec`,
    /// `KIND_EXIT` → `ProcessExit`, any other value → `None` (skipped). pid +
    /// image are extracted for the valid kinds; a zero `ppid` is omitted and a
    /// non-zero one carried through. A too-short buffer → `None`, never panics.
    #[test]
    fn map_record_maps_both_kinds_and_skips() {
        // KIND_EXEC → ProcessExec; pid + image extracted; zero ppid omitted.
        let exec = make_record(KIND_EXEC, 4242, 0, b"bash");
        let ev = map_record(&exec).expect("well-formed exec record maps");
        assert_eq!(ev.kind, EventKind::ProcessExec);
        assert_eq!(ev.fields["pid"], 4242);
        assert_eq!(ev.fields["image"], "bash");
        let obj = ev.fields.as_object().unwrap();
        assert!(!obj.contains_key("ppid"), "zero ppid must be omitted");
        assert!(!obj.contains_key("cmdline"));

        // KIND_EXIT → ProcessExit; pid + image extracted; non-zero ppid carried.
        let exit = make_record(KIND_EXIT, 99, 7, b"echo");
        let ev = map_record(&exit).expect("well-formed exit record maps");
        assert_eq!(ev.kind, EventKind::ProcessExit);
        assert_eq!(ev.fields["pid"], 99);
        assert_eq!(ev.fields["image"], "echo");
        assert_eq!(ev.fields["ppid"], 7);

        // Unknown kind (99) → skipped, no event.
        let unknown = make_record(99, 1, 0, b"x");
        assert!(
            map_record(&unknown).is_none(),
            "unknown kind must be skipped"
        );

        // Truncated record -> skipped, no panic.
        assert!(map_record(&exec[..10]).is_none());
        assert!(map_record(&[]).is_none());
    }

    /// Build a synthetic `NetEvent` byte buffer: `kind` + `pid` + `daddr` +
    /// `dport` + `family` + 16-byte `comm` (`#[repr(C)]`, native-endian),
    /// matching the shared layout (4+4+4+2+2+16 = 32 bytes).
    fn make_net_record(
        kind: u32,
        pid: u32,
        daddr_be: u32,
        dport_be: u16,
        family: u16,
        comm: &[u8],
    ) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf[0..4].copy_from_slice(&kind.to_ne_bytes());
        buf[4..8].copy_from_slice(&pid.to_ne_bytes());
        buf[8..12].copy_from_slice(&daddr_be.to_ne_bytes());
        buf[12..14].copy_from_slice(&dport_be.to_ne_bytes());
        buf[14..16].copy_from_slice(&family.to_ne_bytes());
        let n = comm.len().min(16);
        buf[16..16 + n].copy_from_slice(&comm[..n]);
        buf
    }

    /// `map_net_record` maps a well-formed AF_INET connect record to a
    /// `NetConnect` event, converting the network-order dest addr/port to a
    /// dotted-quad + host-order port. Non-AF_INET / truncated → `None`, no panic.
    #[test]
    fn map_net_record_maps_connect_and_skips() {
        // daddr = 127.0.0.1 (network order 0x0100007F as read little-endian);
        // dport = 80 (network order 0x5000); family = AF_INET (2); comm = curl.
        let rec = make_net_record(KIND_CONNECT, 4242, 0x0100_007F, 0x5000, 2, b"curl");
        let ev = map_net_record(&rec).expect("well-formed connect record maps");
        assert_eq!(ev.kind, EventKind::NetConnect);
        assert_eq!(ev.fields["pid"], 4242);
        assert_eq!(ev.fields["image"], "curl");
        assert_eq!(ev.fields["daddr"], "127.0.0.1");
        assert_eq!(ev.fields["dport"], 80); // host order
        assert_eq!(ev.fields["proto"], "tcp");

        // Non-AF_INET family (e.g. AF_INET6 = 10) is dropped defensively.
        let v6 = make_net_record(KIND_CONNECT, 1, 0, 0, 10, b"x");
        assert!(map_net_record(&v6).is_none(), "non-AF_INET must be skipped");

        // Unknown kind → skipped.
        let bad_kind = make_net_record(99, 1, 0x0100_007F, 0x5000, 2, b"x");
        assert!(
            map_net_record(&bad_kind).is_none(),
            "unknown kind must be skipped"
        );

        // Truncated record → skipped, no panic.
        assert!(map_net_record(&rec[..20]).is_none());
        assert!(map_net_record(&[]).is_none());
    }

    /// Build a synthetic `FileEvent` byte buffer: `kind` + `pid` + `flags` +
    /// 16-byte `comm` + `PATH_CAP`-byte `path` (`#[repr(C)]`, native-endian),
    /// matching the shared layout (4+4+4+16+PATH_CAP bytes).
    fn make_file_record(kind: u32, pid: u32, flags: u32, comm: &[u8], path: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; core::mem::size_of::<FileEvent>()];
        buf[0..4].copy_from_slice(&kind.to_ne_bytes());
        buf[4..8].copy_from_slice(&pid.to_ne_bytes());
        buf[8..12].copy_from_slice(&flags.to_ne_bytes());
        let cn = comm.len().min(16);
        buf[12..12 + cn].copy_from_slice(&comm[..cn]);
        let pn = path.len().min(PATH_CAP);
        buf[28..28 + pn].copy_from_slice(&path[..pn]);
        buf
    }

    /// `map_file_record` maps a well-formed open record to a `FileOpen` event with
    /// pid + image + path + `op == "open"`. Unknown kind / truncated / empty path
    /// → `None`, no panic.
    #[test]
    fn map_file_record_maps_open_and_skips() {
        let rec = make_file_record(KIND_OPEN, 4242, 0, b"cat", b"/etc/passwd");
        let ev = map_file_record(&rec).expect("well-formed open record maps");
        assert_eq!(ev.kind, EventKind::FileOpen);
        assert_eq!(ev.fields["pid"], 4242);
        assert_eq!(ev.fields["image"], "cat");
        assert_eq!(ev.fields["path"], "/etc/passwd");
        assert_eq!(ev.fields["op"], "open");

        // Unknown kind → skipped.
        let bad_kind = make_file_record(99, 1, 0, b"x", b"/tmp/x");
        assert!(
            map_file_record(&bad_kind).is_none(),
            "unknown kind must be skipped"
        );

        // Empty path → skipped (carries no signal).
        let empty = make_file_record(KIND_OPEN, 1, 0, b"x", b"");
        assert!(
            map_file_record(&empty).is_none(),
            "empty path must be skipped"
        );

        // Truncated record → skipped, no panic.
        assert!(map_file_record(&rec[..20]).is_none());
        assert!(map_file_record(&[]).is_none());
    }

    /// `map_file_record` decodes the raw `openat` `flags` via [`is_write_open`]:
    /// a read-only open (`O_RDONLY` == 0, no create/trunc) → `FileOpen`/`op ==
    /// "open"`; a write-intent open (`O_WRONLY|O_CREAT`, `O_RDWR`, or a
    /// `O_TRUNC` open) → `FileWrite`/`op == "write"`.
    #[test]
    fn map_file_record_decodes_write_intent() {
        // O_RDONLY (0) → FileOpen.
        let rdonly = make_file_record(KIND_OPEN, 1, 0, b"cat", b"/etc/passwd");
        let ev = map_file_record(&rdonly).expect("well-formed record maps");
        assert_eq!(ev.kind, EventKind::FileOpen);
        assert_eq!(ev.fields["op"], "open");

        // O_WRONLY|O_CREAT → FileWrite.
        let wronly_creat = make_file_record(KIND_OPEN, 2, O_WRONLY | O_CREAT, b"vim", b"/tmp/a");
        let ev = map_file_record(&wronly_creat).expect("well-formed record maps");
        assert_eq!(ev.kind, EventKind::FileWrite);
        assert_eq!(ev.fields["op"], "write");

        // O_RDWR → FileWrite.
        let rdwr = make_file_record(KIND_OPEN, 3, O_RDWR, b"dd", b"/tmp/b");
        let ev = map_file_record(&rdwr).expect("well-formed record maps");
        assert_eq!(ev.kind, EventKind::FileWrite);
        assert_eq!(ev.fields["op"], "write");

        // O_RDONLY | O_TRUNC (truncation modifies, even without a write-mode
        // access flag) → FileWrite.
        let rdonly_trunc = make_file_record(KIND_OPEN, 4, O_TRUNC, b"tee", b"/tmp/c");
        let ev = map_file_record(&rdonly_trunc).expect("well-formed record maps");
        assert_eq!(ev.kind, EventKind::FileWrite);
        assert_eq!(ev.fields["op"], "write");
    }

    /// Pure unit test for [`is_write_open`], covering each branch directly.
    #[test]
    fn is_write_open_covers_all_branches() {
        assert!(!is_write_open(0), "O_RDONLY alone is not write intent");
        assert!(is_write_open(O_WRONLY), "O_WRONLY is write intent");
        assert!(is_write_open(O_RDWR), "O_RDWR is write intent");
        assert!(
            is_write_open(O_CREAT),
            "O_RDONLY|O_CREAT is write intent (creation)"
        );
        assert!(
            is_write_open(O_TRUNC),
            "O_RDONLY|O_TRUNC is write intent (truncation)"
        );
    }

    /// NON-root fail-soft: `try_start` must return promptly (never hang) — and on
    /// an unprivileged host it returns `Err` (`EPERM`), which makes the platform
    /// factory fall back to a usable `StubBus` (`bus_label == "stub"`) with no
    /// panic. On a root/`CAP_BPF` host (Task 3) it may instead return `Ok`; that
    /// path yields `bus_label == "ebpf"` and is torn down cleanly here.
    #[test]
    fn try_start_is_fail_soft_when_not_root() {
        let start = Instant::now();
        let res = EbpfBus::try_start();
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "try_start must return promptly, not hang"
        );
        match res {
            Err(_) => {
                // Expected unprivileged path: the factory falls back to stub.
                let sub = crate::Substrate::for_this_platform();
                assert_eq!(
                    sub.bus_label, "stub",
                    "non-root run must fall back to the stub bus"
                );
                // Usable: subscribe / publish / receive round-trips.
                let mut rx = sub.bus.subscribe(&[EventKind::ProcessExec]);
                sub.bus.publish(SubstrateEvent {
                    kind: EventKind::ProcessExec,
                    ts: 1,
                    fields: serde_json::json!({ "pid": 1 }),
                });
                let ev = rx.try_recv().expect("stub fallback delivers events");
                assert_eq!(ev.kind, EventKind::ProcessExec);
            }
            Ok(bus) => {
                // Root host: exercise Drop (stop + join) on a live session.
                drop(bus);
            }
        }
    }
}
