//! Kernel-side eBPF program for the Linux substrate.
//!
//! THREE independent sensor classes, each with its OWN ring buffer and wire struct:
//!
//! Process lifecycle (`EVENTS` ring, [`ProcEvent`], discriminated by `kind`):
//! - `sched_process_exec`: on every successful `execve`, emits a `KIND_EXEC`
//!   record (pid + comm from cheap BPF helpers).
//! - `sched_process_exit`: when a task exits, emits a `KIND_EXIT` record
//!   (pid + comm; exit code deferred).
//!
//! Network connect intent (`NET_EVENTS` ring, [`NetEvent`]):
//! - `sys_enter_connect`: on `connect(2)` entry, reads the user `sockaddr`; for
//!   AF_INET (IPv4) it emits a `KIND_CONNECT` record (pid + comm + dest IP/port,
//!   both in NETWORK byte order). Non-AF_INET destinations are dropped in-kernel.
//!   This is CO-RE-free: it reads the syscall's user `sockaddr` argument via
//!   `bpf_probe_read_user`, never a `struct sock` field.
//!
//! File open intent (`FILE_EVENTS` ring, [`FileEvent`]):
//! - `sys_enter_openat`: on `openat(2)` entry, reads the user `filename` and
//!   `flags` args and emits a `KIND_OPEN` record (pid + comm + path, truncated to
//!   `PATH_CAP`). CO-RE-free (reads the syscall's user `filename` argument via
//!   `bpf_probe_read_user_str_bytes`, never a `struct file` field). High-volume.
//!
//! The userspace `EbpfBus` loader (behind `torda-substrate`'s `linux-ebpf`
//! feature) drains all three maps and republishes the events onto the shared
//! `EventBus` as `ProcessExec` / `ProcessExit` / `NetConnect` / `FileOpen`.
//!
//! Builds ONLY for `bpfel-unknown-none` (see `.cargo/config.toml`); it is
//! `no_std`/`no_main` and excluded from the workspace, so the host build never
//! compiles it.
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use torda_substrate_ebpf_common::{
    FileEvent, NetEvent, ProcEvent, KIND_CONNECT, KIND_EXEC, KIND_EXIT, KIND_OPEN, PATH_CAP,
};

/// `AF_INET` (IPv4). The only address family captured in v0; every other family
/// is dropped in-kernel.
const AF_INET: u16 = 2;

/// Byte offset of the 2nd `connect(2)` argument (`struct sockaddr __user *
/// uservaddr`) within the `syscalls:sys_enter_connect` tracepoint format:
/// common fields (8) + `__syscall_nr` padded (8) + arg0 `fd` (8) = 24. Syscall
/// enter tracepoints store each arg as an 8-byte slot starting at offset 16.
const CONNECT_USERVADDR_OFF: usize = 24;

/// Byte offset of the 2nd `openat(2)` argument (`const char __user *filename`)
/// within the `syscalls:sys_enter_openat` tracepoint format:
/// `openat(int dfd@16, const char __user *filename@24, int flags@32,
/// umode_t mode@40)`. Syscall-enter tracepoints store each arg as an 8-byte slot
/// starting at offset 16, so `filename` (arg1) sits at 24 — matching
/// [`CONNECT_USERVADDR_OFF`].
const OPENAT_FILENAME_OFF: usize = 24;

/// Byte offset of the 3rd `openat(2)` argument (`int flags`) within the
/// `syscalls:sys_enter_openat` tracepoint format (arg2 = offset 16 + 2*8 = 32).
const OPENAT_FLAGS_OFF: usize = 32;

/// Ring buffer carrying [`ProcEvent`]s to userspace. 256 KiB (a power-of-2
/// multiple of the page size, as the kernel requires). Shared by BOTH the exec
/// and exit tracepoints.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Ring buffer carrying [`NetEvent`]s to userspace. A SEPARATE 256 KiB ring from
/// [`EVENTS`]: the network sensor never shares the process ring or its layout.
#[map]
static NET_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Ring buffer carrying [`FileEvent`]s to userspace. A SEPARATE 256 KiB ring from
/// [`EVENTS`]/[`NET_EVENTS`]: the file sensor never shares another ring or layout.
#[map]
static FILE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// `sched_process_exec` tracepoint entry point. Returns 0 on success; a non-zero
/// return only means "we dropped this event" (e.g. ring full) and never fails
/// the exec.
#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    match try_sched_process_exec(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sched_process_exec(_ctx: TracePointContext) -> Result<u32, u32> {
    emit(KIND_EXEC)
}

/// `sched_process_exit` tracepoint entry point. Same contract as the exec
/// handler: 0 on success, non-zero only signals a dropped event.
#[tracepoint]
pub fn sched_process_exit(ctx: TracePointContext) -> u32 {
    match try_sched_process_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sched_process_exit(_ctx: TracePointContext) -> Result<u32, u32> {
    emit(KIND_EXIT)
}

/// Reserve a [`ProcEvent`] on the shared ring buffer, fill pid + comm from cheap
/// BPF helpers, tag it with `kind`, and submit. Returns `Err(1)` (dropped) if
/// the ring is full. Both tracepoints funnel through here so they stay in sync.
fn emit(kind: u32) -> Result<u32, u32> {
    // Reserve space in the ring buffer; if it is full, drop this event.
    let mut entry = match EVENTS.reserve::<ProcEvent>(0) {
        Some(entry) => entry,
        None => return Err(1),
    };

    // pid = thread-group id (the userspace-visible PID) = high 32 bits.
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    // 16-byte task command name; fall back to zeros if the helper fails.
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    entry.write(ProcEvent {
        kind,
        pid,
        // ppid requires a task_struct/CO-RE traversal; deferred (see the common
        // crate). Kept zero so the wire layout is stable for the loader.
        ppid: 0,
        comm,
    });
    entry.submit(0);
    Ok(0)
}

/// `syscalls:sys_enter_connect` tracepoint entry point. Same drop-not-fail
/// contract as the process handlers: it is observational, so any non-zero return
/// only means "we dropped this event" and never affects the `connect(2)` call.
#[tracepoint]
pub fn sys_enter_connect(ctx: TracePointContext) -> u32 {
    match try_sys_enter_connect(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// Read the `connect(2)` user `sockaddr`, and for an AF_INET destination push a
/// [`NetEvent`] onto [`NET_EVENTS`]. CO-RE-free: only the syscall's user pointer
/// argument is read, via `bpf_probe_read_user`, never a kernel `struct sock`.
///
/// Bounded + panic-free: it reads exactly the bytes it needs (family `u16`, then
/// port `u16` + addr `u32` for AF_INET). A bad user pointer or a non-AF_INET
/// family short-circuits with a drop. Ring full → `Err(1)` (dropped), never a
/// syscall failure.
fn try_sys_enter_connect(ctx: TracePointContext) -> Result<u32, u32> {
    // The 2nd connect arg: `struct sockaddr __user *uservaddr`. `read_at` pulls
    // the pointer VALUE out of the tracepoint format buffer (kernel memory).
    let uservaddr: u64 = unsafe { ctx.read_at(CONNECT_USERVADDR_OFF).map_err(|_| 1u32)? };
    if uservaddr == 0 {
        // NULL sockaddr (malformed call) → nothing to read; drop.
        return Ok(0);
    }
    let base = uservaddr as usize;

    // Read ONLY the leading `sa_family` (u16) from USER memory first. A
    // non-AF_INET destination (AF_INET6, AF_UNIX, ...) is dropped in-kernel so
    // userspace only ever sees IPv4 records in v0.
    let family: u16 = unsafe { bpf_probe_read_user(base as *const u16).map_err(|_| 1u32)? };
    if family != AF_INET {
        return Ok(0);
    }

    // AF_INET `sockaddr_in`: `sin_port` (u16, net order) at +2, `sin_addr.s_addr`
    // (u32, net order) at +4. Copied verbatim — NO byte-swapping here; userspace
    // converts (see `NetEvent` docs).
    let dport: u16 = unsafe { bpf_probe_read_user((base + 2) as *const u16).map_err(|_| 1u32)? };
    let daddr: u32 = unsafe { bpf_probe_read_user((base + 4) as *const u32).map_err(|_| 1u32)? };

    // Reserve space in the SEPARATE network ring; if it is full, drop this event.
    let mut entry = match NET_EVENTS.reserve::<NetEvent>(0) {
        Some(entry) => entry,
        None => return Err(1),
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    entry.write(NetEvent {
        kind: KIND_CONNECT,
        pid,
        daddr,
        dport,
        family,
        comm,
    });
    entry.submit(0);
    Ok(0)
}

/// `syscalls:sys_enter_openat` tracepoint entry point. Same drop-not-fail
/// contract as the other handlers: it is observational, so any non-zero return
/// only means "we dropped this event" and never affects the `openat(2)` call.
#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    match try_sys_enter_openat(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// Read the `openat(2)` user `filename` + `flags` and push a [`FileEvent`] onto
/// [`FILE_EVENTS`]. CO-RE-free: only the syscall's user pointer/scalar arguments
/// are read (the filename via `bpf_probe_read_user_str_bytes`), never a kernel
/// `struct file`/`path`.
///
/// Bounded + panic-free: the filename is copied into a fixed [`PATH_CAP`]-byte
/// buffer (NUL-terminated + truncated by the helper). A NULL or unreadable
/// filename pointer short-circuits with a drop (no pathless record is emitted).
/// Ring full → `Err(1)` (dropped), never a syscall failure.
fn try_sys_enter_openat(ctx: TracePointContext) -> Result<u32, u32> {
    // The 2nd openat arg: `const char __user *filename`. `read_at` pulls the
    // pointer VALUE out of the tracepoint format buffer (kernel memory).
    let filename_ptr: u64 = unsafe { ctx.read_at(OPENAT_FILENAME_OFF).map_err(|_| 1u32)? };
    if filename_ptr == 0 {
        // NULL filename (malformed call) → nothing to read; drop.
        return Ok(0);
    }
    // The 3rd openat arg: `int flags`. Best-effort — a read failure just yields 0.
    let flags: u64 = unsafe { ctx.read_at(OPENAT_FLAGS_OFF) }.unwrap_or(0);

    // Reserve space in the SEPARATE file ring; if it is full, drop this event.
    // The reservation must stay BEFORE the path read (rather than mirroring the
    // connect handler's read-then-reserve shape): the ~280-byte `FileEvent`
    // carries a PATH_CAP buffer, and reserving first lets the compiler build the
    // event in-place in the ring entry. Reserving after the read would force the
    // `path` local and a separate `FileEvent` temporary to coexist on the stack,
    // blowing the 512-byte BPF stack limit at codegen time.
    let mut entry = match FILE_EVENTS.reserve::<FileEvent>(0) {
        Some(entry) => entry,
        None => return Err(1),
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    // Copy the filename from USER memory into a fixed buffer. The helper
    // NUL-terminates and bounds the copy to the buffer (TRUNCATING longer paths),
    // so this is bounded and panic-free. On a bad user pointer we MUST
    // `entry.discard(0)` before returning: an `aya_ebpf` `RingBufEntry` is NOT
    // auto-discarded on drop, so a bare `return` would leave the reserved entry
    // neither submitted nor discarded — which the BPF verifier rejects at load
    // ("Unreleased reference id"). Discard releases it (no pathless record sent).
    let mut path = [0u8; PATH_CAP];
    if unsafe { bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut path) }.is_err() {
        entry.discard(0);
        return Ok(0);
    }

    entry.write(FileEvent {
        kind: KIND_OPEN,
        pid,
        flags: flags as u32,
        comm,
        path,
    });
    entry.submit(0);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// The kernel refuses to load a BPF program without a GPL-compatible license
/// declaration when it uses GPL-only helpers.
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
