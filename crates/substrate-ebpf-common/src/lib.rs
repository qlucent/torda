//! Shared, `no_std` wire types for the Linux eBPF substrate.
//!
//! This crate is the single source of truth for the memory layout of events
//! that cross the kernel/userspace boundary through an aya ring buffer. Both the
//! kernel-side eBPF program ([`torda-substrate-ebpf`]) and the userspace `EbpfBus`
//! loader (behind the `linux-ebpf` feature on `torda-substrate`) depend on this
//! crate, so the `#[repr(C)]` layout is identical on both sides.
//!
//! It is `no_std` so it can be linked into the BPF object; the userspace loader
//! turns on the `user` feature to get an `aya::Pod` impl for zero-copy reads.
#![no_std]

/// A [`ProcEvent`] with `kind == KIND_EXEC`: emitted by the `sched_process_exec`
/// tracepoint on every successful `execve`.
pub const KIND_EXEC: u32 = 0;
/// A [`ProcEvent`] with `kind == KIND_EXIT`: emitted by the `sched_process_exit`
/// tracepoint when a task exits.
pub const KIND_EXIT: u32 = 1;

/// One process-lifecycle observation, pushed onto the ring buffer by the kernel
/// program and read verbatim by the userspace loader. A single struct carries
/// BOTH `sched_process_exec` and `sched_process_exit` records; the leading
/// [`kind`](Self::kind) field discriminates them ([`KIND_EXEC`] / [`KIND_EXIT`]).
///
/// `#[repr(C)]` pins the field order/layout so both sides agree byte-for-byte.
/// Fields are cheap to obtain in-kernel:
/// - `kind`: `KIND_EXEC` (exec tracepoint) or `KIND_EXIT` (exit tracepoint).
/// - `pid`: the process (thread-group) id, `bpf_get_current_pid_tgid() >> 32`.
/// - `comm`: the 16-byte task command name, `bpf_get_current_comm()`.
/// - `ppid`: parent pid. Populating it requires a `task_struct` traversal
///   (CO-RE), which is deliberately deferred; the kernel program currently sets
///   it to `0`. The field exists now so the wire layout is stable.
///
/// Layout note: `kind` was added as a leading field so exec and exit events
/// share one ring-buffer struct; every other field's offset shifted by 4 bytes.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ProcEvent {
    /// Event discriminant: [`KIND_EXEC`] or [`KIND_EXIT`].
    pub kind: u32,
    /// Process (thread-group) id.
    pub pid: u32,
    /// Parent process id (currently `0` until CO-RE parent lookup lands).
    pub ppid: u32,
    /// Task command name (`TASK_COMM_LEN` = 16 bytes, NUL-padded).
    pub comm: [u8; 16],
}

// SAFETY: `ProcEvent` is `#[repr(C)]` and contains only integer/array POD
// fields with no padding-sensitive invariants, so the userspace loader may read
// it directly out of the ring buffer. Only compiled for the userspace side.
#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcEvent {}

/// A [`NetEvent`] with `kind == KIND_CONNECT`: emitted by the
/// `syscalls:sys_enter_connect` tracepoint when a task calls `connect(2)` with
/// an AF_INET (IPv4) destination. This captures connect INTENT (the syscall
/// entry), not connection establishment.
pub const KIND_CONNECT: u32 = 0;

/// One outbound network-connect observation, pushed onto the *separate*
/// `NET_EVENTS` ring buffer by the kernel program and read verbatim by the
/// userspace loader. It is a DISTINCT wire struct from [`ProcEvent`]: the two
/// sensor classes never share a ring buffer or a layout.
///
/// `#[repr(C)]` pins the field order/layout so both sides agree byte-for-byte.
///
/// ## Byte order (IMPORTANT)
/// [`daddr`](Self::daddr) and [`dport`](Self::dport) are copied straight out of
/// the user-space `sockaddr_in` via `bpf_probe_read_user`, so they retain the
/// wire/NETWORK byte order the kernel stores (`sin_addr.s_addr` and `sin_port`
/// are big-endian). The userspace mapper is responsible for converting them to a
/// dotted-quad string and a HOST-order port (`u16::from_be`). The kernel side
/// does NO byte-swapping.
///
/// Fields are cheap to obtain in-kernel:
/// - `kind`: always [`KIND_CONNECT`] in v0 (the discriminant field mirrors
///   [`ProcEvent`] so the layout is forward-compatible with future net kinds).
/// - `pid`: the process (thread-group) id, `bpf_get_current_pid_tgid() >> 32`.
/// - `daddr`: IPv4 destination address, NETWORK byte order (`sin_addr.s_addr`).
/// - `dport`: destination port, NETWORK byte order (`sin_port`).
/// - `family`: address family; always `AF_INET` (2) in v0 (non-AF_INET is
///   dropped in-kernel), carried so userspace can defensively re-check it.
/// - `comm`: the 16-byte task command name, `bpf_get_current_comm()`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct NetEvent {
    /// Event discriminant: [`KIND_CONNECT`].
    pub kind: u32,
    /// Process (thread-group) id.
    pub pid: u32,
    /// IPv4 destination address, NETWORK byte order (`sockaddr_in.sin_addr.s_addr`).
    pub daddr: u32,
    /// Destination port, NETWORK byte order (`sockaddr_in.sin_port`).
    pub dport: u16,
    /// Address family; `AF_INET` (2) in v0.
    pub family: u16,
    /// Task command name (`TASK_COMM_LEN` = 16 bytes, NUL-padded).
    pub comm: [u8; 16],
}

// SAFETY: `NetEvent` is `#[repr(C)]` and contains only integer/array POD fields
// with no padding-sensitive invariants (the u16 pair sits on a natural 4-byte
// boundary, so there is no interior padding), so the userspace loader may read
// it directly out of the ring buffer. Only compiled for the userspace side.
#[cfg(feature = "user")]
unsafe impl aya::Pod for NetEvent {}

/// A [`FileEvent`] with `kind == KIND_OPEN`: emitted by the
/// `syscalls:sys_enter_openat` tracepoint when a task calls `openat(2)`. This
/// captures open INTENT (the syscall entry), not a successful open or a specific
/// access mode.
pub const KIND_OPEN: u32 = 0;

/// Maximum captured length of the `openat(2)` filename, including the trailing
/// NUL, in [`FileEvent::path`]. Paths longer than this are TRUNCATED in-kernel
/// (`bpf_probe_read_user_str_bytes` bounds the copy to the buffer). 256 bytes is
/// large enough for the vast majority of real paths while keeping the wire record
/// small on the high-volume `openat` stream.
pub const PATH_CAP: usize = 256;

/// One file-open observation, pushed onto the *separate* `FILE_EVENTS` ring
/// buffer by the kernel program and read verbatim by the userspace loader. It is
/// a DISTINCT wire struct from [`ProcEvent`]/[`NetEvent`]: the three sensor
/// classes never share a ring buffer or a layout.
///
/// `#[repr(C)]` pins the field order/layout so both sides agree byte-for-byte.
/// The struct is 284 bytes and padding-free: `kind`/`pid`/`flags` are three
/// `u32`s (12 bytes), followed by the 16-byte `comm` and the [`PATH_CAP`]-byte
/// `path`, all naturally aligned with no interior gaps.
///
/// Fields are cheap to obtain in-kernel:
/// - `kind`: always [`KIND_OPEN`] in v0 (the discriminant field mirrors
///   [`ProcEvent`]/[`NetEvent`] so the layout is forward-compatible).
/// - `pid`: the process (thread-group) id, `bpf_get_current_pid_tgid() >> 32`.
/// - `flags`: the `openat(2)` `flags` argument (e.g. `O_RDONLY`/`O_WRONLY`),
///   copied verbatim; the userspace mapper does not interpret it in v0.
/// - `comm`: the 16-byte task command name, `bpf_get_current_comm()`.
/// - `path`: the `openat` filename, copied from USER memory via
///   `bpf_probe_read_user_str_bytes` into a fixed [`PATH_CAP`]-byte buffer
///   (NUL-terminated, TRUNCATED to fit). Trailing bytes past the NUL are unset.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FileEvent {
    /// Event discriminant: [`KIND_OPEN`].
    pub kind: u32,
    /// Process (thread-group) id.
    pub pid: u32,
    /// The `openat(2)` `flags` argument, copied verbatim (uninterpreted in v0).
    pub flags: u32,
    /// Task command name (`TASK_COMM_LEN` = 16 bytes, NUL-padded).
    pub comm: [u8; 16],
    /// The `openat` filename, NUL-terminated + truncated to [`PATH_CAP`] bytes.
    pub path: [u8; PATH_CAP],
}

// SAFETY: `FileEvent` is `#[repr(C)]` and contains only integer/array POD fields
// with no padding-sensitive invariants (three leading u32s then two byte arrays,
// all naturally aligned, no interior padding), so the userspace loader may read
// it directly out of the ring buffer. Only compiled for the userspace side.
#[cfg(feature = "user")]
unsafe impl aya::Pod for FileEvent {}
