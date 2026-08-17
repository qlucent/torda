//! # torda-transport — the swappable carrier under the P3b control channel
//!
//! This crate provides a **byte-level, message-framed, bidirectional transport
//! seam**. It is deliberately *domain-agnostic*: it knows nothing about
//! remediation, OCSF, commands, or results. It moves **opaque frames** — a frame
//! is just a `Vec<u8>` — and guarantees that one logical message goes in and the
//! same logical message comes out the other end, with frame boundaries preserved.
//!
//! ## The seam
//!
//! The P3b control channel is layered:
//!
//! ```text
//!   control-channel loop   (domain: signed commands / results)   <- built later
//!   ------------------------------------------------------------
//!   Transport trait        (this crate: opaque, framed bytes)    <- the seam
//!   ------------------------------------------------------------
//!   carrier impl           DuplexTransport (in-memory, tests)
//!                          mTLS socket      (P3b-7, real network)
//! ```
//!
//! Callers depend only on the [`Transport`] trait, so the in-memory
//! [`DuplexTransport`] used by tests/demos can later be swapped for a real mTLS
//! socket without any change above the seam. The domain (what the bytes *mean*)
//! lives entirely above this crate.
//!
//! ## Framing
//!
//! A carrier such as a TCP/TLS stream delivers a byte *stream*, not messages, so
//! frame boundaries would be lost. To keep them, every frame is length-delimited:
//! a `u32` big-endian length prefix followed by exactly that many payload bytes
//! (see [`encode_frame`] / [`decode_frame`]). A cap of [`MAX_FRAME_LEN`] bytes is
//! enforced so a hostile or corrupt length prefix cannot force a huge allocation.
//!
//! No clock, no randomness, no threads, no network — the in-memory pieces are
//! fully deterministic and single-threaded, which makes tests reproducible.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{Error, ErrorKind, Result};
use std::rc::Rc;

/// Number of bytes in the length prefix that precedes each frame's payload.
const LEN_PREFIX: usize = 4;

/// Maximum payload size, in bytes, that framing will encode or decode.
///
/// A generous but bounded cap (16 MiB). It exists purely as a safety valve: a
/// length prefix larger than this is rejected *before* any allocation, so a
/// corrupt or hostile prefix (e.g. `0xFFFF_FFFF`) can never trick a peer into
/// reserving gigabytes of memory. Chosen well above any realistic control-channel
/// message yet far below values that would threaten process memory.
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// A bidirectional, message-framed byte channel. One `send` delivers exactly one
/// frame; one `recv` yields exactly one whole frame, or `None` when the peer has
/// closed and no more frames remain. Domain-agnostic: frames are opaque bytes.
/// Implementations: an in-memory [`DuplexTransport`] (tests/demo) and, later, an
/// mTLS socket (P3b-7) — callers depend only on this trait.
pub trait Transport {
    /// Deliver exactly one `frame` to the peer. The frame is opaque; its bytes
    /// are transmitted verbatim and will surface as one whole frame from the
    /// peer's [`recv`](Transport::recv). Returns an error if the frame exceeds
    /// [`MAX_FRAME_LEN`] or the underlying carrier fails.
    fn send(&mut self, frame: &[u8]) -> Result<()>;

    /// Yield exactly one whole frame, or `None` when the peer has closed and no
    /// buffered frames remain. Never returns a partial frame. Implementations
    /// must not panic on truncated or hostile input.
    fn recv(&mut self) -> Result<Option<Vec<u8>>>;
}

/// Encode `payload` as a length-delimited frame: a `u32` big-endian length prefix
/// followed by the payload bytes, i.e. `len(u32 BE) || payload`.
///
/// Returns an [`ErrorKind::InvalidInput`] error if `payload` is longer than
/// [`MAX_FRAME_LEN`] (which also guarantees it fits in a `u32`), so an oversized
/// message is rejected at the sender rather than producing a frame the peer would
/// refuse to decode.
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > MAX_FRAME_LEN {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "frame payload exceeds MAX_FRAME_LEN",
        ));
    }
    // Length fits in u32 because MAX_FRAME_LEN <= u32::MAX.
    let len = payload.len() as u32;
    let mut out = Vec::with_capacity(LEN_PREFIX + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Try to remove and return one whole frame from the front of `buf`.
///
/// Semantics — panic-free on any input, including truncated or garbage bytes:
/// - **Full frame present:** the length prefix and its payload are removed from
///   the front of `buf` and the payload is returned as `Ok(Some(payload))`. Any
///   trailing bytes (e.g. the start of a following frame) are left in `buf`.
/// - **Partial frame:** fewer than `LEN_PREFIX` bytes, or a valid prefix but not
///   yet all its payload bytes, returns `Ok(None)` and leaves `buf` **unchanged**
///   so the caller can retry once more bytes have arrived.
/// - **Hostile / oversized prefix:** a length prefix greater than
///   [`MAX_FRAME_LEN`] returns an [`ErrorKind::InvalidData`] error **without
///   allocating** the claimed size and without consuming `buf`.
pub fn decode_frame(buf: &mut Vec<u8>) -> Result<Option<Vec<u8>>> {
    // Not enough bytes to even read the length prefix yet — wait for more.
    if buf.len() < LEN_PREFIX {
        return Ok(None);
    }

    // Read the big-endian length prefix. Indexing 0..4 is safe: len >= LEN_PREFIX.
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

    // Reject a hostile/corrupt length BEFORE reserving anything.
    if len > MAX_FRAME_LEN {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "frame length prefix exceeds MAX_FRAME_LEN",
        ));
    }

    // Full frame = prefix + payload. If not all bytes are present, wait; leave
    // `buf` intact. `checked_add` avoids any theoretical overflow (len is capped,
    // so it cannot actually overflow, but stay defensive).
    let need = match LEN_PREFIX.checked_add(len) {
        Some(n) => n,
        None => return Err(Error::new(ErrorKind::InvalidData, "frame length overflow")),
    };
    if buf.len() < need {
        return Ok(None);
    }

    // Extract the payload and remove `need` bytes from the front of `buf`,
    // preserving any trailing bytes for the next call.
    let payload = buf[LEN_PREFIX..need].to_vec();
    buf.drain(..need);
    Ok(Some(payload))
}

/// One end of an in-memory, paired [`Transport`] created by [`DuplexTransport::pair`].
///
/// The two ends share two frame queues crosswise: bytes this end `send`s become
/// readable by the other end's `recv`, and vice-versa. It is fully deterministic,
/// single-threaded, and free of clocks, randomness, and locks-under-contention —
/// ideal for driving both sides from one test thread.
///
/// ## `recv` "none" semantics
///
/// `recv` returns:
/// - `Ok(Some(frame))` while the inbound queue holds at least one whole frame;
/// - `Ok(None)` when the inbound queue is empty. This covers **both** "empty but
///   the peer is still open" and "peer dropped/closed and drained" — callers that
///   need to distinguish end-of-stream can consult [`peer_closed`](DuplexTransport::peer_closed).
///
/// Because outgoing bytes are framed with [`encode_frame`] and incoming bytes are
/// de-framed with [`decode_frame`], the in-memory path exercises exactly the same
/// framing a real stream carrier would.
pub struct DuplexTransport {
    /// Frame-byte queue this end reads from (the peer writes into it).
    inbound: Rc<RefCell<Channel>>,
    /// Frame-byte queue this end writes into (the peer reads from it).
    outbound: Rc<RefCell<Channel>>,
    /// Reassembly buffer for bytes pulled off `inbound` but not yet a full frame.
    rx: Vec<u8>,
}

/// A shared, single-direction byte channel: a FIFO of byte chunks plus an
/// `open` flag that flips to `false` when the writing end is dropped.
struct Channel {
    /// Byte chunks written by the producer, consumed in order by the reader.
    bytes: VecDeque<Vec<u8>>,
    /// `true` while the writing end is alive; set to `false` when it is dropped.
    open: bool,
}

impl Channel {
    fn new() -> Self {
        Channel {
            bytes: VecDeque::new(),
            open: true,
        }
    }
}

impl DuplexTransport {
    /// Create a connected pair of endpoints. Each returned value is one end of the
    /// same in-memory link: `a.send(x)` makes `x` available to `b.recv()`, and
    /// `b.send(y)` makes `y` available to `a.recv()`.
    pub fn pair() -> (DuplexTransport, DuplexTransport) {
        let a_to_b = Rc::new(RefCell::new(Channel::new()));
        let b_to_a = Rc::new(RefCell::new(Channel::new()));

        let a = DuplexTransport {
            inbound: Rc::clone(&b_to_a),
            outbound: Rc::clone(&a_to_b),
            rx: Vec::new(),
        };
        let b = DuplexTransport {
            inbound: Rc::clone(&a_to_b),
            outbound: Rc::clone(&b_to_a),
            rx: Vec::new(),
        };
        (a, b)
    }

    /// Returns `true` once the peer end has been dropped, meaning no further
    /// frames can ever arrive. Combined with a `recv` of `Ok(None)`, this signals
    /// a true end-of-stream versus a merely-empty-but-open channel.
    pub fn peer_closed(&self) -> bool {
        !self.inbound.borrow().open
    }

    /// Drain any newly available bytes from the shared inbound channel into the
    /// local reassembly buffer, then try to pop one whole frame.
    fn pull_frame(&mut self) -> Result<Option<Vec<u8>>> {
        // Move all currently queued chunks into the reassembly buffer.
        {
            let mut chan = self.inbound.borrow_mut();
            while let Some(chunk) = chan.bytes.pop_front() {
                self.rx.extend_from_slice(&chunk);
            }
        }
        decode_frame(&mut self.rx)
    }
}

impl Transport for DuplexTransport {
    fn send(&mut self, frame: &[u8]) -> Result<()> {
        let encoded = encode_frame(frame)?;
        // Detect a dropped *receiver* by reader-liveness. The outbound channel is
        // shared by exactly two `Rc`s: this endpoint (the writer) and the peer
        // (its reader). A `strong_count` of 1 means only this endpoint remains —
        // the reader has been dropped — so the frame would go to no one. The
        // channel's `open` flag reflects the *writer's* liveness (set in `Drop`),
        // not the reader's, so it cannot answer this question; the count can.
        if Rc::strong_count(&self.outbound) == 1 {
            return Err(Error::new(
                ErrorKind::BrokenPipe,
                "peer receiver has closed",
            ));
        }
        self.outbound.borrow_mut().bytes.push_back(encoded);
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<Vec<u8>>> {
        self.pull_frame()
    }
}

impl Drop for DuplexTransport {
    fn drop(&mut self) {
        // Mark the channel we write into as closed so the peer's `recv`/`peer_closed`
        // can observe end-of-stream. This does not touch buffered-but-unread bytes.
        self.outbound.borrow_mut().open = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trips_byte_identically() {
        let msg = b"hello, opaque frame".to_vec();
        let mut buf = encode_frame(&msg).unwrap();
        let out = decode_frame(&mut buf).unwrap();
        assert_eq!(out, Some(msg));
        assert!(buf.is_empty(), "buffer fully consumed");
    }

    #[test]
    fn frame_round_trips_empty_payload() {
        // A zero-length payload is a valid frame (just the length prefix).
        let mut buf = encode_frame(&[]).unwrap();
        assert_eq!(buf.len(), LEN_PREFIX);
        assert_eq!(decode_frame(&mut buf).unwrap(), Some(Vec::new()));
    }

    #[test]
    fn two_back_to_back_frames_decode_separately() {
        let m1 = b"first".to_vec();
        let m2 = b"second frame".to_vec();
        let mut buf = encode_frame(&m1).unwrap();
        buf.extend_from_slice(&encode_frame(&m2).unwrap());

        assert_eq!(decode_frame(&mut buf).unwrap(), Some(m1));
        assert_eq!(decode_frame(&mut buf).unwrap(), Some(m2));
        assert_eq!(decode_frame(&mut buf).unwrap(), None);
    }

    #[test]
    fn a_truncated_frame_yields_none_without_consuming() {
        // Length prefix says 10 bytes, but only 3 payload bytes are present.
        let mut buf = 10u32.to_be_bytes().to_vec();
        buf.extend_from_slice(&[1, 2, 3]);
        let before = buf.clone();

        assert_eq!(decode_frame(&mut buf).unwrap(), None);
        assert_eq!(buf, before, "partial frame left intact for retry");

        // A prefix shorter than 4 bytes is also just "not enough yet".
        let mut tiny = vec![0u8, 0u8];
        let tiny_before = tiny.clone();
        assert_eq!(decode_frame(&mut tiny).unwrap(), None);
        assert_eq!(tiny, tiny_before);
    }

    #[test]
    fn a_garbage_or_oversized_length_prefix_errors_without_allocating() {
        // 0xFFFF_FFFF bytes claimed — far above the cap. Must error, not allocate.
        let mut buf = 0xFFFF_FFFFu32.to_be_bytes().to_vec();
        buf.extend_from_slice(b"only a few real bytes");
        let err = decode_frame(&mut buf).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);

        // Exactly one over the cap also errors.
        let mut over = ((MAX_FRAME_LEN as u32) + 1).to_be_bytes().to_vec();
        assert!(decode_frame(&mut over).is_err());
    }

    #[test]
    fn encode_rejects_payload_over_the_cap() {
        // The cap must fit in a u32 so an encoded length prefix is always valid.
        assert!(MAX_FRAME_LEN as u64 <= u32::MAX as u64);
        // A payload one byte over the cap is rejected before framing.
        let too_big = vec![0u8; MAX_FRAME_LEN + 1];
        let err = encode_frame(&too_big).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        // A payload exactly at the cap is accepted.
        let at_cap = vec![0u8; MAX_FRAME_LEN];
        assert!(encode_frame(&at_cap).is_ok());
    }

    #[test]
    fn duplex_passes_frames_both_directions() {
        let (mut a, mut b) = DuplexTransport::pair();
        let m1 = b"a -> b".to_vec();
        let m2 = b"b -> a".to_vec();

        a.send(&m1).unwrap();
        assert_eq!(b.recv().unwrap(), Some(m1));

        b.send(&m2).unwrap();
        assert_eq!(a.recv().unwrap(), Some(m2));
    }

    #[test]
    fn duplex_preserves_frame_boundaries_across_multiple_sends() {
        let (mut a, mut b) = DuplexTransport::pair();
        a.send(b"one").unwrap();
        a.send(b"two").unwrap();
        a.send(b"three").unwrap();

        assert_eq!(b.recv().unwrap(), Some(b"one".to_vec()));
        assert_eq!(b.recv().unwrap(), Some(b"two".to_vec()));
        assert_eq!(b.recv().unwrap(), Some(b"three".to_vec()));
        assert_eq!(b.recv().unwrap(), None);
    }

    #[test]
    fn recv_on_empty_or_closed_peer_returns_none() {
        // Fresh, empty, still-open end.
        let (mut a, b) = DuplexTransport::pair();
        assert_eq!(a.recv().unwrap(), None);
        assert!(!a.peer_closed());

        // Drop the peer: recv still returns None, now with peer_closed() true.
        drop(b);
        assert_eq!(a.recv().unwrap(), None);
        assert!(a.peer_closed());
    }

    #[test]
    fn send_to_a_dropped_receiver_errors() {
        // Requirement #3: a send to a closed peer must error, not silently succeed.
        let (mut a, b) = DuplexTransport::pair();
        drop(b);
        let err = a.send(b"x").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::BrokenPipe);
    }

    #[test]
    fn buffered_frames_survive_peer_drop() {
        // Frames sent before the peer drops remain readable afterwards.
        let (mut a, mut b) = DuplexTransport::pair();
        a.send(b"buffered").unwrap();
        drop(a);
        assert!(b.peer_closed());
        assert_eq!(b.recv().unwrap(), Some(b"buffered".to_vec()));
        assert_eq!(b.recv().unwrap(), None);
    }
}
