//! Synchronous-rustls carrier for the P3b control channel: a real
//! [`torda_transport::Transport`] over a `std::net::TcpStream` wrapped in **mutual-TLS**.
//!
//! This is the real-network counterpart to `torda_transport::DuplexTransport`. It carries
//! the SAME length-delimited frames (via [`torda_transport::encode_frame`] /
//! [`torda_transport::decode_frame`], 16 MiB cap) over a TLS record layer, so the control
//! loop/client above the [`torda_transport::Transport`] seam cannot tell the two carriers
//! apart — no code above the seam changes.
//!
//! ## What the handshake gates
//!
//! [`accept`] (agent side) completes the TLS handshake **before returning a transport**.
//! Because the configs from this crate require mutual certificate authentication, an
//! untrusted or absent peer certificate makes the handshake fail and the constructor returns
//! an [`io::Error`] — *no application frame is ever exchanged with an unauthenticated peer*.
//! Both peers derive the same fresh session id from TLS exporter material after mTLS.
//! The ISSUER-side counterpart lives in the FSL `torda-control-server` crate.
//!
//! ## Fallibility
//!
//! Every socket, handshake, and read/write path returns [`io::Result`]; there is **no**
//! `unwrap`/`expect` on I/O, handshake, or hostile-peer input. rustls' own errors are
//! mapped into [`io::Error`]. Blocking reads are fine here: the control channel is
//! strict request/response.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::{ServerConfig, ServerConnection, StreamOwned};

use torda_transport::{decode_frame, encode_frame, Transport};

/// Size of the scratch buffer used to pull ciphertext-decrypted bytes off the TLS
/// stream one chunk at a time during [`Transport::recv`].
const READ_CHUNK: usize = 16 * 1024;

/// Map any `std::error::Error` (e.g. a `rustls::Error`) into an [`io::Error`] so the
/// whole crate speaks `io::Result` and never surfaces a rustls type on a fallible path.
fn to_io<E>(e: E) -> io::Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    io::Error::other(e)
}

/// Domain separation for the control session TLS exporter. Shared by both peers.
pub const CONTROL_SESSION_EXPORTER_LABEL: &[u8] = b"EXPORTER-torda-control-session-v1";

/// Encode all 32 exported bytes as a 64-character session id.
pub fn session_from_exported_bytes(material: [u8; 32]) -> String {
    let mut hex = String::with_capacity(64);
    for byte in material {
        use std::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    hex
}

/// Length-frame `frame` and write it to a TLS stream, flushing so the peer sees it as one
/// whole message. Reuses `torda_transport`'s framing (16 MiB cap), so the wire format is
/// identical to the in-memory carrier.
fn send_framed<S: Write>(stream: &mut S, frame: &[u8]) -> io::Result<()> {
    let framed = encode_frame(frame)?;
    stream.write_all(&framed)?;
    stream.flush()?;
    Ok(())
}

/// Read from a TLS stream until `inbuf` holds one whole frame, then return it.
///
/// Returns `Ok(None)` on a clean end-of-stream (read of 0 bytes) with no complete frame
/// buffered. Never panics on truncated or hostile input: [`decode_frame`] enforces the
/// 16 MiB cap and treats a partial/garbage prefix safely.
fn recv_framed<S: Read>(stream: &mut S, inbuf: &mut Vec<u8>) -> io::Result<Option<Vec<u8>>> {
    loop {
        // A previously-buffered frame (or the tail of a prior read) may already be complete.
        if let Some(frame) = decode_frame(inbuf)? {
            return Ok(Some(frame));
        }
        let mut chunk = [0u8; READ_CHUNK];
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            // Clean close with no full frame pending.
            return Ok(None);
        }
        inbuf.extend_from_slice(&chunk[..n]);
    }
}

/// The **agent-side** control-channel carrier: a mutual-TLS `TcpStream` presenting the
/// agent (server) certificate and having authenticated the client certificate during the
/// handshake. Constructed by [`accept`]. Implements [`torda_transport::Transport`].
pub struct TlsServerTransport {
    stream: StreamOwned<ServerConnection, TcpStream>,
    inbuf: Vec<u8>,
}

impl Transport for TlsServerTransport {
    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        send_framed(&mut self.stream, frame)
    }

    fn recv(&mut self) -> io::Result<Option<Vec<u8>>> {
        recv_framed(&mut self.stream, &mut self.inbuf)
    }
}

/// **Agent side.** Take an accepted `TcpStream`, complete the mutual-TLS handshake with
/// `cfg` (which REQUIRES a CA-signed client cert), and return the carrier plus the
/// session id derived from this authenticated TLS connection.
///
/// The handshake is driven to completion HERE, before any application frame is read, so
/// an untrusted or absent client certificate is rejected by rustls' client-cert verifier
/// and surfaces as an `Err` from this function — a hostile peer never reaches the loop.
pub fn accept(
    mut stream: TcpStream,
    cfg: Arc<ServerConfig>,
) -> io::Result<(TlsServerTransport, String)> {
    let mut conn = ServerConnection::new(cfg).map_err(to_io)?;
    // Complete the handshake explicitly. An untrusted/absent client cert fails path
    // validation inside rustls and complete_io returns the resulting io::Error HERE,
    // before any application data is exchanged.
    while conn.is_handshaking() {
        conn.complete_io(&mut stream)?;
    }
    // Enforce client authentication even when a caller supplies a permissive config.
    if conn
        .peer_certificates()
        .is_none_or(|chain| chain.is_empty())
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "control transport requires an authenticated client certificate",
        ));
    }
    let material = conn
        .export_keying_material([0u8; 32], CONTROL_SESSION_EXPORTER_LABEL, None)
        .map_err(to_io)?;
    let session = session_from_exported_bytes(material);
    let stream = StreamOwned::new(conn, stream);
    Ok((
        TlsServerTransport {
            stream,
            inbuf: Vec::new(),
        },
        session,
    ))
}
