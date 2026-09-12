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
//! The session id is derived from the authenticated client identity (see
//! [`session_from_cert`]). The ISSUER-side counterpart (`connect` + the client carrier) lives
//! in the FSL `torda-control-server` crate and derives the SAME cert-bound id.
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

use rustls::pki_types::CertificateDer;
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

/// Derive the control-**session** id from an authenticated peer leaf certificate's DER.
///
/// The id is the first 16 hex chars of `SHA-256(leaf_cert_DER)`. It is computed with
/// the audited `ring` SHA-256 (the same crypto provider rustls uses) — never a
/// hand-rolled hash. Because both ends hash the SAME client leaf certificate (the agent
/// hashes the client cert it received in [`accept`]; the issuer hashes the client cert
/// it presented in [`connect`]), both independently derive an identical id, binding the
/// session to the cryptographically authenticated CLIENT identity.
///
/// A per-connection nonce (to make the id unique across reconnects of the same identity)
/// is a deliberate future refinement; this slice uses a single connection per session,
/// so the cert-bound id is sufficient and fully deterministic for testing.
pub fn session_from_cert(der: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    let mut hex = String::with_capacity(16);
    for byte in digest.as_ref().iter().take(8) {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// Derive the session id from a peer certificate chain, failing (never panicking) if the
/// authenticated chain is somehow absent or empty.
fn session_from_chain(chain: Option<&[CertificateDer<'static>]>) -> io::Result<String> {
    let leaf = chain
        .and_then(<[CertificateDer<'static>]>::first)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "no authenticated peer leaf certificate after the handshake",
            )
        })?;
    Ok(session_from_cert(leaf.as_ref()))
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
/// session id derived from the authenticated client certificate.
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
    // The authenticated client leaf is now available; bind the session id to it.
    let session = session_from_chain(conn.peer_certificates())?;
    let stream = StreamOwned::new(conn, stream);
    Ok((
        TlsServerTransport {
            stream,
            inbuf: Vec::new(),
        },
        session,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_from_cert_is_16_hex_chars_and_stable() {
        let s1 = session_from_cert(b"some-cert-der-bytes");
        let s2 = session_from_cert(b"some-cert-der-bytes");
        assert_eq!(s1, s2, "same DER hashes to the same session id");
        assert_eq!(
            s1.len(),
            16,
            "session id is 16 hex chars (first 8 SHA-256 bytes)"
        );
        assert!(
            s1.chars().all(|c| c.is_ascii_hexdigit()),
            "session id is hex"
        );
    }

    #[test]
    fn different_certs_yield_different_sessions() {
        assert_ne!(session_from_cert(b"cert-A"), session_from_cert(b"cert-B"));
    }

    #[test]
    fn empty_peer_chain_errors_not_panics() {
        assert!(session_from_chain(None).is_err());
        assert!(session_from_chain(Some(&[])).is_err());
    }
}
