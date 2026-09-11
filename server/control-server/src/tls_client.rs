//! Issuer-side mutual-TLS carrier + file-loaded client config.
//!
//! This is the CLIENT counterpart to `torda_transport_tls`'s agent-side `accept` /
//! `TlsServerTransport`. It carries the SAME length-delimited frames (via
//! [`torda_transport::encode_frame`] / [`torda_transport::decode_frame`], 16 MiB cap) over a
//! TLS record layer, so the [`ControlPlaneClient`](crate::ControlPlaneClient) above the
//! [`torda_transport::Transport`] seam cannot tell this carrier from the in-memory one.
//!
//! [`connect`] completes the TLS handshake (verifying the server cert against the trusted CA
//! and presenting the client cert) **before** returning a transport, so a server cert that
//! does not chain to the trusted CA surfaces as an [`io::Error`] with no application frame
//! exchanged. The session id is bound to the client's OWN leaf via
//! [`torda_transport_tls::session_from_cert`] — identical to what the agent derives from the
//! client leaf it received, so both ends independently agree.
//!
//! [`client_config_from_files`] builds the mutual-TLS [`ClientConfig`] from ops-provisioned
//! files, reusing `torda_transport_tls`'s audited, fail-closed, size-capped cert/key loaders.
//! Mutual auth is unchanged: the server is verified against the loaded CA roots and the client
//! cert is presented — no `dangerous()` / accept-any verifier. The ring provider is supplied
//! explicitly per-config.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, StreamOwned};

use torda_transport::{decode_frame, encode_frame, Transport};
use torda_transport_tls::{
    load_certs, load_private_key, load_root_store, read_capped_cert_file, session_from_cert,
};

/// Size of the scratch buffer used to pull ciphertext-decrypted bytes off the TLS stream one
/// chunk at a time during [`Transport::recv`].
const READ_CHUNK: usize = 16 * 1024;

/// Map any `std::error::Error` (e.g. a `rustls::Error`) into an [`io::Error`] so the carrier
/// speaks `io::Result` and never surfaces a rustls type on a fallible path.
fn to_io<E>(e: E) -> io::Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    io::Error::other(e)
}

/// The **issuer-side** control-channel carrier: a mutual-TLS `TcpStream` presenting the client
/// certificate and having verified the server certificate during the handshake. Constructed by
/// [`connect`]. Implements [`torda_transport::Transport`].
pub struct TlsClientTransport {
    stream: StreamOwned<ClientConnection, TcpStream>,
    inbuf: Vec<u8>,
}

impl Transport for TlsClientTransport {
    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        let framed = encode_frame(frame)?;
        self.stream.write_all(&framed)?;
        self.stream.flush()?;
        Ok(())
    }

    fn recv(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            // A previously-buffered frame (or the tail of a prior read) may already be complete.
            if let Some(frame) = decode_frame(&mut self.inbuf)? {
                return Ok(Some(frame));
            }
            let mut chunk = [0u8; READ_CHUNK];
            let n = self.stream.read(&mut chunk)?;
            if n == 0 {
                // Clean close with no full frame pending.
                return Ok(None);
            }
            self.inbuf.extend_from_slice(&chunk[..n]);
        }
    }
}

/// **Issuer side.** Take a connected `TcpStream`, complete the mutual-TLS handshake with `cfg`
/// (verifying the server cert against the trusted CA and presenting the client cert), and
/// return the carrier plus the session id derived from `client_leaf` — the client's OWN leaf
/// certificate, hashed identically to the way the agent's `accept` hashes the copy it received,
/// so both ends agree on the session id.
///
/// The handshake is driven to completion HERE: a server cert that does not chain to the trusted
/// CA fails verification and surfaces as an `Err` before any application frame.
///
/// ## Why `client_leaf` is passed explicitly
///
/// rustls does not expose the client certificate a `ClientConfig`/`ClientConnection` presents,
/// so — to compute the same cert-bound session id the agent derives from the received client
/// leaf — the caller passes that leaf explicitly. This keeps session derivation bound to the
/// authenticated CLIENT identity without hand-reaching into rustls internals.
pub fn connect(
    mut stream: TcpStream,
    cfg: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    client_leaf: &CertificateDer<'_>,
) -> io::Result<(TlsClientTransport, String)> {
    let mut conn = ClientConnection::new(cfg, server_name).map_err(to_io)?;
    // Complete the handshake explicitly. A server cert that does not chain to the trusted CA
    // fails verification inside rustls and complete_io returns the io::Error HERE.
    while conn.is_handshaking() {
        conn.complete_io(&mut stream)?;
    }
    // Bind the session id to the client's OWN leaf — identical to what the agent computes from
    // the client leaf it received, so both ends independently agree.
    let session = session_from_cert(client_leaf.as_ref());
    let stream = StreamOwned::new(conn, stream);
    Ok((
        TlsClientTransport {
            stream,
            inbuf: Vec::new(),
        },
        session,
    ))
}

/// Build a mutual-TLS [`ClientConfig`] from ops-provisioned FILES.
///
/// - `ca_paths`: one or more CA files (PEM or DER); ALL their CA certs form the multi-CA trust
///   root used to verify the SERVER certificate ([`ClientConfig::with_root_certificates`]) — no
///   `dangerous()`/accept-any verifier.
/// - `cert_chain`: the client leaf chain file (PEM chain or single DER).
/// - `key`: the client private-key file (PEM or DER); presented via
///   [`ClientConfig::with_client_auth_cert`] so the server can authenticate this client.
///
/// Reuses `torda_transport_tls`'s audited, size-capped, fail-closed loaders
/// ([`load_root_store`], [`load_certs`], [`load_private_key`], [`read_capped_cert_file`]). The
/// ring provider is supplied explicitly. Any error maps to [`io::Error`]; no panics.
pub fn client_config_from_files(
    ca_paths: &[&Path],
    cert_chain: &Path,
    key: &Path,
) -> io::Result<Arc<ClientConfig>> {
    let roots = load_root_store(ca_paths)?;
    let chain = load_certs(&read_capped_cert_file(cert_chain)?)?;
    let leaf_key = load_private_key(&read_capped_cert_file(key)?)?;

    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_root_certificates(roots)
            .with_client_auth_cert(chain, leaf_key)
            .map_err(io::Error::other)?;

    Ok(Arc::new(config))
}
