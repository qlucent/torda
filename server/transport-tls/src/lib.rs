//! # torda-transport-tls — mutual-TLS config + test PKI for the control channel
//!
//! This crate is the **crypto configuration foundation** for the P3b control
//! channel's real-network carrier. It produces ready-to-use [`rustls`] configs for
//! **mutual TLS (mTLS)**: both ends of the connection prove their identity by
//! presenting an X.509 certificate signed by a shared certificate authority (CA).
//! The server refuses any client that presents no certificate or one not signed by
//! the trusted CA; the client refuses any server whose certificate does not chain
//! to the same CA.
//!
//! ## What mutual TLS guarantees here
//!
//! - **Server identity:** the client verifies the server's certificate against the
//!   CA trust roots ([`rustls::ClientConfig::with_root_certificates`]). No
//!   accept-any / `dangerous()` verifier is used anywhere in this crate.
//! - **Client identity:** the server installs a **required** client-certificate
//!   verifier ([`rustls::server::WebPkiClientVerifier`] built with `.build()`, not
//!   the optional `allow_unauthenticated` variant), so a handshake without a valid
//!   client cert fails.
//!
//! ## Relationship to the app-layer ed25519 auth
//!
//! mTLS authenticates the **transport peers** (this machine is talking to that
//! machine). It **complements — it does not replace** — the app-layer ed25519
//! signatures that authenticate individual *commands* on the control channel.
//! Transport-level mTLS proves "who is on the socket"; command-level ed25519 proves
//! "who authored and triggered this specific action". Both are required: a valid
//! TLS peer may still only run commands it can produce a valid ed25519 signature
//! for.
//!
//! ## Scope
//!
//! This task is **configuration only**. There is no `TlsTransport`, no socket, and
//! no I/O here — that carrier (implementing [`torda_transport::Transport`]) lands in a
//! later task and will consume the configs this crate produces.
//!
//! ## Crypto provider
//!
//! rustls is built with `default-features = false` and the **ring** provider. This
//! crate installs the provider **explicitly** per-config via
//! [`rustls::ServerConfig::builder_with_provider`] /
//! [`rustls::ClientConfig::builder_with_provider`] rather than relying on a global
//! `install_default()`, so config construction is deterministic and free of
//! process-global install ordering. All crypto comes from audited libraries
//! (rustls + ring for TLS, rcgen for certificate minting); nothing is hand-rolled.

use std::sync::Arc;

mod certs;
mod reload;
mod stream;
pub use certs::{
    client_config_from_files, load_certs, load_crls, load_crls_from_files, load_private_key,
    read_capped_cert_file, server_config_from_files, server_config_from_files_with_crl,
    write_pki_to_der, write_pki_to_pem, CertFilePaths, MAX_CERT_FILE_BYTES,
};
pub use reload::{CertFileSpec, ReloadableServerConfig};
pub use stream::{accept, connect, session_from_cert, TlsClientTransport, TlsServerTransport};

use rustls::pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivateKeyDer, PrivatePkcs8KeyDer,
};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

/// An in-memory **test** public-key infrastructure: a self-signed CA plus a server
/// certificate and a client certificate, each signed by that CA.
///
/// This exists so tests and demos can exercise real mTLS handshakes without
/// touching the filesystem or a real CA. **It is not for production.** In
/// production, certificates and private keys are loaded from files provisioned by
/// ops, and the trust root is a real organizational/enterprise CA — that loading
/// path is deliberately deferred to ops and is out of scope for this crate.
///
/// The DER blobs held here use the `rustls-pki-types` types that [`rustls`]
/// consumes directly, so [`server_config`] and [`client_config`] can build configs
/// with no conversion.
pub struct TestPki {
    /// The CA certificate, in DER form. Used as the sole trust anchor by both the
    /// server's client-cert verifier and the client's server-cert verifier.
    pub ca_cert: CertificateDer<'static>,
    /// The server's certificate chain (leaf first). Here it is a single
    /// CA-signed leaf; the CA itself is the trust anchor and is not included.
    pub server_cert_chain: Vec<CertificateDer<'static>>,
    /// The server's private key (PKCS#8 DER), matching `server_cert_chain`'s leaf.
    pub server_key: PrivateKeyDer<'static>,
    /// The client's certificate chain (leaf first), signed by the same CA.
    pub client_cert_chain: Vec<CertificateDer<'static>>,
    /// The client's private key (PKCS#8 DER), matching `client_cert_chain`'s leaf.
    pub client_key: PrivateKeyDer<'static>,
}

/// Mint a fresh in-memory [`TestPki`]: a CA, plus a server cert and a client cert
/// each **signed by that CA**.
///
/// Every call generates new key material (rcgen uses its own RNG), so no secrets
/// are baked into the binary. This is **test** PKI — see [`TestPki`] for why
/// production uses ops-provisioned files and a real trust store instead.
///
/// # Panics
///
/// Panics if certificate generation fails. Generation has no external inputs and
/// does not fail in practice; a failure indicates a broken crypto environment, and
/// panicking keeps this test/demo helper's signature simple.
pub fn generate_test_pki() -> TestPki {
    // A CA that is allowed to sign other certificates.
    let mut ca_params =
        rcgen::CertificateParams::new(Vec::new()).expect("CA params from empty SAN list");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "torda-transport-tls test CA");
    let ca_key = rcgen::KeyPair::generate().expect("generate CA key pair");
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA cert");

    // Server leaf, signed by the CA.
    let (server_leaf, server_key) = signed_leaf(&ca_cert, &ca_key, "localhost");
    // Client leaf, signed by the CA.
    let (client_leaf, client_key) = signed_leaf(&ca_cert, &ca_key, "torda-agent-client");

    TestPki {
        ca_cert: ca_cert.der().clone(),
        server_cert_chain: vec![server_leaf],
        server_key,
        client_cert_chain: vec![client_leaf],
        client_key,
    }
}

/// Mint one end-entity (leaf) certificate for `name`, signed by the CA, returning
/// its DER certificate and matching PKCS#8 private key.
fn signed_leaf(
    ca_cert: &rcgen::Certificate,
    ca_key: &rcgen::KeyPair,
    name: &str,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let params =
        rcgen::CertificateParams::new(vec![name.to_string()]).expect("leaf params from SAN");
    let key = rcgen::KeyPair::generate().expect("generate leaf key pair");
    let cert = params
        .signed_by(&key, ca_cert, ca_key)
        .expect("sign leaf cert by CA");
    let der = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    (der, key_der)
}

/// Like [`signed_leaf`] but pins an EXPLICIT X.509 `serial_number` on the leaf, so a CRL can
/// name that exact serial to revoke it. rcgen otherwise assigns a random serial, which a CRL
/// could not reference deterministically. Returns the cert DER + matching PKCS#8 key.
fn signed_leaf_with_serial(
    ca_cert: &rcgen::Certificate,
    ca_key: &rcgen::KeyPair,
    name: &str,
    serial: rcgen::SerialNumber,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let mut params =
        rcgen::CertificateParams::new(vec![name.to_string()]).expect("leaf params from SAN");
    params.serial_number = Some(serial);
    let key = rcgen::KeyPair::generate().expect("generate leaf key pair");
    let cert = params
        .signed_by(&key, ca_cert, ca_key)
        .expect("sign leaf cert by CA");
    let der = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    (der, key_der)
}

/// A [`TestPki`]-plus-CRL bundle for exercising certificate **revocation** (CRL) enforcement
/// over a real handshake. All leaves share ONE CA (so a single CA-signed CRL governs them),
/// and the CA is minted with the `cRLSign` key usage so it may sign the CRL.
///
/// This is **test/demo** support (see [`TestPki`]); it is `pub` so the mTLS demo can show CRL
/// enforcement end to end. Not for production.
pub struct RevocationTestPki {
    /// PKI whose CLIENT leaf has been REVOKED by [`Self::crl_der`] (same CA + server leaf as
    /// [`Self::pki_good`]). Its client presents a serial listed in the CRL.
    pub pki_revoked: TestPki,
    /// PKI sharing the SAME CA and server leaf, but whose CLIENT leaf carries a DIFFERENT
    /// serial that is NOT in the CRL — a non-revoked peer that must still connect.
    pub pki_good: TestPki,
    /// The DER serial number of the revoked client leaf (the value named in the CRL).
    pub revoked_serial: Vec<u8>,
    /// A CRL, signed by the shared CA, revoking [`Self::revoked_serial`]. Its `next_update`
    /// is far in the future so it is never treated as expired at handshake time.
    pub crl_der: CertificateRevocationListDer<'static>,
}

/// Mint a [`RevocationTestPki`]: one CA (able to sign CRLs), a server leaf, a REVOKED client
/// leaf (explicit serial) and a distinct non-revoked client leaf, plus a CA-signed CRL that
/// revokes the first client's serial.
///
/// The CRL uses fixed [`rcgen::date_time_ymd`] timestamps (deterministic, no wall clock):
/// `this_update` in the past and `next_update` in the year 2100, so rustls never treats it as
/// expired during a test handshake. rcgen supplies the `time::OffsetDateTime` values via
/// `date_time_ymd`, so no extra crate is pulled in.
///
/// # Panics
///
/// Panics if certificate/CRL generation fails — like [`generate_test_pki`], generation has no
/// external inputs and only fails in a broken crypto environment; panicking keeps this
/// test/demo helper's signature simple.
pub fn generate_revocation_test_pki() -> RevocationTestPki {
    // A CA allowed to sign certificates AND CRLs. rcgen refuses to sign a CRL unless the
    // issuer's key usages include `CrlSign` (or are empty); we set it explicitly, and webpki
    // likewise honours the `cRLSign` bit when validating the CRL against this trust anchor.
    let mut ca_params =
        rcgen::CertificateParams::new(Vec::new()).expect("CA params from empty SAN list");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    ca_params.distinguished_name.push(
        rcgen::DnType::CommonName,
        "torda-transport-tls revocation test CA",
    );
    let ca_key = rcgen::KeyPair::generate().expect("generate CA key pair");
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA cert");

    // Server leaf, and two client leaves (one to revoke, one to keep) with explicit serials.
    let (server_leaf, server_key) = signed_leaf(&ca_cert, &ca_key, "localhost");
    let revoked_serial_value: u64 = 0x1234_5678;
    let (revoked_client_leaf, revoked_client_key) = signed_leaf_with_serial(
        &ca_cert,
        &ca_key,
        "torda-agent-client",
        rcgen::SerialNumber::from(revoked_serial_value),
    );
    let (good_client_leaf, good_client_key) = signed_leaf_with_serial(
        &ca_cert,
        &ca_key,
        "torda-agent-client-ok",
        rcgen::SerialNumber::from(0x0BAD_F00Du64),
    );
    let revoked_serial = rcgen::SerialNumber::from(revoked_serial_value)
        .as_ref()
        .to_vec();

    // A CRL, signed by the CA, revoking the first client's serial. Fixed timestamps keep it
    // deterministic; the far-future `next_update` keeps it valid ("unexpired") at handshake.
    let this_update = rcgen::date_time_ymd(2023, 1, 1);
    let next_update = rcgen::date_time_ymd(2100, 1, 1);
    let crl_params = rcgen::CertificateRevocationListParams {
        this_update,
        next_update,
        crl_number: rcgen::SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs: vec![rcgen::RevokedCertParams {
            serial_number: rcgen::SerialNumber::from(revoked_serial_value),
            revocation_time: this_update,
            reason_code: Some(rcgen::RevocationReason::KeyCompromise),
            invalidity_date: None,
        }],
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };
    let crl = crl_params
        .signed_by(&ca_cert, &ca_key)
        .expect("sign CRL by the CA");
    let crl_der = crl.der().clone();

    let ca_der = ca_cert.der().clone();
    RevocationTestPki {
        pki_revoked: TestPki {
            ca_cert: ca_der.clone(),
            server_cert_chain: vec![server_leaf.clone()],
            server_key: server_key.clone_key(),
            client_cert_chain: vec![revoked_client_leaf],
            client_key: revoked_client_key,
        },
        pki_good: TestPki {
            ca_cert: ca_der,
            server_cert_chain: vec![server_leaf],
            server_key,
            client_cert_chain: vec![good_client_leaf],
            client_key: good_client_key,
        },
        revoked_serial,
        crl_der,
    }
}

/// Build a [`RootCertStore`] whose single trust anchor is the test CA in `pki`.
///
/// Both configs use this: the server trusts it to validate client certs, the
/// client trusts it to validate the server cert. Because it holds only the test
/// CA, any certificate not chaining to that CA is rejected.
fn ca_root_store(pki: &TestPki) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots
        .add(pki.ca_cert.clone())
        .expect("test CA cert is a valid trust anchor");
    roots
}

/// Build a mutual-TLS [`ServerConfig`] from the test `pki`.
///
/// The returned config:
/// - **requires** a client certificate — the verifier is built with
///   [`WebPkiClientVerifier::builder(..).build()`](WebPkiClientVerifier), the
///   mandatory variant, *not* `allow_unauthenticated`. A client that presents no
///   cert, or a cert not signed by the test CA, is rejected during the handshake.
/// - presents the server's CA-signed cert/key so the client can authenticate it.
///
/// The ring crypto provider is supplied explicitly (no global install).
pub fn server_config(pki: &TestPki) -> Arc<ServerConfig> {
    let roots = Arc::new(ca_root_store(pki));
    let client_verifier = WebPkiClientVerifier::builder(roots)
        .build()
        .expect("build required client-cert verifier from test CA");

    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring provider supports the default protocol versions")
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(pki.server_cert_chain.clone(), pki.server_key.clone_key())
            .expect("server cert/key are a valid, matching pair");

    Arc::new(config)
}

/// Build a mutual-TLS [`ClientConfig`] from the test `pki`.
///
/// The returned config:
/// - verifies the **server** against the test CA roots
///   ([`ClientConfig::with_root_certificates`]) — no `dangerous()` verifier, no
///   accept-any behavior.
/// - presents the client's CA-signed cert/key
///   ([`ClientConfig::with_client_auth_cert`]) so the server can authenticate it.
///
/// The ring crypto provider is supplied explicitly (no global install).
pub fn client_config(pki: &TestPki) -> Arc<ClientConfig> {
    let roots = ca_root_store(pki);

    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring provider supports the default protocol versions")
            .with_root_certificates(roots)
            .with_client_auth_cert(pki.client_cert_chain.clone(), pki.client_key.clone_key())
            .expect("client cert/key are a valid, matching pair");

    Arc::new(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All three public entry points succeed against a freshly minted test PKI.
    #[test]
    fn configs_build_from_test_pki() {
        let pki = generate_test_pki();
        let _server = server_config(&pki);
        let _client = client_config(&pki);
        // Reaching here means the required verifier built, both cert/key pairs
        // matched, and the ring provider supported the default protocol versions.
    }

    /// A client cert signed by the CA validates against a verifier built from that
    /// same CA. We assert both halves of the guarantee: (a) the verifier is the
    /// mandatory (client-auth-required) variant, and (b) that verifier's own
    /// `verify_client_cert` — the exact path validation rustls runs during a
    /// handshake — accepts the CA-signed client chain.
    #[test]
    fn client_cert_signed_by_the_ca_is_accepted_by_the_server_verifier() {
        let pki = generate_test_pki();

        // (a) `.build()` yields the REQUIRED verifier: client auth is mandatory.
        let verifier = build_client_verifier(&pki.ca_cert);
        assert!(
            verifier.client_auth_mandatory(),
            "verifier must REQUIRE a client cert, not merely allow one"
        );

        // (b) The CA-signed client leaf validates against the verifier.
        assert!(
            verify_client_chain(&verifier, &pki.client_cert_chain).is_ok(),
            "CA-signed client cert should validate against its own CA's verifier"
        );
    }

    /// A client cert signed by a DIFFERENT, untrusted CA is rejected: its chain
    /// does not lead to the trusted CA, so the trusted CA's verifier fails path
    /// validation with an error (no accept).
    #[test]
    fn a_cert_from_a_different_untrusted_ca_is_rejected() {
        let trusted = generate_test_pki();
        let attacker = generate_test_pki(); // an independent CA + certs

        let trusted_verifier = build_client_verifier(&trusted.ca_cert);
        let attacker_verifier = build_client_verifier(&attacker.ca_cert);

        // Sanity: the attacker's client cert DOES validate against its own CA...
        assert!(
            verify_client_chain(&attacker_verifier, &attacker.client_cert_chain).is_ok(),
            "attacker cert is internally valid against its own CA"
        );

        // ...but is REJECTED by the trusted CA's verifier — the guarantee we need.
        assert!(
            verify_client_chain(&trusted_verifier, &attacker.client_cert_chain).is_err(),
            "a cert from an untrusted CA must NOT validate against the trusted CA"
        );
    }

    /// Build a required (`.build()`) [`WebPkiClientVerifier`] trusting only `ca`.
    fn build_client_verifier(
        ca: &CertificateDer<'static>,
    ) -> Arc<dyn rustls::server::danger::ClientCertVerifier> {
        let mut roots = RootCertStore::empty();
        roots.add(ca.clone()).expect("trust anchor adds");
        WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .expect("required verifier builds")
    }

    /// Run the verifier's real handshake-time path validation on `chain`'s leaf,
    /// returning whether the chain is accepted. This is exactly what rustls calls
    /// when a client presents its cert, so it proves the trust decision without a
    /// live socket.
    fn verify_client_chain(
        verifier: &Arc<dyn rustls::server::danger::ClientCertVerifier>,
        chain: &[CertificateDer<'static>],
    ) -> Result<(), rustls::Error> {
        let (leaf, intermediates) = chain.split_first().expect("chain has a leaf");
        let now = rustls::pki_types::UnixTime::now();
        verifier
            .verify_client_cert(leaf, intermediates, now)
            .map(|_verified| ())
    }
}
