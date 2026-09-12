//! # torda-control-server — the FSL orchestration/issuer surface of the control channel
//!
//! The P3b control channel has a deliberate ROLE INVERSION: the **agent** is the mutual-TLS
//! SERVER (it runs the listener, [`torda_transport_tls::accept`]s connections, and locally
//! executes signed commands through its replay-guarded
//! [`AgentControlLoop`](torda_control_plane::AgentControlLoop)). The **orchestration control
//! plane** is the mTLS CLIENT / issuer: it connects IN, signs commands, and correlates the
//! agent's signed results.
//!
//! Everything the shipped `torda` agent links to authenticate peers, verify/sign commands,
//! and run the loop stays Apache-2.0 (in `torda-control-plane` + `torda-transport-tls`). This
//! crate holds ONLY the thinner issuer half — the pieces an operator/orchestrator uses to
//! drive an agent — under FSL-1.1-ALv2 (see `LICENSING.md`). Because no Apache crate takes a
//! normal dependency on this crate, the agent binary remains Apache-only.
//!
//! ## Modules
//!
//! - [`tls_client`] — the issuer-side mTLS carrier ([`connect`] + [`TlsClientTransport`]) and
//!   the file-loaded client [`ClientConfig`](rustls::ClientConfig) builder
//!   ([`client_config_from_files`]). The agent-side `accept` / `TlsServerTransport` and ALL
//!   certificate/PKI loading stay in `torda-transport-tls`.
//! - [`issuer`] — the operator-side driver [`ControlPlaneClient`], its result-replay guard
//!   [`ResultCorrelator`], and the [`establish_session`] helper. The agent-side loop, handler,
//!   signer, verifier, and wire types stay in `torda-control-plane`.

mod issuer;
mod tls_client;

pub use issuer::{establish_session, ControlPlaneClient, ResultCorrelator};
pub use tls_client::{client_config_from_files, connect, TlsClientTransport};
