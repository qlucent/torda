# Licensing

Torda uses **two licenses**, split so the part you run is fully open and
the backend core is protected from resale.

> This document is an explanation, not legal advice. The authoritative texts are
> [`LICENSE`](LICENSE) (Apache-2.0) and [`LICENSE-FSL-1.1.md`](LICENSE-FSL-1.1.md)
> (FSL-1.1-ALv2). Have counsel review before you rely on this.

## The short version

- **The agent is Apache-2.0.** The binary that runs on your machines — the eBPF/ETW
  probes, the modules, the OCSF emitter, the config/transport/remediation client —
  is permissively licensed. You can read, audit, modify, run, and redistribute it
  freely. A security agent that runs as root should be auditable; that's the point.
- **The backend engine is FSL-1.1-ALv2.** The Findings Engine and the ingest/scoring
  pipeline — the canonical scoring, dedup, group-by-fix, and reachability logic that
  is the project's differentiation — are **source-available**: you may use, read,
  modify, and self-host them for any purpose **except** offering them as a competing
  commercial product or service. Each version automatically **converts to Apache-2.0
  two years** after its release ([Functional Source License 1.1](https://fsl.software/)).

## Which license covers which crate

| License | Crates |
| --- | --- |
| **Apache-2.0** ([`LICENSE`](LICENSE)) | the agent (`torda`) and everything it links: `torda-core`, `torda-substrate`, `torda-ocsf`, `torda-findings`, `torda-compliance`, all `torda-mod-*` modules, `torda-remediation`, `torda-control-plane`, `torda-transport`, `torda-transport-tls`, and the kernel-side eBPF crates. The open feed-format crate `torda-feed` (`crates/feed`) — the signed bundle format, verification, local store, and CLI — is Apache-2.0 too, as is the collector bundle and dashboards under `deploy/`. |
| **FSL-1.1-ALv2** ([`LICENSE-FSL-1.1.md`](LICENSE-FSL-1.1.md)) | `torda-findings-engine` (`server/findings-engine`) and `torda-ingest` (`server/ingest`) — the Findings Engine + ingest/scoring pipeline; `torda-control-server` (`server/control-server`) — the orchestration/issuer half of the control channel; and `torda-feed-live` (`server/feed-live`) — the enterprise (paid) live-feed source + entitlement issuer. |

The boundary is dependency-clean: nothing Apache-licensed depends on an FSL crate,
so the agent is genuinely Apache-only.

## Why this split

The agent is the thing you install and trust with root; keeping it Apache-2.0
maximizes auditability and adoption, and the OCSF envelope it speaks is an open
standard. The defensible value is the **backend aggregation** — one canonical
explainable score across every source, grouped by fix, with runtime-confirmed
reachability. FSL protects exactly that from a competitor repackaging it as a rival
service, while still letting you self-host and audit it, and it becomes fully open
(Apache-2.0) after two years.

## Roadmap note

The control channel has a deliberate **role inversion**: the agent is the mutual-TLS
**server** (it runs the listener, authenticates peers, and locally executes signed
commands through its replay-guarded loop), while the orchestration control plane is the
mTLS **client / issuer** that connects in and signs commands. The first split along this
seam is done: the issuer/orchestration surface — the client carrier + file-loaded client
config (`connect`, `TlsClientTransport`, `client_config_from_files`) and the operator-side
driver (`ControlPlaneClient`, `ResultCorrelator`, `establish_session`) — now lives in the
FSL crate **`torda-control-server`**, while everything the agent links to *be* the server
(accept/`TlsServerTransport`, the cert/PKI loaders, `Ed25519Verifier`/`CommandSigner`,
`AgentControlLoop`, and all of `torda-remediation`/`torda-transport`) stays Apache-2.0. No
Apache crate takes a normal dependency on `torda-control-server`, so the agent stays a
genuine Apache-only build; the only normal consumer is the FSL `torda-ingest`.

`torda-remediation`, `torda-control-plane`, and `torda-transport*` still contain some
server-adjacent code that remains Apache because the agent links it; further carving of
orchestration-only surface into FSL crates can follow the same client/issuer boundary.

## Feed tiering

Enrichment (the CVSS / EPSS / KEV / advisory evidence the Findings Engine scores from)
is delivered as a **feed**, split along the same open-core seam:

- **Community** — a static, periodically-published, **signed** bundle consumed by the
  Apache `torda-feed` crate. The bundle format, its Ed25519 signature + per-file digest
  verification, the local store, and the `torda-feed` CLI are all Apache-2.0: anyone can
  produce, publish, verify, and consume a feed, and side-load one offline for air-gapped
  hosts. This is the open format, like the OCSF envelope the agent speaks.
- **Enterprise** — a live, curated source (`torda-feed-live`, FSL) that implements the
  same `FeedSource` trait behind a signed **entitlement token**, verified offline against
  the issuer's public key. The bundle **signature** (content integrity, verified by the
  Apache crate) is deliberately separate from the **entitlement** (access, enforced by the
  FSL crate): a valid bundle you are not entitled to is still refused, and either tier
  installs through the same verified store.

The dependency direction stays clean: `torda-feed-live` (FSL) depends on `torda-feed`
(Apache), never the reverse, and the agent links neither — feed consumption lives on the
findings/ingest (backend) side.

## Contributing

Contributions to an Apache-2.0 crate are made under Apache-2.0; contributions to an
FSL crate are made under FSL-1.1-ALv2. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
