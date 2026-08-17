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
| **Apache-2.0** ([`LICENSE`](LICENSE)) | the agent (`torda`) and everything it links: `torda-core`, `torda-substrate`, `torda-ocsf`, `torda-findings`, `torda-compliance`, all `torda-mod-*` modules, `torda-remediation`, `torda-control-plane`, `torda-transport`, `torda-transport-tls`, and the kernel-side eBPF crates. The collector bundle and dashboards under `deploy/` are Apache-2.0 too. |
| **FSL-1.1-ALv2** ([`LICENSE-FSL-1.1.md`](LICENSE-FSL-1.1.md)) | `torda-findings-engine` (`server/findings-engine`) and `torda-ingest` (`server/ingest`) — the Findings Engine + ingest/scoring pipeline. |

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

Some crates the agent links (`torda-remediation`, `torda-control-plane`, `torda-transport*`)
contain both client and server-side code. They are Apache-2.0 today because the
agent links them. A planned refactor splits each into a client
half (stays Apache, agent-linked) and a server/orchestration half (moves to FSL), so
more of the backend can be protected without making the useful agent an FSL build.

## Contributing

Contributions to an Apache-2.0 crate are made under Apache-2.0; contributions to an
FSL crate are made under FSL-1.1-ALv2. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
