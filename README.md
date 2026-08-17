# Torda

> An open-source, **OCSF-native endpoint security agent**. One shared kernel
> probe set — **eBPF on Linux, ETW on Windows** — feeds thin detection modules
> that emit OCSF, with cross-sensor **attack-chain correlation**, streamed to a
> file a log shipper carries into **your own SIEM**. No per-seat license; you
> own your data. Security-posture-first. **Not** an APM tool.

The agent watches process, network, and file activity through a single probe
set, judges each with a small deterministic ruleset, and — crucially —
**correlates across sensors** to surface multi-stage attack chains (a suspicious
process that drops a file *and* beacons out) that no single sensor sees alone.
Every record is OCSF on the wire, so your existing pipeline never re-parses an
ad-hoc format.

## Why this exists

Two real, unsolved problems for engineering and ops teams:

1. **Detection overload.** Most agents dump raw detections with inconsistent
   vendor severities and zero aggregation. Ops drown in thousands of rows. The
   **Findings Engine** recomputes **one canonical, explainable score** across
   every source — never trusting a source's own label — dedups, and **groups by
   fix**, so teams see a short work-queue of remediations, not a wall of CVEs.

2. **Risky auto-remediation.** Auto-patching agents own a catastrophic blast
   radius, so teams disable them and patch by hand. The **Remediation Bridge
   never decides or auto-applies** — it is a signed, audited execution channel
   for the team's *own* methods, with dry-run (the default), canary, rollback,
   kill switch, and verification.

## What it detects

Each sensor runs a pure, deterministic ruleset and emits an OCSF record only
when a rule actually fires. The correlation module joins sensors by pid.

| Sensor | OCSF class | Rules (real names) |
| --- | --- | --- |
| **Process** | `1007` Process Activity | `lolbin`, `suspicious_path`, `lolbin_in_suspicious_path`, `short_lived_suspicious` |
| **Network** | `4001` Network Activity | `suspicious_port` (known C2 / backdoor / remote-shell ports), `suspicious_port_to_external` |
| **File** | `1001` File System Activity | `write_to_system_dir`, `write_to_persistence_location`, `write_to_sensitive_config`, `read_of_sensitive_file` |
| **Correlation** | `9002` Correlated Activity | `suspicious_process_suspicious_connection`, `suspicious_process_suspicious_file_write`, the **dropper-then-C2** chain `suspicious_process_wrote_file_and_connected`, and the **read-secret-then-beacon** exfil chain `suspicious_process_read_sensitive_and_connected` |

The `9002` correlation rules each fire only when **all** component halves are
independently suspicious for the same process — an AND, never an OR. (Note: class
`9001` is **Agent Health** telemetry, *not* a chain.)

### Vulnerability findings (SBOM → CVE, scored)

The agent also builds a real **SBOM** from installed packages (dpkg / rpm /
Windows registry) and emits it as OCSF `5020`. Server-side, that SBOM is matched
against real advisory data — Linux dpkg/rpm components against **OSV**,
**release-aware** (a Debian host is matched only against Debian's fixed versions,
an Ubuntu host against Ubuntu's) with a faithful dpkg/rpm version comparator; and
Windows components against an **NVD** community feed (which OSV doesn't cover),
mapping the registry DisplayName to the affected product. Each hit is scored from
**real CVSS + EPSS + CISA KEV** data (never a source's own label; a
KEV/known-exploited CVE is driven to *act-now* regardless of its numeric score).
The result is a **fix-first** queue: "upgrade this one package, close these N CVEs
across these M hosts." (The bundled NVD snapshot is a small, date-stamped
*community* feed with a curated common-app mapping; a live NVD sync with full CPE
matching is the enterprise feed, behind the same interface.)

## Quickstart — the ~1-hour tryable path

Run all `cargo` commands from the repo root (it **is** the Cargo workspace).

**1. Get the agent.** Install a **package** from the
[latest release](../../releases/latest) — `.deb`/`.rpm` on Linux (the build
includes the eBPF backend), or the `.msi` on Windows (ETW backend) — or grab the
raw binary, or build from source. The **default source build has no real kernel
backend** — it runs a stub event bus that observes no process/network/file
activity — so to capture real events, build with the platform feature:

```bash
cargo build --release --features linux-ebpf     # Linux — eBPF process/network/file events
cargo build --release --features windows-etw    # Windows — ETW process/network/file events
```

Opening a kernel probe is privileged: run as **root** (or grant
`CAP_BPF`+`CAP_PERFMON`) on Linux, or as **Administrator** on Windows. Without
the feature or the privilege the agent **fails soft** to the stub bus — it never
crashes, it just collects nothing from the kernel that cycle.

**2. Run it as a daemon writing OCSF to a file.** The agent makes **no network
call** of its own — the NDJSON file is the seam a shipper carries onward.

```bash
./target/release/torda --daemon --output /var/log/torda/events.ndjson
```

Configure it once via the commented TOML sample
[`deploy/torda.toml`](deploy/torda.toml) (`--config <path>`;
CLI flags/env override config values). The full run-it-as-a-service path
(systemd unit, config precedence, shipping to *your own* secured SIEM) is in
**[`docs/DEPLOY.md`](docs/DEPLOY.md)**.

**3. See it: stand up the collector bundle.** From
[`deploy/collector/`](deploy/collector/README.md), `docker compose up` brings up
OpenSearch + OpenSearch Dashboards + Vector with **five prebuilt dashboards** — no
cloud account, no license:

- **Findings — fix-first**: the differentiation — every detection collapsed into a
  short, risk-ranked queue of *fixes* (not a wall of rows).
- **Vulnerability Management**: severity by CVSS, a known-exploited (KEV) callout,
  top vulnerabilities / packages / hosts, the upgrade queue.
- **Vulnerability details**: a row-level, filterable, CSV-exportable CVE table.
- **Security posture & agent activity**: the agent's footprint vs its budget, what
  it's catching, posture (compliance / FIM / drift), and trends over time.
- **Findings lifecycle**: opened vs closed per week, open backlog, and **MTTR** —
  are you closing findings faster than they open? (Timestamps are engine-generated
  from event time; the demo uses a crafted multi-week seed. On real data the *opened*
  and *backlog* trends are live immediately; the *closed*/MTTR panels fill in once
  fixes flow through the Remediation Bridge — see the collector README.)

Point the agent's `--output` at the ingest file the stack tails and watch records
land; run the SBOM through `findings-from-events --osv --nvd --enrich` to populate
the vulnerability views. Full walk-through:
**[`deploy/collector/README.md`](deploy/collector/README.md)**.

**One command:** [`scripts/demo.sh`](scripts/demo.sh) `--reset` automates the
entire zero-agent flow (stack up → ingest pipeline + templates → bundled sample
OCSF events and findings → dashboard import) so all five dashboards are populated
to screen-record. The bundled findings carry **real, web-verified CVE data** (and
a crafted multi-week lifecycle history); the live engine path — running
`findings-from-events` yourself — is in the collector README.

**4. The wow — fire a real attack chain.** With the daemon running, trigger a
dropper-then-C2 (a suspicious file write *and* a suspicious connection from one
process) with the self-asserting demo:

```bash
cargo run --features linux-ebpf --bin corr-triple-demo    # Linux, root
cargo run --features windows-etw --bin corr-triple-demo   # Windows, Administrator
```

Watch a `class_uid: 9002` (`suspicious_process_wrote_file_and_connected`) record
land in the attack-chains panel within seconds. Other demo bins
(`procmon-ebpf-demo`, `netmon-ebpf-demo`, `filemon-demo`, `corr-file-demo`, …;
see `crates/agent/Cargo.toml`'s `[[bin]]` entries) exercise the other paths.

## Architecture

The agent is a **substrate + modules + emitter** pipeline. One shared substrate
is the **only door** to the OS: the stub bus by default, or real aya/eBPF (Linux)
and ETW (Windows) collection behind the `linux-ebpf` / `windows-etw` features.
Modules depend **only** on the `torda-core` traits — a module subscribes to the
`EventBus` or reads the `SnapshotProvider`; **no module opens a kernel probe or
queries the OS directly**. Everything on the wire is `torda_ocsf::OcsfEnvelope`. On
the backend, the Findings Engine recomputes the canonical score and the
Remediation Bridge gates every action.

## Status

**Working and live-proven today:**

- Linux (eBPF) + Windows (ETW) **process, network, and file** sensing.
- Cross-sensor **attack-chain correlation** (the `9002` rules, incl. the
  dropper-then-C2 triple and the read-secret-then-beacon exfil chain).
- Real **vulnerability detection**: SBOM (dpkg/rpm/registry) → **release-aware
  OSV** matching → **CVSS/EPSS/KEV** scoring → a fix-first CVE queue, all
  recomputed (never a source label), with known-exploited CVEs prioritized to
  act-now.
- The **Findings Engine**: one canonical explainable score, dedup, and
  **group-by-fix** across runtime + vuln + posture findings.
- **Daemon mode** with a rotating **file sink** (`--daemon` / `--output`), unified
  TOML config, and a systemd unit sample.
- A one-command **collector bundle** (OpenSearch + Dashboards + Vector) with five
  prebuilt dashboards (fix-first, vulnerability management, CVE detail, a posture /
  agent-activity overview with trends, and a findings-lifecycle view — opened vs
  closed + MTTR, from engine-generated lifecycle timestamps; the closed/MTTR half
  goes live once fixes flow through remediation).

**Honest caveats:** the collector bundle is a **DEV-preview** — it disables the
OpenSearch security plugin (no TLS, no auth) and is safe only bound to
`localhost`; **never** expose it on a network or in production (see the warning
in [`deploy/collector/README.md`](deploy/collector/README.md)). Snapshot modules
emit once at startup, config changes need a restart, and there is one sink at a
time (see [`docs/DEPLOY.md`](docs/DEPLOY.md) §5).

**Roadmap (not yet shipped):** macOS sensing, a hosted backend/console, and
production hardening (a TLS + auth OpenSearch profile, a bundled Windows service
wrapper).

## License

Two licenses, split so the part you run is fully open and the backend core is
protected from resale:

- **The agent is Apache-2.0** — the binary you install and run as root (probes,
  modules, OCSF emitter, transport/remediation client) and everything it links, plus
  the collector bundle and dashboards under `deploy/`. Read, audit, modify, run, and
  redistribute it freely. See [`LICENSE`](LICENSE).
- **The backend engine is FSL-1.1-ALv2** — the Findings Engine and ingest/scoring
  pipeline (`server/findings-engine`, `server/ingest`) are **source-available**: use,
  read, modify, and self-host for any purpose *except* offering them as a competing
  product or service. Each version **converts to Apache-2.0 two years** after release
  ([Functional Source License](https://fsl.software/)). See
  [`LICENSE-FSL-1.1.md`](LICENSE-FSL-1.1.md).

Full breakdown of which crate is under which license, and why:
[`LICENSING.md`](LICENSING.md).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). The contribution guardrails are the
project's non-negotiables: **one shared substrate** (modules never touch the
kernel), **OCSF on the wire**, **recompute findings** (never trust a source's
severity), and **remediation is a bridge, never a decider** (safety gates
mandatory). Tests gate merges.
