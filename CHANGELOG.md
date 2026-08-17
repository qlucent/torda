# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_Nothing yet._

## [0.1.0] — 2026-07-20

First public release: an open-source, OCSF-native endpoint security agent with a
deterministic detection core, a fix-first findings engine, and a one-command
collector bundle you can point at your own SIEM.

### Added

- **Substrate + modules + emitter pipeline.** One shared substrate is the only
  door to the OS; detection modules depend solely on the `torda-core` traits
  (`EventBus` / `SnapshotProvider`) and never touch the kernel directly. The
  emitter is a clean seam (stdout/file today, transport later).
- **Real endpoint sensing** behind platform features: **eBPF on Linux**
  (`--features linux-ebpf`, aya) and **ETW on Windows** (`--features
  windows-etw`), covering process, network, and file activity. The default build
  runs a stub bus (no kernel backend) and fails soft when a probe can't be opened.
- **Deterministic detection rules**, one OCSF class per sensor: process activity
  (`1007`), network activity (`4001`), file system activity (`1001`).
- **Cross-sensor attack-chain correlation** (`9002`), each an AND of independently
  suspicious halves — including the dropper-then-C2 chain
  (`suspicious_process_wrote_file_and_connected`) and the read-secret-then-beacon
  exfil chain (`suspicious_process_read_sensitive_and_connected`).
- **Real vulnerability detection.** An SBOM built from installed packages
  (dpkg / rpm / Windows registry) emitted as OCSF `5020`, matched **release-aware**
  against **OSV** advisories (a Debian host only against Debian's fixed versions,
  Ubuntu against Ubuntu's) with faithful dpkg/rpm/semver version comparison.
- **Findings Engine.** One canonical, explainable score recomputed from real
  **CVSS + EPSS + CISA KEV** inputs — never a source's own severity label — with a
  known-exploited (KEV) CVE driven to act-now regardless of its numeric score.
  Findings are deduped and **grouped by fix**, producing a short remediation
  queue instead of a wall of rows.
- **Daemon mode** with a rotating file sink (`--daemon` / `--output`), a unified
  TOML config with CLI/env override, and a sample systemd unit.
- **Collector bundle** (`deploy/collector/`): a one-command Docker Compose stack —
  OpenSearch + OpenSearch Dashboards + Vector — with five prebuilt dashboards:
  Findings (fix-first), Vulnerability Management, Vulnerability details (row-level,
  filterable, CSV-exportable), Security posture & agent activity (with trends), and
  Findings lifecycle (opened vs closed per week, open backlog, MTTR).
- **Findings lifecycle timestamps**: the engine stamps `first_seen`/`last_seen`/
  `closed_at` (from event time — deterministic) so opened-vs-closed and MTTR are
  chartable; the collector derives `mttr_days` via an ingest pipeline.
- **Install packages**: prebuilt `.deb` + `.rpm` (Linux, eBPF backend) and `.msi`
  (Windows, ETW backend) built and attached to each `v*` GitHub Release, alongside
  the raw binaries.
- **Split licensing**: the **agent is Apache-2.0** (the binary you run + everything
  it links + the collector/dashboards); the **backend engine** (`findings-engine`,
  `ingest`) is **FSL-1.1-ALv2** — source-available, non-compete, converting to
  Apache-2.0 after two years. See `LICENSING.md`.
- **Community health**: `SECURITY.md`, code of conduct, contributing guide, issue/PR
  templates, and CI (fmt + clippy + build + test).

### Security / notes

- The collector bundle is a **DEV-preview**: it disables the OpenSearch security
  plugin (no TLS, no auth) and is safe only bound to `localhost`. **Never** expose
  it on a network or in production. See `deploy/collector/README.md`.
- Loading eBPF/ETW is privileged — run the agent as root (or with
  `CAP_BPF`+`CAP_PERFMON`) on Linux, or as Administrator on Windows.

### Known limitations

- Snapshot modules emit once at startup; config changes need a restart; one sink
  at a time. macOS sensing, a hosted backend/console, and a TLS+auth OpenSearch
  profile are on the roadmap.

[Unreleased]: https://github.com/qlucent/torda/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/qlucent/torda/releases/tag/v0.1.0
