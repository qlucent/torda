# Contributing

This project aims to be a best-in-class open-source security agent that
solves real problems for both engineering and ops teams. Contributions
across platforms (Linux/macOS/Windows), modules, and the backend are
welcome.

## Repo layout

The repo root **is** the Cargo workspace — run every `cargo` command from the
repo root, and all relative paths in this guide (`crates/...`, `docs/...`,
`server/...`) are relative to it.

## License of contributions

This project is dual-licensed (see [`LICENSING.md`](LICENSING.md)): the agent and
everything it links is **Apache-2.0**, and the backend engine
(`server/findings-engine`, `server/ingest`) is **FSL-1.1-ALv2**. By submitting a
contribution you agree to license it under the same license as the crate you're
changing — Apache-2.0 for an Apache crate, FSL-1.1-ALv2 for an FSL crate. Keep the
license boundary intact: **no Apache-licensed crate may take a dependency on an FSL
crate** (it would pull the agent under FSL).

## Build, test, lint

```bash
cargo build                       # build the whole workspace (default stub substrate)
cargo test                        # all tests
cargo test -p torda-substrate        # tests for one crate
cargo run                         # run the P0 agent: emits OCSF NDJSON to stdout, logs to stderr
cargo clippy --all-targets        # lint — CI runs this with -D warnings
cargo fmt                         # format
```

The default build has no real kernel backend — it runs a stub event bus and
stub snapshot tables, so you can build and test without root/Administrator
or any platform toolchain. To exercise a real probe, add a feature:

```bash
cargo build --release --features linux-ebpf     # Linux — needs a recent kernel; run as root/CAP_BPF+CAP_PERFMON
cargo build --release --features windows-etw    # Windows — run as Administrator
```

CI (`.github/workflows/ci.yml`) currently gates only the default (stub)
build on `ubuntu-latest` (+ a nice-to-have `windows-latest` leg): `fmt
--check`, `clippy --all-targets -D warnings`, `build --workspace`, `test
--workspace`. Feature-gated `linux-ebpf`/`windows-etw` CI legs are a
documented follow-up — they need a
nightly+bpf-linker toolchain or an elevated runner that CI v1 doesn't have.

## Running a module or demo

Each capability module usually ships a small self-asserting demo binary
under `crates/agent/src/bin/` (see the `[[bin]]` entries in
`crates/agent/Cargo.toml`) that proves the module against either a
synthetic `StubBus` or a real kernel backend:

```bash
cargo run --bin procmon-demo                              # StubBus, no privilege needed
cargo run --features linux-ebpf --bin procmon-ebpf-demo   # real eBPF, run as root in WSL/Linux
cargo run --features windows-etw --bin etw-demo           # real ETW, run as Administrator
```

Without the feature or the required privilege, these fail soft to the stub
bus and exit 0 rather than crash — that's by design (see `README.md`'s
Quickstart and `docs/DEPLOY.md`).

To see the attack-chain correlation the project is differentiated on, the
fastest path is the collector bundle in `deploy/collector/` (see its
README) plus `cargo run --features linux-ebpf --bin corr-triple-demo` (or
the `windows-etw` equivalent).

## Non-negotiable rules (PRs that violate these will be asked to change)

A PR is expected to hold these even if the change looks small:

1. **Keep changes scoped.** If your change is bigger than the issue calls
   for, say so in the PR rather than quietly expanding scope.
2. **Deterministic core. No LLM and no network call in any hot path.**
3. **Shared substrate only.** Every capability implements the `Module` trait
   in `torda-core`. A module subscribes to `EventBus` or reads
   `SnapshotProvider` — it **never** opens a kernel probe or queries the OS
   directly. The substrate (`crates/substrate`) is the only door. If a
   change makes a module collect its own kernel data, it will be rejected —
   this is the "one light agent" invariant.
4. **OCSF on the wire.** Modules emit `torda_ocsf::OcsfEnvelope`. The backend
   never re-parses an ad-hoc format.
5. **Findings: never trust a source's severity label.** Always recompute the
   canonical score and persist every input so the score stays explainable.
6. **Remediation is a bridge, never a decider.** No code path applies a fix
   the user didn't author and trigger. The safety gates (sign, dry-run,
   canary, rollback, kill switch, audit) are mandatory.
7. **Tests gate merges.** Golden-vector tests for substrate + Findings
   Engine changes; integration tests for ingest → score → decide → verify
   changes. New behavior needs a test vector, not just a manual check.

## Definition of done per change

- `cargo build` and `cargo test` green (from the repo root).
- `cargo fmt` and `cargo clippy --all-targets` clean.
- New behavior covered by a test vector.
- No module reaches outside the substrate.
- Public traits documented; safety-relevant code has an audit log line.

## Sending a PR

Open the PR against `main` and fill in
[`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md) — it
mirrors the Definition of Done above and asks which architecture invariants
your change touches. Small, reviewable PRs scoped to one phase/module are
much easier to land than large ones that cross several at once.

## Reporting a vulnerability

Do not open a public issue for a security vulnerability — see
[`SECURITY.md`](SECURITY.md).

## Good first issues

- Real package providers for `SnapshotProvider` (dpkg/rpm/pacman/brew/registry).
- EPSS/KEV feed sync for the enrichment step in `server/findings-engine`.
- Additional OCSF class mappings in `crates/ocsf`.
