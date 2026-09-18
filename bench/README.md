# torda-bench

A repeatable, framework-anchored evaluation of the **torda** agent (eBPF/ETW →
OCSF) against a peer OSS EDR (Wazuh), plus vuln-scoring accuracy vs Grype/Trivy.

**Open by design (Apache-2.0).** A benchmark is only worth anything if anyone can
reproduce it — so this is a workspace member of the public agent repo, links
`torda-ocsf` for the *real* envelope + class UIDs (no hand-copied table to drift),
and doubles as the agent's detection-regression suite.

Ground truth is **declared, not inferred**: every case in `config/techniques.toml`
states the ATT&CK technique it exercises and the OCSF class + torda rule that
*should* fire. Scoring compares captured OCSF against that — never a tool's own
opinion of what it saw.

## Quick start

```bash
# 1. Prove the scoring loop with NO agent/Docker (runs anywhere, incl. Windows):
make selftest                         # == cargo test -p torda-bench

# Score an existing capture (offline):
cargo run -p torda-bench -- score --captures tests/fixtures/captures_synthetic.json

# 2. Live Linux run (privileged target, real eBPF — Linux host / GCP VM):
make bootstrap                        # build target image (torda + torda-bench + sentinel)
make bench-linux                      # coverage + latency + conformance -> results/<run>/
make report                           # print the newest run's report.md
```

## CLI

```
torda-bench score --registry <t.toml> --captures <c.json> [--out-dir <d>]
torda-bench run   --registry <t.toml> --sink <ndjson> [--tier AB] [--platform linux]
                  [--results-root results] [--no-isolate] [--no-preflight]
```

`score` is pure (the self-test path). `run` executes atomics and must run inside
an isolated target with a live, privileged torda streaming to `--sink`. `score`
exits non-zero if any Tier-A case is not `HIT`, so `make`/CI can gate on it.

## What it measures (spec §2)

| # | Dimension | Metric | Status |
|---|-----------|--------|--------|
| 1 | ATT&CK detection coverage | % Tier-A techniques with a correct OCSF record | **built** (`score`) |
| 2 | Detection latency | median / p95 time-to-record per class | **built** (`latency`) |
| 5 | OCSF conformance | % records that deserialize into the real `OcsfEnvelope` | **built** (`conformance`) |
| — | Peer parity (Wazuh) | side-by-side matrix | TODO §11.4 |
| 4 | Vuln-scoring accuracy | precision/recall + KEV + release-aware | TODO §11.7 |
| 3/6 | Footprint & eBPF overhead | cpu/mem/dropped-event % | TODO §11.8 |

## Tiers (the honest gap)

- **Tier A** — detections torda claims today; these produce the coverage %.
- **Tier B** — techniques peer tools catch that torda historically didn't. A
  Tier-B case that now fires is scored **GAP_CLOSED** — e.g. `ancestry-chain`
  after the P0-1 ancestry-correlation slice. The harness reports improvements, it
  doesn't hide them.

Verdicts (spec §6.1): `HIT` / `MISS` / `PARTIAL` (right class, wrong rule) / FP
attribution for Tier A; `GAP` / `GAP_CLOSED` for Tier B.

## Layout

```
config/techniques.toml   the ATT&CK registry (declared ground truth) — the heart
src/                     model, capture, score, latency, conformance, report + CLI
atomics/linux/           one idempotent, self-reversing script per technique
images/                  ubuntu + rocky privileged targets (build torda + harness)
scripts/bench_entry.sh   in-target: start torda, run the suite
tests/fixtures/          the synthetic capture the self-test scores
results/<run>/           run artifacts (matrix.md, *.json, report.md)
```

## Validation

- `make selftest` is fully validated on any machine (pure Rust; links `torda-ocsf`,
  scores a synthetic `captures.json` covering every verdict). It's the fast
  regression gate and the spec §11.2 "prove the loop works" milestone.
- The live `bench-*` paths need a **privileged Linux host** (eBPF loads against the
  host kernel; CI can't prove it — the feature build is fail-soft to a stub). A
  `preflight` fires one known-good atomic and aborts if nothing lands, so a
  mis-built/unprivileged agent fails loudly instead of false-MISSing the suite.

## Isolation (non-negotiable, spec §0)

Atomics run **only** inside a disposable target carrying `/etc/torda-bench/ISOLATED`
(baked into the images, never on the control host); `run` refuses without it
(`--no-isolate` to override). No atomic reaches the network outside the isolated
subnet — C2 tests target a local sinkhole / TEST-NET address, never the internet.

## Conformance validator

Conformance = a record **deserializes into the real `torda_ocsf::OcsfEnvelope`**
(all required attributes present + typed) AND its `class_uid` is one the agent
emits. Because it links the real type, the check tracks the agent's contract with
no schema to drift. Upgrading to the upstream per-class OCSF JSON-schema is a
tracked follow-up; the interface (per-class pass% + violations) stays.

Full design + build order: `torda-benchmark-spec.md` (repo root of the spec).
