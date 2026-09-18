# Benchmark results

Numbers, not adjectives. Every figure here is produced by the harness in this
repo and is **reproducible** with the commands at the bottom — run it yourself.

- **Latest verified run:** 2026-09-18
- **Environment:** GCP `e2-standard-4`, Ubuntu 22.04, kernel `6.8.0-gcp` (BTF), torda
  built `--features linux-ebpf`, run privileged. Peers on the **same** image, same
  atomics, same windows, shared loopback sinkhole.
- **Commit:** the `bench/` harness + agent at merge of PR #27.

Machine-readable artifacts (`coverage.json`, `latency.json`, `ocsf_conformance.json`,
`matrix.md`) are written to `results/<timestamp>/` by every run — the tables below
are those files, transcribed.

## 1. ATT&CK detection coverage — torda

**Tier-A: 11/11 (100%)** · idle-baseline false positives: **0**

| Case | ATT&CK | Verdict | Latency (ms) |
|---|---|---|---|
| lolbin-basic | T1059 | HIT | 33 |
| lolbin-susp-path | T1059.004 | HIT | 111 |
| susp-path-exec | T1036.005 | HIT | 81 |
| c2-port-connect | T1571 | HIT | 57 |
| c2-external-beacon | T1071 | HIT | 32 |
| write-system-dir | T1543 | HIT | 22 |
| write-persistence | T1547 | HIT | 99 |
| write-sensitive-cfg | T1556 | HIT | 69 |
| read-secret | T1552.001 | HIT | 79 |
| chain-dropper-c2 | T1105+T1571 | HIT | 79 |
| chain-exfil-beacon | T1552+T1041 | HIT | 40 |

Tier-B (techniques a peer might catch that torda historically didn't) is reported
separately as the honest gap. Two flipped to **GAP_CLOSED** as agent slices
shipped: `ancestry-chain` (ancestry correlation) and `scheduled-task` (periodic
snapshot refresh) — the benchmark quantifies our own progress.

## 2. OCSF conformance — torda

**100%** of emitted records deserialize into the canonical `OcsfEnvelope` with a
known `class_uid` (validated against the real type in `crates/ocsf`). This is a
lane no OSS peer holds up, and the harness makes it a hard, reproducible number.

## 3. Peer parity (first pass)

Same atomics, same target. Peers are scored by the **exact ATT&CK technique** their
alert maps to (spec §6.1).

| Tool | Tier-A (exact technique) | Idle-baseline FP |
|---|---|---|
| **torda** | **11/11 (100%)** | **0** |
| Falco (eBPF+rules) | 0/11 | 0 |
| Wazuh (log/FIM HIDS) | 0/11 | 126 |

**Read this honestly:** the peers *did* fire alerts — strict per-technique scoring
does not credit them because Falco's default host ruleset is sparse and tags at
**tactic** granularity, and Wazuh detects the file/auth activity as coarse HIDS
categories ("integrity changed", auth) and is **noisy** (126 alerts in the idle
window). The defensible differentiator is that **torda maps precisely to specific
ATT&CK techniques with near-zero noise**. Planned fairness upgrades before we
publish this as a headline: a tactic-level secondary score (partial credit),
enriched peer rulesets, and scoping Wazuh's FIM. See `bench/peers/README.md`.

## Reproduce it

```bash
# Pure scoring loop, no agent/Docker, anywhere (incl. Windows):
cargo test -p torda-bench          # the harness's own self-tests

# Live, on a disposable privileged Linux target (eBPF):
cd bench
make bootstrap                     # build torda + torda-bench + ISOLATED sentinel
make bench-linux                   # coverage + latency + conformance -> results/<ts>/
make report                        # print the newest run's report.md

# Peer parity on the same target (see peers/README.md):
sudo bash peers/falco-setup.sh
sudo torda-bench run --peer falco --sink /var/log/falco.json --results-root results-falco
sudo WAZUH_VERSION=4.9 bash peers/wazuh-setup.sh
sudo torda-bench run --peer wazuh --sink /var/ossec/logs/alerts/alerts.json --results-root results-wazuh
```

`torda-bench score` exits non-zero if any Tier-A case is not `HIT`, so the 100%
claim is a gate, not a footnote.
