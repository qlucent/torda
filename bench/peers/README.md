# Peer parity

Score a peer EDR against the **same** `config/techniques.toml`, on the **same**
target, over the **same** windows — a side-by-side ATT&CK matrix (spec §5). A peer
emits neither OCSF nor torda rule names, so it is scored by the **ATT&CK technique**
its alert maps to (`torda-bench run --peer …`, `src/peer.rs`).

## Peer set (why these)

| Tool | Class | Why | Technique source |
|------|-------|-----|------------------|
| **Wazuh** | OSS SIEM/HIDS agent | The popular OSS endpoint agent; log + FIM + rootcheck + (with auditd) exec | `rule.mitre.id` (explicit technique ids) |
| **Falco** | OSS eBPF runtime security (CNCF) | The **closest architectural peer** — eBPF syscalls + a rules engine, like torda | ATT&CK tags on rules |

Deliberately **excluded** from the *public, reproducible* benchmark: commercial
EDRs (CrowdStrike/SentinelOne/Defender) — their EULAs typically forbid published
benchmarks and they cannot ship reproducibly. `osquery` belongs to the *footprint*
dimension (it is telemetry, not a detection-rule engine on its own).

## Run it (on a disposable Linux target)

```bash
# Wazuh
sudo WAZUH_VERSION=4.9 bash peers/wazuh-setup.sh
sudo torda-bench run --peer wazuh --registry config/techniques.toml \
  --sink /var/ossec/logs/alerts/alerts.json --results-root results-wazuh

# Falco
sudo bash peers/falco-setup.sh
sudo torda-bench run --peer falco --registry config/techniques.toml \
  --sink /var/log/falco.json --results-root results-falco
```

Run torda's own suite (`scripts/bench_entry.sh`) on the **same** image for the
apples-to-apples comparison, then read the three `matrix.md` files side by side.

## Fairness

Stock community rulesets, pinned by version; no tuning up torda or down the peer
(spec §5). Wazuh does no syscall-level network correlation and needs auditd for
exec visibility, so a low score on the eBPF-style cases is the honest measurement
of a log/FIM HIDS vs an eBPF agent — that gap **is** the result.
