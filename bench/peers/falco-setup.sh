#!/usr/bin/env bash
# Falco (CNCF) — the closest architectural peer to torda: eBPF syscall monitoring +
# a rules engine, ATT&CK-tagged rules, OSS. Standalone (no manager); writes JSON
# alerts to a file the harness scores by technique. `modern-bpf` needs no driver on
# kernel 5.8+, so this runs cleanly on a stock GCP Ubuntu image.
set -eu
export DEBIAN_FRONTEND=noninteractive

echo "=== install falco (modern-bpf, non-interactive) ==="
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc \
  | gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" \
  > /etc/apt/sources.list.d/falcosecurity.list
# Preseed the driver choice so the package postinst never prompts.
echo "falco falco/driver_choice select modern-bpf" | debconf-set-selections
apt-get update -qq
apt-get install -y -qq falco >/dev/null

echo "=== run falco (modern eBPF via config override) → JSON at /var/log/falco.json ==="
pkill -f 'falco ' 2>/dev/null || true
sleep 1
# Current Falco selects the driver via `engine.kind` (the old `--modern-bpf` CLI
# flag was removed). modern_ebpf is CO-RE — no kernel headers/driver build needed.
falco -o engine.kind=modern_ebpf \
  -o json_output=true \
  -o file_output.enabled=true \
  -o file_output.filename=/var/log/falco.json \
  -o file_output.keep_alive=true \
  -o stdout_output.enabled=false \
  >/var/log/falco.stderr 2>&1 &
sleep 6
echo -n "falco: "
if pgrep -f 'falco ' >/dev/null; then echo running; else echo "NOT running"; tail -8 /var/log/falco.stderr; fi
