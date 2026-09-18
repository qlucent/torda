#!/usr/bin/env bash
# T1547 — write to a persistence location → `write_to_persistence_location` (OCSF 1001).
set -eu
target="/etc/systemd/system/torda-bench.service"
cat > "$target" <<'UNIT'
[Unit]
Description=torda-bench persistence marker (harmless)
[Service]
ExecStart=/bin/true
UNIT
