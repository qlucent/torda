#!/usr/bin/env bash
# T1571 — connect to a known-suspicious C2 port. Targets the LOCAL bench sinkhole
# (never the internet). The connect(2) intent fires `suspicious_port` (OCSF 4001)
# whether or not the sinkhole accepts. Bounded by `timeout`.
set -eu
host="${SINK_LOOPBACK:-127.0.0.1}"
port="${SINK_PORT:-4444}"
timeout 3 bash -c "exec 3<>/dev/tcp/${host}/${port}" 2>/dev/null || true
