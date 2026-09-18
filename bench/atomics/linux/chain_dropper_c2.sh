#!/usr/bin/env bash
# T1105+T1571 — dropper writes a payload THEN beacons, from the SAME suspicious
# process, firing `suspicious_process_wrote_file_and_connected` (OCSF 9002). bash
# copied to /tmp/nc makes the image a lolbin-in-/tmp (process half HIGH) and lets
# `-c` run write+connect in ONE pid. The payload goes to a WATCHED path
# (/etc/cron.d) — /tmp is filemon-ignored. The connect targets the loopback
# SINKHOLE (bench_entry.sh) so it SUCCEEDS and the process stays alive; the
# trailing `:` (a builtin) stops bash exec-replacing /tmp/nc with the final
# command, so the pid keeps its suspicious image while corr correlates the
# (drain-lagged) write+connect.
set -eu
host="${SINK_LOOPBACK:-127.0.0.1}"
port="${SINK_PORT:-4444}"
cp -f "$(command -v bash)" /tmp/nc && chmod +x /tmp/nc
timeout 6 /tmp/nc -c "printf 'bench-drop' > /etc/cron.d/torda-bench-drop; exec 3<>/dev/tcp/${host}/${port}; sleep 3; :" 2>/dev/null || true
