#!/usr/bin/env bash
# T1105+T1571 — dropper writes a payload THEN beacons, from the SAME suspicious
# process, firing `suspicious_process_wrote_file_and_connected` (OCSF 9002). We use
# bash copied to /tmp/nc so (a) the image is a lolbin in /tmp (process half is
# HIGH) and (b) `-c` reliably runs the write+connect in ONE pid for the join.
set -eu
host="${SINK_LOOPBACK:-127.0.0.1}"
port="${SINK_PORT:-4444}"
cp -f "$(command -v bash)" /tmp/nc && chmod +x /tmp/nc
timeout 5 /tmp/nc -c "printf payload > /tmp/dropped.bin; exec 3<>/dev/tcp/${host}/${port}; sleep 1" 2>/dev/null || true
