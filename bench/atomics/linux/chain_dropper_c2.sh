#!/usr/bin/env bash
# T1105+T1571 — dropper writes a payload THEN beacons, from the SAME process, so
# torda's cross-sensor correlation fires `suspicious_process_wrote_file_and_connected`
# (OCSF 9002). Runs the lolbin-in-/tmp so the process half is suspicious.
set -eu
host="${SINK_LOOPBACK:-127.0.0.1}"
port="${SINK_PORT:-4444}"
src="$(command -v nc || command -v xxd || command -v base64)"
cp -f "$src" /tmp/nc && chmod +x /tmp/nc
# One shell process: write a payload file, then connect out — same pid for the join.
timeout 5 /tmp/nc -c "printf payload > /tmp/dropped.bin; exec 3<>/dev/tcp/${host}/${port}" 2>/dev/null \
  || timeout 5 bash -c "printf payload > /tmp/dropped.bin; exec 3<>/dev/tcp/${host}/${port}" 2>/dev/null \
  || true
