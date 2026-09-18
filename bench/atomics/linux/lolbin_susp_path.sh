#!/usr/bin/env bash
# T1059.004 — a LOLBin executed from a suspicious path (/tmp). Copy a lolbin (nc,
# else xxd/base64) into /tmp and run it → `lolbin_in_suspicious_path` (OCSF 1007).
set -eu
src="$(command -v nc || command -v xxd || command -v base64)"
cp -f "$src" /tmp/nc
chmod +x /tmp/nc
# Run it briefly; --help/-h keeps it bounded and needs no network.
/tmp/nc -h >/dev/null 2>&1 || /tmp/nc --help >/dev/null 2>&1 || true
