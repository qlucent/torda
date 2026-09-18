#!/usr/bin/env bash
# T1036.005 — a NON-lolbin executed from a suspicious path → `suspicious_path`
# (OCSF 1007), without the lolbin family. Uses `sleep` (not a lolbin) copied to
# /tmp and kept alive ~2s so /proc enrichment resolves the /tmp path.
set -eu
cp -f "$(command -v sleep)" /tmp/xsleep
chmod +x /tmp/xsleep
/tmp/xsleep 2 || true
