#!/usr/bin/env bash
# T1036.005 — a NON-lolbin executed from a suspicious path. Copy a benign binary
# into /tmp and run it → `suspicious_path` (OCSF 1007), without the lolbin family.
set -eu
cp -f "$(command -v true)" /tmp/xtrue
chmod +x /tmp/xtrue
/tmp/xtrue || true
