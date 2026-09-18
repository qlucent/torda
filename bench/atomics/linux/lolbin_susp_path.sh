#!/usr/bin/env bash
# T1059.004 — a LOLBin executed from a suspicious path (/tmp) → `lolbin_in_suspicious_path`
# (OCSF 1007). Uses base64 (a lolbin, always present) copied to /tmp, and keeps it
# ALIVE ~2s (encoding /dev/zero) so the substrate's /proc/<pid>/exe enrichment
# resolves the full /tmp path before the process exits — a fire-and-exit binary
# would only resolve the bare comm and miss the path half.
set -eu
cp -f "$(command -v base64)" /tmp/b64x
chmod +x /tmp/b64x
timeout 2 /tmp/b64x /dev/zero >/dev/null 2>&1 || true
