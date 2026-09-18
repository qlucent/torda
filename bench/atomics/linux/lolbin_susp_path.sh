#!/usr/bin/env bash
# T1059.004 — a LOLBin executed from a suspicious path (/tmp) → `lolbin_in_suspicious_path`
# (OCSF 1007). The /tmp copy MUST keep the lolbin BASENAME (procmon matches base
# names against LOLBINS), so it is /tmp/base64 (not a renamed copy). Kept ALIVE
# ~2s (encoding /dev/zero) so /proc/<pid>/exe enrichment resolves the /tmp path
# before exit — a fire-and-exit binary would resolve only the bare comm and miss
# the path half.
set -eu
cp -f "$(command -v base64)" /tmp/base64
chmod +x /tmp/base64
timeout 2 /tmp/base64 /dev/zero >/dev/null 2>&1 || true
