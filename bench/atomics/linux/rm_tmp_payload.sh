#!/usr/bin/env bash
# Reverse the /tmp droppers used by the lolbin-path / susp-path / chain / ancestry cases.
set -eu
rm -f /tmp/nc /tmp/xtrue /tmp/xsleep /tmp/b64x /tmp/dropped.bin 2>/dev/null || true
