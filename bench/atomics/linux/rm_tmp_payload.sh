#!/usr/bin/env bash
# Reverse the /tmp droppers used by the lolbin-path / chain / ancestry cases.
set -eu
rm -f /tmp/nc /tmp/xtrue /tmp/dropped.bin 2>/dev/null || true
