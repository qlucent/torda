#!/usr/bin/env bash
# Reverse the droppers used by the lolbin-path / susp-path / chain / ancestry cases.
set -eu
rm -f /tmp/nc /tmp/xtrue /tmp/xsleep /tmp/base64 /tmp/dropped.bin \
      /etc/cron.d/torda-bench-drop 2>/dev/null || true
