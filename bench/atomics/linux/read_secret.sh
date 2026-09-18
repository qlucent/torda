#!/usr/bin/env bash
# T1552.001 — read a sensitive/secret file → `read_of_sensitive_file` (OCSF 1001).
set -eu
cat /etc/shadow >/dev/null 2>&1 || cat /etc/gshadow >/dev/null 2>&1 || true
