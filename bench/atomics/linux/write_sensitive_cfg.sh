#!/usr/bin/env bash
# T1556 — write to a sensitive config file → `write_to_sensitive_config` (OCSF 1001).
# Appends a harmless comment to sshd_config (reversed by the cleanup).
set -eu
target="/etc/ssh/sshd_config"
[ -f "$target" ] || { mkdir -p /etc/ssh; : > "$target"; }
printf '# torda-bench-marker %s\n' "$(date +%s)" >> "$target"
