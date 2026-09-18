#!/usr/bin/env bash
# Strip the marker lines this bench appended to sshd_config (leave the rest intact).
set -eu
target="/etc/ssh/sshd_config"
[ -f "$target" ] || exit 0
grep -v 'torda-bench-marker' "$target" > "${target}.tbclean" 2>/dev/null || true
mv "${target}.tbclean" "$target" 2>/dev/null || true
