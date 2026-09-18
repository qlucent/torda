#!/usr/bin/env bash
# T1543 — write into a system directory → `write_to_system_dir` (OCSF 1001).
set -eu
target="/usr/local/lib/torda-bench-marker"
printf 'bench-write %s\n' "$(date +%s)" > "$target"
