#!/usr/bin/env bash
# T1543 — write into a system/binary directory → `write_to_system_dir` (OCSF 1001).
# filemon's SYSTEM_DIRS are /usr/bin,/usr/sbin,/bin,/sbin (not /usr/local), so we
# drop a marker into /usr/bin (removed by the cleanup) on this throwaway target.
set -eu
printf 'bench-write %s\n' "$(date +%s)" > /usr/bin/torda-bench-marker
