#!/usr/bin/env bash
# T1053.003 (Tier B) — add cron persistence AFTER boot. Historically a
# snapshot-once blind spot; P0-3 periodic refresh may now catch the write to a
# persistence location. Expected miss; a hit is scored GAP_CLOSED.
set -eu
target="/etc/cron.d/torda-bench"
printf '* * * * * root /bin/true # torda-bench-marker\n' > "$target"
