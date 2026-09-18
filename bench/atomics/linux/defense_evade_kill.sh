#!/usr/bin/env bash
# T1562.001 (Tier B) — attempt to kill/disable the agent. torda has no tamper
# resistance / self-protection yet, so this is an expected MISS (the gap is the
# point). Sends SIGTERM to a decoy named like the agent; NEVER kills the real
# bench agent (guarded by the TORDA_BENCH_PID the harness exports).
set -eu
guard="${TORDA_BENCH_PID:-0}"
# Only target processes that are NOT the bench's own torda instance.
for pid in $(pgrep -x torda 2>/dev/null || true); do
  [ "$pid" = "$guard" ] && continue
  kill -TERM "$pid" >/dev/null 2>&1 || true
done
