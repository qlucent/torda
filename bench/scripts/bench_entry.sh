#!/usr/bin/env bash
# In-target entrypoint for a Linux run: start the torda daemon streaming to the
# sink, then run the technique suite against it with the torda-bench harness.
# Invoked inside the privileged target container by `make bench-linux`.
set -eu
cd "$(dirname "$0")/.."   # -> bench/
SINK="${SINK:-/var/log/torda/bench.ndjson}"
TIER="${TIER:-AB}"
mkdir -p "$(dirname "$SINK")"
: > "$SINK"

torda --config config/torda.toml --output "$SINK" &
TORDA_PID=$!
export TORDA_BENCH_PID="$TORDA_PID"   # so the tamper case never kills our own agent
trap 'kill "$TORDA_PID" 2>/dev/null || true' EXIT

sleep 5   # let the eBPF backend attach before the first atomic
torda-bench run --registry config/techniques.toml --sink "$SINK" --tier "$TIER"
