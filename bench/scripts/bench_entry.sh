#!/usr/bin/env bash
# In-target entrypoint for a Linux run: start a loopback SINKHOLE (so C2/chain
# connects SUCCEED and the acting process stays alive to be correlated — a refused
# connect makes bash exit immediately, losing the process context before its
# drain-lagged connect/write are correlated), then the torda daemon streaming to
# the sink, then the technique suite. Invoked inside the privileged target by
# `make bench-linux`.
set -eu
cd "$(dirname "$0")/.."   # -> bench/
SINK="${SINK:-/var/log/torda/bench.ndjson}"
TIER="${TIER:-AB}"
SINK_PORT="${SINK_PORT:-4444}"
export SINK_PORT
mkdir -p "$(dirname "$SINK")"
: > "$SINK"

# Loopback sinkhole on SINK_PORT: one long-lived python listener that accepts +
# discards every connection. python (not nc/ncat/socat) is deliberately used so
# the sinkhole itself is NOT a lolbin — it must not add process-detection noise to
# the capture windows.
python3 -c "
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', ${SINK_PORT})); s.listen(128)
while True:
    try:
        c, _ = s.accept(); c.close()
    except Exception:
        pass
" &
SINK_NC_PID=$!

torda --config config/torda.toml --output "$SINK" &
TORDA_PID=$!
export TORDA_BENCH_PID="$TORDA_PID"   # so the tamper case never kills our own agent
trap 'kill "$TORDA_PID" "$SINK_NC_PID" 2>/dev/null || true' EXIT

sleep 5   # let the eBPF backend attach before the first atomic
torda-bench run --registry config/techniques.toml --sink "$SINK" --tier "$TIER"
