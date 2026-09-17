#!/usr/bin/env bash
# Validate the eBPF process-event enrichment (full exe path + cmdline) end to end
# on a REAL single-PID-namespace Linux (bare metal or a normal VM — NOT WSL2,
# whose per-distro PID namespaces don't match the kernel's eBPF PIDs).
#
# Run as root (eBPF load needs it):  sudo bash scripts/validate-ebpf-enrichment.sh
# Assumes the agent is already built with the linux-ebpf feature; set TORDA_BIN to
# override the path (default: ./target/debug/torda).
set -u

BIN="${TORDA_BIN:-./target/debug/torda}"
OUT="$(mktemp /tmp/torda-ebpf.XXXX.ndjson)"
LOG="$(mktemp /tmp/torda-ebpf.XXXX.log)"

if [[ $EUID -ne 0 ]]; then echo "must run as root (sudo) to load eBPF"; exit 2; fi
if [[ ! -x "$BIN" ]]; then
  echo "agent binary not found/executable at: $BIN"
  echo "build first:  cargo build -p torda --features linux-ebpf"
  exit 2
fi

echo "== starting agent (eBPF daemon) =="
"$BIN" --daemon --output "$OUT" >"$LOG" 2>&1 &
AGENT=$!
sleep 3

grep -qi "ebpf event bus" "$LOG" \
  && echo "  eBPF bus loaded OK" \
  || { echo "  !! eBPF bus did NOT load (see below) — need root + a BTF kernel"; grep -i "substrate\|bus\|ebpf\|stub" "$LOG" | head; }

echo "== triggering LOLBin execs (long-lived so /proc enrichment can read them) =="
sleep 3 &                                             # benign: full path + cmdline
sleep 3 | timeout 5 base64 --decode >/dev/null 2>&1 & # base64 (lolbin) blocks ~3s; cmdline 'base64 --decode'
timeout 3 nc -l 9098 </dev/null >/dev/null 2>&1 &     # nc (lolbin) listens ~3s
sleep 4
kill "$AGENT" 2>/dev/null; wait "$AGENT" 2>/dev/null

echo
echo "== RESULTS =="
total=$(grep -c '"class_uid":1007' "$OUT" 2>/dev/null || echo 0)
withcmd=$(grep -c '"cmdline"' "$OUT" 2>/dev/null || echo 0)
fullpath=$(grep -o '"image":"/[^"]*"' "$OUT" 2>/dev/null | sort -u | wc -l)
rulehit=$(grep -c 'lolbin_suspicious_cmdline' "$OUT" 2>/dev/null || echo 0)
echo "Process Activity (1007) events : $total"
echo "events carrying cmdline        : $withcmd"
echo "distinct full-path images      : $fullpath"
echo "lolbin_suspicious_cmdline hits : $rulehit"
echo
echo "-- sample enriched exec (base64) --"
grep '"class_uid":1007' "$OUT" | grep '"activity":"exec"' | grep 'base64' | head -1
echo "-- sample full-path images --"
grep -o '"image":"/[^"]*"' "$OUT" | sort -u | head -8
echo
if [[ "$withcmd" -gt 0 && "$fullpath" -gt 0 && "$rulehit" -gt 0 ]]; then
  echo "PASS: enrichment populated (cmdline + full path) and lolbin_suspicious_cmdline fired."
else
  echo "CHECK: enrichment not fully observed — inspect $OUT and $LOG."
fi
echo "(raw output: $OUT ; log: $LOG)"
