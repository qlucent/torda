#!/usr/bin/env bash
# T1055 (Tier B) — process injection. torda has no memory/injection sensor, so this
# is an expected MISS (it quantifies the gap peer tools cover with injection
# analytics). Best-effort trigger: ptrace-attach a victim via gdb and poke memory.
set -eu
sleep 30 &
victim=$!
if command -v gdb >/dev/null 2>&1; then
  gdb -p "$victim" -batch \
    -ex 'call (void*)mmap(0,4096,7,0x22,-1,0)' \
    -ex detach -ex quit >/dev/null 2>&1 || true
fi
kill "$victim" >/dev/null 2>&1 || true
