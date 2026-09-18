#!/usr/bin/env bash
# T1003.007 (Tier B) — credential dump via /proc scraping. torda does not analyze
# /proc memory reads, so this is an expected MISS. Best-effort trigger: read a
# victim's memory map + mem (bounded).
set -eu
sleep 30 &
victim=$!
cat "/proc/${victim}/maps" >/dev/null 2>&1 || true
timeout 2 dd if="/proc/${victim}/mem" of=/dev/null bs=1 count=64 2>/dev/null || true
kill "$victim" >/dev/null 2>&1 || true
