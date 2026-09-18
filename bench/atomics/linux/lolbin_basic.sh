#!/usr/bin/env bash
# T1059 — execute a living-off-the-land binary. base64 is in torda's LOLBINS set,
# so this exec alone should fire the `lolbin` rule (OCSF 1007).
set -eu
base64 /etc/hostname >/dev/null 2>&1 || true
