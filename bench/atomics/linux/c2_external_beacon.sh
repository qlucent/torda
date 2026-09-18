#!/usr/bin/env bash
# T1071 — beacon to an EXTERNAL host on a suspicious port → `suspicious_port_to_external`
# (OCSF 4001). Dest defaults to TEST-NET-3 (203.0.113.0/24), which is non-RFC1918
# (so netmon classifies it external) AND unroutable (so nothing leaves the subnet).
# In a wired bench, point SINK_EXTERNAL at the sinkhole VM's address instead.
set -eu
host="${SINK_EXTERNAL:-203.0.113.10}"
port="${SINK_PORT:-4444}"
timeout 3 bash -c "exec 3<>/dev/tcp/${host}/${port}" 2>/dev/null || true
