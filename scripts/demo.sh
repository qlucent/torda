#!/usr/bin/env bash
#
# demo.sh — stand up the torda collector bundle and populate all four
# dashboards from bundled sample data, end to end, with no agent required. This
# is the zero-agent "wow" path (README quickstart step 3 / collector README) made
# one command, so you can screen-record the result.
#
#   Usage:  scripts/demo.sh [--reset]
#     --reset   tear the stack down (docker compose down -v) first, for a clean
#               run — recommended before recording so count tiles don't inflate.
#
# Prerequisites: docker (with compose), curl, and a Rust toolchain (cargo). Run
# it from anywhere; it locates the repo root itself. It only touches the local
# DEV-preview stack on localhost — see the security note in
# deploy/collector/README.md. NEVER expose that stack on a network.
#
# What it does NOT do: record the GIF/asciinema (that's your step) and it does
# not exercise the real eBPF/ETW agent (that needs a privileged Linux/Windows
# host — see the quickstart). This is the viewing side, fed by bundled samples.

set -euo pipefail

# --- locate the repo + collector dirs (works regardless of CWD) --------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COLLECTOR="$REPO_ROOT/deploy/collector"
OS_URL="http://localhost:9200"
OSD_URL="http://localhost:5601"

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$1"; }
die()  { printf '\033[1;31mERROR: %s\033[0m\n' "$1" >&2; exit 1; }

for tool in docker curl cargo; do
  command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done
[ -d "$COLLECTOR" ] || die "collector dir not found: $COLLECTOR"

cd "$COLLECTOR"

# --- optional clean slate ----------------------------------------------------
if [ "${1:-}" = "--reset" ]; then
  step "Reset: docker compose down -v (clean slate)"
  docker compose down -v || true
fi

# --- 1. start the stack ------------------------------------------------------
step "1/6 Starting the collector stack (OpenSearch + Dashboards + Vector)"
docker compose up -d

step "Waiting for OpenSearch to report healthy (up to ~3 min on first pull)"
for i in $(seq 1 90); do
  status="$(curl -s "$OS_URL/_cluster/health" 2>/dev/null | grep -o '"status":"[a-z]*"' || true)"
  case "$status" in
    *green*|*yellow*) echo "  OpenSearch: $status"; break ;;
  esac
  [ "$i" = 90 ] && die "OpenSearch did not become healthy in time"
  sleep 2
done

# --- 2. apply the ingest pipeline + index templates (BEFORE any data) --------
step "2/6 Applying the MTTR ingest pipeline + index templates"
# The findings template sets default_pipeline: torda-findings-mttr, so the
# pipeline must exist before any finding is indexed (it derives mttr_days for the
# lifecycle dashboard from the engine's first_seen/closed_at).
curl -sf -XPUT "$OS_URL/_ingest/pipeline/torda-findings-mttr" \
  -H 'Content-Type: application/json' \
  --data-binary @opensearch/findings-mttr-pipeline.json >/dev/null
curl -sf -XPUT "$OS_URL/_index_template/torda-ocsf" \
  -H 'Content-Type: application/json' \
  --data-binary @opensearch/index-template.json >/dev/null
curl -sf -XPUT "$OS_URL/_index_template/torda-findings" \
  -H 'Content-Type: application/json' \
  --data-binary @opensearch/findings-index-template.json >/dev/null
curl -sf -XPUT "$OS_URL/_index_template/torda-remediation" \
  -H 'Content-Type: application/json' \
  --data-binary @opensearch/remediation-index-template.json >/dev/null
echo "  pipeline + templates applied"

# --- 3. stage the sample OCSF events -----------------------------------------
step "3/6 Staging sample OCSF events into the Vector ingest path"
mkdir -p ingest
cp events.sample.ndjson ingest/events.ndjson
echo "  $(wc -l < ingest/events.ndjson) events staged"

# --- 4. stage the findings (crafted seed with ~4 weeks of lifecycle history) ---
step "4/6 Staging findings (crafted ~4-week lifecycle seed)"
cp findings.sample.ndjson ingest/findings.ndjson
cp remediation.sample.ndjson ingest/remediation.ndjson
echo "  $(wc -l < ingest/findings.ndjson) findings, $(wc -l < ingest/remediation.ndjson) fix-first rows"
echo "  NOTE: the LIVE engine path is 'findings-from-events --osv --nvd --enrich'"
echo "  (collector README §3b-3e). It stamps lifecycle timestamps from event time, but a"
echo "  one-shot demo run stamps everything at 'now' — so this bundled seed supplies the"
echo "  multi-week opened/closed history the lifecycle dashboard charts. Same engine schema."

# --- 5. wait for Vector to index ---------------------------------------------
step "5/6 Waiting for Vector to index events + findings"
for i in $(seq 1 60); do
  n="$(curl -s "$OS_URL/torda-findings-*/_count" 2>/dev/null | grep -o '"count":[0-9]*' | grep -o '[0-9]*' || echo 0)"
  [ "${n:-0}" -gt 0 ] && { echo "  findings indexed: $n"; break; }
  [ "$i" = 60 ] && echo "  (findings not yet visible; Vector may still be catching up)"
  sleep 2
done

# --- 6. import the dashboards ------------------------------------------------
step "6/6 Importing the four prebuilt dashboards"
curl -sf -X POST "$OSD_URL/api/saved_objects/_import?overwrite=true" \
  -H "osd-xsrf: true" \
  --form file=@dashboards/dashboards.ndjson >/dev/null
echo "  dashboards imported"

# --- done --------------------------------------------------------------------
step "Done — open the dashboards"
cat <<EOF

  Open  ${OSD_URL}  ->  Dashboards  (four ship with a 1-year time range):
    - Findings — fix-first
    - Vulnerability Management
    - Vulnerability details
    - Security posture & agent activity

  Counts:
    events:      $(curl -s "$OS_URL/torda-ocsf-*/_count"        | grep -o '"count":[0-9]*' | grep -o '[0-9]*' || echo '?')
    findings:    $(curl -s "$OS_URL/torda-findings-*/_count"    | grep -o '"count":[0-9]*' | grep -o '[0-9]*' || echo '?')
    remediation: $(curl -s "$OS_URL/torda-remediation-*/_count" | grep -o '"count":[0-9]*' | grep -o '[0-9]*' || echo '?')

  Tear down when finished:  (cd deploy/collector && docker compose down -v)
EOF
