#!/bin/bash
# One-shot bootstrap for the secure collector profile: provision a dedicated,
# least-privilege OpenSearch user for Vector so the log shipper is NOT the admin
# superuser. Runs once (via docker-compose.secure.yml), then exits.
set -euo pipefail

OS="https://opensearch:9200"
ADMIN="admin:${OPENSEARCH_ADMIN_PASSWORD}"

echo "[bootstrap] waiting for the security plugin to be ready..."
until curl -s -k -u "$ADMIN" "$OS/_plugins/_security/health" | grep -q '"status":"UP"'; do
  sleep 3
done

echo "[bootstrap] creating role torda-ingest (write to torda-* indices only)"
curl -s -k -u "$ADMIN" -X PUT "$OS/_plugins/_security/api/roles/torda-ingest" \
  -H 'Content-Type: application/json' -d '{
    "cluster_permissions": ["cluster_composite_ops", "cluster:monitor/main"],
    "index_permissions": [
      {
        "index_patterns": ["torda-ocsf-*", "torda-findings-*", "torda-remediation-*"],
        "allowed_actions": ["create_index", "crud", "indices:admin/mapping/put"]
      }
    ]
  }' >/dev/null

echo "[bootstrap] creating user torda-ingest mapped to that role"
curl -s -k -u "$ADMIN" -X PUT "$OS/_plugins/_security/api/internalusers/torda-ingest" \
  -H 'Content-Type: application/json' -d "{
    \"password\": \"${OPENSEARCH_INGEST_PASSWORD}\",
    \"opendistro_security_roles\": [\"torda-ingest\"],
    \"description\": \"Least-privilege ingest user for Vector (torda collector)\"
  }" >/dev/null

echo "[bootstrap] done — Vector will authenticate as torda-ingest, not admin."
