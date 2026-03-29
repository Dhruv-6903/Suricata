#!/usr/bin/env bash
# =============================================================================
# maintain.sh
# Module 11: Maintenance tasks – rule updates, log monitoring,
# index retention, and backup of dashboards/configs.
# Run as root on Ubuntu 22.04 (ideally via cron).
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -eq 0 ]] || error "Please run this script as root (sudo)."

BACKUP_DIR="${BACKUP_DIR:-/opt/suricata-backups}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"   # Keep indices for this many days
ES_HOST="${ES_HOST:-https://localhost:9200}"
ES_PASS_FILE="/etc/elasticsearch/.elastic_password"
ELASTIC_PASS=$(cat "$ES_PASS_FILE" 2>/dev/null || echo "")
ES_CA="/etc/filebeat/certs/http_ca.crt"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# 1. Update Suricata rules
# ---------------------------------------------------------------------------
info "=== [1/5] Updating Suricata rules ==="
bash "${SCRIPT_DIR}/update_rules.sh"
info "  ✔ Rules updated"

# ---------------------------------------------------------------------------
# 2. Check log ingestion / Filebeat errors
# ---------------------------------------------------------------------------
info "=== [2/5] Checking Filebeat log for ingestion errors ==="
FB_LOG="/var/log/filebeat/filebeat"
if [[ -f "${FB_LOG}" ]]; then
    ERR_COUNT=$(grep -c -i "error\|failed" "${FB_LOG}" 2>/dev/null || echo 0)
    if [[ "$ERR_COUNT" -gt 0 ]]; then
        warn "  Found ${ERR_COUNT} error line(s) in Filebeat log – recent errors:"
        grep -i "error\|failed" "${FB_LOG}" | tail -10
    else
        info "  ✔ No errors in Filebeat log"
    fi
else
    warn "  Filebeat log not found at ${FB_LOG}"
fi

# ---------------------------------------------------------------------------
# 3. Check Elasticsearch index sizes
# ---------------------------------------------------------------------------
info "=== [3/5] Checking index sizes ==="
if [[ -n "$ELASTIC_PASS" ]] && [[ -f "$ES_CA" ]]; then
    curl -sk -u "elastic:${ELASTIC_PASS}" \
        --cacert "$ES_CA" \
        "${ES_HOST}/_cat/indices/suricata-*?v&h=index,store.size,docs.count&s=store.size:desc" \
        | head -20 || warn "  Could not query Elasticsearch"
else
    warn "  Skipping index size check – credentials not available"
fi

# ---------------------------------------------------------------------------
# 4. Apply index retention policy (delete indices older than RETENTION_DAYS)
# ---------------------------------------------------------------------------
info "=== [4/5] Applying index retention (${RETENTION_DAYS} days) ==="
if [[ -n "$ELASTIC_PASS" ]] && [[ -f "$ES_CA" ]]; then
    CUTOFF_DATE=$(date -d "-${RETENTION_DAYS} days" +%Y.%m.%d 2>/dev/null \
                  || date -v "-${RETENTION_DAYS}d" +%Y.%m.%d 2>/dev/null \
                  || echo "")
    if [[ -n "$CUTOFF_DATE" ]]; then
        # Convert cutoff date to epoch for reliable numeric comparison
        CUTOFF_EPOCH=$(date -d "${CUTOFF_DATE//./-}" +%s 2>/dev/null \
                       || date -j -f "%Y.%m.%d" "$CUTOFF_DATE" +%s 2>/dev/null \
                       || echo 0)
        info "  Deleting suricata-* indices older than $CUTOFF_DATE..."
        # List all suricata indices; delete those whose date suffix < cutoff
        curl -sk -u "elastic:${ELASTIC_PASS}" \
            --cacert "$ES_CA" \
            "${ES_HOST}/_cat/indices/suricata-*?h=index" \
            | while read -r idx; do
                IDX_DATE=$(echo "$idx" | grep -oE '[0-9]{4}\.[0-9]{2}\.[0-9]{2}' | head -1)
                if [[ -n "$IDX_DATE" ]]; then
                    IDX_EPOCH=$(date -d "${IDX_DATE//./-}" +%s 2>/dev/null \
                                || date -j -f "%Y.%m.%d" "$IDX_DATE" +%s 2>/dev/null \
                                || echo 9999999999)
                    if [[ "$IDX_EPOCH" -lt "$CUTOFF_EPOCH" ]]; then
                        info "    Deleting index: $idx (date: $IDX_DATE)"
                        curl -sk -X DELETE \
                            -u "elastic:${ELASTIC_PASS}" \
                            --cacert "$ES_CA" \
                            "${ES_HOST}/${idx}" | grep -q '"acknowledged":true' \
                            && info "    ✔ Deleted" || warn "    ✗ Delete failed"
                    fi
                fi
            done
        info "  ✔ Retention policy applied"
    else
        warn "  Could not calculate cutoff date – skipping retention"
    fi
else
    warn "  Skipping retention – credentials not available"
fi

# ---------------------------------------------------------------------------
# 5. Backup dashboards and configurations
# ---------------------------------------------------------------------------
info "=== [5/5] Backing up dashboards and configurations ==="
BACKUP_TS=$(date +%Y%m%d_%H%M%S)
BACKUP_PATH="${BACKUP_DIR}/${BACKUP_TS}"
mkdir -p "$BACKUP_PATH"

# Back up config files
for f in /etc/suricata/suricata.yaml \
          /etc/suricata/rules/custom.rules \
          /etc/filebeat/filebeat.yml \
          /etc/elasticsearch/elasticsearch.yml \
          /etc/kibana/kibana.yml; do
    [[ -f "$f" ]] && cp "$f" "$BACKUP_PATH/" && info "  ✔ Backed up $f"
done

# Export Kibana dashboards via Saved Objects API
if [[ -n "$ELASTIC_PASS" ]]; then
    info "  Exporting Kibana saved objects..."
    curl -sk \
        -u "elastic:${ELASTIC_PASS}" \
        "http://localhost:5601/api/saved_objects/_export" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -d '{"type":["dashboard","visualization","index-pattern"],"includeReferencesDeep":true}' \
        -o "${BACKUP_PATH}/kibana_objects.ndjson" 2>/dev/null \
        && info "  ✔ Kibana objects exported: ${BACKUP_PATH}/kibana_objects.ndjson" \
        || warn "  Could not export Kibana objects"
fi

# Clean up old backups (keep last 10)
ls -dt "${BACKUP_DIR}"/2* 2>/dev/null | tail -n +11 | xargs rm -rf 2>/dev/null || true
info "  ✔ Old backups pruned (keeping last 10)"

echo ""
info "Maintenance complete. Backups stored in: $BACKUP_PATH"

# ---------------------------------------------------------------------------
# Cron installation helper
# ---------------------------------------------------------------------------
if [[ "${1:-}" == "--install-cron" ]]; then
    CRON_LINE="0 2 * * * root /bin/bash ${SCRIPT_DIR}/maintain.sh >> /var/log/suricata-maintain.log 2>&1"
    CRON_FILE="/etc/cron.d/suricata-maintain"
    echo "$CRON_LINE" > "$CRON_FILE"
    chmod 644 "$CRON_FILE"
    info "Cron job installed: $CRON_FILE (runs daily at 02:00)"
fi
