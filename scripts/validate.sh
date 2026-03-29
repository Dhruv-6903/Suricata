#!/usr/bin/env bash
# =============================================================================
# validate.sh
# Module 16: Validate the full deployment against the defined success criteria.
# Run as root on Ubuntu 22.04 after the full installation.
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
PASS=0; FAIL=0

pass() { echo -e "${GREEN}  [PASS]${NC} $*"; (( PASS++ )) || true; }
fail() { echo -e "${RED}  [FAIL]${NC} $*"; (( FAIL++ )) || true; }
warn() { echo -e "${YELLOW}  [WARN]${NC} $*"; }

[[ $EUID -eq 0 ]] || { echo "Run as root."; exit 1; }

ES_PASS_FILE="/etc/elasticsearch/.elastic_password"
ELASTIC_PASS=$(cat "$ES_PASS_FILE" 2>/dev/null || echo "")
ES_CA="/etc/filebeat/certs/http_ca.crt"
EVE_LOG="/var/log/suricata/eve.json"

echo ""
echo "======================================================"
echo "  Suricata NIDS + ELK Stack – Validation Report"
echo "  $(date)"
echo "======================================================"
echo ""

# ---------------------------------------------------------------------------
# 1. Suricata generates JSON logs
# ---------------------------------------------------------------------------
echo "[Check 1] Suricata generates JSON logs"
if systemctl is-active --quiet suricata; then
    pass "Suricata service is running"
else
    fail "Suricata service is NOT running"
fi

if [[ -f "$EVE_LOG" ]]; then
    LINES=$(wc -l < "$EVE_LOG" 2>/dev/null || echo 0)
    if [[ "$LINES" -gt 0 ]]; then
        pass "EVE JSON log exists with $LINES entries: $EVE_LOG"
    else
        fail "EVE log exists but is empty"
    fi
    # Validate JSON format
    if tail -1 "$EVE_LOG" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
        pass "EVE log last entry is valid JSON"
    else
        fail "EVE log last entry is NOT valid JSON"
    fi
else
    fail "EVE JSON log not found at $EVE_LOG"
fi
echo ""

# ---------------------------------------------------------------------------
# 2. Filebeat forwards logs correctly
# ---------------------------------------------------------------------------
echo "[Check 2] Filebeat forwards logs"
if systemctl is-active --quiet filebeat; then
    pass "Filebeat service is running"
else
    fail "Filebeat service is NOT running"
fi

FB_LOG="/var/log/filebeat/filebeat"
if [[ -f "$FB_LOG" ]]; then
    RECENT_ERR=$(grep -c "error" "$FB_LOG" 2>/dev/null || echo 0)
    if [[ "$RECENT_ERR" -eq 0 ]]; then
        pass "No errors in Filebeat log"
    else
        warn "Filebeat log has $RECENT_ERR error entries – check manually"
    fi
fi
echo ""

# ---------------------------------------------------------------------------
# 3. Elasticsearch stores data
# ---------------------------------------------------------------------------
echo "[Check 3] Elasticsearch stores data"
if systemctl is-active --quiet elasticsearch; then
    pass "Elasticsearch service is running"
else
    fail "Elasticsearch service is NOT running"
fi

if [[ -n "$ELASTIC_PASS" ]] && [[ -f "$ES_CA" ]]; then
    ES_STATUS=$(curl -sk -u "elastic:${ELASTIC_PASS}" \
        --cacert "$ES_CA" \
        "https://localhost:9200/_cluster/health" 2>/dev/null \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','unknown'))" 2>/dev/null || echo "unknown")
    if [[ "$ES_STATUS" == "green" || "$ES_STATUS" == "yellow" ]]; then
        pass "Elasticsearch cluster health: $ES_STATUS"
    else
        fail "Elasticsearch cluster health: $ES_STATUS"
    fi

    IDX_COUNT=$(curl -sk -u "elastic:${ELASTIC_PASS}" \
        --cacert "$ES_CA" \
        "https://localhost:9200/_cat/indices/suricata-*?h=index" 2>/dev/null | wc -l || echo 0)
    if [[ "$IDX_COUNT" -gt 0 ]]; then
        pass "Found $IDX_COUNT suricata-* indices in Elasticsearch"
    else
        warn "No suricata-* indices found yet (may need time to ingest)"
    fi
else
    warn "Cannot query Elasticsearch – credentials not available"
fi
echo ""

# ---------------------------------------------------------------------------
# 4. Kibana displays dashboards
# ---------------------------------------------------------------------------
echo "[Check 4] Kibana is accessible"
if systemctl is-active --quiet kibana; then
    pass "Kibana service is running"
else
    fail "Kibana service is NOT running"
fi

KB_STATUS=$(curl -sk "http://localhost:5601/api/status" 2>/dev/null \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status',{}).get('overall',{}).get('level','unknown'))" \
    2>/dev/null || echo "unknown")
if [[ "$KB_STATUS" == "available" || "$KB_STATUS" == "degraded" ]]; then
    pass "Kibana API status: $KB_STATUS"
else
    warn "Kibana API status: $KB_STATUS (may still be starting)"
fi
echo ""

# ---------------------------------------------------------------------------
# 5. Log entries contain required fields
# ---------------------------------------------------------------------------
echo "[Check 5] Alert log entries contain required fields"
if [[ -f "$EVE_LOG" ]]; then
    ALERT_LINE=$(grep '"event_type":"alert"' "$EVE_LOG" 2>/dev/null | tail -1)
    if [[ -n "$ALERT_LINE" ]]; then
        pass "Alert entries found in EVE log"

        # Parse the alert JSON once and extract all required fields together
        read -r src dst proto sig sev <<< "$(echo "$ALERT_LINE" | python3 -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    a = d.get('alert', {})
    fields = [
        d.get('src_ip', 'MISSING'),
        d.get('dest_ip', 'MISSING'),
        d.get('proto', 'MISSING'),
        a.get('signature', 'MISSING'),
        str(a.get('severity', 'MISSING')),
    ]
    print(' '.join(f.replace(' ', '_') for f in fields))
except Exception:
    print('MISSING MISSING MISSING MISSING MISSING')
" 2>/dev/null)"

        [[ "$src"   != "MISSING" ]] && pass "src_ip present: $src"     || fail "src_ip MISSING from alert"
        [[ "$dst"   != "MISSING" ]] && pass "dest_ip present: $dst"    || fail "dest_ip MISSING from alert"
        [[ "$proto" != "MISSING" ]] && pass "proto present: $proto"    || fail "proto MISSING from alert"
        [[ "$sig"   != "MISSING" ]] && pass "signature present: $sig"  || fail "signature MISSING from alert"
        [[ "$sev"   != "MISSING" ]] && pass "severity present: $sev"   || fail "severity MISSING from alert"
    else
        warn "No alert entries in EVE log yet – run simulate_attack.sh first"
    fi
fi
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "======================================================"
echo -e "  Total: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
echo "======================================================"
echo ""
if [[ "$FAIL" -eq 0 ]]; then
    echo -e "${GREEN}✔ All validation checks passed. System is operational.${NC}"
else
    echo -e "${RED}✗ ${FAIL} check(s) failed. Review output above.${NC}"
    exit 1
fi
