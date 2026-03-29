#!/usr/bin/env bash
# =============================================================================
# simulate_attack.sh
# Module 5: Generate attack traffic to trigger Suricata alerts.
# Run from Kali Linux or any host on the same subnet.
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

TARGET="${1:-192.168.1.10}"   # First argument = target IP, defaults to example
EVE_LOG="/var/log/suricata/eve.json"

info "Attack Simulation Script"
info "Target: $TARGET"
echo ""

# ---------------------------------------------------------------------------
# Helper: Check for required tools
# ---------------------------------------------------------------------------
require_tool() {
    command -v "$1" &>/dev/null || error "Required tool '$1' not found. Install it and retry."
}

require_tool curl
require_tool nmap

# ---------------------------------------------------------------------------
# Simulation 1 – HTTP Directory Traversal (custom rule SID 9000001)
# ---------------------------------------------------------------------------
info "[1/6] HTTP Directory Traversal..."
curl -s -o /dev/null -w "  HTTP status: %{http_code}\n" \
    "http://${TARGET}/../../../../etc/passwd" || true
sleep 1

# ---------------------------------------------------------------------------
# Simulation 2 – HTTP SQL Injection (custom rule SID 9000002)
# ---------------------------------------------------------------------------
info "[2/6] HTTP SQL Injection..."
curl -s -o /dev/null -w "  HTTP status: %{http_code}\n" \
    "http://${TARGET}/login?user=admin'--&pass=x" || true
sleep 1

# ---------------------------------------------------------------------------
# Simulation 3 – HTTP XSS (custom rule SID 9000003)
# ---------------------------------------------------------------------------
info "[3/6] HTTP XSS..."
curl -s -o /dev/null -w "  HTTP status: %{http_code}\n" \
    "http://${TARGET}/search?q=<script>alert(1)</script>" || true
sleep 1

# ---------------------------------------------------------------------------
# Simulation 4 – Nikto-style scan (custom rule SID 9000004)
# ---------------------------------------------------------------------------
info "[4/6] Nikto user-agent scan..."
curl -s -o /dev/null -w "  HTTP status: %{http_code}\n" \
    -A "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:001)" \
    "http://${TARGET}/" || true
sleep 1

# ---------------------------------------------------------------------------
# Simulation 5 – ICMP ping sweep (custom rule SID 9000009)
# ---------------------------------------------------------------------------
info "[5/6] ICMP ping sweep..."
# nmap ping scan – sends multiple ICMP echo requests
nmap -sn -PE "${TARGET}/28" -oN /dev/null 2>/dev/null || true
sleep 1

# ---------------------------------------------------------------------------
# Simulation 6 – TCP SYN port scan (custom rule SID 9000010)
# ---------------------------------------------------------------------------
info "[6/6] TCP SYN port scan..."
# Half-open SYN scan across top ports
nmap -sS --top-ports 100 -T4 "$TARGET" -oN /dev/null 2>/dev/null || \
    warn "  SYN scan requires root – try: sudo nmap -sS --top-ports 100 $TARGET"
sleep 1

# ---------------------------------------------------------------------------
# Check EVE log for generated alerts
# ---------------------------------------------------------------------------
echo ""
info "Checking EVE log for alerts..."
if [[ -f "$EVE_LOG" ]]; then
    ALERT_COUNT=$(grep -c '"event_type":"alert"' "$EVE_LOG" 2>/dev/null || echo 0)
    info "  Total alerts in eve.json so far: $ALERT_COUNT"
    echo ""
    info "Last 5 alert entries:"
    grep '"event_type":"alert"' "$EVE_LOG" 2>/dev/null | tail -5 \
        | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line.strip())
        sig = e.get('alert', {}).get('signature', 'N/A')
        sid = e.get('alert', {}).get('signature_id', 'N/A')
        sev = e.get('alert', {}).get('severity', 'N/A')
        src = e.get('src_ip', 'N/A')
        dst = e.get('dest_ip', 'N/A')
        proto = e.get('proto', 'N/A')
        ts  = e.get('timestamp', 'N/A')
        print(f'  [{ts}] SID={sid} Sev={sev} {src}->{dst}/{proto}: {sig}')
    except Exception:
        pass
" 2>/dev/null || grep '"event_type":"alert"' "$EVE_LOG" | tail -5
else
    warn "EVE log not found at $EVE_LOG"
    warn "  Make sure Suricata is running on the target machine."
fi

echo ""
info "Simulation complete."
info "Open Kibana → Security → Dashboards → [Suricata] to review results."
