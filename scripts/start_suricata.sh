#!/usr/bin/env bash
# =============================================================================
# start_suricata.sh
# Module 4: Run Suricata as a persistent systemd service.
# Run as root on Ubuntu 22.04.
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -eq 0 ]] || error "Please run this script as root (sudo)."

IFACE="${SURICATA_IFACE:-eth0}"
SURICATA_CONF="/etc/suricata/suricata.yaml"
LOG_DIR="/var/log/suricata"
EVE_LOG="${LOG_DIR}/eve.json"
SYSTEMD_OVERRIDE="/etc/systemd/system/suricata.service.d"

# ---------------------------------------------------------------------------
# 1. Verify config before starting
# ---------------------------------------------------------------------------
info "Running pre-start config check..."
suricata -T -c "$SURICATA_CONF" -l /tmp 2>&1 | tail -5
info "  ✔ Config check passed"

# ---------------------------------------------------------------------------
# 2. Write systemd override so Suricata listens on the correct interface
# ---------------------------------------------------------------------------
info "Configuring systemd service override for interface: $IFACE"
mkdir -p "$SYSTEMD_OVERRIDE"
cat > "${SYSTEMD_OVERRIDE}/override.conf" << EOF
[Service]
ExecStart=
ExecStart=/usr/bin/suricata -c ${SURICATA_CONF} --pidfile /run/suricata.pid -i ${IFACE} --user suricata
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
EOF
systemctl daemon-reload

# ---------------------------------------------------------------------------
# 3. Enable and start the service
# ---------------------------------------------------------------------------
info "Enabling and starting Suricata service..."
systemctl enable suricata
systemctl restart suricata

# ---------------------------------------------------------------------------
# 4. Wait for EVE log to appear (up to 30 s)
# ---------------------------------------------------------------------------
info "Waiting for EVE JSON log to be created..."
for i in $(seq 1 30); do
    if [[ -f "$EVE_LOG" ]]; then
        info "  ✔ EVE log present: $EVE_LOG"
        break
    fi
    sleep 1
    [[ $i -eq 30 ]] && warn "EVE log not yet created – Suricata may still be initialising."
done

# ---------------------------------------------------------------------------
# 5. Status summary
# ---------------------------------------------------------------------------
systemctl status suricata --no-pager || true
echo ""
info "Suricata is running. Tail the EVE log with:"
echo "  sudo tail -f ${EVE_LOG} | jq ."
