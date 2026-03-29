#!/usr/bin/env bash
# =============================================================================
# update_rules.sh
# Module 3: Update Suricata rule sources and apply latest signatures.
# Run as root on Ubuntu 22.04.
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -eq 0 ]] || error "Please run this script as root (sudo)."

SURICATA_UPDATE_CONF="/etc/suricata/update.yaml"
CUSTOM_RULES_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/rules/custom.rules"
CUSTOM_RULES_DEST="/etc/suricata/rules/custom.rules"

# ---------------------------------------------------------------------------
# 1. Configure rule sources in update.yaml
# ---------------------------------------------------------------------------
info "Writing suricata-update source configuration..."
cat > "$SURICATA_UPDATE_CONF" << 'EOF'
# suricata-update configuration
# Module 3.1: Multiple threat intelligence sources

sources:
  # Emerging Threats Open – free attack detection rules
  et/open:
    enabled: true

  # Emerging Threats Pro (requires API key – set ETPRO_SECRET env var)
  # et/pro:
  #   enabled: true
  #   secret-code: "YOUR_ETPRO_SECRET"

  # OISF Traffic ID rules
  oisf/trafficid:
    enabled: true

  # Abuse.ch SSL Blacklist
  abuse.ch/sslbl-ja3:
    enabled: true

  # PT Research (community)
  ptresearch/attackdetection:
    enabled: true

# Disable specific rules that cause false positives in your environment
# disable-rules:
#   - "2009582"   # Example: disable ET rule by SID

# Modify specific rule actions
# modify-rules:
#   - "re:^alert" "drop"   # Example: change all alerts to drops (IPS mode only)
EOF
info "  Wrote: $SURICATA_UPDATE_CONF"

# ---------------------------------------------------------------------------
# 2. Update source list and fetch latest rules
# ---------------------------------------------------------------------------
info "Updating suricata-update source list..."
suricata-update update-sources

info "Enabling configured sources..."
suricata-update enable-source et/open       || warn "et/open enable skipped (may already be enabled)"
suricata-update enable-source oisf/trafficid || warn "oisf/trafficid enable skipped"
suricata-update enable-source ptresearch/attackdetection || warn "ptresearch enable skipped"

# Try abuse.ch but don't fail if unavailable
suricata-update enable-source abuse.ch/sslbl-ja3 2>/dev/null \
    || warn "abuse.ch/sslbl-ja3 not available – skipping"

info "Downloading and merging rules..."
suricata-update -c "$SURICATA_UPDATE_CONF" \
    --output /etc/suricata/rules/suricata.rules \
    --no-reload

# ---------------------------------------------------------------------------
# 3. Deploy / refresh custom rules
# ---------------------------------------------------------------------------
if [[ -f "$CUSTOM_RULES_SRC" ]]; then
    info "Deploying custom rules from repository..."
    cp "$CUSTOM_RULES_SRC" "$CUSTOM_RULES_DEST"
    info "  Custom rules: $CUSTOM_RULES_DEST"
else
    warn "Custom rules source not found at $CUSTOM_RULES_SRC – skipping"
fi

# ---------------------------------------------------------------------------
# 4. Reload Suricata rules without restart (if running)
# ---------------------------------------------------------------------------
if systemctl is-active --quiet suricata; then
    info "Reloading Suricata rules (live reload)..."
    suricatasc -c reload-rules /var/run/suricata/suricata-command.socket 2>/dev/null \
        || (info "  Graceful reload via SIGUSR2..."; kill -USR2 "$(pidof suricata)")
    info "  ✔ Rules reloaded"
else
    info "  Suricata not running – rules will be loaded on next start"
fi

info "Rule update complete."
echo ""
info "Rule file: /etc/suricata/rules/suricata.rules"
info "Custom rules: $CUSTOM_RULES_DEST"
