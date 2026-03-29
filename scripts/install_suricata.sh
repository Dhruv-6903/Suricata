#!/usr/bin/env bash
# =============================================================================
# install_suricata.sh
# Module 1 & 2: Install Suricata, validate it, and apply configuration.
# Run as root on Ubuntu 22.04.
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ---------------------------------------------------------------------------
# Variables (override via environment if needed)
# ---------------------------------------------------------------------------
IFACE="${SURICATA_IFACE:-eth0}"
HOME_NET="${SURICATA_HOME_NET:-192.168.1.0/24}"
SURICATA_CONF="/etc/suricata/suricata.yaml"
CUSTOM_RULES="/etc/suricata/rules/custom.rules"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ---------------------------------------------------------------------------
# 0. Prerequisite check
# ---------------------------------------------------------------------------
[[ $EUID -eq 0 ]] || error "Please run this script as root (sudo)."
info "Running on: $(lsb_release -ds 2>/dev/null || uname -sr)"

# ---------------------------------------------------------------------------
# 1. Add Suricata PPA and install
# ---------------------------------------------------------------------------
info "Adding Suricata stable PPA..."
add-apt-repository -y ppa:oisf/suricata-stable
apt-get update -qq

info "Installing Suricata and suricata-update..."
apt-get install -y suricata suricata-update jq

# ---------------------------------------------------------------------------
# 2. Validate installation (Module 1 validation)
# ---------------------------------------------------------------------------
info "Validating Suricata installation..."
suricata --build-info | grep -q "HAVE_LIBPCRE"  && info "  ✔ PCRE support present" \
    || warn "  ✗ PCRE support not detected"
suricata --build-info | grep -q "HAVE_LIBYAML"  && info "  ✔ YAML support present" \
    || warn "  ✗ YAML support not detected"
suricata --build-info | grep -q "HAVE_LIBJANSSON" && info "  ✔ JSON (Jansson) support present" \
    || warn "  ✗ JSON support not detected"
suricata --build-info | grep -q "HAVE_LIBPCAP"  && info "  ✔ PCAP support present" \
    || warn "  ✗ PCAP support not detected"
suricata --build-info | grep -q "HAVE_LIBMAXMINDDB" && info "  ✔ GeoIP (MaxMindDB) support present" \
    || warn "  ✗ GeoIP support not detected"
suricata --build-info | grep -q "HAVE_LIBNETFILTER_QUEUE" && info "  ✔ NFQ (netfilter) support present" \
    || warn "  ✗ NFQ support not detected – OK for passive IDS"

# ---------------------------------------------------------------------------
# 3. Apply configuration
# ---------------------------------------------------------------------------
info "Backing up default Suricata config..."
cp -n "$SURICATA_CONF" "${SURICATA_CONF}.orig" 2>/dev/null || true

info "Deploying custom suricata.yaml..."
cp "${REPO_ROOT}/config/suricata/suricata.yaml" "$SURICATA_CONF"

# Patch the interface and HOME_NET for this host
sed -i "s/interface: eth0/interface: ${IFACE}/g" "$SURICATA_CONF"
sed -i "s|HOME_NET: \"\[192.168.1.0/24\]\"|HOME_NET: \"[${HOME_NET}]\"|" "$SURICATA_CONF"

# ---------------------------------------------------------------------------
# 4. Create log directory
# ---------------------------------------------------------------------------
info "Ensuring log directory exists..."
mkdir -p /var/log/suricata
chown suricata:suricata /var/log/suricata 2>/dev/null || true

# ---------------------------------------------------------------------------
# 5. Install custom rules (Module 3)
# ---------------------------------------------------------------------------
info "Deploying custom rules..."
mkdir -p /etc/suricata/rules
cp "${REPO_ROOT}/rules/custom.rules" "$CUSTOM_RULES"
info "  Custom rules: $CUSTOM_RULES"

# ---------------------------------------------------------------------------
# 6. Validate config syntax
# ---------------------------------------------------------------------------
info "Validating Suricata configuration syntax..."
if suricata -T -c "$SURICATA_CONF" -l /tmp 2>&1 | grep -q "Configuration provided was successfully loaded"; then
    info "  ✔ Configuration syntax valid"
else
    suricata -T -c "$SURICATA_CONF" -l /tmp
    error "Configuration validation failed – check the output above."
fi

info "Suricata installation and configuration complete."
echo ""
info "Next steps:"
echo "  1. Run: sudo bash scripts/update_rules.sh"
echo "  2. Run: sudo bash scripts/start_suricata.sh"
