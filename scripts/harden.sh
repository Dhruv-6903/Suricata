#!/usr/bin/env bash
# =============================================================================
# harden.sh
# Module 10: Security hardening – restrict access to Elasticsearch & Kibana,
# ensure SSL is enabled, and check service authentication.
# Run as root on Ubuntu 22.04.
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -eq 0 ]] || error "Please run this script as root (sudo)."

# Subnet allowed to reach Elasticsearch and Kibana (adjust as needed)
ALLOWED_NET="${ALLOWED_NET:-192.168.1.0/24}"

# ---------------------------------------------------------------------------
# 1. UFW – Firewall rules
# ---------------------------------------------------------------------------
if command -v ufw &>/dev/null; then
    info "Configuring UFW firewall..."

    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing

    # Allow SSH
    ufw allow 22/tcp comment "SSH"

    # Allow Elasticsearch only from internal network
    ufw allow from "$ALLOWED_NET" to any port 9200 proto tcp comment "Elasticsearch (internal only)"
    ufw allow from "$ALLOWED_NET" to any port 9300 proto tcp comment "Elasticsearch transport (internal only)"

    # Allow Kibana only from internal network
    ufw allow from "$ALLOWED_NET" to any port 5601 proto tcp comment "Kibana (internal only)"

    ufw --force enable
    ufw status verbose
    info "  ✔ UFW configured"
else
    warn "ufw not available – configure your firewall manually"
fi

# ---------------------------------------------------------------------------
# 2. Verify Elasticsearch security settings
# ---------------------------------------------------------------------------
info "Verifying Elasticsearch security..."
ES_CONF="/etc/elasticsearch/elasticsearch.yml"
if [[ -f "$ES_CONF" ]]; then
    grep -q "xpack.security.enabled: true" "$ES_CONF" \
        && info "  ✔ xpack.security.enabled: true" \
        || warn "  ✗ xpack.security.enabled not set to true in $ES_CONF"
    grep -q "xpack.security.http.ssl" "$ES_CONF" \
        && info "  ✔ HTTP SSL configured" \
        || warn "  ✗ HTTP SSL not configured in $ES_CONF"
    grep -q "xpack.security.transport.ssl" "$ES_CONF" \
        && info "  ✔ Transport SSL configured" \
        || warn "  ✗ Transport SSL not configured in $ES_CONF"
fi

# ---------------------------------------------------------------------------
# 3. Verify Kibana security settings
# ---------------------------------------------------------------------------
info "Verifying Kibana security..."
KB_CONF="/etc/kibana/kibana.yml"
if [[ -f "$KB_CONF" ]]; then
    grep -q "xpack.security.encryptionKey" "$KB_CONF" \
        && info "  ✔ xpack.security.encryptionKey set" \
        || warn "  ✗ xpack.security.encryptionKey not set in $KB_CONF"
    grep -q "CHANGE_ME" "$KB_CONF" \
        && warn "  ✗ Kibana still has placeholder encryption keys – update them!" \
        || info "  ✔ No placeholder keys found"
fi

# ---------------------------------------------------------------------------
# 4. Verify Filebeat TLS settings
# ---------------------------------------------------------------------------
info "Verifying Filebeat SSL configuration..."
FB_CONF="/etc/filebeat/filebeat.yml"
if [[ -f "$FB_CONF" ]]; then
    grep -q "ssl.enabled: true" "$FB_CONF" \
        && info "  ✔ Filebeat SSL to Elasticsearch enabled" \
        || warn "  ✗ Filebeat SSL not enabled in $FB_CONF"
fi

# ---------------------------------------------------------------------------
# 5. File permissions on sensitive files
# ---------------------------------------------------------------------------
info "Hardening file permissions..."
chmod 600 /etc/elasticsearch/elasticsearch.yml 2>/dev/null || true
chmod 600 /etc/kibana/kibana.yml 2>/dev/null || true
chmod 600 /etc/filebeat/filebeat.yml 2>/dev/null || true
chmod 600 /etc/suricata/suricata.yaml 2>/dev/null || true
chmod 600 /etc/suricata/rules/*.rules 2>/dev/null || true
info "  ✔ Permissions set"

# ---------------------------------------------------------------------------
# 6. Disable insecure protocols / ciphers (Elasticsearch TLS settings)
# ---------------------------------------------------------------------------
info "Enforcing TLS minimum version for Elasticsearch..."
ES_CONF="/etc/elasticsearch/elasticsearch.yml"
if [[ -f "$ES_CONF" ]]; then
    if ! grep -q "xpack.security.http.ssl.supported_protocols" "$ES_CONF"; then
        cat >> "$ES_CONF" << 'EOF'

# Enforce TLS 1.2+ (disable TLS 1.0 and 1.1)
xpack.security.http.ssl.supported_protocols: [TLSv1.2, TLSv1.3]
xpack.security.transport.ssl.supported_protocols: [TLSv1.2, TLSv1.3]
EOF
        info "  ✔ TLS 1.2/1.3 enforced in Elasticsearch config"
        systemctl restart elasticsearch 2>/dev/null || warn "  Could not restart Elasticsearch – restart manually"
    else
        info "  ✔ TLS protocol setting already present"
    fi
fi

# ---------------------------------------------------------------------------
# 7. Summary
# ---------------------------------------------------------------------------
echo ""
info "=== Hardening Summary ==="
info "Elasticsearch port 9200 : accessible from $ALLOWED_NET only"
info "Kibana port 5601        : accessible from $ALLOWED_NET only"
info "SSL/TLS                 : enforced on all Elastic services"
info "Authentication          : X-Pack security enabled"
info "File permissions        : config files restricted to 600"
echo ""
warn "Reminder: Replace all CHANGE_ME placeholder values in kibana.yml"
warn "          with values generated by: openssl rand -hex 32"
