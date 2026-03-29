#!/usr/bin/env bash
# =============================================================================
# install_elk.sh
# Modules 6, 7, 8: Install Elasticsearch, Kibana, and Filebeat on Ubuntu 22.04.
# Run as root.
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -eq 0 ]] || error "Please run this script as root (sudo)."

ELK_VERSION="${ELK_VERSION:-8.13.0}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ---------------------------------------------------------------------------
# 1. Add Elastic APT repository
# ---------------------------------------------------------------------------
info "Adding Elastic repository (version ${ELK_VERSION})..."
apt-get install -y apt-transport-https gnupg curl wget

# Import signing key
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch \
    | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

# Add repository
MAJOR=$(echo "$ELK_VERSION" | cut -d. -f1)
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] \
https://artifacts.elastic.co/packages/${MAJOR}.x/apt stable main" \
    > /etc/apt/sources.list.d/elastic-${MAJOR}.x.list

apt-get update -qq

# ---------------------------------------------------------------------------
# 2. Install Elasticsearch
# ---------------------------------------------------------------------------
info "Installing Elasticsearch ${ELK_VERSION}..."
apt-get install -y "elasticsearch=${ELK_VERSION}"

info "Deploying Elasticsearch configuration..."
cp "${REPO_ROOT}/config/elasticsearch/elasticsearch.yml" \
   /etc/elasticsearch/elasticsearch.yml

# Set JVM heap (half of available RAM, capped at 31 GB)
TOTAL_MEM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
HEAP_MB=$(( TOTAL_MEM_KB / 2 / 1024 ))
HEAP_MB=$(( HEAP_MB > 31744 ? 31744 : HEAP_MB ))
HEAP_MB=$(( HEAP_MB < 512 ? 512 : HEAP_MB ))
info "  Setting JVM heap: ${HEAP_MB}m"
sed -i "s/-Xms[0-9]*[gGmM]/-Xms${HEAP_MB}m/" /etc/elasticsearch/jvm.options 2>/dev/null || true
sed -i "s/-Xmx[0-9]*[gGmM]/-Xmx${HEAP_MB}m/" /etc/elasticsearch/jvm.options 2>/dev/null || true

info "Starting and enabling Elasticsearch..."
systemctl daemon-reload
systemctl enable elasticsearch
systemctl start elasticsearch

# ---------------------------------------------------------------------------
# 3. Wait for Elasticsearch to be ready and retrieve credentials
# ---------------------------------------------------------------------------
info "Waiting for Elasticsearch to start (up to 90 s)..."
for i in $(seq 1 90); do
    if curl -sk https://localhost:9200 -u "elastic:$(cat /etc/elasticsearch/.elastic_password 2>/dev/null || true)" \
            --cacert /etc/elasticsearch/certs/http_ca.crt &>/dev/null; then
        info "  ✔ Elasticsearch is up"
        break
    fi
    sleep 1
    [[ $i -eq 90 ]] && warn "Elasticsearch may not be ready yet – check 'systemctl status elasticsearch'"
done

# Extract auto-generated elastic password if available
ELASTIC_PASS_FILE="/etc/elasticsearch/.elastic_password"
if [[ ! -f "$ELASTIC_PASS_FILE" ]]; then
    info "Resetting elastic password..."
    ELASTIC_PASS=$(/usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -s -b 2>/dev/null || echo "")
    if [[ -n "$ELASTIC_PASS" ]]; then
        echo "$ELASTIC_PASS" > "$ELASTIC_PASS_FILE"
        chmod 600 "$ELASTIC_PASS_FILE"
        info "  Elastic password saved to $ELASTIC_PASS_FILE"
    fi
fi

# ---------------------------------------------------------------------------
# 4. Install Kibana
# ---------------------------------------------------------------------------
info "Installing Kibana ${ELK_VERSION}..."
apt-get install -y "kibana=${ELK_VERSION}"

info "Deploying Kibana configuration..."
cp "${REPO_ROOT}/config/kibana/kibana.yml" /etc/kibana/kibana.yml

# Generate encryption keys and patch kibana.yml
ENC_KEY1=$(openssl rand -hex 32)
ENC_KEY2=$(openssl rand -hex 32)
ENC_KEY3=$(openssl rand -hex 32)
sed -i "s/CHANGE_ME_32_CHAR_ENCRYPTION_KEY_HERE_001/${ENC_KEY1}/" /etc/kibana/kibana.yml
sed -i "s/CHANGE_ME_32_CHAR_ENCRYPTION_KEY_HERE_002/${ENC_KEY2}/" /etc/kibana/kibana.yml
sed -i "s/CHANGE_ME_32_CHAR_ENCRYPTION_KEY_HERE_003/${ENC_KEY3}/" /etc/kibana/kibana.yml

# Set kibana_system password
if [[ -f "$ELASTIC_PASS_FILE" ]]; then
    ELASTIC_PASS=$(cat "$ELASTIC_PASS_FILE")
    KIBANA_PASS=$(openssl rand -hex 16)
    curl -sk -X POST "https://localhost:9200/_security/user/kibana_system/_password" \
        -H "Content-Type: application/json" \
        -u "elastic:${ELASTIC_PASS}" \
        --cacert /etc/elasticsearch/certs/http_ca.crt \
        -d "{\"password\":\"${KIBANA_PASS}\"}" | jq . || true
    # Store password in Kibana keystore
    echo "$KIBANA_PASS" | /usr/share/kibana/bin/kibana-keystore add elasticsearch.password --stdin 2>/dev/null || true
    info "  kibana_system password configured"
fi

# Copy Elasticsearch CA cert for Kibana
mkdir -p /etc/kibana/certs
cp /etc/elasticsearch/certs/http_ca.crt /etc/kibana/certs/ 2>/dev/null || true
sed -i 's|/etc/elasticsearch/certs/http_ca.crt|/etc/kibana/certs/http_ca.crt|' /etc/kibana/kibana.yml

info "Starting and enabling Kibana..."
systemctl enable kibana
systemctl start kibana

# ---------------------------------------------------------------------------
# 5. Install Filebeat
# ---------------------------------------------------------------------------
info "Installing Filebeat ${ELK_VERSION}..."
apt-get install -y "filebeat=${ELK_VERSION}"

info "Deploying Filebeat configuration..."
cp "${REPO_ROOT}/config/filebeat/filebeat.yml" /etc/filebeat/filebeat.yml

# Store Elasticsearch password in Filebeat keystore
if [[ -f "$ELASTIC_PASS_FILE" ]]; then
    ELASTIC_PASS=$(cat "$ELASTIC_PASS_FILE")
    echo "$ELASTIC_PASS" | filebeat keystore add ELASTICSEARCH_PASSWORD --stdin --force 2>/dev/null || true
    info "  Elasticsearch password stored in Filebeat keystore"
fi

# Copy CA cert for Filebeat
mkdir -p /etc/filebeat/certs
cp /etc/elasticsearch/certs/http_ca.crt /etc/filebeat/certs/ 2>/dev/null || true
sed -i 's|/etc/elasticsearch/certs/http_ca.crt|/etc/filebeat/certs/http_ca.crt|' /etc/filebeat/filebeat.yml
sed -i 's|ssl.certificate_authorities: \["/etc/elasticsearch|ssl.certificate_authorities: ["/etc/filebeat|' \
    /etc/filebeat/filebeat.yml

# Enable Suricata module
filebeat modules enable suricata

# Load index templates, pipelines, and dashboards
info "Loading Filebeat assets (templates, pipelines, dashboards)..."
ELASTIC_PASS=$(cat "$ELASTIC_PASS_FILE" 2>/dev/null || echo "")
filebeat setup \
    --index-management \
    --pipelines \
    --dashboards \
    -E "output.elasticsearch.username=elastic" \
    -E "output.elasticsearch.password=${ELASTIC_PASS}" \
    2>/dev/null || warn "Filebeat setup encountered warnings – check logs"

info "Starting and enabling Filebeat..."
systemctl enable filebeat
systemctl start filebeat

# ---------------------------------------------------------------------------
# 6. Summary
# ---------------------------------------------------------------------------
echo ""
info "=== ELK Stack Installation Summary ==="
info "Elasticsearch : https://localhost:9200"
info "Kibana        : http://$(hostname -I | awk '{print $1}'):5601"
info "Elastic user  : elastic"
[[ -f "$ELASTIC_PASS_FILE" ]] && info "Elastic pass  : $(cat $ELASTIC_PASS_FILE)"
echo ""
info "Verify services:"
echo "  systemctl status elasticsearch kibana filebeat"
echo ""
info "Next step: run  sudo bash scripts/simulate_attack.sh  to test detection."
