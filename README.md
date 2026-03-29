# Suricata-Based Network Intrusion Detection with ELK Stack Integration

A production-ready NIDS (Network Intrusion Detection System) that monitors network traffic with [Suricata](https://suricata.io/), ships structured JSON logs via [Filebeat](https://www.elastic.co/beats/filebeat), indexes them in [Elasticsearch](https://www.elastic.co/elasticsearch/), and visualises them in [Kibana](https://www.elastic.co/kibana/).

---

## Table of Contents

1. [Architecture](#architecture)
2. [Prerequisites](#prerequisites)
3. [Repository Structure](#repository-structure)
4. [Quick Start](#quick-start)
5. [Module Reference](#module-reference)
   - [Module 1 & 2 – Suricata Installation & Configuration](#module-1--2--suricata-installation--configuration)
   - [Module 3 – Rule Management](#module-3--rule-management)
   - [Module 4 – Suricata Execution](#module-4--suricata-execution)
   - [Module 5 – Attack Simulation](#module-5--attack-simulation)
   - [Module 6 – Filebeat Integration](#module-6--filebeat-integration)
   - [Module 7 – Elasticsearch Setup](#module-7--elasticsearch-setup)
   - [Module 8 – Kibana Setup](#module-8--kibana-setup)
   - [Module 9 – Data Visualisation](#module-9--data-visualisation)
   - [Module 10 – Security & Hardening](#module-10--security--hardening)
   - [Module 11 – Maintenance](#module-11--maintenance)
6. [Validation](#validation)
7. [Configuration Reference](#configuration-reference)
8. [Troubleshooting](#troubleshooting)

---

## Architecture

```
Traffic Source
     │
     ▼
┌─────────────────────────────────────────────────────────────┐
│  Suricata (Detection Engine)                                │
│  • Monitors network interface (AF_PACKET / PCAP)            │
│  • Applies ET Open + custom detection rules                 │
│  • Outputs structured JSON → /var/log/suricata/eve.json     │
└────────────────────────┬────────────────────────────────────┘
                         │ eve.json
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Filebeat (Log Shipper)                                     │
│  • Tails eve.json                                           │
│  • Parses JSON, tags events (type: suricata)                │
│  • Forwards to Elasticsearch over TLS                       │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTPS (port 9200)
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Elasticsearch (Data Store)                                 │
│  • Indexes events in suricata-* indices                     │
│  • Authentication + TLS enforced                            │
│  • ILM policy: hot→warm→cold→delete (30-day retention)     │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Kibana (Visualisation Layer)                               │
│  • Pre-built Suricata dashboards                            │
│  • Data views: Alerts, HTTP, DNS, TLS, Flow                 │
│  • Authenticated, encryption keys configured                │
└─────────────────────────────────────────────────────────────┘

Attack Simulator (Kali Linux)
 • HTTP scans, SQL injection, port scans → generates alerts
```

**Network topology:** all systems on the same subnet (e.g. `192.168.1.0/24`).
**Required ports:** `9200` (Elasticsearch), `5601` (Kibana).

---

## Prerequisites

| Component | Version | Notes |
|-----------|---------|-------|
| Ubuntu | 22.04 LTS | Suricata + ELK host |
| Suricata | ≥ 7.x | Installed from OISF PPA |
| Elasticsearch | 8.x | Same major version as Kibana/Filebeat |
| Kibana | 8.x | |
| Filebeat | 8.x | |
| Kali Linux | any | Optional, for attack simulation |

**Required OS packages** (installed automatically by the scripts):

```
suricata suricata-update jq
elasticsearch kibana filebeat
apt-transport-https gnupg curl wget
```

**Suricata build dependencies** (validated at install time):

| Library | Purpose |
|---------|---------|
| libpcre / libpcre2 | Pattern matching in rules |
| libyaml | YAML config parsing |
| libpcap | Packet capture |
| libjansson | JSON log formatting |
| libmaxminddb | GeoIP enrichment |
| libnetfilter_queue | IPS / inline mode (optional) |

---

## Repository Structure

```
.
├── config/
│   ├── suricata/
│   │   ├── suricata.yaml          # Suricata main configuration
│   │   └── threshold.conf         # Alert suppression / rate-limiting
│   ├── filebeat/
│   │   └── filebeat.yml           # Filebeat input, output, and module config
│   ├── elasticsearch/
│   │   ├── elasticsearch.yml      # Elasticsearch node configuration
│   │   └── ilm_policy.json        # Index Lifecycle Management policy
│   └── kibana/
│       └── kibana.yml             # Kibana server and security configuration
├── rules/
│   └── custom.rules               # Custom Suricata detection rules
├── scripts/
│   ├── install_suricata.sh        # Module 1 & 2 – install + configure Suricata
│   ├── update_rules.sh            # Module 3   – fetch latest rule sets
│   ├── start_suricata.sh          # Module 4   – start as systemd service
│   ├── simulate_attack.sh         # Module 5   – generate test attack traffic
│   ├── install_elk.sh             # Modules 6-8 – install ELK stack
│   ├── harden.sh                  # Module 10  – firewall + TLS hardening
│   ├── maintain.sh                # Module 11  – rules, retention, backup
│   └── validate.sh                # Module 16  – end-to-end validation
└── README.md
```

---

## Quick Start

> All scripts must be run as **root** (`sudo bash scripts/<script>.sh`).

```bash
# 1. Clone the repository
git clone https://github.com/Dhruv-6903/Suricata.git
cd Suricata

# 2. Install and configure Suricata (set your interface and HOME_NET first)
export SURICATA_IFACE=eth0
export SURICATA_HOME_NET=192.168.1.0/24
sudo bash scripts/install_suricata.sh

# 3. Download latest detection rules
sudo bash scripts/update_rules.sh

# 4. Start Suricata as a persistent service
sudo bash scripts/start_suricata.sh

# 5. Install the ELK stack
export ELK_VERSION=8.13.0
sudo bash scripts/install_elk.sh

# 6. Harden the deployment
export ALLOWED_NET=192.168.1.0/24
sudo bash scripts/harden.sh

# 7. (From Kali or any host on the subnet) Simulate attacks
bash scripts/simulate_attack.sh 192.168.1.10

# 8. Validate the full deployment
sudo bash scripts/validate.sh
```

---

## Module Reference

### Module 1 & 2 – Suricata Installation & Configuration

**Script:** `scripts/install_suricata.sh`

**What it does:**

1. Adds the [OISF Suricata stable PPA](https://launchpad.net/~oisf/+archive/ubuntu/suricata-stable).
2. Installs `suricata` and `suricata-update`.
3. Validates the build includes all required libraries (PCRE, YAML, JSON, PCAP, GeoIP).
4. Deploys `config/suricata/suricata.yaml` to `/etc/suricata/suricata.yaml`.
5. Patches the monitoring interface and `HOME_NET` for the local host.
6. Runs `suricata -T` to validate config syntax.

**Key configuration blocks in `suricata.yaml`:**

| Block | Setting | Description |
|-------|---------|-------------|
| `af-packet` | `interface: eth0` | Capture interface (set via `SURICATA_IFACE`) |
| `vars.address-groups` | `HOME_NET` | Internal network CIDR |
| `vars.address-groups` | `EXTERNAL_NET: "!$HOME_NET"` | Everything outside HOME_NET |
| `community-id` | `yes` | Cross-system log correlation |
| `outputs.eve-log` | `filename: /var/log/suricata/eve.json` | JSON log path |
| `outputs.eve-log.types` | alert, http, dns, tls, ssh, smtp, flow | Required log types |
| `flow.memcap` | `128mb` | Memory for flow tracking |
| `flow.hash-size` | `65536` | Flow hash table size |
| `flow.prealloc` | `10000` | Pre-allocated flow entries |
| `stream.memcap` | `64mb` | TCP stream reassembly memory |

---

### Module 3 – Rule Management

**Script:** `scripts/update_rules.sh`

**Rule sources enabled:**

| Source | Type |
|--------|------|
| `et/open` | Emerging Threats Open (attack detection) |
| `oisf/trafficid` | Traffic identification |
| `abuse.ch/sslbl-ja3` | SSL/JA3 blacklist |
| `ptresearch/attackdetection` | PT Research community rules |
| `custom.rules` | Project-specific custom rules |

**Custom rules** (`rules/custom.rules`) cover:

- HTTP directory traversal, SQL injection, XSS
- Vulnerability scanner detection (Nikto)
- SSH / FTP brute-force
- DNS tunnelling / excessive queries
- ICMP ping sweeps and TCP SYN port scans
- Telnet access, external SMB/RDP attempts
- Possible HTTP C2 beaconing

Rules are live-reloaded without restarting Suricata (`SIGUSR2` / `reload-rules`).

---

### Module 4 – Suricata Execution

**Script:** `scripts/start_suricata.sh`

- Writes a systemd service override to bind Suricata to the configured interface.
- Enables and starts the `suricata` systemd service (persistent across reboots).
- Waits up to 30 s for `eve.json` to appear.

**Verify:**

```bash
systemctl status suricata
sudo tail -f /var/log/suricata/eve.json | jq .
```

---

### Module 5 – Attack Simulation

**Script:** `scripts/simulate_attack.sh <target-ip>`

Sends the following traffic from an attacker machine (Kali Linux recommended):

| Test | Rule triggered | SID |
|------|---------------|-----|
| HTTP directory traversal (`../`) | CUSTOM HTTP Directory Traversal | 9000001 |
| HTTP SQL injection (`'--`) | CUSTOM HTTP SQL Injection | 9000002 |
| HTTP XSS (`<script>`) | CUSTOM HTTP XSS | 9000003 |
| Nikto user-agent | CUSTOM Scanner UA Nikto | 9000004 |
| ICMP ping sweep (`nmap -sn`) | CUSTOM ICMP Ping Sweep | 9000009 |
| TCP SYN port scan (`nmap -sS`) | CUSTOM TCP SYN Port Scan | 9000010 |

**Expected alert fields in `eve.json`:**

```json
{
  "timestamp": "2024-01-01T12:00:00.000Z",
  "event_type": "alert",
  "src_ip": "192.168.1.20",
  "dest_ip": "192.168.1.10",
  "proto": "TCP",
  "alert": {
    "signature_id": 9000001,
    "signature": "CUSTOM HTTP Directory Traversal Attempt",
    "severity": 1
  }
}
```

---

### Module 6 – Filebeat Integration

**Script:** `scripts/install_elk.sh` (Filebeat section)
**Config:** `config/filebeat/filebeat.yml`

- Input: `/var/log/suricata/eve.json` with `json.keys_under_root: true`.
- Tags each event: `["suricata", "ids", "nids"]` and `fields.type: suricata`.
- Enables the built-in `suricata` Filebeat module.
- Loads index templates, ingest pipelines, and pre-built dashboards (`filebeat setup`).
- Writes to separate indices per event type:

| Index pattern | Event type |
|---------------|-----------|
| `suricata-alerts-YYYY.MM.DD` | alert |
| `suricata-dns-YYYY.MM.DD` | dns |
| `suricata-http-YYYY.MM.DD` | http |
| `suricata-tls-YYYY.MM.DD` | tls |
| `suricata-flow-YYYY.MM.DD` | flow |
| `suricata-logs-YYYY.MM.DD` | everything else |

---

### Module 7 – Elasticsearch Setup

**Script:** `scripts/install_elk.sh` (Elasticsearch section)
**Config:** `config/elasticsearch/elasticsearch.yml`

| Setting | Value |
|---------|-------|
| `cluster.name` | `suricata-nids` |
| `network.host` | `0.0.0.0` (restricted by firewall) |
| `http.port` | `9200` |
| `xpack.security.enabled` | `true` |
| `xpack.security.http.ssl.enabled` | `true` |
| `discovery.type` | `single-node` |

The script automatically:
- Sets JVM heap to half of available RAM (capped at 31 GB).
- Resets the `elastic` superuser password and saves it to `/etc/elasticsearch/.elastic_password`.

**ILM policy** (`config/elasticsearch/ilm_policy.json`):

| Phase | Trigger | Action |
|-------|---------|--------|
| hot | 0 days | Accept writes, rollover at 50 GB or 1 day |
| warm | 7 days | Shrink, force-merge, no replicas |
| cold | 14 days | Freeze |
| delete | 30 days | Delete index |

---

### Module 8 – Kibana Setup

**Script:** `scripts/install_elk.sh` (Kibana section)
**Config:** `config/kibana/kibana.yml`

| Setting | Description |
|---------|-------------|
| `server.host` | `0.0.0.0` (port 5601) |
| `elasticsearch.hosts` | Authenticated HTTPS connection |
| `xpack.security.encryptionKey` | Generated by `openssl rand -hex 32` |
| `xpack.encryptedSavedObjects.encryptionKey` | Generated at install time |
| `xpack.reporting.encryptionKey` | Generated at install time |

Access Kibana at: `http://<host-ip>:5601`

---

### Module 9 – Data Visualisation

Once Filebeat has loaded the dashboards (`filebeat setup --dashboards`), navigate to:

**Kibana → Analytics → Dashboards → search "Suricata"**

Pre-built views include:

| Dashboard | Data |
|-----------|------|
| [Suricata] Alerts | All IDS alerts with sig, severity, src/dst IP |
| [Suricata] HTTP | HTTP requests, methods, URIs, user-agents |
| [Suricata] DNS | DNS queries, record types, domains |
| [Suricata] TLS | TLS sessions, JA3 fingerprints, certs |

**KQL query examples:**

```kql
# All alerts
event.type: "alert"

# High-severity alerts only
event.type: "alert" AND alert.severity: 1

# Alerts for specific signature
alert.signature_id: 9000001

# Traffic from a specific IP
src_ip: "192.168.1.20"

# HTTP events to a specific destination
event.type: "http" AND dest_ip: "192.168.1.10"
```

---

### Module 10 – Security & Hardening

**Script:** `scripts/harden.sh`

1. **UFW firewall** – restricts ports 9200 and 5601 to `ALLOWED_NET` only; SSH (22) allowed from anywhere.
2. **Elasticsearch** – verifies `xpack.security.enabled: true`, HTTP/transport SSL, enforces TLS 1.2+.
3. **Kibana** – verifies encryption keys are set and no `CHANGE_ME` placeholders remain.
4. **Filebeat** – verifies SSL to Elasticsearch is enabled.
5. **File permissions** – sets all config files to `chmod 600`.

---

### Module 11 – Maintenance

**Script:** `scripts/maintain.sh [--install-cron]`

| Task | Description |
|------|-------------|
| Rule updates | Runs `update_rules.sh` to pull latest signatures |
| Log monitoring | Scans Filebeat log for ingestion errors |
| Index size check | Lists `suricata-*` index sizes via Elasticsearch API |
| Retention | Deletes indices older than `RETENTION_DAYS` (default: 30) |
| Config backup | Copies all config files to `/opt/suricata-backups/<timestamp>/` |
| Dashboard backup | Exports Kibana saved objects to `kibana_objects.ndjson` |

**Install as a daily cron job:**

```bash
sudo bash scripts/maintain.sh --install-cron
# Creates /etc/cron.d/suricata-maintain (runs at 02:00 daily)
```

---

## Validation

**Script:** `scripts/validate.sh`

Checks all success criteria:

| Check | What is verified |
|-------|-----------------|
| 1 | Suricata service running; `eve.json` exists and contains valid JSON |
| 2 | Filebeat service running; no errors in Filebeat log |
| 3 | Elasticsearch cluster healthy; `suricata-*` indices exist |
| 4 | Kibana service running; API returns `available` |
| 5 | Alert entries contain `src_ip`, `dest_ip`, `proto`, `signature`, `severity` |

Run after `simulate_attack.sh` to ensure end-to-end flow:

```bash
sudo bash scripts/validate.sh
```

---

## Configuration Reference

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SURICATA_IFACE` | `eth0` | Network interface for packet capture |
| `SURICATA_HOME_NET` | `192.168.1.0/24` | Internal network CIDR for `HOME_NET` |
| `ELK_VERSION` | `8.13.0` | ELK stack version to install |
| `ALLOWED_NET` | `192.168.1.0/24` | Subnet allowed to reach Elasticsearch/Kibana |
| `BACKUP_DIR` | `/opt/suricata-backups` | Backup destination directory |
| `RETENTION_DAYS` | `30` | Days to retain Elasticsearch indices |
| `ES_HOST` | `https://localhost:9200` | Elasticsearch endpoint for maintenance |

### Key File Paths

| File | Purpose |
|------|---------|
| `/etc/suricata/suricata.yaml` | Suricata main config |
| `/etc/suricata/threshold.conf` | Alert suppression rules |
| `/etc/suricata/rules/suricata.rules` | Merged rule set from suricata-update |
| `/etc/suricata/rules/custom.rules` | Project custom rules |
| `/var/log/suricata/eve.json` | EVE JSON log (Filebeat input) |
| `/var/log/suricata/fast.log` | Human-readable alert log |
| `/etc/filebeat/filebeat.yml` | Filebeat configuration |
| `/etc/elasticsearch/elasticsearch.yml` | Elasticsearch configuration |
| `/etc/kibana/kibana.yml` | Kibana configuration |
| `/etc/elasticsearch/.elastic_password` | Auto-generated elastic password |

---

## Troubleshooting

### Suricata not generating logs

```bash
# Check service status and errors
sudo systemctl status suricata
sudo journalctl -u suricata -n 50

# Validate config
sudo suricata -T -c /etc/suricata/suricata.yaml -l /tmp

# Check interface exists
ip link show eth0
```

### Filebeat not forwarding logs

```bash
sudo systemctl status filebeat
sudo journalctl -u filebeat -n 50

# Test connection to Elasticsearch
sudo filebeat test output
```

### Kibana cannot connect to Elasticsearch

```bash
# Check the kibana_system password is correct in the keystore
sudo /usr/share/kibana/bin/kibana-keystore list

# Verify Elasticsearch is up
curl -sk https://localhost:9200 \
  -u "elastic:$(sudo cat /etc/elasticsearch/.elastic_password)" \
  --cacert /etc/elasticsearch/certs/http_ca.crt | jq .
```

### No alerts in Kibana despite traffic

1. Check the Kibana data view matches the index pattern (`suricata-*`).
2. Verify the time filter in Kibana is set to a range that includes the event timestamps.
3. Run `sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'` to confirm Suricata is generating alerts.
4. Check Filebeat is reading the file: `sudo filebeat test config`.
