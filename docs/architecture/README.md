# Architecture Overview

## System Architecture

SOC-in-a-Box implements a layered security architecture with microservices running in Docker containers, providing comprehensive threat detection, incident response, and adversary simulation capabilities.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      ATTACK SIMULATION LAYER                            │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │  Caldera (MITRE ATT&CK Adversary Emulation)                     │    │
│  │  • Pre-built adversary profiles                                 │    │
│  │  • Custom attack chains                                         │    │
│  │  • Agent deployment on endpoints                                │    │
│  └─────────────────────────────────────────────────────────────────┘    │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │ Attacks
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         ENDPOINT LAYER                                  │
│  ┌──────────────────────┐           ┌──────────────────────┐            │
│  │  Windows Victims     │           │  Linux Victims       │            │
│  │  • Wazuh Agent       │           │  • Wazuh Agent       │            │
│  │  • Sysmon Logging    │           │  • Suricata IDS      │            │
│  │  • Event Collection  │           │  • Auditd Logging    │            │
│  └──────────┬───────────┘           └──────────┬───────────┘            │
└─────────────┼──────────────────────────────────┼────────────────────────┘
              │ Logs/Events                      │ Logs/Events
              └────────────────┬─────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      SIEM/XDR LAYER (Wazuh)                             │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  Wazuh Manager                                                    │  │
│  │  • Log ingestion (port 1514)                                      │  │
│  │  • Event correlation                                              │  │
│  │  • Rule processing (50+ custom rules)                             │  │
│  │  • MITRE ATT&CK mapping                                           │  │
│  │  • Alert generation                                               │  │
│  └───────────────────────┬───────────────────────────────────────────┘  │
│                          │                                              │
│  ┌───────────────────────┴──────────────────────────────────────────┐   │
│  │  Wazuh Indexer (OpenSearch)                                      │   │
│  │  • Event storage and indexing                                    │   │
│  │  • Full-text search                                              │   │
│  │  • Historical analysis                                           │   │
│  └───────────────────────┬──────────────────────────────────────────┘   │
│                          │                                              │
│  ┌───────────────────────┴──────────────────────────────────────────┐   │
│  │  Wazuh Dashboard                                                 │   │
│  │  • Security events visualization                                 │   │
│  │  • MITRE ATT&CK dashboard                                        │   │
│  │  • Compliance reporting                                          │   │
│  │  • Agent management                                              │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │ Alerts
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      ORCHESTRATION LAYER (SOAR)                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  Shuffle                                                         │   │
│  │  • Webhook receivers for alerts                                  │   │
│  │  • Automated playbooks                                           │   │
│  │  • Integration with TheHive, Cortex, MISP                        │   │
│  │  • Alert enrichment workflows                                    │   │
│  └───────────────────────┬──────────────────────────────────────────┘   │
└─────────────────────────────┼───────────────────────────────────────────┘
                              │ Triggers
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                   INCIDENT RESPONSE LAYER                               │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────────┐           │
│  │  TheHive     │ ◄──► │   Cortex     │ ◄──► │    MISP      │           │
│  │  :9000       │      │   :9001      │      │   :8443      │           │
│  └──────────────┘      └──────────────┘      └──────────────┘           │
│                                                                         │
│  TheHive:                Cortex:              MISP:                     │
│  • Case management      • IOC enrichment     • Threat intel feeds       │
│  • Alert triage         • VirusTotal         • 50,000+ IOCs             │
│  • Task assignment      • AbuseIPDB          • Event sharing            │
│  • Collaboration        • MaxMind GeoIP      • MITRE ATT&CK tags        │
│  • Observables          • File analysis      • APT intelligence         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. Attack Simulation Layer

**Caldera (Port 8888)**
- Purpose: Red team adversary emulation
- Technology: Python-based ATT&CK automation
- Capabilities:
  - Deploy agents on endpoints
  - Execute MITRE ATT&CK techniques
  - Chain multiple attack steps
  - Validate detection coverage

### 2. Endpoint Layer

**Windows Agents**
- Wazuh Agent: Log forwarding to manager
- Sysmon: Enhanced Windows event logging
  - Process creation (Event ID 1)
  - Network connections (Event ID 3)
  - Process access (Event ID 10)
  - Registry modifications (Event ID 13)

**Linux Agents**
- Wazuh Agent: Log collection
- Suricata: Network intrusion detection
- Auditd: System call auditing

### 3. SIEM/XDR Layer (Wazuh)

**Wazuh Manager**
- Receives logs from all agents
- Processes 50+ custom detection rules
- Correlates events across endpoints
- Maps to MITRE ATT&CK framework
- Generates alerts for suspicious activity

**Wazuh Indexer (OpenSearch)**
- Elasticsearch-compatible search engine
- Indexes all security events
- Enables fast querying and analysis
- Retention: Configurable (default 30 days)

**Wazuh Dashboard**
- Web-based UI (HTTPS port 443)
- Real-time security event monitoring
- MITRE ATT&CK heatmap
- Compliance dashboards (PCI DSS, GDPR, HIPAA)
- Agent health monitoring

### 4. Orchestration Layer (SOAR)

**Shuffle**
- Security orchestration and automation
- Workflow engine for automated response
- Integrations:
  - Wazuh (webhook receiver)
  - TheHive (case creation)
  - Cortex (enrichment)
  - Email/Slack (notifications)

**Automated Playbooks:**
1. Alert Enrichment
2. Malware Response
3. Phishing Analysis
4. Brute Force Response

### 5. Incident Response Layer

**TheHive (Port 9000)**
- Collaborative case management
- Alert to case conversion
- Task assignment and tracking
- Observable management (IPs, domains, hashes)
- Integration with Cortex for analysis

**Cortex (Port 9001)**
- Automated IOC analysis
- Analyzers:
  - FileInfo: File metadata extraction
  - VirusTotal: Malware scanning
  - AbuseIPDB: IP reputation
  - MaxMind: Geo-location
  - Yara: Malware pattern matching
  - Abuse_Finder: Abuse contact lookup

**MISP (Port 8443)**
- Threat intelligence platform
- Active threat feeds:
  - abuse.ch URLhaus
  - abuse.ch MalwareBazaar
  - CIRCL OSINT Feed
  - Botvrij.eu
- 50,000+ indicators of compromise
- Event sharing and correlation

## Data Flow

### Detection Flow

```
1. Attack occurs on endpoint
   ↓
2. Sysmon/Auditd captures event
   ↓
3. Wazuh Agent forwards to Manager (port 1514)
   ↓
4. Manager processes against detection rules
   ↓
5. Rule matches → Alert generated
   ↓
6. Alert stored in Indexer
   ↓
7. Alert displayed in Dashboard
   ↓
8. (Optional) Shuffle workflow triggered via webhook
```

### Incident Response Flow

```
1. Wazuh generates alert
   ↓
2. Shuffle receives webhook
   ↓
3. Playbook extracts IOCs (IPs, hashes, domains)
   ↓
4. Cortex analyzers enrich IOCs
   ↓
5. MISP checks for known threats
   ↓
6. TheHive case created with enriched data
   ↓
7. Analyst investigates and responds
```

## Network Architecture

### Docker Network: `soc-network`

All containers communicate via a dedicated Docker bridge network (`soc-network`).

**Internal Connectivity:**
```
wazuh.manager:1514 ← Agents
wazuh.manager:55000 ← API clients
elasticsearch:9200 ← Wazuh Manager, Cortex
cassandra:9042 ← TheHive
```

### Port Mappings

| Service | Container Port | Host Port | Protocol | Purpose |
|---------|---------------|-----------|----------|---------|
| Wazuh Dashboard | 5601 | 443 | HTTPS | Web UI |
| Wazuh Manager | 1514 | 1514 | TCP | Agent connections |
| Wazuh Manager | 1515 | 1515 | TCP | Agent enrollment |
| Wazuh API | 55000 | 55000 | HTTPS | REST API |
| TheHive | 9000 | 9000 | HTTP | Web UI |
| Cortex | 9001 | 9001 | HTTP | Web UI |
| Shuffle | 80 | 3001 | HTTP | Web UI |
| Caldera | 8888 | 8888 | HTTP | Web UI |
| MISP | 443 | 8443 | HTTPS | Web UI |

## Storage Architecture

### Docker Volumes

| Volume | Purpose | Approximate Size |
|--------|---------|-----------------|
| wazuh-indexer-data | Security events | 50-100GB |
| elasticsearch-data | TheHive/Cortex data | 10-20GB |
| cassandra-data | TheHive cases | 5-10GB |
| misp-data | Threat intelligence | 10-20GB |
| shuffle-opensearch-data | Workflow data | 5GB |

### Data Retention

- **Wazuh Events**: 30 days (configurable)
- **TheHive Cases**: Indefinite
- **MISP Events**: Indefinite
- **Shuffle Workflow Logs**: 90 days

## Scalability Considerations

### Horizontal Scaling

The architecture supports scaling:

1. **Wazuh Indexer**: Can be clustered (3+ nodes)
2. **Elasticsearch**: Can be clustered
3. **Cassandra**: Supports multi-node clusters
4. **Wazuh Manager**: Can deploy multiple managers with load balancing

### Resource Requirements

**Minimum Production:**
- CPU: 8 cores
- RAM: 32GB
- Storage: 200GB SSD

**Recommended Enterprise:**
- CPU: 16 cores
- RAM: 64GB
- Storage: 500GB SSD (RAID 10)

## Security Considerations

### Network Isolation

- All services run on isolated Docker network
- No direct internet access (except for threat feed updates)
- External access only through mapped ports

### Authentication

- All services require authentication
- Default credentials should be changed in production
- API keys should be rotated regularly

### TLS/SSL

- Wazuh Dashboard: HTTPS (self-signed by default)
- Wazuh Manager ↔ Agents: TLS encryption
- MISP: HTTPS enabled
- Consider proper certificates for production

### Data Protection

- Sensitive data in Wazuh Indexer
- Case data in TheHive/Cassandra
- Threat intel in MISP
- All volumes should be backed up regularly

## Monitoring and Maintenance

### Health Checks

```bash
# Check all containers
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Check Wazuh cluster status
docker exec -it wazuh.manager /var/ossec/bin/cluster_control -l

# Check Wazuh agents
docker exec -it wazuh.manager /var/ossec/bin/agent_control -l
```

### Log Locations

- Wazuh Manager: `/var/ossec/logs/`
- TheHive: `/var/log/thehive/`
- Cortex: `/var/log/cortex/`
- Docker logs: `docker logs <container_name>`

## References

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [TheHive Documentation](https://docs.thehive-project.org/)
- [Shuffle Documentation](https://shuffler.io/docs)
- [MITRE Caldera Documentation](https://caldera.readthedocs.io/)
- [MISP Documentation](https://www.misp-project.org/documentation/)
