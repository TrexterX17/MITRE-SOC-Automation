# SOC-in-a-Box Architecture Diagram

```
                                    ┌─────────────────────────────────────────────────────────────┐
                                    │                 ATTACK SIMULATION LAYER                     │
                                    │                                                             │
                                    │  ┌────────────────────────────────────────────────────────┐ │
                                    │  │  MITRE Caldera                                         | │
                                    │  │  Port: 8888                                            │ │
                                    │  │  • Adversary emulation framework                       │ │
                                    │  │  • MITRE ATT&CK technique execution                    │ │
                                    │  │  • Agent-based attack simulation                       │ │
                                    │  │  • Detection validation                                │ │
                                    │  └────────────────────────────────────────────────────────┘ │
                                    └──────────────────────────┬──────────────────────────────────┘
                                                               │ Simulated Attacks
                                                               ▼
┌───────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                       ENDPOINT LAYER                                                  │
│                                                                                                       │
│  ┌──────────────────────────────────┐           ┌──────────────────────────────────┐                  │
│  │  Windows Victims                 │           │  Linux Victims                   │                  │
│  │  ─────────────────               │           │  ──────────────                  │                  │
│  │  • Wazuh Agent (1514/TCP)        │           │  • Wazuh Agent (1514/TCP)        │                  │
│  │  • Sysmon Event Logging          │           │  • Suricata IDS                  │                  │
│  │  • Windows Event Logs            │           │  • Auditd System Logging         │                  │
│  │  • PowerShell Logging            │           │  • System Logs                   │                  │
│  │                                  │           │                                  │                  │
│  │  Events Collected:               │           │  Events Collected:               │                  │
│  │  - Process Creation              │           │  - Authentication logs           │                  │
│  │  - Network Connections           │           │  - File access                   │                  │
│  │  - Process Access                │           │  - Network traffic               │                  │
│  │  - Registry Modifications        │           │  - Command execution             │                  │
│  │  - File Creation                 │           │  - IDS alerts                    │                  │
│  └────────────┬─────────────────────┘           └────────────┬─────────────────────┘                  │
└───────────────┼──────────────────────────────────────────────┼────────────────────────────────────────┘
                │                                              │
                │ Encrypted TLS                                │ Encrypted TLS
                │ Log Forwarding                               │ Log Forwarding
                └────────────────────┬─────────────────────────┘
                                     ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    SIEM/XDR LAYER                                                      │
│                                                                                                        │
│  ┌──────────────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │  Wazuh Manager                                                                                   │  │
│  │  Port: 1514 (Agent), 1515 (Enrollment), 55000 (API)                                              │  │
│  │  ────────────────────────────────────────────────────────────                                    │  │
│  │  • Centralized log collection                                                                    │  │
│  │  • Real-time event correlation                                                                   │  │
│  │  • 50+ custom detection rules                                                                    │  │
│  │  • MITRE ATT&CK framework mapping                                                                │  │
│  │  • Alert generation and prioritization                                                           │  │
│  │  • File integrity monitoring                                                                     │  │
│  │  • Vulnerability detection                                                                       │  │
│  │  • Compliance monitoring (PCI DSS, GDPR, HIPAA)                                                  │  │
│  └─────────────────────────────────────┬────────────────────────────────────────────────────────────┘  │
│                                        │                                                               │
│                                        ▼                                                               │
│  ┌──────────────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │  Wazuh Indexer (OpenSearch)                                                                      │  │
│  │  Port: 9200 (Internal)                                                                           │  │
│  │  ─────────────────────────                                                                       │  │
│  │  • High-performance event storage                                                                │  │
│  │  • Full-text search capabilities                                                                 │  │
│  │  • 30-day event retention (configurable)                                                         │  │
│  │  • RESTful API for queries                                                                       │  │
│  │  • Clustered deployment support                                                                  │  │
│  └─────────────────────────────────────┬────────────────────────────────────────────────────────────┘  │
│                                        │                                                               │
│                                        ▼                                                               │
│  ┌──────────────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │  Wazuh Dashboard                                                                                 │  │
│  │  Port: 443 (HTTPS)                                                                               │  │
│  │  ──────────────────                                                                              │  │
│  │  • Security event visualization                                                                  │  │
│  │  • MITRE ATT&CK heatmap                                                                          │  │
│  │  • Real-time monitoring dashboards                                                               │  │
│  │  • Compliance reporting                                                                          │  │
│  │  • Agent health monitoring                                                                       │  │
│  │  • Custom dashboard creation                                                                     │  │
│  │  • Alert management interface                                                                    │  │
│  └──────────────────────────────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────┬──────────────────────────────────────────────────────────────┘
                                          │ Alerts (Webhook/API)
                                          ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                               ORCHESTRATION LAYER (SOAR)                                               │
│                                                                                                        │
│  ┌──────────────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │  Shuffle SOAR                                                                                    │  │
│  │  Port: 3001 (HTTP)                                                                               │  │
│  │  ──────────────────                                                                              │  │
│  │  • Security orchestration and automation                                                         │  │
│  │  • Automated playbook execution                                                                  │  │
│  │  • Multi-tool integration platform                                                               │  │
│  │                                                                                                  │  │
│  │  Playbooks:                                                                                      │  │
│  │  ├─ Alert Enrichment (IOC lookup, reputation checks)                                             │  │
│  │  ├─ Malware Response (sandbox submission, isolation)                                             │  │
│  │  ├─ Phishing Analysis (URL/attachment inspection)                                                │  │
│  │  ├─ Brute Force Response (IP blocking, account lockout)                                          │  │
│  │  └─ Credential Dump Response (memory collection, password reset)                                 │  │
│  │                                                                                                  │  │
│  │  Integrations:                                                                                   │  │
│  │  • Wazuh (webhook receiver)                                                                      │  │
│  │  • TheHive (case creation)                                                                       │  │
│  │  • Cortex (enrichment)                                                                           │  │
│  │  • MISP (threat intel)                                                                           │  │
│  │  • Email/Slack (notifications)                                                                   │  │
│  └──────────────────────────────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────┬──────────────────────────────────────────────────────────────┘
                                          │ Workflow Triggers
                                          ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                               INCIDENT RESPONSE LAYER                                                  │
│                                                                                                        │
│  ┌─────────────────────┐       ┌─────────────────────┐       ┌─────────────────────┐                   │
│  │    TheHive          │◄─────►│      Cortex         │◄─────►│       MISP          │                   │
│  │    Port: 9000       │       │    Port: 9001       │       │    Port: 8443       │                   │
│  │    (HTTP)           │       │     (HTTP)          │       │     (HTTPS)         │                   │
│  └─────────────────────┘       └─────────────────────┘       └─────────────────────┘                   │
│                                                                                                        │
│  TheHive Capabilities:         Cortex Capabilities:          MISP Capabilities:                        │
│  ──────────────────            ─────────────────             ──────────────────                        │
│  • Case Management             • IOC Enrichment              • Threat Intelligence Hub                 │
│  • Alert Triage                • VirusTotal Integration      • 50,000+ IOCs                            │
│  • Task Assignment             • AbuseIPDB Queries           • Threat Feeds:                           │
│  • Observable Tracking         • MaxMind GeoIP                 - abuse.ch URLhaus                      │
│  • Team Collaboration          • File Analysis                - MalwareBazaar                          │
│  • Metrics & Reporting         • Yara Scanning                - CIRCL OSINT                            │
│  • Template Library            • Custom Analyzers             - Botvrij.eu                             │
│  • Integration APIs            • Automated Enrichment       • Event Sharing                            │
│  • Case Templates              • Responder Actions          • MITRE ATT&CK Mapping                     │
│                                • Multi-source Analysis       • API Access                              │
│                                                             • Automated Correlation                    │
│                                                                                                        │
│  Storage Backend:              Storage Backend:             Storage Backend:                           │
│  • Cassandra (Cases)           • Elasticsearch (Results)    • MySQL (Events)                           │
│  • Elasticsearch (Search)      • Docker for Analyzers       • Redis (Cache)                            │
│                                                                                                        │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘

════════════════════════════════════════════════════════════════════════════════════════════════════════
                                        DATA FLOW SUMMARY
════════════════════════════════════════════════════════════════════════════════════════════════════════

  ┌────────────┐
  │  Caldera   │  Executes simulated attacks
  └──────┬─────┘
         │
         ▼
  ┌────────────┐
  │  Endpoint  │  Logs generated by Sysmon/Auditd/Suricata
  └──────┬─────┘
         │
         ▼
  ┌────────────┐
  │   Wazuh    │  Analyzes logs with 50+ detection rules
  │  Manager   │  Generates alerts for suspicious activity
  └──────┬─────┘
         │
         ├─────────────────┐
         │                 │
         ▼                 ▼
  ┌────────────┐    ┌────────────┐
  │  Dashboard │    │  Shuffle   │  Triggers automated playbooks
  │  (Human)   │    │   (SOAR)   │
  └────────────┘    └──────┬─────┘
                           │
                           ▼
                    ┌────────────┐
                    │  TheHive   │  Creates cases with enriched data
                    └──────┬─────┘
                           │
                    ┌──────┴──────┐
                    │             │
                    ▼             ▼
             ┌────────────┐  ┌────────────┐
             │   Cortex   │  │    MISP    │  Provides threat intelligence
             │ (Enrich)   │  │  (Intel)   │  and IOC correlation
             └────────────┘  └────────────┘

════════════════════════════════════════════════════════════════════════════════════════════════════════
                                    NETWORK TOPOLOGY
════════════════════════════════════════════════════════════════════════════════════════════════════════

Docker Network: soc-network (172.x.x.x/16)

External Access Points:
┌──────────────────────────────────────────────────────────────┐
│  Host Machine (Windows/Linux)                                │
│  ├─ https://localhost:443      → Wazuh Dashboard             │
│  ├─ http://localhost:9000      → TheHive                     │
│  ├─ http://localhost:9001      → Cortex                      │
│  ├─ http://localhost:3001      → Shuffle                     │
│  ├─ http://localhost:8888      → Caldera                     │
│  ├─ https://localhost:8443     → MISP                        │
│  └─ tcp://localhost:1514       → Wazuh Agent Connection      │
└──────────────────────────────────────────────────────────────┘

Internal Communication (Docker):
┌──────────────────────────────────────────────────────────────┐
│  soc-network                                                 │
│  ├─ wazuh.manager:1514         → Agent connections           │
│  ├─ wazuh.indexer:9200         → Data storage                │
│  ├─ elasticsearch:9200         → TheHive/Cortex storage      │
│  ├─ cassandra:9042             → TheHive case storage        │
│  ├─ thehive:9000               → Case management             │
│  ├─ cortex:9001                → Analysis                    │
│  ├─ shuffle-backend:5001       → SOAR backend                │
│  └─ misp:443                   → Threat intelligence         │
└──────────────────────────────────────────────────────────────┘

════════════════════════════════════════════════════════════════════════════════════════════════════════
```

## Key Features

### Detection
- **50+ Custom Rules** mapped to MITRE ATT&CK
- **Real-time Correlation** across multiple data sources
- **Multi-platform Support** (Windows, Linux, Network)

### Response
- **Automated Playbooks** for common scenarios
- **Case Management** with full audit trail
- **IOC Enrichment** from multiple sources

### Intelligence
- **50,000+ IOCs** from trusted feeds
- **Threat Event Correlation** via MISP
- **MITRE ATT&CK Mapping** throughout

### Simulation
- **Red Team Automation** with Caldera
- **Detection Validation** framework
- **Attack Chain Simulation** capabilities
