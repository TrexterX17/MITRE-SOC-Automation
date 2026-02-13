# 🛡️ SOC-in-a-Box

## Automated Threat Hunting Lab with Real-Time APT Simulation

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Powered-blue.svg)](https://www.docker.com/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-red.svg)](https://attack.mitre.org/)

A comprehensive, fully-integrated Security Operations Center (SOC) environment featuring automated detection, incident response, threat intelligence, and adversary emulation capabilities. Built entirely with open-source tools.

[SOC Architecture](assets/diagrams/architecture.md)

---

## 🎯 Project Overview

SOC-in-a-Box demonstrates enterprise-grade security operations capabilities:

- **Real-time Threat Detection** - Wazuh SIEM with 50+ custom MITRE ATT&CK-mapped rules
- **Automated Incident Response** - TheHive case management with Cortex enrichment
- **Security Orchestration (SOAR)** - Shuffle automated playbooks
- **Threat Intelligence** - MISP integration with 50,000+ IOCs from multiple feeds
- **Adversary Simulation** - MITRE Caldera for attack emulation and detection validation
- **Endpoint Monitoring** - Sysmon and Suricata for comprehensive visibility

---

## 🏗️ Architecture

```
┌───────────────────────────────────────────────────────────────────────┐
│                         SOC-in-a-Box Architecture                     │
├───────────────────────────────────────────────────────────────────────┤
│                                                                       │
│   ┌─────────────┐     ┌─────────────┐     ┌──────────────┐            │
│   │   Caldera   │     │   Victim    │     │   Victim     │            │
│   │  (Red Team) │ ──> │  (Windows)  │     │  (Linux)     │            │
│   └─────────────┘     └──────┬──────┘     └───────┬──────┘            │
│                              │                    │                   │
│                              ▼                    ▼                   │
│   ┌──────────────────────────────────────────────────────────┐        │
│   │                    Wazuh SIEM/XDR                        │        │
│   │         (Log Collection, Detection, Correlation)         │        │
│   └──────────────────────────┬───────────────────────────────┘        │
│                              │                                        │
│              ┌───────────────┼───────────────┐                        │
│              ▼               ▼               ▼                        │
│   ┌─────────────┐   ┌─────────────┐      ┌────────────────┐           │
│   │   Shuffle   │   │   TheHive   │      │    MISP        │           │
│   │   (SOAR)    │──>│   (Cases)   │ <─>  │ (Threat Intel) │           │
│   └─────────────┘   └──────┬──────┘      └────────────────┘           │
│                            │                                          │
│                            ▼                                          │
│                     ┌─────────────┐                                   │
│                     │   Cortex    │                                   │
│                     │ (Enrichment)│                                   │
│                     └─────────────┘                                   │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Technology Stack

| Component | Tool | Version | Purpose |
|-----------|------|---------|---------|
| SIEM/XDR | Wazuh | 4.7.2 | Log aggregation, threat detection, compliance |
| Case Management | TheHive | 5.2 | Incident response, case tracking |
| Automated Analysis | Cortex | 3.1.7 | IOC enrichment, automated analysis |
| SOAR | Shuffle | Latest | Playbook automation, orchestration |
| Threat Intelligence | MISP | Latest | Threat intel platform, IOC sharing |
| Adversary Simulation | Caldera | Latest | MITRE ATT&CK emulation |
| Endpoint Telemetry | Sysmon | Latest | Windows event logging |
| Network IDS | Suricata | Latest | Network threat detection |

---

## 📋 Features

### Detection Capabilities
- ✅ 50+ Custom detection rules mapped to MITRE ATT&CK
- ✅ Credential access detection (Mimikatz, LSASS dumping)
- ✅ Lateral movement detection (PsExec, WMI, WinRM)
- ✅ Persistence mechanism detection (Registry, Services, Scheduled Tasks)
- ✅ Ransomware behavior detection (Shadow copy deletion, file encryption)
- ✅ Living-off-the-land binary (LOLBAS) detection

### Automation
- ✅ Automated alert enrichment via Cortex
- ✅ Automated case creation in TheHive
- ✅ Threat intelligence correlation with MISP
- ✅ Custom Shuffle playbooks for common scenarios

### Attack Simulation
- ✅ MITRE Caldera adversary profiles
- ✅ Full kill-chain simulation capabilities
- ✅ Detection validation framework

---

## 🚀 Quick Start

### Prerequisites

- **Hardware:** 16GB+ RAM, 4 CPU cores, 100GB SSD (minimum)
- **Software:** Docker & Docker Compose, Git, WSL2 (for Windows users)

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/soc-in-a-box.git
cd soc-in-a-box

# Configure system settings (Linux/WSL)
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf

# Create Docker network
docker network create soc-network

# Start Wazuh Stack
cd wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d

# Start TheHive + Cortex
cd ../../docker
docker compose -f docker-compose.thehive.yml up -d

# Start Shuffle SOAR
docker compose -f docker-compose.shuffle.yml up -d

# Start Caldera
docker compose -f docker-compose.caldera.yml up -d

# Start MISP
docker compose -f docker-compose.misp.yml up -d
```

### Access Services

| Service | URL | Default Credentials |
|---------|-----|---------------------|
| Wazuh Dashboard | https://localhost:443 | admin / SecretPassword |
| TheHive | http://localhost:9000 | admin@thehive.local / secret |
| Cortex | http://localhost:9001 | admin / admin |
| Shuffle | http://localhost:3001 | admin / shuffle123 |
| Caldera | http://localhost:8888 | red / admin |
| MISP | https://localhost:8443 | admin@admin.test / admin |

---

## 📊 MITRE ATT&CK Coverage

### Tactics Covered

| Tactic | Techniques | Coverage |
|--------|------------|----------|
| Initial Access | T1566.001, T1566.002 | ██████░░░░ 60% |
| Execution | T1059.001, T1059.003, T1047 | ████████░░ 80% |
| Persistence | T1547.001, T1053.005, T1543.003 | ████████░░ 80% |
| Privilege Escalation | T1134, T1548 | ██████░░░░ 60% |
| Defense Evasion | T1070.001, T1070.006, T1562.001 | ████████░░ 80% |
| Credential Access | T1003.001, T1003.002, T1110 | ██████████ 100% |
| Discovery | T1082, T1016, T1018 | ████████░░ 80% |
| Lateral Movement | T1021.002, T1021.006, T1047 | ████████░░ 80% |
| Collection | T1560 | ██████░░░░ 60% |
| Exfiltration | T1048, T1567 | ██████░░░░ 60% |

### Detection Rules Summary

```
Total Rules: 50+
├── Windows Rules: 35
├── Linux Rules: 10
├── Network Rules: 5
└── Custom Correlation: 5
```

---

## 🎬 Demo Scenarios

### Scenario 1: Ransomware Attack Simulation
Simulates a complete ransomware attack chain:
1. Initial access via phishing (simulated)
2. Execution of encoded PowerShell
3. Credential dumping with Mimikatz
4. Lateral movement via PsExec
5. Shadow copy deletion
6. File encryption simulation

### Scenario 2: APT-Style Attack
Advanced persistent threat simulation:
1. Spearphishing delivery
2. Persistence via registry
3. Discovery commands
4. Data staging and exfiltration

### Scenario 3: Insider Threat
Internal threat detection:
1. Unusual access patterns
2. Mass file access
3. Data exfiltration attempt

---

## 📁 Repository Structure

```
soc-in-a-box/
├── README.md
├── LICENSE
├── docker/
│   ├── docker-compose.thehive.yml
│   ├── docker-compose.shuffle.yml
│   ├── docker-compose.caldera.yml
│   └── docker-compose.misp.yml
├── detection-rules/
│   ├── windows/
│   │   └── custom_rules.xml
│   ├── linux/
│   └── network/
├── playbooks/
│   └── shuffle/
├── docs/
│   ├── architecture/
│   ├── installation/
│   ├── configuration/
│   ├── runbooks/
│   └── attack-scenarios/
├── configs/
│   ├── wazuh/
│   ├── thehive/
│   ├── cortex/
│   ├── shuffle/
│   └── caldera/
└── assets/
    ├── screenshots/
    └── diagrams/
```

---

## 📖 Documentation

- [Installation Guide](docs/installation/README.md)
- [Architecture Overview](docs/architecture/README.md)
- [Detection Rules](detection-rules/README.md)
- [Playbooks](playbooks/README.md)
- [Attack Scenarios](docs/attack-scenarios/README.md)

---

## 🔧 Project Highlights

### Key Metrics

- **Threat Events in MISP:** 21+ pages (thousands of events)
- **IOCs in MISP:** 50,000+ (malware hashes, IPs, domains)
- **MITRE ATT&CK Techniques Covered:** 30+
- **Custom Detection Rules:** 50+
- **Automated Playbooks:** Alert enrichment, case creation, malware response
- **Threat Feeds:** abuse.ch, CIRCL, Botvrij.eu, URLhaus

### Demonstrated Skills

- ✅ SIEM deployment and configuration
- ✅ Custom detection rule development
- ✅ Incident response workflow design
- ✅ SOAR playbook automation
- ✅ Threat intelligence integration
- ✅ Red team/Blue team operations
- ✅ Docker container orchestration
- ✅ Security documentation

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [Wazuh](https://wazuh.com/) - Open source security platform
- [TheHive Project](https://thehive-project.org/) - Incident response platform
- [Shuffle](https://shuffler.io/) - SOAR platform
- [MITRE ATT&CK](https://attack.mitre.org/) - Threat framework
- [MITRE Caldera](https://caldera.mitre.org/) - Adversary emulation
- [MISP Project](https://www.misp-project.org/) - Threat intelligence sharing

---

## 📧 Contact

**Project Author** - Faraz Ahmed and Pramath Yaji

⭐ **If you found this project helpful, please give it a star!** ⭐
