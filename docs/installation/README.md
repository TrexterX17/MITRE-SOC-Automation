# Installation Guide

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [System Requirements](#system-requirements)
3. [Installation Steps](#installation-steps)
4. [Post-Installation Configuration](#post-installation-configuration)
5. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Hardware Requirements

**Minimum Configuration:**
- CPU: 4 cores
- RAM: 16GB
- Storage: 100GB SSD
- Network: Stable internet connection

**Recommended Configuration:**
- CPU: 8 cores
- RAM: 32GB
- Storage: 200GB SSD
- Network: Gigabit ethernet

### Software Requirements

**Operating System:**
- Windows 10/11 with WSL2
- Ubuntu 22.04 LTS
- Debian 11+
- macOS 12+ (with Docker Desktop)

**Required Software:**
- Docker Engine 20.10+
- Docker Compose v2+
- Git 2.30+

**For Windows Users:**
- WSL2 enabled
- Ubuntu 22.04 from Microsoft Store
- Docker Desktop with WSL2 backend

---

## System Requirements

### Configure System Settings

#### For Linux/WSL:

```bash
# Increase virtual memory (required for Elasticsearch/OpenSearch)
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf

# Verify setting
sysctl vm.max_map_count
```

#### For Windows WSL2:

Create/edit `%UserProfile%\.wslconfig`:

```ini
[wsl2]
memory=8GB
processors=4
swap=4GB
localhostForwarding=true
```

Then restart WSL:
```powershell
wsl --shutdown
```

---

## Installation Steps

### Step 1: Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/soc-in-a-box.git
cd soc-in-a-box
```

### Step 2: Create Docker Network

```bash
docker network create soc-network
```

### Step 3: Deploy Wazuh SIEM

```bash
# Clone Wazuh Docker repository
git clone https://github.com/wazuh/wazuh-docker.git -b v4.7.2

# Navigate to single-node deployment
cd wazuh-docker/single-node

# Generate certificates (IMPORTANT)
docker compose -f generate-indexer-certs.yml run --rm generator

# Start Wazuh stack
docker compose up -d

# Wait 3-5 minutes for initialization
# Check logs
docker compose logs -f
```

**Access Wazuh:**
- URL: https://localhost:443
- Username: `admin`
- Password: `SecretPassword`

### Step 4: Deploy TheHive + Cortex

```bash
cd ../../docker

# Start TheHive and Cortex
docker compose -f docker-compose.thehive.yml up -d

# Wait 3-5 minutes for initialization
docker compose -f docker-compose.thehive.yml logs -f
```

**Access TheHive:**
- URL: http://localhost:9000
- Username: `admin@thehive.local`
- Password: `secret`

**Access Cortex:**
- URL: http://localhost:9001
- Username: `admin`
- Password: `admin`

### Step 5: Deploy Shuffle SOAR

```bash
docker compose -f docker-compose.shuffle.yml up -d

# Wait 2-3 minutes
docker compose -f docker-compose.shuffle.yml logs -f
```

**Access Shuffle:**
- URL: http://localhost:3001
- Username: `admin`
- Password: `shuffle123`

### Step 6: Deploy Caldera

```bash
docker compose -f docker-compose.caldera.yml up -d

# Wait 1-2 minutes
docker compose -f docker-compose.caldera.yml logs -f
```

**Access Caldera:**
- URL: http://localhost:8888
- Username: `red` or `admin`
- Password: `admin`

### Step 7: Deploy MISP (Optional)

```bash
docker compose -f docker-compose.misp.yml up -d

# Wait 5-10 minutes (MISP takes longer to initialize)
docker compose -f docker-compose.misp.yml logs -f misp
```

**Access MISP:**
- URL: https://localhost:8443
- Username: `admin@admin.test`
- Password: `admin`

### Step 8: Verify Installation

```bash
# Check all containers are running
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Expected containers:
# - wazuh.manager
# - wazuh.indexer
# - wazuh.dashboard
# - thehive
# - cortex
# - elasticsearch
# - cassandra
# - shuffle-frontend
# - shuffle-backend
# - shuffle-orborus
# - shuffle-opensearch
# - caldera
# - misp (optional)
```

---

## Post-Installation Configuration

### Configure Wazuh Agents

#### Windows Agent Installation:

```powershell
# Download agent
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.2-1.msi -OutFile wazuh-agent.msi

# Install (replace MANAGER_IP with your Wazuh server IP)
msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER="MANAGER_IP" WAZUH_AGENT_NAME="windows-host"

# Start service
NET START WazuhSvc
```

#### Linux Agent Installation:

```bash
# Add repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list

# Install agent
sudo apt update
sudo apt install wazuh-agent -y

# Configure manager IP
sudo sed -i "s/MANAGER_IP/YOUR_MANAGER_IP/" /var/ossec/etc/ossec.conf

# Start agent
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

### Install Sysmon (Windows)

```powershell
# Create directory
New-Item -ItemType Directory -Path "C:\Sysmon" -Force
cd C:\Sysmon

# Download Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
Expand-Archive -Path "Sysmon.zip" -DestinationPath "." -Force

# Download SwiftOnSecurity config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "sysmonconfig.xml"

# Install Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig.xml

# Verify installation
Get-Service Sysmon64
```

### Configure Wazuh to Collect Sysmon Logs

```bash
# Enter Wazuh manager container
docker exec -it wazuh.manager bash

# Edit agent configuration
cat >> /var/ossec/etc/shared/default/agent.conf << 'EOF'
<agent_config>
  <!-- Sysmon Event Collection -->
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  
  <!-- Windows Security Events -->
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
  </localfile>
  
  <!-- PowerShell Events -->
  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</agent_config>
EOF

# Restart manager
/var/ossec/bin/wazuh-control restart
exit
```

### Configure Cortex Analyzers

1. **Create Organization in Cortex:**
   - Go to http://localhost:9001
   - Click "Organizations" → "Add Organization"
   - Name: `SOC`
   - Click "Save"

2. **Create TheHive Integration User:**
   - Click on "SOC" organization
   - Go to "Users" tab
   - Click "Add User"
   - Login: `thehive`
   - Roles: Select `orgadmin` and `analyze`
   - Click "Create API Key" and save it

3. **Enable Analyzers:**
   - Go to "Analyzers" tab
   - Enable these free analyzers:
     - FileInfo
     - Abuse_Finder
     - MaxMind_GeoIP (requires free API key)

4. **Add API Keys (Optional but Recommended):**
   - VirusTotal: https://www.virustotal.com/gui/join-us
   - AbuseIPDB: https://www.abuseipdb.com/register
   - AlienVault OTX: https://otx.alienvault.com/api

### Deploy Custom Detection Rules

```bash
# Copy custom rules to Wazuh manager
docker cp detection-rules/windows/custom_rules.xml wazuh.manager:/var/ossec/etc/rules/custom_rules.xml

# Set permissions
docker exec -it wazuh.manager bash -c "chown wazuh:wazuh /var/ossec/etc/rules/custom_rules.xml && /var/ossec/bin/wazuh-control restart"
```

### Configure MISP Threat Feeds

1. Access MISP: https://localhost:8443
2. Go to "Sync Actions" → "List Feeds"
3. Click "Load default feed metadata"
4. Enable these feeds:
   - CIRCL OSINT Feed
   - abuse.ch URLhaus
   - abuse.ch Malware Bazaar
   - Botvrij.eu
5. For each feed, click "Fetch and store all data"

---

## Troubleshooting

### Containers Not Starting

**Check logs:**
```bash
docker compose logs -f [service-name]
```

**Common issue - vm.max_map_count:**
```bash
sudo sysctl -w vm.max_map_count=262144
```

### Wazuh Agents Not Connecting

**Check manager is listening:**
```bash
docker exec -it wazuh.manager netstat -tlnp | grep 1514
```

**Check firewall (Windows):**
```powershell
netsh advfirewall firewall add rule name="Wazuh Agent" dir=in action=allow protocol=tcp localport=1514,1515
```

**Check agent status:**
```bash
# On manager
docker exec -it wazuh.manager /var/ossec/bin/agent_control -l
```

### No Events Appearing in Wazuh

**Check agent is sending data:**
```bash
docker exec -it wazuh.manager tail -f /var/ossec/logs/ossec.log
```

**Restart agent:**
- Windows: `Restart-Service WazuhSvc`
- Linux: `sudo systemctl restart wazuh-agent`

### TheHive/Cortex Connection Issues

**Check network connectivity:**
```bash
docker network inspect soc-network
```

**Recreate containers:**
```bash
docker compose -f docker-compose.thehive.yml down
docker compose -f docker-compose.thehive.yml up -d
```

### Shuffle Not Accessible

**Check all Shuffle containers:**
```bash
docker ps | grep shuffle
```

**Restart Shuffle:**
```bash
docker compose -f docker-compose.shuffle.yml restart
```

### Port Conflicts

**Check if ports are in use:**
```bash
# Linux/WSL
netstat -tlnp | grep -E "443|9000|9001|3001|8888"

# Windows
netstat -ano | findstr "443 9000 9001 3001 8888"
```

### Memory Issues

**Check Docker memory:**
```bash
docker stats
```

**Increase Docker memory:**
- Docker Desktop → Settings → Resources → Memory

---

## Support

For issues and questions:
- Create an issue on GitHub
- Check the documentation in `/docs`
- Review container logs

---

## Next Steps

After installation:
1. [Configure Detection Rules](../detection-rules/README.md)
2. [Set Up Attack Scenarios](../docs/attack-scenarios/README.md)
3. [Create Shuffle Playbooks](../playbooks/README.md)
