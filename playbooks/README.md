# Shuffle SOAR Playbooks

## Overview

Automated security playbooks for common SOC scenarios using Shuffle SOAR platform. These playbooks demonstrate Security Orchestration, Automation, and Response (SOAR) capabilities.

## Available Playbooks

### 1. Wazuh Alert Enrichment

**Purpose**: Automatically enrich security alerts with threat intelligence

**Trigger**: Wazuh alert webhook (severity level >= 10)

**Workflow**:
```
1. Receive Wazuh alert via webhook
   ↓
2. Extract IOCs (IPs, domains, hashes, URLs)
   ↓
3. Query VirusTotal for hash/URL reputation
   ↓
4. Query AbuseIPDB for IP reputation
   ↓
5. Check MISP for known threats
   ↓
6. Aggregate enrichment data
   ↓
7. If malicious → Create TheHive case
   ↓
8. Add enriched observables to case
   ↓
9. Assign severity and tags
   ↓
10. (Optional) Send Slack/Email notification
```

**Apps Used**:
- Wazuh (webhook trigger)
- Cortex (VirusTotal, AbuseIPDB analyzers)
- MISP (threat intelligence)
- TheHive (case creation)
- Email/Slack (notifications)

**Expected Outcome**:
- Automated IOC enrichment within seconds
- TheHive case with full context
- Reduced analyst investigation time by 80%

---

### 2. Malware Response

**Purpose**: Automated response to malware detection

**Trigger**: Wazuh malware alert (rule groups: malware, trojan, ransomware)

**Workflow**:
```
1. Receive malware detection alert
   ↓
2. Extract file hash and endpoint details
   ↓
3. Create HIGH priority TheHive case
   ↓
4. Query VirusTotal for malware classification
   ↓
5. Check MISP for known campaigns
   ↓
6. (Optional) Trigger Velociraptor collection:
   - Memory dump
   - Process list
   - Network connections
   - File system artifacts
   ↓
7. (Optional) Isolate endpoint
   ↓
8. Submit hash to sandbox (Cuckoo/Any.run)
   ↓
9. Add analysis results to case
   ↓
10. Notify SOC team (Email/Slack)
```

**Apps Used**:
- Wazuh
- TheHive
- Cortex (VirusTotal)
- Velociraptor (optional)
- Email/Slack

**Expected Outcome**:
- Immediate high-priority case creation
- Comprehensive malware analysis
- Optional endpoint isolation
- Full forensic artifact collection

---

### 3. Phishing Response

**Purpose**: Automated phishing email analysis and response

**Trigger**: Phishing alert or manual case creation

**Workflow**:
```
1. Receive phishing report
   ↓
2. Extract URLs and attachments from email
   ↓
3. Analyze URLs:
   - URLhaus reputation
   - VirusTotal URL scan
   - Screenshot capture
   ↓
4. Analyze attachments:
   - File hash check
   - Malware scanning
   - Sandbox detonation
   ↓
5. Check sender domain reputation
   ↓
6. If malicious:
   - Block URLs in proxy/firewall
   - Add IOCs to MISP
   - Create TheHive case
   - Alert other users
   ↓
7. Generate phishing report
```

**Apps Used**:
- Email (EML parser)
- Cortex (URLhaus, VirusTotal)
- TheHive
- MISP
- Firewall API (for blocking)

**Expected Outcome**:
- Automated URL/attachment analysis
- Malicious content blocked
- IOCs shared via MISP
- User awareness alert sent

---

### 4. Brute Force Response

**Purpose**: Respond to brute force login attempts

**Trigger**: Wazuh brute force alert (multiple failed logins)

**Workflow**:
```
1. Detect 5+ failed logins from same IP in 5 minutes
   ↓
2. Extract source IP and target account
   ↓
3. Query AbuseIPDB for IP reputation
   ↓
4. Check MISP for known attacker IPs
   ↓
5. If external IP:
   - Block at firewall
   - Add to blacklist
   ↓
6. If internal IP:
   - Create HIGH priority case
   - Alert on possible compromised account
   - Trigger account review
   ↓
7. Log all details in TheHive case
   ↓
8. Add IP to MISP as malicious
```

**Apps Used**:
- Wazuh
- AbuseIPDB
- MISP
- TheHive
- Firewall API

**Expected Outcome**:
- Automatic IP blocking
- Prevention of account compromise
- Threat intelligence update
- Case for investigation

---

### 5. Credential Dump Response

**Purpose**: Critical response to credential dumping attempts

**Trigger**: Wazuh LSASS access alert (Rule ID 100060)

**Workflow**:
```
1. CRITICAL: LSASS memory access detected
   ↓
2. Create CRITICAL TheHive case
   ↓
3. Extract endpoint details:
   - Hostname
   - Username
   - Process name
   - Parent process
   ↓
4. (Optional) Isolate endpoint immediately
   ↓
5. Trigger Velociraptor collection:
   - Memory dump for analysis
   - Process memory
   - Authentication logs
   - Network connections
   ↓
6. Identify all accounts on system
   ↓
7. Force password reset (with approval)
   ↓
8. Check for lateral movement
   ↓
9. Alert security team immediately
```

**Apps Used**:
- Wazuh
- TheHive
- Velociraptor
- Active Directory API
- Email/Slack (urgent notification)

**Expected Outcome**:
- Immediate critical alert
- Endpoint isolation
- Memory forensics
- Password reset
- Prevented lateral movement

---

## Playbook Configuration

### Prerequisites

1. **Shuffle Setup**:
   - Shuffle accessible at http://localhost:3001
   - Admin account configured
   - Apps activated

2. **API Keys Required**:
   - TheHive API key
   - Cortex API key (optional)
   - VirusTotal API key (optional)
   - AbuseIPDB API key (optional)
   - Email/Slack webhook (optional)

3. **Wazuh Integration**:
   - Wazuh API accessible
   - Webhook configured in Wazuh

### Creating a Playbook

1. **Login to Shuffle**: http://localhost:3001
2. **Go to Workflows** → **New Workflow**
3. **Add Trigger**: Webhook or Schedule
4. **Add Apps**:
   - Drag from left panel
   - Connect with arrows
   - Configure each app
5. **Configure Data Flow**:
   - Use `$exec` variables to pass data
   - Example: `$exec.title`, `$exec.source_ip`
6. **Test Workflow**: Use "Run" button
7. **Enable**: Toggle to active

### Example: Alert Enrichment Playbook

```yaml
Workflow: Wazuh Alert Enrichment
Trigger: Webhook

Steps:
  1. Webhook Receiver
     - URL: https://shuffle:3001/api/v1/hooks/webhook_xyz
     - Method: POST
  
  2. Extract IOCs
     - Parse JSON from Wazuh
     - Extract: source_ip, file_hash, domain
  
  3. VirusTotal Check
     - App: VirusTotal
     - Action: Get IP Report
     - Input: $exec.source_ip
  
  4. AbuseIPDB Check
     - App: HTTP
     - URL: https://api.abuseipdb.com/api/v2/check
     - Headers: Key: API-Key-Here
  
  5. Create TheHive Case
     - App: TheHive
     - Action: Create Alert
     - Title: $exec.rule_description
     - Description: Enriched alert data
     - Tags: [$exec.mitre_technique]
  
  6. Send Notification
     - App: Email
     - To: soc@company.com
     - Subject: New Security Alert
```

---

## Metrics and Reporting

### Playbook Performance

Monitor these metrics for each playbook:

- **Execution Time**: Time from trigger to completion
- **Success Rate**: Percentage of successful executions
- **Error Rate**: Failed executions
- **Cases Created**: Number of TheHive cases generated

### Expected Performance

| Playbook | Avg Execution Time | Success Rate |
|----------|-------------------|--------------|
| Alert Enrichment | 10-15 seconds | 95%+ |
| Malware Response | 30-60 seconds | 90%+ |
| Phishing Response | 45-90 seconds | 85%+ |
| Brute Force Response | 5-10 seconds | 95%+ |

---

## Best Practices

1. **Error Handling**: Always include error branches
2. **Logging**: Log all actions for audit trail
3. **Notifications**: Alert on playbook failures
4. **Testing**: Test with dummy data before production
5. **Documentation**: Document all playbook changes
6. **Review**: Regularly review and optimize playbooks
7. **Approval Gates**: Require human approval for critical actions (endpoint isolation, password resets)

---

## Troubleshooting

### Playbook Not Triggering

**Check**:
- Webhook URL is correct
- Wazuh can reach Shuffle
- Firewall rules allow traffic
- Shuffle is running: `docker ps | grep shuffle`

**Debug**:
```bash
# Check Shuffle logs
docker logs shuffle-backend

# Test webhook manually
curl -X POST http://localhost:3001/api/v1/hooks/YOUR_WEBHOOK_ID \
  -H "Content-Type: application/json" \
  -d '{"test": "data"}'
```

### App Connections Failing

**Check**:
- API keys are valid
- Services are reachable
- Credentials are correct

**Test Connectivity**:
```bash
# Test TheHive connection
curl -X GET http://thehive:9000/api/v1/status \
  -H "Authorization: Bearer YOUR_API_KEY"

# Test from Shuffle container
docker exec -it shuffle-backend curl http://thehive:9000
```

### Playbook Executing But Failing

**Check**:
- Review execution logs in Shuffle UI
- Verify data format from trigger
- Check app configurations
- Validate API responses

---

## Advanced Playbooks

### Custom Playbook Ideas

1. **Automated Threat Hunting**:
   - Periodic MISP IOC queries
   - Retroactive log searches
   - Proactive threat detection

2. **Compliance Reporting**:
   - Scheduled compliance checks
   - Report generation
   - Automated evidence collection

3. **Asset Management**:
   - Track new devices
   - Unauthorized software detection
   - Configuration drift alerts

4. **Insider Threat Detection**:
   - Unusual data access patterns
   - After-hours activity monitoring
   - Mass file downloads

---

## References

- [Shuffle Documentation](https://shuffler.io/docs)
- [TheHive API](https://docs.thehive-project.org/thehive/api-docs/)
- [Wazuh API](https://documentation.wazuh.com/current/user-manual/api/reference.html)
- [SOAR Best Practices](https://www.sans.org/white-papers/)
