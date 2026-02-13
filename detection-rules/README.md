# Detection Rules

## Overview

This directory contains custom detection rules mapped to the MITRE ATT&CK framework. All rules are designed for the Wazuh SIEM platform and provide comprehensive threat detection coverage.

## Rule Categories

### Windows Rules (`windows/custom_rules.xml`)

**Total: 35+ rules covering:**

- **Initial Access (TA0001)**
  - T1566.001 - Phishing: Spearphishing Attachment
  
- **Execution (TA0002)**
  - T1059.001 - PowerShell (Encoded commands, suspicious flags, download & execute)
  - T1059.003 - Windows Command Shell
  - T1047 - WMI Execution

- **Persistence (TA0003)**
  - T1547.001 - Registry Run Keys
  - T1053.005 - Scheduled Tasks
  - T1543.003 - Windows Services

- **Privilege Escalation (TA0004)**
  - T1134 - Access Token Manipulation

- **Defense Evasion (TA0005)**
  - T1070.001 - Clear Windows Event Logs
  - T1562.001 - Disable Security Tools
  - T1027 - Obfuscated Files (Certutil abuse)

- **Credential Access (TA0006)**
  - T1003.001 - LSASS Memory Dumping
  - T1003.002 - SAM Database Extraction
  - T1110.001 - Brute Force Attacks

- **Discovery (TA0007)**
  - T1082 - System Information Discovery
  - T1016 - System Network Configuration
  - T1018 - Remote System Discovery

- **Lateral Movement (TA0008)**
  - T1021.002 - SMB/Windows Admin Shares (PsExec)
  - T1021.006 - Windows Remote Management

- **Collection (TA0009)**
  - T1560 - Archive Collected Data

- **Exfiltration (TA0010)**
  - T1048 - Exfiltration Over Alternative Protocol

- **Impact (TA0040)**
  - T1490 - Ransomware Indicators (Shadow copy deletion, boot recovery disabled)

### Linux Rules

**Included in custom_rules.xml:**

- **Privilege Escalation**
  - T1548.003 - Sudo Command Execution

- **Credential Access**
  - T1110.001 - SSH Brute Force

- **Execution**
  - T1059 - Reverse Shell Detection

- **Persistence**
  - T1053.003 - Crontab Modification

## MITRE ATT&CK Mapping

| Rule ID Range | Tactic | Techniques Covered |
|---------------|--------|-------------------|
| 100001-100009 | Initial Access | 1 technique |
| 100010-100029 | Execution | 4 techniques |
| 100030-100039 | Persistence | 3 techniques |
| 100040-100049 | Privilege Escalation | 1 technique |
| 100050-100059 | Defense Evasion | 3 techniques |
| 100060-100069 | Credential Access | 3 techniques |
| 100070-100079 | Discovery | 3 techniques |
| 100080-100089 | Lateral Movement | 2 techniques |
| 100090-100099 | Collection | 1 technique |
| 100100-100199 | Exfiltration | 1 technique |
| 100300-100399 | Impact (Ransomware) | 1 technique |
| 100200-100299 | Linux-specific | 4 techniques |

## Rule Severity Levels

Wazuh uses rule levels 0-15 to indicate severity:

| Level | Severity | Examples |
|-------|----------|----------|
| 6 | Low | Discovery commands (systeminfo, whoami) |
| 8 | Medium | Archive creation, network enumeration |
| 10 | Medium-High | Scheduled tasks, registry modifications |
| 12 | High | Encoded PowerShell, PsExec execution |
| 14 | Critical | Log clearing, credential dumping attempts |
| 15 | Critical | LSASS access, shadow copy deletion |

## Installation

### Deploy Rules to Wazuh

```bash
# Copy rules to Wazuh manager
docker cp detection-rules/windows/custom_rules.xml wazuh.manager:/var/ossec/etc/rules/custom_rules.xml

# Set proper permissions
docker exec -it wazuh.manager bash -c "chown wazuh:wazuh /var/ossec/etc/rules/custom_rules.xml"

# Restart Wazuh manager to load rules
docker exec -it wazuh.manager /var/ossec/bin/wazuh-control restart

# Verify rules are loaded
docker exec -it wazuh.manager grep -r "100001" /var/ossec/etc/rules/
```

### Test Rules

```bash
# Use Wazuh logtest tool to test detection
docker exec -it wazuh.manager /var/ossec/bin/wazuh-logtest
```

## Rule Format

Wazuh rules follow this XML structure:

```xml
<rule id="100XXX" level="XX">
  <if_sid>parent_rule_id</if_sid>
  <field name="field_name" type="pcre2">regex_pattern</field>
  <description>Human-readable description</description>
  <mitre>
    <id>TXXXX.XXX</id>
  </mitre>
  <group>group_name,tags,</group>
</rule>
```

### Key Elements:

- **id**: Unique rule identifier (100000-199999 for custom rules)
- **level**: Severity level (0-15)
- **if_sid**: Parent rule to inherit from
- **field**: Event field to match with regex
- **mitre**: MITRE ATT&CK technique ID
- **group**: Categorization tags

## Testing Attack Scenarios

### Test PowerShell Detection (T1059.001)

```powershell
# Encoded PowerShell - Should trigger Rule 100010
powershell -enc VwByAGkAdABlAC0ASABvAHMAdAAgACIAVABlAHMAdAAi

# Suspicious flags - Should trigger Rule 100011
powershell -ExecutionPolicy Bypass -NoProfile -Command "Write-Host 'Test'"
```

### Test Scheduled Task Detection (T1053.005)

```powershell
# Should trigger Rule 100031
schtasks /create /tn "TestTask" /tr "cmd.exe /c echo test" /sc daily /st 12:00
schtasks /delete /tn "TestTask" /f
```

### Test Discovery Detection (T1082, T1016)

```powershell
# Should trigger Rule 100070
systeminfo
whoami /all

# Should trigger Rule 100071
ipconfig /all
netstat -an
```

### Test Credential Access (T1003.002)

```powershell
# Should trigger Rule 100062
reg query "HKLM\SAM"
```

## Adding Custom Rules

To add your own detection rules:

1. **Choose a Rule ID**: Use 100000-199999 range
2. **Determine Severity**: Select appropriate level
3. **Map to MITRE**: Identify the ATT&CK technique
4. **Test Thoroughly**: Validate with real attacks
5. **Document**: Add to this README

### Example Custom Rule:

```xml
<rule id="100500" level="12">
  <if_sid>61603</if_sid>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)mymalware\.exe</field>
  <description>Custom malware detection</description>
  <mitre>
    <id>T1204</id>
  </mitre>
  <group>malware,custom,</group>
</rule>
```

## Rule Performance

- All rules use PCRE2 regex for efficient pattern matching
- Rules inherit from Sysmon base rules (61xxx series) for performance
- Frequency-based rules (brute force) use timeframe windows

## References

- [Wazuh Ruleset Documentation](https://documentation.wazuh.com/current/user-manual/ruleset/index.html)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sysmon Configuration](https://github.com/SwiftOnSecurity/sysmon-config)

## Contributing

To contribute new detection rules:

1. Create rule following the format above
2. Test against actual attack scenarios
3. Document the detection logic
4. Submit pull request with test cases
