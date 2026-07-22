# MITRE ATT&CK Mapping

## Overview

This document provides comprehensive mapping of all detection use cases implemented in the Enterprise SOC Monitoring using Splunk SIEM project to the [MITRE ATT&CK Framework](https://attack.mitre.org/). 

The MITRE ATT&CK Framework is a globally recognized knowledge base of adversary tactics and techniques based on real-world observations. By mapping security detections to this framework, we establish a standardized approach to understanding attacker behavior and ensuring comprehensive threat coverage across different attack phases.

This project implements multiple Windows security detections aligned with MITRE ATT&CK techniques commonly used by attackers during different phases of an intrusion, enabling effective SOC monitoring and threat detection.

---

## Detection Mapping Summary

| Detection Use Case | MITRE Tactic | Technique ID | Technique Name | Data Source |
|---|---|---|---|---|
| Failed Login Detection | Credential Access | T1110 | Brute Force | Windows Security Logs |
| Brute Force Detection | Credential Access | T1110 | Brute Force | Windows Security Logs |
| PowerShell Execution | Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | Sysmon |
| User Account Creation | Persistence | T1136 | Create Account | Windows Security Logs |
| Service Creation | Persistence | T1543.003 | Create or Modify System Process: Windows Service | Windows System Logs |
| Scheduled Task Creation | Persistence | T1053.005 | Scheduled Task/Job: Scheduled Task | Windows Security Logs |
| USB Device Detection | Lateral Movement | T1091 | Replication Through Removable Media | Windows Security Logs |
| File Integrity Monitoring | Impact | T1565 | Data Manipulation | Sysmon |

---

## Detailed Detection Analysis

### 1. Failed Login Detection

**MITRE Tactic:** Credential Access  
**Technique:** T1110 – Brute Force

#### Description
Attackers frequently attempt to gain unauthorized access by repeatedly trying incorrect passwords. This detection identifies individual failed authentication events that may indicate password guessing or reconnaissance activities.

#### Detection Method
- **Windows Event ID:** 4625 (Failed Logon)
- **Data Source:** Windows Security Logs
- **Alert Condition:** Single or infrequent failed login attempts

#### Significance
Early detection of failed logons helps identify targeted reconnaissance attempts before they escalate into full brute-force attacks.

---

### 2. Brute Force Detection

**MITRE Tactic:** Credential Access  
**Technique:** T1110 – Brute Force

#### Description
Multiple failed login attempts within a short period indicate automated password attacks against a user account or system. This detection uses threshold-based alerting to identify coordinated attack patterns.

#### Detection Method
- **Windows Event ID:** 4625 (Failed Logon)
- **Detection Logic:** Threshold-based alerting using SPL
- **Alert Condition:** Multiple failed logons within defined time window

#### SPL Example
```spl
index=windows EventCode=4625 
| stats count by dest, src 
| where count > 10
```

#### Significance
Threshold-based brute force detection enables rapid response to active credential compromise attempts.

---

### 3. PowerShell Execution Detection

**MITRE Tactic:** Execution  
**Technique:** T1059.001 – Command and Scripting Interpreter: PowerShell

#### Description
PowerShell is commonly abused by attackers for executing malicious commands, downloading payloads, privilege escalation, and lateral movement. Monitoring PowerShell execution provides visibility into script-based attacks.

#### Detection Method
- **Sysmon Event ID:** 1 (Process Creation)
- **Filter Criteria:** Image = powershell.exe
- **Data Source:** Sysmon

#### SPL Example
```spl
index=sysmon EventID=1 Image="*powershell.exe"
| fields ComputerName, Image, CommandLine, ParentImage
```

#### Significance
PowerShell execution visibility is critical for detecting fileless malware, lateral movement, and post-exploitation activities.

---

### 4. User Account Creation Detection

**MITRE Tactic:** Persistence  
**Technique:** T1136 – Create Account

#### Description
Attackers may create new local accounts to maintain persistent access after compromising a system. This detection monitors account creation events to identify unauthorized administrative access or persistence mechanisms.

#### Detection Method
- **Windows Event ID:** 4720 (A user account was created)
- **Data Source:** Windows Security Logs
- **Alert Condition:** Any new account creation event

#### Significance
Monitoring account creation helps identify persistence mechanisms and unauthorized administrative access attempts.

---

### 5. Windows Service Creation Detection

**MITRE Tactic:** Persistence  
**Technique:** T1543.003 – Create or Modify System Process: Windows Service

#### Description
Malicious services can be installed to automatically execute malware during system startup, providing attackers with persistent code execution. Service creation monitoring enables detection of this common persistence technique.

#### Detection Method
- **Windows Event ID:** 7045 (A new service was installed on the system)
- **Data Source:** Windows System Logs
- **Alert Condition:** Service creation events from non-standard paths or with suspicious names

#### Significance
Service-based persistence is difficult to remove and provides reliable code execution across reboots, making this detection critical for incident response.

---

### 6. Scheduled Task Creation Detection

**MITRE Tactic:** Persistence  
**Technique:** T1053.005 – Scheduled Task/Job: Scheduled Task

#### Description
Scheduled tasks are frequently used by attackers to establish persistence and execute malicious payloads automatically. This detection identifies task creation events that may indicate automated malware execution.

#### Detection Method
- **Windows Event ID:** 4698 (A scheduled task was created)
- **Data Source:** Windows Security Logs
- **Alert Condition:** Scheduled task creation with suspicious attributes or scripts

#### Significance
Scheduled tasks provide persistent, recurring code execution that survives system reboots, making them attractive to attackers for maintaining presence.

---

### 7. USB Device Detection

**MITRE Tactic:** Lateral Movement  
**Technique:** T1091 – Replication Through Removable Media

#### Description
Removable media can be used to introduce malware into an environment, bypass network controls, or transfer sensitive data between systems. Monitoring USB device connections provides visibility into removable media usage.

#### Detection Method
- **Windows Event ID:** 6416 (A new external device was recognized by the system)
- **Data Source:** Windows Security Logs
- **Alert Condition:** USB device connection events

#### Significance
USB monitoring helps prevent data exfiltration, malware introduction via removable media, and unauthorized data transfers in sensitive environments.

---

### 8. File Integrity Monitoring

**MITRE Tactic:** Impact  
**Technique:** T1565 – Data Manipulation

#### Description
Unauthorized file creation or modification may indicate malware activity, ransomware behavior, or attempts to tamper with sensitive data. File integrity monitoring provides real-time visibility into file system changes.

#### Detection Method
- **Sysmon Event ID:** 11 (FileCreate)
- **Data Source:** Sysmon
- **Alert Condition:** Files created/modified in critical directories or with suspicious extensions

#### SPL Example
```spl
index=sysmon EventID=11 (TargetFilename="*\.exe" OR TargetFilename="*\.dll" OR TargetFilename="*\.bat")
| fields Computer, TargetFilename, UtcTime
```

#### Significance
File integrity monitoring enables detection of ransomware, malware installation, and unauthorized data modification in real-time.

---

## ATT&CK Coverage Summary

| Tactic | Techniques | Count |
|---|---|---|
| Credential Access | T1110 | 1 |
| Execution | T1059.001 | 1 |
| Persistence | T1136, T1543.003, T1053.005 | 3 |
| Lateral Movement | T1091 | 1 |
| Impact | T1565 | 1 |
| **Total** | **7 Unique Techniques** | **7** |

---

## Detection Coverage Statistics

| Metric | Value |
|---|---|
| Total Detection Rules | 8 |
| MITRE Tactics Covered | 5 |
| MITRE Techniques Covered | 7 |
| Windows Event IDs | 4625, 4720, 4698, 6416, 7045 |
| Sysmon Event IDs | 1, 11 |
| Primary Data Sources | Windows Security Logs, Sysmon |

---

## Coverage Gaps & Future Enhancements

To improve detection coverage, consider implementing detections for:

- **Discovery Techniques:** T1087 (Account Discovery), T1010 (Application Window Discovery)
- **Defense Evasion:** T1197 (BITS Jobs), T1140 (Deobfuscate/Decode Files or Information)
- **Command & Control:** T1071 (Application Layer Protocol)
- **Exfiltration:** T1041 (Exfiltration Over C2 Channel), T1020 (Automated Exfiltration)

---

## Benefits of MITRE ATT&CK Mapping

✓ **Standardization:** Aligns security detections with an industry-recognized, adversary-focused framework  
✓ **Threat Understanding:** Helps SOC analysts understand and contextualize attacker behavior  
✓ **Threat Hunting:** Enables proactive threat hunting based on known attack patterns  
✓ **Gap Analysis:** Identifies gaps in detection coverage across the attack lifecycle  
✓ **Maturity Assessment:** Measures and improves security monitoring maturity  
✓ **Compliance:** Aligns with enterprise SOC best practices and security compliance requirements  
✓ **Communication:** Provides common language for security teams and stakeholders  

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sysmon Documentation](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Windows Event ID Reference](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-events)

---

## Conclusion

This project demonstrates practical Security Operations Center (SOC) monitoring by mapping Windows security detections to the MITRE ATT&CK Framework. By establishing this mapping, we create a foundation for:

- **Comprehensive Threat Coverage:** Understanding which attack techniques are detected
- **Effective Incident Response:** Rapidly identifying and responding to known attack patterns
- **Continuous Improvement:** Identifying coverage gaps and prioritizing new detections
- **SOC Maturity:** Building industry-aligned detection and response capabilities

The eight detection rules implemented in this project cover critical attack phases including Credential Access, Execution, Persistence, Lateral Movement, and Impact, providing a well-rounded foundation for enterprise threat detection.
