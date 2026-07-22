# Detection Rules

**Enterprise SOC Monitoring using Splunk SIEM**

This document outlines all security detection rules implemented in the enterprise SOC monitoring infrastructure. Each rule is designed to identify suspicious activities, potential threats, and security anomalies across the monitored environment.

---

## Table of Contents

1. [Failed Login Detection](#1-failed-login-detection)
2. [Brute Force Detection](#2-brute-force-detection)
3. [PowerShell Execution Detection](#3-powershell-execution-detection)
4. [User Account Creation Detection](#4-user-account-creation-detection)
5. [Service Creation Detection](#5-service-creation-detection)
6. [Scheduled Task Detection](#6-scheduled-task-detection)
7. [USB Device Detection](#7-usb-device-detection)
8. [File Integrity Monitoring](#8-file-integrity-monitoring)

---

## 1. Failed Login Detection

### Overview

| Property | Value |
|----------|-------|
| **Objective** | Detect unsuccessful Windows logon attempts that may indicate unauthorized access attempts |
| **Event ID** | 4625 |
| **Severity** | Medium |
| **MITRE ATT&CK** | [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/) |

### Detection Query

```spl
index=main EventCode=4625
| stats count by Account_Name, host
```

### Investigation Steps

- Verify source hostname and IP address
- Review username(s) targeted
- Check frequency and timing of failed login attempts
- Correlate with successful logins (Event ID 4624)
- Identify geographical anomalies
- Review account lockout events

### Expected Alert

**Multiple failed authentication attempts detected**

---

## 2. Brute Force Detection

### Overview

| Property | Value |
|----------|-------|
| **Objective** | Identify repeated failed login attempts against a specific user account |
| **Event ID** | 4625 |
| **Severity** | High |
| **MITRE ATT&CK** | [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/) |

### Detection Query

```spl
index=main EventCode=4625
| stats count by Account_Name
| where count >= 5
```

### Investigation Steps

- Determine the targeted account
- Review source host(s) and IP addresses
- Check for account lockout events
- Verify if successful login occurred after failures
- Review failed login source geography
- Assess account privilege level

### Expected Alert

**Potential brute-force attack detected**

---

## 3. PowerShell Execution Detection

### Overview

| Property | Value |
|----------|-------|
| **Objective** | Detect PowerShell process execution that may indicate attacker activity or unauthorized script execution |
| **Event ID** | Sysmon Event 1 (Process Creation) |
| **Severity** | High |
| **MITRE ATT&CK** | [T1059.001 - PowerShell](https://attack.mitre.org/techniques/T1059/001/) |

### Detection Query

```spl
index=main Image="*powershell.exe"
| stats count by parent_process, user, host
```

### Investigation Steps

- Review the executed command or script
- Identify parent process
- Validate user and execution context
- Investigate suspicious or obfuscated scripts
- Check for script block logging events
- Verify business justification for execution

### Expected Alert

**PowerShell process execution detected**

---

## 4. User Account Creation Detection

### Overview

| Property | Value |
|----------|-------|
| **Objective** | Detect creation of new local user accounts that may indicate unauthorized account provisioning |
| **Event ID** | 4720 |
| **Severity** | High |
| **MITRE ATT&CK** | [T1136 - Create Account](https://attack.mitre.org/techniques/T1136/) |

### Detection Query

```spl
index=main EventCode=4720
| stats count by New_Account_Name, user, host
```

### Investigation Steps

- Verify administrator activity and authorization
- Review created username for suspicious naming
- Identify creator account
- Validate business justification
- Check for suspicious account properties (e.g., disabled status)
- Correlate with privileged group additions

### Expected Alert

**New local user account created**

---

## 5. Service Creation Detection

### Overview

| Property | Value |
|----------|-------|
| **Objective** | Detect creation of Windows services that may be used for persistence or lateral movement |
| **Event ID** | 7045 |
| **Severity** | High |
| **MITRE ATT&CK** | [T1543.003 - Windows Service](https://attack.mitre.org/techniques/T1543/003/) |

### Detection Query

```spl
index=main EventCode=7045
| stats count by Service_Name, Image_Path, user, host
```

### Investigation Steps

- Review service name for suspicious characteristics
- Verify executable path and location
- Check digital signature and publisher information
- Confirm legitimacy with system administrators
- Assess service start type (auto-start vs. manual)
- Review service account permissions

### Expected Alert

**New Windows service installed**

---

## 6. Scheduled Task Detection

### Overview

| Property | Value |
|----------|-------|
| **Objective** | Detect scheduled task creation used for persistence or automated malicious execution |
| **Event ID** | 4698 |
| **Severity** | High |
| **MITRE ATT&CK** | [T1053.005 - Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) |

### Detection Query

```spl
index=main EventCode=4698
| stats count by Task_Name, Task_Content, user, host
```

### Investigation Steps

- Identify task creator and creation authority
- Review execution schedule (trigger timing)
- Verify task command and script path
- Check for persistence indicators
- Assess task execution context (privilege level)
- Review task history and execution logs

### Expected Alert

**New scheduled task detected**

---

## 7. USB Device Detection

### Overview

| Property | Value |
|----------|-------|
| **Objective** | Detect USB device insertion into monitored endpoints to prevent data exfiltration and unauthorized media access |
| **Event ID** | 6416 |
| **Severity** | Medium |
| **MITRE ATT&CK** | [T1091 - Replication Through Removable Media](https://attack.mitre.org/techniques/T1091/) |

### Detection Query

```spl
index=main EventCode=6416
| stats count by Device_Name, user, host, DeviceClass
```

### Investigation Steps

- Identify device manufacturer and model
- Review user account that connected device
- Verify device authorization (approved list)
- Check for file access and copy operations
- Review device serial number for tracking
- Assess data sensitivity in user context

### Expected Alert

**USB storage device connected**

---

## 8. File Integrity Monitoring

### Overview

| Property | Value |
|----------|-------|
| **Objective** | Detect creation, modification, or deletion of monitored critical files to identify potential tampering |
| **Event ID** | Sysmon Event 11 (File Create/Modification) |
| **Severity** | Medium |
| **MITRE ATT&CK** | [T1565 - Data Manipulation](https://attack.mitre.org/techniques/T1565/) |

### Detection Query

```spl
index=main EventCode=11
| stats count by TargetFilename, Image, user, host, EventType
```

### Investigation Steps

- Identify the modified or deleted file
- Review process responsible for modification
- Verify user activity and authorization
- Check file timestamps and version history
- Assess file sensitivity and criticality
- Review backup and recovery status

### Expected Alert

**File modification activity detected**

---

## Detection Rules Summary

| Detection Rule | Event ID | Data Source | Severity | MITRE Technique |
|---|---|---|---|---|
| Failed Login | 4625 | Windows Event Logs | Medium | T1110 |
| Brute Force | 4625 | Windows Event Logs | High | T1110 |
| PowerShell Execution | Sysmon 1 | Sysmon | High | T1059.001 |
| User Account Creation | 4720 | Windows Event Logs | High | T1136 |
| Service Creation | 7045 | Windows Event Logs | High | T1543.003 |
| Scheduled Task | 4698 | Windows Event Logs | High | T1053.005 |
| USB Device Detection | 6416 | Windows Event Logs | Medium | T1091 |
| File Integrity Monitoring | Sysmon 11 | Sysmon | Medium | T1565 |

---

## Alert Severity Levels

| Severity | Definition | Response Time |
|----------|-----------|---|
| **High** | Potential active threat requiring immediate investigation | < 1 hour |
| **Medium** | Suspicious activity requiring timely investigation | < 4 hours |
| **Low** | Informational findings for trend analysis | < 24 hours |

---

## Incident Response Workflow

1. **Alert Triggered** → Detection rule conditions met
2. **Initial Triage** → Verify alert legitimacy and assess severity
3. **Investigation** → Execute investigation steps and gather evidence
4. **Containment** → Take protective actions if threat confirmed
5. **Remediation** → Address root cause and remove threats
6. **Documentation** → Record findings and update rules as needed

---

## Tuning and Maintenance

Detection rules require regular tuning to:
- Reduce false positives
- Maintain relevance to evolving threats
- Optimize query performance
- Align with business changes

Review and update detection rules quarterly or as needed based on:
- Security incident findings
- Threat intelligence updates
- Infrastructure changes
- MITRE ATT&CK framework updates

---

## Related Documentation

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Splunk Search Language (SPL) Documentation](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/SearchLanguage)
- [Windows Event Log Reference](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings)
- [Sysmon Documentation](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)

---

**Last Updated:** 2026-07-22  
**Status:** Active  
**Version:** 2.0
