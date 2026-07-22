\# Detection Rules



This document contains all security detection rules implemented in the Enterprise SOC Monitoring using Splunk SIEM project.



\---



\# Table of Contents



1\. Failed Login Detection

2\. Brute Force Detection

3\. PowerShell Execution Detection

4\. User Account Creation Detection

5\. Service Creation Detection

6\. Scheduled Task Detection

7\. USB Device Detection

8\. File Integrity Monitoring



\---



\# 1. Failed Login Detection



\## Objective



Detect unsuccessful Windows logon attempts that may indicate unauthorized access attempts.



\## Windows Event ID



4625



\## SPL Query



```spl

index=main EventCode=4625

| stats count by Account\_Name, host

```



\## MITRE ATT\&CK



Technique: T1110 - Brute Force



\## Severity



Medium



\## Investigation Steps



\- Verify source hostname

\- Review username targeted

\- Check frequency of failed logins

\- Correlate with successful logins (Event ID 4624)



\## Expected Alert



Multiple failed authentication attempts detected.



\---



\# 2. Brute Force Detection



\## Objective



Identify repeated failed login attempts against a user account.



\## Windows Event ID



4625



\## SPL Query



```spl

index=main EventCode=4625

| stats count by Account\_Name

| where count >= 5

```



\## MITRE ATT\&CK



Technique: T1110 - Brute Force



\## Severity



High



\## Investigation Steps



\- Determine targeted account

\- Review source host

\- Check lockout events

\- Verify successful login after failures



\## Expected Alert



Potential brute-force attack detected.



\---



\# 3. PowerShell Execution Detection



\## Objective



Detect PowerShell execution which may indicate attacker activity.



\## Sysmon Event ID



1



\## SPL Query



```spl

index=main Image="\*powershell.exe"

```



\## MITRE ATT\&CK



Technique: T1059.001 - PowerShell



\## Severity



High



\## Investigation Steps



\- Review executed command

\- Check parent process

\- Validate user

\- Investigate suspicious scripts



\## Expected Alert



PowerShell process execution detected.



\---



\# 4. User Account Creation Detection



\## Objective



Detect creation of new local user accounts.



\## Windows Event ID



4720



\## SPL Query



```spl

index=main EventCode=4720

```



\## MITRE ATT\&CK



Technique: T1136 - Create Account



\## Severity



High



\## Investigation Steps



\- Verify administrator activity

\- Review created username

\- Check creator account

\- Validate business justification



\## Expected Alert



New local user account created.



\---



\# 5. Service Creation Detection



\## Objective



Detect creation of Windows services that may be used for persistence.



\## Windows Event ID



7045



\## SPL Query



```spl

index=main EventCode=7045

```



\## MITRE ATT\&CK



Technique: T1543.003 - Windows Service



\## Severity



High



\## Investigation Steps



\- Review service name

\- Verify executable path

\- Check publisher

\- Confirm legitimacy



\## Expected Alert



New Windows service installed.



\---



\# 6. Scheduled Task Detection



\## Objective



Detect scheduled task creation used for persistence.



\## Windows Event ID



4698



\## SPL Query



```spl

index=main EventCode=4698

```



\## MITRE ATT\&CK



Technique: T1053.005 - Scheduled Task



\## Severity



High



\## Investigation Steps



\- Identify task creator

\- Review execution schedule

\- Verify task command

\- Check persistence indicators



\## Expected Alert



New scheduled task detected.



\---



\# 7. USB Device Detection



\## Objective



Detect USB device insertion into monitored endpoints.



\## Windows Event ID



6416



\## SPL Query



```spl

index=main EventCode=6416

```



\## MITRE ATT\&CK



Technique: T1091 - Replication Through Removable Media



\## Severity



Medium



\## Investigation Steps



\- Identify device

\- Review user

\- Verify authorization

\- Check copied files



\## Expected Alert



USB storage device connected.



\---



\# 8. File Integrity Monitoring



\## Objective



Detect creation, modification, or deletion of monitored files.



\## Sysmon Event ID



11



\## SPL Query



```spl

index=main EventCode=11

```



\## MITRE ATT\&CK



Technique: T1565 - Data Manipulation



\## Severity



Medium



\## Investigation Steps



\- Identify modified file

\- Review process responsible

\- Verify user activity

\- Check timestamps



\## Expected Alert



File modification activity detected.



\---



\# Detection Summary



| Detection | Event ID | Severity | MITRE Technique |

|-----------|----------|----------|-----------------|

| Failed Login | 4625 | Medium | T1110 |

| Brute Force | 4625 | High | T1110 |

| PowerShell Execution | Sysmon 1 | High | T1059.001 |

| User Account Creation | 4720 | High | T1136 |

| Service Creation | 7045 | High | T1543.003 |

| Scheduled Task | 4698 | High | T1053.005 |

| USB Detection | 6416 | Medium | T1091 |

| File Integrity Monitoring | Sysmon 11 | Medium | T1565 |



\---



\# Conclusion



These detection rules simulate common Security Operations Center (SOC) monitoring use cases. Each rule focuses on identifying suspicious Windows activities using Splunk SPL searches, Windows Event Logs, and Sysmon telemetry. Together, they provide visibility into authentication attacks, persistence mechanisms, endpoint activity, and file system changes while aligning detections with the MITRE ATT\&CK framework.

