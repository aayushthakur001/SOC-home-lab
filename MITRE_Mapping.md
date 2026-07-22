\# MITRE ATT\&CK Mapping



This document maps all implemented detection use cases in the Enterprise SOC Monitoring using Splunk SIEM project to the MITRE ATT\&CK Framework.



\---



\# Overview



The MITRE ATT\&CK Framework is a globally recognized knowledge base of adversary tactics and techniques based on real-world observations. Mapping detections to MITRE ATT\&CK helps Security Operations Center (SOC) analysts understand attacker behavior, improve detection coverage, and standardize incident investigations.



This project implements multiple Windows security detections aligned with MITRE ATT\&CK techniques commonly used by attackers during different phases of an intrusion.



\---



\# MITRE ATT\&CK Detection Mapping



| Detection Use Case | MITRE Tactic | Technique ID | Technique Name | Data Source |

|--------------------|-------------|--------------|----------------|-------------|

| Failed Login Detection | Credential Access | T1110 | Brute Force | Windows Security Logs |

| Brute Force Detection | Credential Access | T1110 | Brute Force | Windows Security Logs |

| PowerShell Execution | Execution | T1059.001 | PowerShell | Sysmon |

| User Account Creation | Persistence | T1136 | Create Account | Windows Security Logs |

| Service Creation | Persistence | T1543.003 | Windows Service | Windows System Logs |

| Scheduled Task Creation | Persistence | T1053.005 | Scheduled Task | Windows Security Logs |

| USB Device Detection | Lateral Movement | T1091 | Replication Through Removable Media | Windows Security Logs |

| File Integrity Monitoring | Impact | T1565 | Data Manipulation | Sysmon |



\---



\# Detection Details



\---



\## 1. Failed Login Detection



\### MITRE Tactic



Credential Access



\### Technique



T1110 – Brute Force



\### Description



Attackers frequently attempt to gain unauthorized access by repeatedly trying incorrect passwords. Monitoring failed authentication events helps identify password guessing and brute-force attacks before successful compromise.



\### Splunk Detection



\- Windows Event ID: \*\*4625\*\*

\- Source: Windows Security Logs



\---



\## 2. Brute Force Detection



\### MITRE Tactic



Credential Access



\### Technique



T1110 – Brute Force



\### Description



Multiple failed login attempts within a short period may indicate an automated password attack against a user account.



\### Splunk Detection



\- Windows Event ID: \*\*4625\*\*

\- Threshold-based alerting using SPL



\---



\## 3. PowerShell Execution Detection



\### MITRE Tactic



Execution



\### Technique



T1059.001 – PowerShell



\### Description



PowerShell is commonly abused by attackers for executing malicious commands, downloading payloads, privilege escalation, and lateral movement.



\### Splunk Detection



\- Sysmon Event ID: \*\*1\*\*

\- Image = powershell.exe



\---



\## 4. User Account Creation Detection



\### MITRE Tactic



Persistence



\### Technique



T1136 – Create Account



\### Description



Attackers may create new local accounts to maintain persistent access after compromising a system.



\### Splunk Detection



\- Windows Event ID: \*\*4720\*\*



\---



\## 5. Windows Service Creation Detection



\### MITRE Tactic



Persistence



\### Technique



T1543.003 – Windows Service



\### Description



Malicious services can be installed to automatically execute malware during system startup.



\### Splunk Detection



\- Windows Event ID: \*\*7045\*\*



\---



\## 6. Scheduled Task Detection



\### MITRE Tactic



Persistence



\### Technique



T1053.005 – Scheduled Task



\### Description



Scheduled tasks are frequently used by attackers to establish persistence and execute malicious payloads automatically.



\### Splunk Detection



\- Windows Event ID: \*\*4698\*\*



\---



\## 7. USB Device Detection



\### MITRE Tactic



Lateral Movement



\### Technique



T1091 – Replication Through Removable Media



\### Description



Removable media can be used to introduce malware into an environment or transfer sensitive data between systems.



\### Splunk Detection



\- Windows Event ID: \*\*6416\*\*



\---



\## 8. File Integrity Monitoring



\### MITRE Tactic



Impact



\### Technique



T1565 – Data Manipulation



\### Description



Unauthorized file creation or modification may indicate malware activity, ransomware behavior, or attempts to tamper with sensitive data.



\### Splunk Detection



\- Sysmon Event ID: \*\*11\*\*



\---



\# ATT\&CK Coverage Summary



| Tactic | Techniques Covered |

|----------|-------------------|

| Credential Access | T1110 |

| Execution | T1059.001 |

| Persistence | T1136, T1543.003, T1053.005 |

| Lateral Movement | T1091 |

| Impact | T1565 |



\---



\# Detection Coverage Statistics



\- Total Detection Rules: \*\*8\*\*

\- MITRE Tactics Covered: \*\*5\*\*

\- MITRE Techniques Covered: \*\*7\*\*

\- Windows Event IDs Used: \*\*4625, 4720, 4698, 6416, 7045\*\*

\- Sysmon Event IDs Used: \*\*1, 11\*\*



\---



\# Benefits of MITRE ATT\&CK Mapping



\- Standardizes security detections using an industry-recognized framework.

\- Helps SOC analysts understand attacker behavior.

\- Improves threat hunting and incident investigation.

\- Identifies gaps in detection coverage.

\- Enhances security monitoring maturity.

\- Aligns detections with enterprise SOC best practices.



\---



\# Conclusion



This project aligns Windows security detections with the MITRE ATT\&CK Framework to demonstrate practical Security Operations Center (SOC) monitoring capabilities. By mapping detection logic to attacker tactics and techniques, the project provides a structured approach to identifying credential attacks, malicious execution, persistence mechanisms, lateral movement, and data manipulation activities. This mapping improves detection visibility, supports incident response, and reflects real-world enterprise SOC workflows.

