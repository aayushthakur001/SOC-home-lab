\# Incident Report



\## Project Information



\*\*Project Name:\*\* Enterprise SOC Monitoring using Splunk SIEM



\*\*Platform:\*\* Splunk Enterprise



\*\*Log Source:\*\* Windows Event Logs \& Microsoft Sysmon



\*\*Monitoring Type:\*\* Blue Team / SOC Monitoring



\---



\# Objective



The objective of this project was to build a Security Operations Center (SOC) monitoring environment using Splunk Enterprise to collect, analyze, and monitor Windows security events. Multiple detection rules were created to identify suspicious activities commonly observed in enterprise environments.



\---



\# Environment Setup



The following components were configured:



\- Splunk Enterprise

\- Splunk Universal Forwarder

\- Microsoft Sysmon

\- Windows Event Logs

\- Dashboard Studio



The Universal Forwarder was installed on the endpoint machine to forward Windows Security Logs and Sysmon logs to the Splunk server for centralized monitoring.



\---



\# Detection Rules Implemented



The following security detections were successfully implemented:



\- Failed Login Detection

\- Brute Force Detection

\- PowerShell Execution Detection

\- User Account Creation Detection

\- Service Creation Detection

\- Scheduled Task Detection

\- USB Device Detection

\- File Integrity Monitoring



Each detection was validated by generating test events and verifying that the corresponding logs appeared in Splunk.



\---



\# Dashboard Development



A professional SOC dashboard was created using Splunk Dashboard Studio.



The dashboard displays:



\- Total Security Events

\- Failed Login Events

\- PowerShell Events

\- User Creation Events

\- Service Creation Events

\- Scheduled Task Events

\- USB Activity

\- File Integrity Monitoring

\- Security Timeline

\- Alert Distribution

\- Severity Distribution



This dashboard provides centralized visibility into endpoint security events.



\---



\# MITRE ATT\&CK Mapping



The implemented detections were mapped to the MITRE ATT\&CK Framework.



Covered tactics include:



\- Credential Access

\- Execution

\- Persistence

\- Lateral Movement

\- Impact



This mapping helps align detections with real-world attacker techniques.



\---



\# Results



The project successfully demonstrated:



\- Centralized log collection

\- Windows security monitoring

\- Threat detection using SPL

\- Dashboard visualization

\- Alert generation

\- MITRE ATT\&CK mapping

\- Security documentation



All configured detection rules successfully generated events during testing.



\---



\# Skills Demonstrated



\- Splunk Enterprise

\- SPL Query Development

\- Windows Event Log Analysis

\- Microsoft Sysmon

\- SIEM Monitoring

\- Threat Detection

\- Dashboard Development

\- Security Event Analysis

\- MITRE ATT\&CK Mapping

\- SOC Investigation



\---



\# Conclusion



This project demonstrates the implementation of a Security Operations Center (SOC) monitoring solution using Splunk Enterprise. It showcases practical skills in log collection, security monitoring, threat detection, dashboard creation, and incident analysis. The project reflects common responsibilities performed by SOC Analysts in enterprise environments and serves as a portfolio project for cybersecurity and SIEM-based roles.

