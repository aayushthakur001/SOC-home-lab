# Enterprise SOC Monitoring Using Splunk SIEM

## Project Overview

This project demonstrates the implementation of a Security Operations Center (SOC) monitoring environment using Splunk Enterprise. The solution was designed to collect, analyze, and visualize Windows security telemetry in order to improve endpoint visibility and support threat detection workflows.

## Project Information

**Platform:** Splunk Enterprise  
**Log Sources:** Windows Event Logs, Microsoft Sysmon  
**Monitoring Type:** Blue Team / SOC Monitoring

## Objective

The objective of this project was to build a centralized SOC monitoring environment capable of ingesting Windows security events, detecting suspicious activity, and presenting findings through a professional dashboard.

## Environment Setup

The environment was configured with the following components:

- Splunk Enterprise
- Splunk Universal Forwarder
- Microsoft Sysmon
- Windows Event Logs
- Splunk Dashboard Studio

The Universal Forwarder was installed on the endpoint machine to forward Windows Security Logs and Sysmon events to the Splunk server for centralized monitoring and analysis.

## Detection Rules Implemented

The following detection use cases were implemented and validated:

- Failed Login Detection
- Brute Force Detection
- PowerShell Execution Detection
- User Account Creation Detection
- Service Creation Detection
- Scheduled Task Detection
- USB Device Detection
- File Integrity Monitoring

Each detection was tested by generating relevant events and confirming that the corresponding logs were successfully ingested and displayed in Splunk.

## Dashboard Development

A SOC dashboard was created using Splunk Dashboard Studio to provide centralized visibility into key security events.

The dashboard includes the following metrics:

- Total Security Events
- Failed Login Events
- PowerShell Events
- User Creation Events
- Service Creation Events
- Scheduled Task Events
- USB Activity
- File Integrity Monitoring
- Security Timeline
- Alert Distribution
- Severity Distribution

This dashboard provides a clear overview of endpoint activity and helps support rapid analysis of security events.

## MITRE ATT&CK Mapping

The implemented detections were mapped to the MITRE ATT&CK framework to align the project with real-world adversary behaviors.

Covered tactics include:

- Credential Access
- Execution
- Persistence
- Lateral Movement
- Impact

This mapping demonstrates how the monitored events relate to common attacker techniques and SOC detection priorities.

## Results

This project successfully demonstrated:

- Centralized log collection
- Windows security monitoring
- Threat detection using SPL
- Dashboard visualization
- Alert generation
- MITRE ATT&CK mapping
- Security documentation

All configured detection rules generated expected events during testing.

## Skills Demonstrated

- Splunk Enterprise
- SPL Query Development
- Windows Event Log Analysis
- Microsoft Sysmon
- SIEM Monitoring
- Threat Detection
- Dashboard Development
- Security Event Analysis
- MITRE ATT&CK Mapping
- SOC Investigation

## Conclusion

This project showcases the implementation of a Security Operations Center monitoring solution using Splunk Enterprise. It reflects practical experience in log collection, security monitoring, detection engineering, and dashboard development for blue team operations.
