\# Enterprise SOC Monitoring using Splunk SIEM



> A production-style Security Operations Center (SOC) project demonstrating Windows security monitoring, threat detection, log analysis, incident investigation, dashboard visualization, and MITRE ATT\&CK mapping using Splunk Enterprise.



\---



\# Table of Contents



\- Project Overview

\- Objectives

\- Features

\- Lab Environment

\- Technologies Used

\- Architecture

\- Project Workflow

\- Splunk Configuration

\- Detection Use Cases

\- Dashboard

\- Alert Rules

\- MITRE ATT\&CK Mapping

\- Incident Response Workflow

\- Screenshots

\- Project Structure

\- Skills Demonstrated

\- Learning Outcomes

\- Future Improvements

\- References



\---



\# Project Overview



Modern organizations generate thousands of security events every day. Security analysts must continuously monitor these logs to detect suspicious activities, investigate incidents, and respond before attackers cause damage.



This project demonstrates a complete Enterprise Security Operations Center (SOC) Monitoring Lab built using Splunk Enterprise.



The lab collects Windows security logs, Sysmon logs, and endpoint telemetry through the Splunk Universal Forwarder. Security detections are implemented using SPL (Search Processing Language), and all findings are visualized through a professional SOC dashboard.



The project simulates the day-to-day responsibilities of a SOC Analyst, including:



\- Security event monitoring

\- Threat detection

\- Alert analysis

\- Incident investigation

\- Dashboard monitoring

\- MITRE ATT\&CK mapping

\- Security reporting

\- Detection engineering



This project is intended for cybersecurity learning, portfolio development, and SOC Analyst interview preparation.



\---



\# Objectives



The primary objectives of this project are:



\- Deploy Splunk Enterprise as a SIEM platform

\- Collect Windows Event Logs

\- Integrate Microsoft Sysmon

\- Configure Splunk Universal Forwarder

\- Monitor endpoint security events

\- Detect common attacker techniques

\- Build SPL detection queries

\- Create SOC monitoring dashboards

\- Configure security alerts

\- Map detections to MITRE ATT\&CK

\- Simulate SOC investigation workflow

\- Produce professional security documentation



\---



\# Key Features



\## Log Collection



\- Windows Security Event Logs

\- Windows System Logs

\- Windows Application Logs

\- Microsoft Sysmon Logs



\---



\## Security Monitoring



\- Failed Login Detection

\- Brute Force Detection

\- PowerShell Monitoring

\- User Account Creation Detection

\- Service Creation Detection

\- Scheduled Task Detection

\- USB Device Monitoring

\- File Integrity Monitoring



\---



\## Threat Detection



\- Suspicious PowerShell Execution

\- Persistence Techniques

\- Unauthorized Account Creation

\- Malicious Service Installation

\- Scheduled Task Persistence

\- Brute Force Attempts

\- Unauthorized USB Activity



\---



\## SOC Dashboard



The dashboard provides centralized visibility into security events using:



\- Total Security Events

\- Failed Login Events

\- PowerShell Events

\- User Creation Events

\- Service Creation Events

\- Scheduled Task Events

\- USB Activity

\- File Integrity Events

\- Security Event Timeline

\- Alert Distribution

\- Severity Distribution



\---



\# Lab Environment



| Component | Details |

|----------|---------|

| SIEM Platform | Splunk Enterprise |

| Operating System | Windows 10 Pro |

| Endpoint Agent | Splunk Universal Forwarder |

| Endpoint Monitoring | Microsoft Sysmon |

| Log Source | Windows Event Logs |

| Dashboard | Splunk Dashboard Studio |

| Detection Language | SPL (Search Processing Language) |

| Framework | MITRE ATT\&CK |

| Project Type | Blue Team / SOC Monitoring |



\---



\# Technologies Used



\- Splunk Enterprise

\- Splunk Universal Forwarder

\- Microsoft Sysmon

\- Windows Event Viewer

\- PowerShell

\- SPL (Search Processing Language)

\- MITRE ATT\&CK Framework

\- Dashboard Studio

\- Windows Security Logs

\- Sysmon Event Logs



\---



\# Skills Demonstrated



This project demonstrates practical experience with:



\- Security Information and Event Management (SIEM)

\- Log Collection

\- Windows Event Analysis

\- Sysmon Monitoring

\- Security Alert Investigation

\- Detection Engineering

\- Threat Monitoring

\- Security Dashboard Development

\- MITRE ATT\&CK Mapping

\- Incident Response

\- Security Documentation



\---

