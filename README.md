# Enterprise SOC Monitoring using Splunk SIEM

> A production-style Security Operations Center (SOC) project demonstrating Windows security monitoring, threat detection, log analysis, incident investigation, dashboard visualization, and MITRE ATT&CK framework mapping.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Objectives](#objectives)
- [Key Features](#key-features)
- [Lab Environment](#lab-environment)
- [Technologies Used](#technologies-used)
- [Architecture](#architecture)
- [Project Workflow](#project-workflow)
- [Splunk Configuration](#splunk-configuration)
- [Detection Use Cases](#detection-use-cases)
- [SOC Dashboard](#soc-dashboard)
- [Alert Rules](#alert-rules)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Incident Response Workflow](#incident-response-workflow)
- [Skills Demonstrated](#skills-demonstrated)
- [Learning Outcomes](#learning-outcomes)
- [Project Structure](#project-structure)
- [Future Improvements](#future-improvements)
- [References](#references)

---

## Project Overview

Modern organizations generate thousands of security events every day. Security analysts must continuously monitor these logs to detect suspicious activities, investigate incidents, and respond before threats escalate.

This project demonstrates a **complete Enterprise Security Operations Center (SOC) Monitoring Lab** built using **Splunk Enterprise**. The lab collects Windows security logs, Sysmon logs, and endpoint telemetry through the Splunk Universal Forwarder. Security detections are implemented using **SPL (Search Processing Language)**, and all findings are visualized through comprehensive SOC dashboards.

### Project Scope

The project simulates the day-to-day responsibilities of a **SOC Analyst**, including:

- ✓ Security event monitoring
- ✓ Threat detection
- ✓ Alert analysis
- ✓ Incident investigation
- ✓ Dashboard monitoring
- ✓ MITRE ATT&CK mapping
- ✓ Security reporting
- ✓ Detection engineering

**Target Audience**: Cybersecurity professionals seeking hands-on SOC experience, portfolio development, and interview preparation.

---

## Objectives

The primary objectives of this project are:

- ✓ Deploy Splunk Enterprise as a SIEM platform
- ✓ Collect and parse Windows Event Logs
- ✓ Integrate Microsoft Sysmon for advanced endpoint monitoring
- ✓ Configure Splunk Universal Forwarder for log ingestion
- ✓ Monitor endpoint security events in real-time
- ✓ Detect common attacker techniques and Tactics, Techniques & Procedures (TTPs)
- ✓ Build robust SPL detection queries
- ✓ Create SOC monitoring dashboards for centralized visibility
- ✓ Configure automated security alerts
- ✓ Map detections to MITRE ATT&CK framework
- ✓ Simulate realistic SOC investigation workflows
- ✓ Produce professional security documentation

---

## Key Features

### Log Collection & Ingestion

- Windows Security Event Logs
- Windows System Logs
- Windows Application Logs
- Microsoft Sysmon Logs
- Real-time log streaming via Universal Forwarder

### Security Monitoring Capabilities

- Failed Login Detection
- Brute Force Attack Detection
- PowerShell Script Execution Monitoring
- User Account Creation & Modification Detection
- Service Creation & Installation Detection
- Scheduled Task Persistence Detection
- USB Device Activity Monitoring
- File Integrity Monitoring (FIM)

### Threat Detection & Response

- Suspicious PowerShell Execution Detection
- Persistence Technique Identification
- Unauthorized Account Creation Alerts
- Malicious Service Installation Detection
- Scheduled Task Persistence Alerts
- Brute Force Attempt Detection
- Unauthorized USB Activity Alerts
- Anomalous Process Execution Detection

### SOC Dashboard & Visualization

Centralized visibility into security events with:

- Total Security Events Counter
- Failed Login Events Tracking
- PowerShell Execution Events
- User Creation Events Log
- Service Creation Events Log
- Scheduled Task Events Tracking
- USB Activity Monitoring
- File Integrity Events
- Real-time Security Event Timeline
- Alert Distribution Chart
- Severity Distribution Visualization
- Geographic Event Mapping

---

## Lab Environment

| Component | Details |
|-----------|---------|
| **SIEM Platform** | Splunk Enterprise |
| **Operating System** | Windows 10 Pro / Windows Server 2019+ |
| **Endpoint Agent** | Splunk Universal Forwarder |
| **Endpoint Monitoring** | Microsoft Sysmon v14+ |
| **Log Source** | Windows Event Logs |
| **Dashboard** | Splunk Dashboard Studio |
| **Detection Language** | SPL (Search Processing Language) |
| **Threat Framework** | MITRE ATT&CK v13+ |
| **Project Type** | Blue Team / SOC Monitoring |
| **Deployment Model** | On-Premises / Virtual Lab |

---

## Technologies Used

| Technology | Purpose |
|-----------|---------|
| **Splunk Enterprise** | SIEM platform and log analysis engine |
| **Splunk Universal Forwarder** | Log collection and forwarding agent |
| **Microsoft Sysmon** | Advanced endpoint event logging |
| **Windows Event Viewer** | Event log management |
| **PowerShell** | Security monitoring and event simulation |
| **SPL** | Detection query language |
| **MITRE ATT&CK Framework** | Attack technique mapping and categorization |
| **Dashboard Studio** | SOC dashboard development |
| **Windows Security Logs** | Security event source |
| **Sysmon Event Logs** | Advanced process and network event source |

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│           SPLUNK ENTERPRISE (SIEM)                  │
│  ┌──────────────────────────────────────────────┐  │
│  │       Search & Detection Engine (SPL)        │  │
│  │  - Detection Queries                         │  │
│  │  - Alert Rules                               │  │
│  │  - Scheduled Searches                        │  │
│  └──────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────┐  │
│  │     Dashboard & Visualization Layer          │  │
│  │  - SOC Dashboards                            │  │
│  │  - Alert Management                          │  │
│  │  - Incident Investigation                    │  │
│  └──────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
         ▲                    ▲
         │                    │
    ┌────┴─────┐         ┌────┴──────┐
    │           │         │           │
┌───────────┐  ┌─────────────────┐  ┌─────────────┐
│ Universal │  │  Windows Event  │  │  Sysmon    │
│ Forwarder │  │  Logs           │  │  Logs      │
└───────────┘  └─────────────────┘  └─────────────┘
    ▲              ▲                   ▲
    └──────────────┴───────────────────┘
              │
    ┌─────────────────────────────┐
    │   WINDOWS ENDPOINT (10 PRO) │
    │  - Security Events          │
    │  - System Events            │
    │  - Application Events       │
    │  - Process Execution        │
    │  - Network Connections      │
    └─────────────────────────────┘
```

---

## Project Workflow

### Phase 1: Environment Setup
1. Deploy Splunk Enterprise instance
2. Install Microsoft Sysmon on Windows endpoint
3. Configure Windows Event Log forwarding
4. Install and configure Universal Forwarder

### Phase 2: Log Collection & Parsing
1. Configure inputs.conf for log sources
2. Create parsing rules for event normalization
3. Tag events by type and severity
4. Validate data ingestion

### Phase 3: Detection Engineering
1. Design detection queries based on attack TTPs
2. Implement SPL detection rules
3. Create correlation searches
4. Configure alerting thresholds

### Phase 4: Dashboard Development
1. Create SOC monitoring dashboard
2. Add event visualizations
3. Configure real-time search panels
4. Implement incident investigation views

### Phase 5: Incident Response
1. Alert triage and investigation
2. Incident severity assessment
3. Root cause analysis
4. Documentation and reporting

---

## Splunk Configuration

### Data Input Configuration

```
inputs.conf - Windows Security Events
inputs.conf - Sysmon Event Logs
props.conf - Event parsing rules
transforms.conf - Field extraction
```

### Index Structure

- **Main Index**: Primary security event repository
- **Sysmon Index**: Advanced endpoint telemetry
- **Audit Index**: Compliance and access logs
- **Alert Index**: Alert and incident records

### Sourcetype Definitions

- `wineventlog:security` - Windows Security Events
- `wineventlog:system` - Windows System Events
- `wineventlog:application` - Windows Application Events
- `sysmon` - Microsoft Sysmon Events

---

## Detection Use Cases

### 1. Brute Force Attack Detection
- **Objective**: Identify multiple failed login attempts
- **Data Source**: Event ID 4625 (Failed Login)
- **Threshold**: 5+ failures in 5 minutes per user
- **MITRE ATT&CK**: T1110 (Brute Force)

### 2. Suspicious PowerShell Execution
- **Objective**: Detect malicious PowerShell usage patterns
- **Data Source**: Event ID 4688, Sysmon Process Creation
- **Indicators**: Encoded commands, suspicious parameters
- **MITRE ATT&CK**: T1059.001 (Command Line Interface)

### 3. Unauthorized Account Creation
- **Objective**: Monitor new user account creation
- **Data Source**: Event ID 4720 (User Account Created)
- **Alert Trigger**: Any new account creation
- **MITRE ATT&CK**: T1136.001 (Local Account)

### 4. Malicious Service Installation
- **Objective**: Detect unauthorized service creation
- **Data Source**: Event ID 7045 (Service Installation)
- **Indicators**: Suspicious service names and paths
- **MITRE ATT&CK**: T1543.003 (Windows Service)

### 5. Scheduled Task Persistence
- **Objective**: Identify suspicious scheduled tasks
- **Data Source**: Event ID 106, Sysmon Task Register
- **Indicators**: Hidden tasks, suspicious executables
- **MITRE ATT&CK**: T1053.005 (Scheduled Task)

### 6. USB Device Monitoring
- **Objective**: Track USB device connections
- **Data Source**: Event ID 20001 (Removable Storage Detection)
- **Alert Trigger**: First-time device connection
- **MITRE ATT&CK**: T1091 (Replication Through Removable Media)

---

## SOC Dashboard

The main SOC dashboard provides:

### Dashboard Sections

**Section 1: Event Summary**
- Total Security Events (24h)
- Events by Severity
- Top Event Types
- Alert Status Overview

**Section 2: Threat Detection**
- Failed Login Attempts
- Brute Force Incidents
- Suspicious PowerShell Executions
- Unauthorized Account Changes

**Section 3: Endpoint Activity**
- Service Creation Events
- Scheduled Task Activity
- USB Device Connections
- Process Execution Timeline

**Section 4: Investigation**
- Real-time Event Log Viewer
- Incident Timeline
- User Activity Tracking
- Anomaly Detection Results

---

## Alert Rules

### Critical Severity Alerts

1. **Brute Force Attack** - 5 failed logins in 5 minutes
2. **Unauthorized Account Creation** - New user account detected
3. **Suspicious PowerShell** - Encoded commands or suspicious parameters
4. **Malware Service Installation** - Suspicious service creation

### High Severity Alerts

1. **Multiple Failed Logins** - 3+ failures per user in 10 minutes
2. **Scheduled Task Persistence** - Suspicious task creation
3. **Privilege Escalation Attempt** - Privilege token granted

### Medium Severity Alerts

1. **USB Device Connected** - New removable storage detected
2. **System Event Anomaly** - Unusual system event patterns
3. **Application Crash** - Unexpected application termination

---

## MITRE ATT&CK Mapping

| Detection | MITRE ATT&CK Tactic | MITRE ATT&CK Technique | Severity |
|-----------|-------------------|----------------------|----------|
| Brute Force Detection | Credential Access | T1110 | Critical |
| PowerShell Execution | Execution | T1059.001 | High |
| Account Creation | Persistence | T1136.001 | Critical |
| Service Installation | Persistence | T1543.003 | Critical |
| Scheduled Task | Persistence | T1053.005 | High |
| USB Monitoring | Initial Access | T1091 | Medium |
| Process Execution | Execution | T1059 | Medium |

---

## Incident Response Workflow

### Step 1: Alert Generation
- Detection rule triggers based on defined thresholds
- Alert notification sent to SOC team
- Incident ticket auto-created

### Step 2: Alert Triage
- Security analyst reviews alert details
- Determines if alert is True Positive or False Positive
- Assigns severity level

### Step 3: Investigation
- Analyst searches for related events
- Reviews user and endpoint context
- Correlates with other security data

### Step 4: Containment
- Take evidence preservation steps
- Isolate affected endpoint if necessary
- Disable compromised accounts if needed

### Step 5: Eradication & Recovery
- Remove malicious artifacts
- Reset compromised credentials
- Restore affected systems

### Step 6: Documentation
- Document findings and actions taken
- Update incident ticket
- Generate incident report
- Share lessons learned

---

## Project Structure

```
SOC-home-lab/
├── README.md
├── docs/
│   ├── setup-guide.md
│   ├── detection-queries.md
│   ├── dashboard-guide.md
│   └── incident-response-guide.md
├── splunk/
│   ├── inputs.conf
│   ├── props.conf
│   ├── transforms.conf
│   └── alerts/
│       ├── brute-force-detection.xml
│       ├── powershell-detection.xml
│       ├── account-creation-detection.xml
│       └── service-installation-detection.xml
├── dashboards/
│   ├── soc-main-dashboard.xml
│   ├── threat-detection-dashboard.xml
│   ├── user-activity-dashboard.xml
│   └── incident-investigation-dashboard.xml
├── detection-queries/
│   ├── brute-force.spl
│   ├── suspicious-powershell.spl
│   ├── account-changes.spl
│   ├── service-creation.spl
│   └── usb-activity.spl
└── scripts/
    ├── event-simulator.ps1
    └── log-generator.ps1
```

---

## Skills Demonstrated

This project demonstrates practical expertise in:

### Security Operations
- ✓ Security Information and Event Management (SIEM)
- ✓ Log Collection and Ingestion
- ✓ Real-time Security Monitoring
- ✓ Alert Management and Triage
- ✓ Incident Investigation and Response

### Technical Skills
- ✓ Windows Event Log Analysis
- ✓ Sysmon Configuration and Monitoring
- ✓ SPL (Splunk Processing Language) Query Development
- ✓ Dashboard Design and Visualization
- ✓ Alert Rule Configuration

### Security Knowledge
- ✓ Windows Security Event Understanding
- ✓ MITRE ATT&CK Framework Application
- ✓ Threat Detection Engineering
- ✓ Attack Technique Recognition
- ✓ Incident Response Procedures

### Professional Competencies
- ✓ Security Documentation
- ✓ Root Cause Analysis
- ✓ Problem Solving and Troubleshooting
- ✓ Cross-functional Communication
- ✓ Continuous Learning and Improvement

---

## Learning Outcomes

Upon completing this project, you will have:

1. **Hands-on SIEM Experience** - Deep understanding of Splunk Enterprise capabilities
2. **Detection Engineering Skills** - Ability to build effective security detection rules
3. **Log Analysis Proficiency** - Expert-level Windows and Sysmon log analysis
4. **Incident Response Knowledge** - Real-world incident response workflow experience
5. **Dashboard Expertise** - Professional SOC dashboard development capabilities
6. **MITRE ATT&CK Mastery** - Ability to map attacks to framework techniques
7. **Security Mindset** - Understanding of attacker tactics and defense strategies
8. **Documentation Skills** - Professional security reporting capabilities

---

## Future Improvements

### Planned Enhancements

- [ ] Machine Learning-based anomaly detection
- [ ] Automated threat intelligence feed integration
- [ ] Advanced correlation rules for multi-stage attacks
- [ ] SOAR (Security Orchestration, Automation and Response) integration
- [ ] Custom Splunk app development
- [ ] Real-time compliance monitoring (NIST, CIS)
- [ ] Advanced user behavior analytics (UEBA)
- [ ] Deception technology (honeypot) integration
- [ ] Automated incident response playbooks
- [ ] Metrics and KPI tracking dashboard

### Expansion Opportunities

- Integration with additional data sources (firewalls, proxies, endpoints)
- Multi-platform support (Linux, macOS)
- Cloud environment monitoring (AWS, Azure, GCP)
- Container and Kubernetes security monitoring
- API and infrastructure as code (IaC) security monitoring

---

## References

### Official Documentation
- [Splunk Enterprise Documentation](https://docs.splunk.com/Documentation/Splunk)
- [Microsoft Sysmon Documentation](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Windows Event Log Reference](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/windows-security-event-ids)

### Learning Resources
- Splunk University
- NIST Cybersecurity Framework
- SANS Institute SEC504 (Hacker Tools and Incident Handling)
- CompTIA Security+
- EC-Council CEH (Certified Ethical Hacker)

### Related Projects & Communities
- Splunk Community Forums
- OWASP Top 10
- CIS Critical Security Controls
- OpenCTI - Open Cyber Threat Intelligence Platform

---

## License

This project is provided as an educational resource for cybersecurity learning and professional development.

---

## Author & Maintenance

**Author**: Aayush Thakur  
**Repository**: [aayushthakur001/SOC-home-lab](https://github.com/aayushthakur001/SOC-home-lab)  
**Last Updated**: July 2026

---

## Disclaimer

This project is designed for educational and authorized security testing purposes only. Ensure you have proper authorization before conducting any security monitoring or testing activities. The author is not responsible for any misuse of the information or techniques provided in this project.

---

**Happy Learning! 🔒**
