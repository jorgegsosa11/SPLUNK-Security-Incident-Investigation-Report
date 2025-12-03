# SPLUNK-Security-Incident-Investigation-Report
A full Splunk-based security investigation report for a human-operated intrusion targeting Kerning City Dental. 
Includes SPL analysis, MITRE mapping, IOCs, timeline, and findings.


**Author:** Jorge Garcia  
**Incident Type:** Human-Operated Intrusion 
**Date Range:** 04 Nov 2025 (02:37–06:40 UTC)

---
## Purpose
This report was created as part of a Capture the Flag (CTF) challenge simulating a real-world human-operated intrusion. 
The goal was to analyze attacker activity using Splunk (SPL), identify IOCs, map the attack to MITRE ATT&CK, 
and produce a formal SOC-style incident report.

---
## Table of Contents
1. Executive Summary  
2. Timeline  
3. Findings  
4. Indicators of Compromise (IOCs)  
5. MITRE ATT&CK Mapping  
6. Recommendations  

---

# 1. Executive Summary

Between **04 November 2025 02:37 UTC** and **06:40 UTC**, Kerning City Dental experienced a targeted intrusion originating from the malicious IP **64.226.121[.]55**, hosted on DigitalOcean in Frankfurt, Germany. The attacker gained access through social engineering, deployed multiple malicious tools, escalated privileges to Domain Admin, collected sensitive data, and exfiltrated it using cloud services before establishing persistence.

This incident is classified as **High Severity**, as it resulted in credential theft, unauthorized data access, and domain-wide compromise. The attacker’s activity has been contained, but urgent credential resets, system isolation, and a full environment sweep are required.

---

# 2. Timeline (UTC)

| Time | Event |
|------|-------|
| 02:37:14 | Attacker executed `whoami` for initial discovery |
| 02:54:31 | `certutil` downloads GoogleUpdateCore.exe |
| 02:54:32 | First C2 beacon to 64.226.121[.]55 |
| 02:54:47 | Continued C2 communication |
| 03:00:43 | Malware re-downloaded via certutil |
| 03:00:44 | New C2 beacon |
| 03:00:56 | Ongoing C2 activity |
| 04:08:11 | Attacker downloads mimikatz.exe as msedge.exe |
| 04:19:13 | Stolen credentials saved to creds.txt |
| 04:24:52 | creds.txt exfiltrated via `curl` → Discord webhook |
| 04:44:48 | AdobeUpdateService.exe downloaded |
| 04:55:09 | robocopy used to stage patient/HR data |
| 04:57:56 | KCD_Exfil.zip exfiltrated via curl |
| 05:00:59 | Failed lateral movement to ADDC01 |
| 05:10:17 | Created domain backdoor account: backup$ |
| 05:11:27 | Added backup$ to Domain Admins |
| 05:16:34 | Persistence added: SecurityHealthSystray Run key |
| 05:26:14 | Rubeus.exe downloaded for Kerberos attack |
| 06:40:30 | Stolen credentials for user james.allen obtained |

---

# 3. Findings (Narrative)

## Initial Access
The attacker impersonated internal IT support and instructed staff to leave systems powered on. BACKOFFICE-PC1 was accessed remotely, enabling the attacker to begin hands-on-keyboard operations.

## Execution & Tool Deployment
The attacker used **certutil.exe** to download multiple malicious payloads:
- GoogleUpdateCore.exe  
- mimikatz.exe (renamed as msedge.exe)  
- Rubeus.exe  
- AdobeUpdateService.exe  

Multiple C2 connections were made to **64.226.121[.]55**.

## Credential Theft
Mimikatz was used to dump credentials into:
- `C:\Users\Public\Libraries\creds.txt`

Credentials for **james.allen** were later confirmed stolen.

## Data Collection & Exfiltration
Data was staged using **robocopy.exe** in:
- `C:\ProgramData\Microsoft\Backup\Staging`

Exfiltration occurred via **curl** to a Discord webhook:
- `creds.txt`
- `KCD_Exfil.zip`

## Persistence & Privilege Escalation
Registry Run Key created:
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SecurityHealthSystray`

Domain backdoor created:
- Account: `backup$`
- Privilege: Domain Admin

## Lateral Movement Attempt
Failed login attempts observed against ADDC01.

---

# 4. Indicators of Compromise (IOCs)

## Malicious IP
- 64.226.121[.]55 (DigitalOcean VPS, Germany)

## Files
- GoogleUpdateCore.exe  
- msedge.exe (Mimikatz)  
- Rubeus.exe  
- AdobeUpdateService.exe  
- creds.txt  
- KCD_Exfil.zip  

## File Paths
- `C:\Users\Public\Libraries\`  
- `C:\ProgramData\Microsoft\`  
- `C:\ProgramData\Microsoft\Backup\Staging\`

## Threat Intelligence
- VirusTotal: **13/95 vendors flagged the IP as malicious**
- Shodan:
  - Cloud: DigitalOcean (Frankfurt)
  - Ports: 22, 443, 8000, 8888, 9050, 31337

---

# 5. MITRE ATT&CK Mapping

| Technique | Description | Evidence |
|----------|-------------|----------|
| **T1598** | Social Engineering | Fake IT helpdesk call |
| **T1105** | Ingress Tool Transfer | certutil.exe downloads |
| **T1033** | Discovery | whoami |
| **T1218** | LOLBin Execution | certutil, robocopy, curl, net1 |
| **T1003** | Credential Dumping | Mimikatz |
| **T1558** | Kerberos Abuse | Rubeus.exe |
| **T1074** | Data Staging | Robocopy staging directory |
| **T1567.002** | Cloud Exfiltration | Discord webhook |
| **T1136** | Account Creation | backup$ |
| **T1547.001** | Registry Run Key | SecurityHealthSystray |

---

# 6. Recommendations

## Immediate (0–24 Hours)
- Reset helpdesk, james.allen, and all privileged credentials  
- Disable/delete backup$ backdoor account  
- Block C2 IP 64.226.121[.]55  
- Isolate BACKOFFICE-PC1  
- Sweep for malicious files and Run keys

## Short-Term (1–7 Days)
- Deploy full logging: Sysmon, ScriptBlock logging  
- Disable or restrict certutil usage  
- Implement alerting for curl, robocopy, and suspicious PowerShell  
- Conduct organization-wide phishing awareness refresher

## Long-Term (30–90 Days)
- Enforce MFA for all accounts  
- Implement EDR with behavioral detections  
- Harden Domain Admin protections  
- Improve segmentation between workstations and servers  

---

# End of Report


