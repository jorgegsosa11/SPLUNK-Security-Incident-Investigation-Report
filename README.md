# SPLUNK-Security-Incident-Investigation-Report
A full Splunk-based security investigation report for a human-operated intrusion targeting Kerning City Dental.
Includes SPL analysis, MITRE mapping, IOCs, timeline, findings, and full SPL query set.

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
6. SPL Queries Used  
7. Recommendations  

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
- Shodan Cloud Profile:
  - Cloud: DigitalOcean (Frankfurt)
  - Open Ports: **22, 443, 8000, 8888, 9050, 31337**

---
# 5. MITRE ATT&CK Mapping

| **Tactic** | **Tools Used** | **Technique ID** | **Technique Name** | **Evidence** |
|-----------|----------------|------------------|---------------------|--------------|
| Initial Access | Social Engineering | T1598 | Phishing / Voice Impersonation | Fake IT helpdesk call |
| Execution | certutil.exe, msedge.exe, Rubeus.exe | T1106 | Native API Execution | Multiple LOLBins executed |
| Discovery | whoami | T1033 | System Owner/User Discovery | whoami executed at 02:37:14 |
| Defense Evasion | certutil.exe, curl.exe, net1.exe, robocopy.exe | T1218 | Signed Binary Proxy Execution | certutil downloads, curl exfiltration |
| Credential Access | mimikatz.exe | T1003 | Credential Dumping | creds.txt created, plaintext password dumping |
| Lateral Movement / Credential Abuse | Rubeus.exe | T1558 | Steal or Forge Kerberos Tickets | Rubeus.exe downloaded at 05:26:14 |
| Collection | robocopy.exe | T1074 | Data Staging | Data staged in C:\\ProgramData\\Microsoft\\Backup\\Staging |
| Exfiltration | curl.exe | T1567.002 | Exfiltration to Cloud Storage | Discord webhook exfiltration |
| Persistence | Registry Run Key | T1547.001 | Boot or Logon Autostart Execution | SecurityHealthSystray persistence key |
| Privilege Escalation | net1.exe, PowerShell | T1136 | Create Account | Backdoor Domain Admin account backup$ created |

# 6. SPL Queries Used
(queries used during the investigation)

### 1. Suspicious Google Executable
```spl
index=endpoint
Image="*google*"
Image!="C:\\Windows\\System32\\*"
Image!="C:\\Program Files\\*"
Image!="C:\\Program Files (x86)\\*"
| table Image CommandLine
```

### 2. First Seen Execution
```spl
index=endpoint Image="*GoogleUpdateCore.exe*"
| sort 0 _time
```

### 3. C2 Communications
```spl
index=endpoint Image="*GoogleUpdateCore.exe*"
| sort 0 _time
| stats count by SourceIp, dest_ip
```

### 4. certutil Abuse
```spl
index=endpoint process_name="certutil.exe" 64.226.121.55
| sort _time
| table _time SourceIp dest_ip CommandLine ParentCommandLine
```

### 5. Mimikatz Search
```spl
index=endpoint mimikatz
```

### 6. Kerberos 4769 Enumeration Attempts
```spl
index=endpoint EventCode=4769
```

Count services:
```spl
index=endpoint EventCode=4769 | stats dc(Service_Name) AS service_accounts
```

### 7. Persistence via Registry
```spl
index=endpoint EventCode=13 User!=*SYSTEM*
| search Registry* OR TargetObject="*Run*" OR "*RunOnce*" OR "*CurrentVersion*"
| table _time EventCode Image User TargetObject Details
```

### 8. whoami Discovery
```spl
index=endpoint EventCode=1 CommandLine="*"
| search CommandLine=*whoami*  

