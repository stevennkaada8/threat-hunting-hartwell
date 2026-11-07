# threat-hunting-hartwell
# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project
<img width="1200" height="675" alt="image" src="https://github.com/user-attachments/assets/8ae8c79e-6282-42c2-8151-dbf73dbc2a46" />

# Threat Hunt Report: Unauthorised Access on Helpdesk Account

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  Scenario

Hartwell Medical Group is a regional multi-specialty physician group operating a public WordPress site for patient scheduling and practice information. On 23 October 2026, the on-call SOC analyst received a cluster of auditd alerts from the Hartwell web server (192.168.1.120) indicating file writes to the Apache webroot by the www-data service account. The goal is to determine, whether this was a genuine compromise, reconstruct how the attacker gained access, what they did once inside and establish the full scope across the environment. If evidence of compromise, persistence or lateral movement is found. please let management know imediatedly.

---

## Steps Taken
## Section 1: Reconnaissance
### 1. Searched the `HartwellHTTPEnriched_CL` Table 

Searched for the account which the attacker had succeeded with and operated under

**Query used to locate events:**

```kql
HartwellHTTPEnriched_CL
| get schema

HartwellApache_CL
| get schema

HartwellHTTPEnriched_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| summarize Requests=count() by id_orig_h, method, content_type
| order by Requests desc
```
<img width="704" height="249" alt="image" src="https://github.com/user-attachments/assets/0e652e54-1a85-44b3-9e45-13d00ed25329" />

---

### 2. Searched the `HartwellApache_CL` Table

Found the service that the attacker was operating from

**Query used to locate service:**

```kql

HartwellApache_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| search "nikto" or "sqlmap" or "wpscan" or "gobuster" or "nmap" or "dirb" or "dirbuster" or "ffuf" or "feroxbuster" or "masscan" or "nuclei" or "zgrab"
| take 20
```
<img width="722" height="212" alt="image" src="https://github.com/user-attachments/assets/b6a6cb91-e7c3-4d26-a747-1332926a0b7b" />


---
## Section 2: The Exploit
### 1. Searched the `HartwellHTTPEnriched_CL` Table to search session name

Searched for the command line that launched the attack

**Query used to locate events:**

```kql
HartwellHTTPEnriched_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| search "PHPSESSID" or "upload_progress" or "PHP_SESSION"
| take 10

```
<img width="741" height="301" alt="image" src="https://github.com/user-attachments/assets/07b01b1b-a646-4394-ac96-f411228dec70" />


---

### 2. Searched the `HartwellHTTPEnriched_CL` Table for the exploit delivery

Searched for the request that was used to deliver the exploit
**Query used to locate events:**

```kql
HartwellHTTPEnriched_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| summarize Requests=count() by id_orig_h, method, content_type
| order by Requests desc
```
<img width="409" height="225" alt="image" src="https://github.com/user-attachments/assets/2b598b2c-f45b-47ec-a350-0117bde4fed3" />



---

### 3. Searched the `HartwellHTTPEnriched_CL` Table to find the new file that appeared

Searched for the files that were dropped on the server and checked each one with .php extension to see which one was unusual

**Query used to locate events:**

```kql
HartwellHTTPEnriched_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where id_orig_h == "192.168.1.100"
| summarize FirstSeen=min(OriginalTime), Requests=count(), Methods=make_set(method) by uri
| order by FirstSeen asc
```
<img width="428" height="317" alt="image" src="https://github.com/user-attachments/assets/b60a2bec-2c99-46c4-a937-8483bc99a4cb" />



---
## Section 3: Remote Control
### 1. Searched the `HartwellSysmon_CL` Table to find the account which the attacker had use

Identified the account that the attacker had used to execute the commands

**Query used to locate events:**

```kql
HartwellSysmon_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where EventID == "1"
| where ParentImage has "apache2"
| summarize Count=count(), First=min(OriginalTime) by User, ParentUser
| order by First asc
```
<img width="605" height="176" alt="image" src="https://github.com/user-attachments/assets/f9777975-2d06-49a4-b883-633c5837c106" />



---

### 2. Searched the `HartwellHTTPEnriched_CL` Table to find the Hidden Trigger

Reviewed every header name to find and files starting with "X" which had the trigger

**Query used to locate events:**

```kql
HartwellHTTPEnriched_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where id_orig_h == "192.168.1.100"
| extend h = extract_all(@'"?([A-Za-z0-9-]+)"?\s*[:=]', request_headers)
| mv-expand h to typeof(string)
| summarize Count=count(), Example=take_any(uri) by h
| order by Count asc
```
<img width="419" height="269" alt="image" src="https://github.com/user-attachments/assets/fc322b1e-5733-4de9-81b6-ff79abbbda3d" />



---

### 3. Searched the `HartwellHTTPEnriched_CL` Table to find the encoding

Found the two-layer encoding scheme the attacker had used to encode the commands which was in a reverse order

**Query used to locate events:**

```kql
HartwellHTTPEnriched_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where id_orig_h == "192.168.1.100"
| extend h = extract_all(@'"?([A-Za-z0-9-]+)"?\s*[:=]', request_headers)
| mv-expand h to typeof(string)
| summarize Count=count(), Example=take_any(uri) by h
| order by Count asc

```
<img width="419" height="284" alt="image" src="https://github.com/user-attachments/assets/f639b1b0-13f5-4be3-b2bd-b8528afaa483" />



---
## Section 4: Mapping the Territory
  ### 9. Searched the `DeviceProcessEvents` Table to find the Installed Update Name

Identified the sc.exe create command and confirmed the installed service's name and bin path both pointed back to the implant, disguised under a name masquerading as a legitimate Windows health service.

**Query used to locate events:**

```kql
let start_time = datetime(2026-04-22T02:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceProcessEvents
| where Timestamp between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where ProcessCommandLine contains "tn"
| project DeviceName, ActionType, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName

```
<img width="1420" height="140" alt="image" src="https://github.com/user-attachments/assets/3a5494d5-cd15-475f-ac93-ced8b06dd122" />
<img width="744" height="80" alt="image" src="https://github.com/user-attachments/assets/e9dff0c6-fa54-4d38-8362-7bfcae757ef0" />

---

### 10. Searched the `DeviceProcessEvents` Table to find the backdoor user

Reviewed net.exe/net1.exe activity and confirmed two correlated events seconds apart. Account creation followed immediately by addition to the local Administrators group attributing the backdoor account name used for privilege escalation.

**Query used to locate events:**

```kql
let start_time = datetime(2026-04-22T02:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceProcessEvents
| where Timestamp between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where ProcessCommandLine contains "tn"
| project DeviceName, ActionType, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName

```
<img width="1435" height="125" alt="image" src="https://github.com/user-attachments/assets/804d1bdc-20fe-45f7-932d-a7210c44ff64" />
<img width="598" height="70" alt="image" src="https://github.com/user-attachments/assets/2302b344-e780-45aa-b9bb-a51b99378f12" />

---

### 11. Searched the `DeviceInfo` and 'AlertEvidence' Table to find the second host

Reviewed alert evidence and device onboarding status across the wider host fleet to identify a second host, beyond the primary compromised endpoint, showing evidence of lateral-movement activity.

**Query used to locate events:**

```kql
let start_time = datetime(2026-04-22T02:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceInfo
| where Timestamp between (start_time .. end_time)

let start_time = datetime(2026-04-22T02:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";
AlertEvidence
| where TimeGenerated between (start_time .. end_time)

```
<img width="1444" height="359" alt="image" src="https://github.com/user-attachments/assets/5daba7c6-6f0e-4d0a-b562-b9fa62a31487" />
<img width="751" height="364" alt="image" src="https://github.com/user-attachments/assets/605e8d23-eef2-4c93-b35d-19ec0bf526ba" />


---
## Chronological Event Timeline 

### 1. Initial Access — Compromised Account

- **Timestamp:** `2026-04-22T04:47:13
- **Event:** The "helpdesk" service account authenticated to NPT-WS01 over the network from an external IP address, bypassing normal interactive logon controls.
- **Action:** Action: Logon success detected (network service exploitation tool activity).
- **Source IP:** 20.110.92.50

### 2. File Drop — Implant Delivered

- **Timestamp:** `2026-04-22T04:59:22`
- **Event:** A file named WindowsUpdate.exe was dropped and launched from a remote location onto NPT-WS01, initiated via WMI rather than by a local user.
- **Action:** File dropped and launched from remote location.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Windows\Temp\WindowsUpdate.exe`

### 3. Command & Control — Outbound Beacon

- **Timestamp:** `2026-04-22T05:45:48`
- **Event:** Cmd.exe, spawned by WindowsUpdate.exe, exhibited suspicious behaviour while communicating outbound over port 443 to an external domain, confirming an active C2 channel.
- **Action:** Suspicious behaviour by cmd.exe observed.
- **Remote URL:** `updates.abordasync.website`

### 4. Persistence — Registry Run Key

- **Timestamp:** `2026-04-22T05:38:39`
- **Event:** A Run key value was written under ...\CurrentVersion\Run, disguised as a legitimate health-check task, pointing back at the implant in C:\Windows\Temp\.
- **Action:** Anomaly detected in ASEP (autostart execution point) registry.
- **Registry Value:** `WindowsHealthCheck`

### 5. Persistence — Scheduled Task

- **Timestamps:** '2026-04-22T05:43:15'
- **Event:** A scheduled task was created via schtasks, impersonating a well-known software updater, configured to relaunch the implant.
- **Action:** Suspicious scheduled task created.
- **Command:** 'cmd.exe /c schtasks /create /tn GoogleUpdaterTask /tr C:\Windows\Temp\WindowsUpdate.exe /sc ...'

### 6. Persistence — Windows Service

- **Timestamp:** `2026-04-22T05:44`
- **Event:** A Windows service was installed via sc.exe, with both the service name and binPath masquerading as a legitimate Windows health service, pointing back at the implant.
- **Action:** Masqueraded task or service.
- **Service Name:** `WindowsHealthSvc`

### 7. Privilege Escalation — Backdoor Account Created

- **Timestamp:** `2026-04-22T05:45:48`
- **Event:** A new local account was created on NPT-WS01 by cmd.exe, running as SYSTEM under WindowsUpdate.exe.
- **Action:** Suspicious account creation.
- **Command:** `cmd.exe /c net user nexus_admin ********** /add`
---

### 8. Privilege Escalation — Admin Group Added

- **Timestamp:** `2026-04-22T05:46:57`
- **Event:** The newly created account was immediately promoted to the local Administrators group, completing the privilege-escalation sequence.
- **Action:** Suspicious Windows account manipulation.
- **Command:** `net localgroup Administrators nexus_admin /add`
---

### 9. Lateral Movement — Second Host

- **Timestamp:** `2026-04-22T05:37:06`
- **Event:** A PowerShell suspicious web request alert fired on a second host, indicating the attacker's activity extended beyond NPT-WS01 within the same operational window.
- **Action:** PowerShell Suspicious Web Request detected.
- **Device:** `npt-srv01`
---
## Summary

An external attacker gained unauthorised access to "NPT-WS01" using the compromised "helpdesk" service account, authenticating remotely from IP 20.110.92.50. Within minutes, the attacker used WMI to remotely execute a disguised implant (WindowsUpdate.exe) dropped into C:\Windows\Temp\, which established an outbound command-and-control channel to updates.abordasync.website. The attacker then laid down three independent persistence mechanisms — a registry Run key, a scheduled task, and a Windows service, each masquerading as legitimate update or health-check tooling — before creating a backdoor local account (nexus_admin) and promoting it to the Administrators group. In the same window, related PowerShell command-and-control activity was observed on a second host, "npt-srv01", indicating the attacker's reach extended beyond the initial point of compromise. This sequence of activities indicates a deliberate, multi-stage intrusion involving credential abuse, remote execution, redundant persistence, privilege escalation, and lateral movement — not an isolated or accidental event.

---

## Response Taken

The compromise of NPT-WS01 was confirmed, along with related activity on a second host, npt-srv01. Both devices were network-isolated, the "helpdesk" account was disabled and its credentials reset, the backdoor account nexus_admin was disabled, and outbound traffic to 20.110.92.50 and updates.abordasync.website was blocked at the perimeter. IT security management and the Finance team were notified.

---
