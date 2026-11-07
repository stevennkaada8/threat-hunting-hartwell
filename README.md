# threat-hunting-hartwell
# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project
<img width="1200" height="675" alt="image" src="https://github.com/user-attachments/assets/8ae8c79e-6282-42c2-8151-dbf73dbc2a46" />

# Threat Hunt Report: Unauthorised Access on Helpdesk Account

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  Scenario

Management has received a helpdesk ticket from a Finance user called Mark Smith reporting repeated login prompts on NPT-WS01 overnight. Subsequent analysis shows a helpdesk account was used to authenticate from an external IP address outside of normal business hours. Microsoft Sentinel has already raised analytic alerts including one on a second host, suggesting the activity may not be confined to a single machine. The goal is to determine, whether this was a genuine compromise, reconstruct how the attacker gained access, what they did once inside and establish the full scope across the environment. If evidence of compromise, persistence or lateral movement is found. please let management know imediatedly.

---

## Steps Taken

### 1. Searched the `DeviceLogonEvents` Table 

Searched for the account which the attacker had succeeded with and operated under

**Query used to locate events:**

```kql
let start_time = datetime(2026-04-22T02:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceLogonEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == HostInQuestion
```
<img width="1420" height="345" alt="image" src="https://github.com/user-attachments/assets/9a439086-8b4d-4bba-b033-b382063744aa" />

---

### 2. Searched the `DeviceLogonEvents` Table

Found the external IP Address which the attacker authenticated from

**Query used to locate event:**

```kql

let start_time = datetime(2026-04-22T02:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceLogonEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where ActionType == "LogonSuccess"
| project TimeGenerated, DeviceName, ActionType, AccountName, RemoteIP
```
<img width="1434" height="484" alt="image" src="https://github.com/user-attachments/assets/90db4837-702c-4d8a-85a1-ac18196ebabb" />

---

### 3. Searched the `DeviceProcessEvents` Table for Process Execution

Searched for the command line that launched the attack

**Query used to locate events:**

```kql
let start_time = datetime(2026-04-22T02:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceProcessEvents
| where TimeGenerated between (start_time .. end_time)
| where AccountName == "helpdesk"
| where DeviceName == HostInQuestion
| project DeviceName, ActionType, FileName, TimeGenerated, ProcessCommandLine, InitiatingProcessCommandLine
```
<img width="1426" height="109" alt="image" src="https://github.com/user-attachments/assets/dea72774-2b82-464e-874c-838b898e2663" />

---

### 4. Searched the `DeviceProcessEvents` Table for the Parent Process

Searched for the immediate parent process that spawned the cmd.exe which had confirmed a remote WMI execution rather than a local user.

**Query used to locate events:**

```kql
let start_time = datetime(2026-04-22T02:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceProcessEvents
| where TimeGenerated between (start_time .. end_time)
| where AccountName == "helpdesk"
| where DeviceName == HostInQuestion
| project DeviceName, ActionType, FileName, TimeGenerated, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName
```
<img width="781" height="105" alt="image" src="https://github.com/user-attachments/assets/0bd2ec94-dfa2-4874-8de6-9213189faab5" />


---

### 5. Searched the `DeviceNetworkEvents` Table to filter legitimate traffic

Searched for command-and-control domain the host beaconed to by filtering outbound HTTPS connections to exclude legitimate Microsoft signed traffic

**Query used to locate events:**

```kql
let start_time = datetime(2026-04-22T02:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceNetworkEvents
| where TimeGenerated between (start_time .. end_time)
| where InitiatingProcessAccountName == "helpdesk"
| project DeviceName, ActionType, RemoteUrl, TimeGenerated, InitiatingProcessCommandLine, InitiatingProcessFileName
```
<img width="1440" height="119" alt="image" src="https://github.com/user-attachments/assets/7238753c-8029-46e1-a696-87290fc12c1b" />


---

### 6. Searched the `DeviceProcessEvents` Table to find the file dropped

Identified the executable dropped into a staging location (C:\Windows\Temp) and captured its SHA256 hash, noting the unusual creating process as an indicator of how the file was delivered onto the host.

**Query used to locate events:**

```kql
let start_time = datetime(2026-04-22T02:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceProcessEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == HostInQuestion
| project DeviceName, ActionType, FileName, SHA256, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName
| where InitiatingProcessAccountName == "helpdesk"
```
<img width="1430" height="108" alt="image" src="https://github.com/user-attachments/assets/3e40896a-8668-482d-b358-4cc715a10bc1" />


---

### 7. Searched the `DeviceRegistryEvents` Table to find the Registry Run-key

Reviewed registry write events under the Run key and identified a disguised value name, masquerading as a legitimate Windows Update, whose data pointed back to the implant staged in Temp.

**Query used to locate events:**

```kql
let start_time = datetime(2026-04-22T02:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceRegistryEvents
| where Timestamp between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where RegistryKey contains "run"
| where isnotempty(RegistryValueName) 
| project DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName
```
<img width="1435" height="110" alt="image" src="https://github.com/user-attachments/assets/69ec52e2-8a10-4ca9-a22a-224f8c8ce5b8" />


---

### 8. Searched the `DeviceProcessEvents` Table to find the scheduled task

Identified the schtasks.exe /create command and extracted the /tn argument, revealing a scheduled task name disguised to impersonate a well known software updater.

**Query used to locate events:**

```kql
let start_time = datetime(2026-04-22T02:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceProcessEvents
| where Timestamp between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where ProcessCommandLine contains "net user"
| project DeviceName, ActionType, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName

```
<img width="1422" height="101" alt="image" src="https://github.com/user-attachments/assets/a8bd609b-1a6a-4711-a9c1-4ae1d374a349" />
<img width="788" height="415" alt="image" src="https://github.com/user-attachments/assets/b94fba91-41f6-41c8-9669-03931a27d2ab" />


---

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
