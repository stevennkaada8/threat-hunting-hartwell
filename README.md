
# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project
<img width="1200" height="675" alt="image" src="https://github.com/user-attachments/assets/8ae8c79e-6282-42c2-8151-dbf73dbc2a46" />

# Threat Hunt Report: The Hartwell Breach

## Platforms and Languages Leveraged
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
  ### 1. Searched the `HartwellSysmon_CL` Table to find the network discovery commands that were executed

Identified the three network commands which were executed by the attacker under the "www-data" user

**Query used to locate events:**

```kql
HartwellSysmon_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where EventID == 1
| where User == "www-data"
| project OriginalTime, Image, CommandLine, ParentImage
| order by OriginalTime asc

```
<img width="371" height="287" alt="image" src="https://github.com/user-attachments/assets/cdeaa5d4-3451-4e34-9b8e-0f2ca6562bba" />
<img width="354" height="293" alt="image" src="https://github.com/user-attachments/assets/a3de6d3b-6692-4f89-82da-f9c18dfa4d60" />
<img width="351" height="300" alt="image" src="https://github.com/user-attachments/assets/bb160f8e-85d4-4763-b61a-b6a94eaf8e99" />


---

### 2. Searched the `HartwellSysmon_CL` Table to find the security tools scanned

The attacker had been looking for security monitoring tools that are being used before proceeding with the next steps

**Query used to locate events:**

```kql
HartwellSysmon_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where EventID == 1
| where User == "www-data"
| project OriginalTime, Image, CommandLine, ParentImage
| order by OriginalTime asc

HartwellSysmon_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where tostring(EventID) == "1"
| where CommandLine has_any ("splunk", "sysmon", "auditd", "audit", "wazuh", "ossec", "falco", "osquery", "clamav", "crowdstrike", "edr", "antivirus")
| project OriginalTime, User, Image, CommandLine
| order by OriginalTime asc

```
<img width="399" height="286" alt="image" src="https://github.com/user-attachments/assets/77d07644-2a8c-4c82-80d8-cad0cc8910d0" />
<img width="382" height="299" alt="image" src="https://github.com/user-attachments/assets/76400c25-0c5a-40c9-a569-d0b5c0ffcdbe" />


---
## Section 5: Credential Harvest
### 1. Searched the 'HartwellSysmon_CL' Table to find the configuration file obtained

The attacker had read the "wp-config.php" which is the Wordpress configuration file which contained the database

**Query used to locate events:**

```kql
HartwellSysmon_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where tostring(EventID) == "1"
| where User == "www-data"
| where CommandLine has_any ("cat ", "head ", "tail ", "grep ", "less ", "more ", "base64 ", "cp ", "strings ")
| project OriginalTime, CommandLine
| order by OriginalTime asc

```
<img width="415" height="256" alt="image" src="https://github.com/user-attachments/assets/ec3844f5-9923-4dad-bcfd-3193f4cbf0f2" />

---

### 2. Searched the `HartwellSysmon_CL` Table to find the table that wwas dumped and the column for passsword

The attacker had queried the database to obtain credentials which also included the passwords

**Query used to locate events:**

```kql
HartwellSysmon_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where tostring(EventID) == "1" and User == "www-data"
| where CommandLine has_any ("mysql", "mysqldump", "psql", "sqlite")
| project OriginalTime, CommandLine
| order by OriginalTime asc


```
<img width="420" height="226" alt="image" src="https://github.com/user-attachments/assets/de19768a-c0fc-4989-9601-bc965b02bc47" />

---
## Section 6: Fighting The Watchers
### 1. Searched the `HartwellSysmon_CL` Table to find which security tools the attacker tried to disable

The attacker had attempted to disable the security tools that were on the server

**Query used to locate events:**

```kql
HartwellSysmon_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where tostring(EventID) == "1"
| where User == "www-data"
| where CommandLine has_any ("systemctl", "service ", "auditctl", "kill", "pkill", "chkconfig")
| project OriginalTime, Image, CommandLine
| order by OriginalTime asc

HartwellSysmon_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where tostring(EventID) == "1"
| where CommandLine has_any ("systemctl stop")
| project OriginalTime, Image, CommandLine
| order by OriginalTime asc

```
<img width="390" height="242" alt="image" src="https://github.com/user-attachments/assets/4af8f3cf-cae0-4761-802b-17f11c117c7a" />
<img width="411" height="290" alt="image" src="https://github.com/user-attachments/assets/bf1a4010-2932-4812-b45e-1855044a17e9" />
<img width="426" height="289" alt="image" src="https://github.com/user-attachments/assets/e96ce5e8-fab3-40e3-9068-d8a0d26b0d5f" />

---
### 2. The attacker wasn't able to successfully disable the services with the systemctl stop command because the user ""www-data" didn't have the privileges so they were denied 

---
## Section 7: Digging In
### 1. Searched the `HartwellSysmon_CL` Table to find the mechanism installed

The attacker had installed a mechanism to maintain access to the host

**Query used to locate events:**

```kql
HartwellSysmon_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where tostring(EventID) == "1"
| where User == "www-data"
| where CommandLine has_any ("crontab", "cron", "systemctl enable", ".service", "authorized_keys", "ssh-keygen", "rc.local", ".bashrc", "profile", "at ", "useradd", "chmod +x")
| project OriginalTime, Image, CommandLine
| order by OriginalTime asc

```
<img width="407" height="328" alt="image" src="https://github.com/user-attachments/assets/37153fc2-6e12-447e-9d78-0ad038fd567a" />



---
### 2. Searched the `HartwellSysmon_CL` Table to find the hidden implant

The attacker had installed an implant with the mechanism which was shown as "/dev/shm/.cache-helper"

**Query used to locate events:**

```kql
HartwellSysmon_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where tostring(EventID) == "1"
| where User == "www-data"
| where CommandLine has_any ("crontab", "cron", "systemctl enable", ".service", "authorized_keys", "ssh-keygen", "rc.local", ".bashrc", "profile", "at ", "useradd", "chmod +x")
| project OriginalTime, Image, CommandLine
| order by OriginalTime asc

```
---
## Section 8: Damage Assessment
### 1. How did the attacker exfiltrate stolen data (wp-config.php contents and database records) from the server?

The attacker had base64 encoded wp-config.php and wp_users.table on the server

### 2. A colleague suggests the attacker may have moved laterally to other systems on the 192.168.1.0/24 network. Examine the available evidence. Is there any indication of lateral movement from the compromised host?

No, there is no evidence of lateral movement: the 45 decoded commands contain no SSH, SCP, rsync or netcat activity, there were no outbound connections to other hosts, and www-data has no credentials valid for remote authentication

---
## Chronological Event Timeline 

### 1. Reconnaissance — Nmap Scan

- **Timestamp:** `2026-10-23T14:52:15
- **Event:** 192.168.1.100 probed the Hartwell web server with Nmap, requesting /robots.txt, /.git/HEAD, /sdk, /HNAP1, /evox/about and the Nmap-specific path /nmaplowercheck....
- **Action:** Vulnerability scanning detected (Nmap user agent).
- **Source IP:** 192.168.1.100

### 2. Initial Access — PHP Session Upload-Progress Exploi

- **Timestamp:** `2026-10-23T14:55:19
- **Event:** The attacker sent crafted requests to check_progress.php?sid=ph2sh_... and index.php. The Apache error log recorded three PHP session warnings (invalid session ID, failed session read, failed session write), which show the session.upload_progress feature being abused.
- **Action:** Exploit delivered via POST with multipart/form-data.
- **Content-Type:** multipart/form-data; boundary=----0x4148php2shel
  
### 3. File Drop — Webshell Planted

- **Timestamp:** `2026-10-23T14:45:50
- **Event:** A new file appeared in the webroot and received 46 requests from the attacker. It was not part of the scanning phase.
- **Action:** Webshell dropped and used.
- **File Path:** /var/www/html/health-check.php

### 4. Execution — Obfuscated Header-Triggered Shell

- **Timestamp:** `2026-10-23T15:01:23
- **Event:** The webshell began executing commands as www-data, driven by a custom HTTP header instead of URL parameters. Each PHP payload was ROT13-encoded and then base64-encoded, and the shell decodes in reverse before running it.
- **Action:** Command execution through the webshell. First commands were id and whoami.
- **Header:** X-HMG-Debug
- **Account:** www-data
- 
### 5. Discovery — System and Network Mapping

- **Timestamps:** '2026-10-23T15:01:42 to 15:12:57'
- **Event:** The attacker identified the host and mapped the local network, then listed accounts and tried to read the shadow file.
- **Action:** System and network discovery.
- **Command:** 'uname -a, hostname, ip a (15:02:18), ss -tlnp (15:02:28), cat /etc/passwd (15:02:39), cat /etc/shadow (15:02:54), ip neigh (15:12:57)'

### 6. Discovery — Security Tooling Check

- **Timestamp:** `2026-10-23T15:02:57`
- **Event:** The attacker searched installed packages for monitoring tools, then listed running services and checked their status.
- **Action:** Security software discovery.
- **Commands:** `dpkg -l | grep -iE 'splunk|sysmon|auditd|wazuh|ossec', systemctl list-units (15:13:21), systemctl is-active sysmon auditd SplunkForwarder (15:14:14)

### 7. Credential Access — Configuration File

- **Timestamp:** `2026-10-23T15:03:10`
- **Event:** The attacker read the WordPress configuration file to get the database credentials, and returned to it several times.
- **Action:** Credentials harvested from a configuration file.
- **Command:** `grep -E 'DB_|TABLE_PREFIX' /var/www/html/wp-config.php'
- **File Path:** `/var/www/html/wp-config.php'
---

### 8. Credential Access — Database Dump

- **Timestamp:** `2026-10-23T15:03:42`
- **Event:** The attacker queried the WordPress database for account details and password hashes. The queries succeeded at 15:09:06 once the password from wp-config.php was added to the command line.
- **Action:** Credential dump from the database.
- **Command:** `mysql -u wpuser -p********** wordpress -e "SELECT user_login,user_pass FROM wp_users"
- **Table/Column:** `wp_users / user_pass'
---

### 9. Defense Evasion — Attempt to Disable Monitoring

- **Timestamp:** `2026-10-23T15:13:55`
- **Event:** The attacker tried to flush the audit rules and stop all three monitoring services, then checked whether it had worked. The attempts failed because www-data has no privileges to stop system services, and logging continued.
- **Action:** Impair defenses attempted and unsuccessful.
- **Commands:** `auditctl -D, systemctl stop sysmon (15:14:01), systemctl stop SplunkForwarder (15:14:07), systemctl is-active sysmon auditd SplunkForwarder (15:14:14)'
- **Services Targeted:** sysmon, auditd, SplunkForwarder
---

### 10. Exfiltration — Encoded Data Returned over HTTP

- **Timestamp:** `2026-10-23T15:14:39`
- **Event:** The attacker base64-encoded wp-config.php and the full wp_users table, and the output came back in the webshell’s HTTP responses. No new outbound connection was opened.
- **Action:** Exfiltration over the existing command-and-control channel.
- **Commands:** `base64 /var/www/html/wp-config.php, mysql ... "SELECT * FROM wp_users" | base64 (15:15:15)'
---

### 11. Persistence — Cron Job and Hidden Implant

- **Timestamp:** `2026-10-23T15:15:49`
- **Event:** The attacker copied sleep into a hidden file in memory-backed storage and added a crontab entry to run it every 5 minutes.
- **Action:** Scheduled task/job created (T1053.003).
- **Command:** `(crontab -l; echo "*/5 * * * * /dev/shm/.cache-helper 300") | crontab - (15:16:00)'
- **File Path:** /dev/shm/.cache-helper
---

### 12. Impact — Ransom Note Written

- **Timestamp:** `2026-10-23T15:16:23`
- **Event:** The attacker wrote a ransom note to the webroot claiming RSA-4096 encryption and demanding 15 BTC. None of the commands I saw encrypt anything, so this looks like a note only.
- **Action:** Ransom note created.
- **File Path:** `/var/www/html/NOTICE.txt'
- **Contact:** recover_hmg@proton.me (reference HMG-2026-4891)
---

### 13. Defense Evasion — Checking Own Footprint

- **Timestamp:** `2026-10-23T15:18:52`
- **Event:** The attacker read the Apache, Sysmon and audit logs to see whether their activity had been recorded.
- **Action:** `Log review.'
- **Commands:** tail -30 /var/log/apache2/access.log, tail -40 /var/log/sysmon/sysmon.log, ausearch -ui 33 (uid 33 is www-data)
---

### 14. Lateral Movement — Not Observed

- **Timestamp:** `N/A`
- **Event:** None of the 45 decoded commands used SSH, SCP, rsync or netcat against another host, there were no outbound connections to other systems, and www-data holds no credentials valid for remote authentication.
- **Action:** `No lateral movement detected.'

---
## Summary

An attacker at 192.168.1.100 scanned the Hartwell Medical Group WordPress server with Nmap, then gained a foothold by abusing the PHP session upload-progress feature through multipart POST requests. The attacker planted a webshell (health-check.php) that took commands in a custom header (X-HMG-Debug), each ROT13 and base64 encoded, and ran them as the www-data account. They mapped the system and network, checked for security tooling, and read wp-config.php for database credentials. They then dumped the wp_users table, including the password hashes, and returned the data base64-encoded over the same HTTP channel. An attempt to disable Sysmon, auditd and the Splunk forwarder failed because www-data lacks the privileges. The attacker then added a cron job running a disguised binary from /dev/shm, left a ransom note in the webroot, and checked the logs for traces of their activity. No evidence of lateral movement was found. The sequence indicates a deliberate, multi-stage intrusion that combined exploitation, credential theft, failed defense evasion, persistence and extortion, with activity confined to the web server.

---

## Response Taken

The web server (192.168.1.120) was network-isolated and 192.168.1.100 was blocked at the perimeter. health-check.php and NOTICE.txt were removed, as were the www-data crontab entry and /dev/shm/.cache-helper. The database password, the WordPress auth keys and salts, and all WordPress user passwords were reset, since the hashes were exposed. PHP session upload-progress handling was reviewed and patched, and Sysmon, auditd and the Splunk forwarder were confirmed running. IT security management and the compliance team were notified of the potential patient-data exposure.

---
