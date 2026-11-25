# Wazuh SOC Lab — Incident Detection Report

Detection lab on Wazuh SIEM (manager + indexer + dashboard on `SOC-Wazuh`, 192.168.56.30) monitoring a
Windows endpoint (`SOC-VICTIM-WIN`, 192.168.56.20) and attacked from Kali (192.168.56.104). Each
incident below shows the attack, the technique, how Wazuh detected it, and the evidence captured.

| # | Attack | Key Event ID | Wazuh rule | Result |
|---|--------|-----------|-----------|--------|
| INC-001 | Network recon (port scan) | — | — (hunt) | Detected by hunting |
| INC-002 | Brute force (failed logins) | 4625 | 60122 (L5) | Alerted |
| INC-003 | Encoded PowerShell | 1 (Sysmon) | 92057 (L12) | Alerted |
| INC-004 | Discovery (recon commands) | 1 (Sysmon) | 92031 | Alerted |

---

## INC-001 — Network Reconnaissance

**Objective:** map open services on the target before attacking.

**Attack (from Kali):**
```bash
sudo nmap -sS -F 192.168.56.20
```
Result: host up, ports **445 (SMB)** and **3389 (RDP)** open.

**MITRE ATT&CK:** T1046 – Network Service Discovery.

**Detection in Wazuh:** recon is **hunt-based, not alert-based** — a port scan is too low-signal to raise
an alert, so no rule fired. The analyst *hunts* for it in **Discover** by filtering on the attacker's
activity. Filtering the alerts index for the scan returned **no alert**, confirming recon's stealth.

**Evidence:** `evidence/INC-001-recon-no-alert-discover.png`

**Analysis / lesson:** reconnaissance is detected by spotting the *pattern* (one source touching many
ports), typically via network telemetry and threat hunting — not by a single pop-up alert.

---

## INC-002 — Brute Force (Credential Access)

**Objective:** guess a valid password by repeated login attempts.

**Attack (from Kali):**
```bash
for p in wrong1 wrong2 wrong3 wrong4 wrong5 wrong6; do smbclient -L //192.168.56.20 -U analyst%$p; done
```
Result: six `NT_STATUS_LOGON_FAILURE` responses (six failed logins as `analyst`).

**MITRE ATT&CK:** T1110 – Brute Force.

**Prerequisite (important finding):** the endpoint initially logged only *successful* logons, so the
attack was invisible. Failed-logon auditing had to be enabled first:
```
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
```

**Detection in Wazuh:**
- **Event ID 4625** (failed logon)
- **Wazuh rule 60122** – "Logon Failure - Unknown user or bad password" (level 5), fired 6×
- Captured: source IP **192.168.56.104**, workstation **KALI**, target user **analyst**, package **NTLM**,
  subStatus **0xc000006a** (bad password) — full attribution of the attacker.

**Evidence:** `evidence/INC-002-bruteforce-4625-logon-failures.png`

**Analysis / lesson:** detection depends on *logging configuration* — enabling failed-logon auditing was
the difference between seeing nothing and a clear burst of 4625 events with the attacker's IP and host.

---

## INC-003 — Encoded (Obfuscated) PowerShell

**Objective:** run a command while hiding what it does, to evade inspection.

**Attack (on the victim):**
```powershell
$c=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Host "INC-003 encoded PowerShell test"'))
powershell.exe -EncodedCommand $c
```
This launches `powershell.exe -EncodedCommand <base64>` — the obfuscation technique used by droppers and
"fileless" malware. (Encoding uses UTF-16/Unicode, which is what `-EncodedCommand` requires.)

**MITRE ATT&CK:** T1059.001 – PowerShell; T1027 – Obfuscated Files or Information.

**Detection in Wazuh:**
- **Event ID 1** (Sysmon – Process Create), which records the full command line
- **Wazuh rule 92057** – "Powershell.exe spawned a powershell process which executed a base64 encoded
  command" (level 12)
- Hunt filter used: `data.win.system.eventID:1 and data.win.eventdata.commandLine:*EncodedCommand*`

**Evidence:** `evidence/INC-003-encoded-powershell-sysmon-eid1.png`

**Analysis / lesson:** even when a command is hidden with Base64, Sysmon logs the **full command line**,
so the *act of encoding* (`-EncodedCommand`) is itself the detection signal. (Optional deeper visibility:
PowerShell Script Block Logging logs the *decoded* script as Event ID 4104.)

---

## INC-004 — Discovery (System/Domain Enumeration)

**Objective:** after gaining access, learn about the host and domain — who you are, your privileges, local
admins, network config, and nearby accounts.

**Attack (on the victim):**
```powershell
whoami
whoami /groups
hostname
systeminfo
net user
net localgroup administrators
ipconfig /all
```
A quick succession of built-in recon tools = a "discovery burst."

**MITRE ATT&CK:** T1033 (System Owner/User Discovery – whoami), T1082 (System Information – systeminfo),
T1087 (Account Discovery – net user/localgroup), T1016 (System Network Config – ipconfig).

**Detection in Wazuh:**
- **Event ID 1** (Sysmon – Process Create) for each recon tool
- **Wazuh rule 92031** fired on the `net` commands (Net command discovery) — 6 hits in a tight burst
- Captured: `net.exe` / `net1.exe` with `parentCommandLine: net user`, on `SOC-VICTIM-WIN`
- Hunt filters: `rule.id:92031`  or  `data.win.system.eventID:1 and data.win.eventdata.image:(*whoami.exe* or *net.exe* or *systeminfo.exe* or *ipconfig.exe*)`

**Evidence:** `evidence/INC-004-discovery-net-sysmon-eid1.png`

**Analysis / lesson:** no single discovery command is malicious, but **several recon tools running in a
short window** is a strong attacker signal. Sysmon's process-creation logging makes the burst visible, and
built-in rules flag the common enumeration binaries.

---

## Summary
Three attacker techniques across the kill chain — reconnaissance, credential access, and obfuscated
execution — were run against the monitored endpoint and detected (or hunted) in Wazuh, each mapped to
MITRE ATT&CK with captured evidence. The key SOC lessons: recon is hunt-based; detection depends on the
right audit/logging being enabled; and endpoint telemetry (Sysmon) defeats command obfuscation.

*Next incidents to add: INC-006 password spray, INC-007 Kerberoasting, INC-008 DCSync (these require DC01 powered on).*
