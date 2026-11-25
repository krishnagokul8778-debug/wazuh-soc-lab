# Wazuh SOC Lab

A home SOC lab built on the **Wazuh SIEM** to detect real attacks against a Windows endpoint and an
Active Directory domain controller. It runs alongside my
[Splunk SOC lab](https://github.com/krishnagokul8778-debug/soc-detection-lab) so the same attacks are
detected on two different SIEMs.

## Lab setup

| Component | Details |
|---|---|
| SIEM | Wazuh 4.14 (manager, indexer, dashboard) on Ubuntu 24.04 (`SOC-Wazuh`) |
| Endpoints | Windows 11 victim (`SOC-VICTIM-WIN`) and domain controller (`DC01`, `soclab.local`) with Wazuh agents + Sysmon |
| Attacker | Kali Linux |
| Network | VirtualBox host-only network (192.168.56.0/24), isolated lab |

## Investigated incidents

| ID | Attack | MITRE ATT&CK | Detection | Result |
|---|---|---|---|---|
| INC-001 | Network recon (Nmap port scan) | T1046 | Threat hunt in Discover | Found by hunting (no alert) |
| INC-002 | Brute force (failed logons) | T1110.001 | Event 4625, rule 60122 | Alerted |
| INC-003 | Encoded PowerShell | T1059.001, T1027 | Sysmon EID 1, rule 92057 | Alerted |
| INC-004 | Discovery commands | T1082, T1087 | Sysmon EID 1, rule 92031 | Alerted |

Full details and screenshots: [Incidents-Report.md](Incidents-Report.md) and [evidence/](evidence/).

## Custom detection rules

Four custom rules in `local_rules.xml` (IDs 100100–100130), mapped to MITRE ATT&CK:

| Rule | Detects | Technique |
|---|---|---|
| 100100 | Encoded PowerShell | T1059.001 / T1027 |
| 100110 | Password spray | T1110.003 |
| 100120 | Kerberoasting | T1558.003 |
| 100130 | DCSync (critical) | T1003.006 |

How each rule works and how to tune it: [Detection-Rules-Explained.md](Detection-Rules-Explained.md).

## Documents

- [Wazuh-SOC-Lab-FINAL-REPORT.pdf](Wazuh-SOC-Lab-FINAL-REPORT.pdf) — full project report
- [Wazuh-SOC-Lab-Writeup.md](Wazuh-SOC-Lab-Writeup.md) — build write-up and problems solved
- [Incidents-Report.md](Incidents-Report.md) — incident investigations
- [Detection-Rules-Explained.md](Detection-Rules-Explained.md) — custom rule walkthrough

## Next steps

Replay the Active Directory attacks (password spray, Kerberoasting, DCSync) against the custom rules.

## Scope

All attacks were run only inside my own isolated lab network.
