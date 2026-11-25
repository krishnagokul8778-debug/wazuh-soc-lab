# Wazuh SOC Lab — Build Write-up

> A Wazuh SIEM deployed **alongside** the Splunk SOC detection lab (see the `SOC Splunk Lab` folder),
> so the same attacks can be demonstrated on two different SIEMs. Built on VirtualBox, Windows 11 host.
> Completed 2026-11-20.

## 1. Goal
Stand up Wazuh (all-in-one: manager + indexer + dashboard) on a dedicated Ubuntu VM, enroll the
existing Windows endpoints as agents, and replay the lab's attack incidents to show detections in
Wazuh's MITRE ATT&CK view — a second SIEM skillset, next to the Splunk lab.

## 2. Architecture
| Role | Host | IP |
|---|---|---|
| Attacker | Kali | 192.168.56.102 |
| Monitored domain controller | DC01 (`soclab.local`) | 192.168.56.5 |
| Monitored target | SOC-VICTIM-WIN (Win11) | 192.168.56.20 |
| **SIEM server** | **SOC-Wazuh (Ubuntu 24.04)** | **192.168.56.30** |
| Host (hypervisor + Splunk) | Windows 11 | 192.168.56.1 |

Data flow: Kali attacks the two Windows hosts → their Wazuh agents ship events on **:1514** →
manager applies decoders/rules → indexer stores → dashboard (**:443**) visualizes → analyst reviews.

## 3. Deployment summary
- VM: repurposed an existing Ubuntu box (renamed `soc-wazuh`), **1 vCPU** (host Core Isolation forces
  VirtualBox into Hyper-V/NEM mode, where 2+ vCPUs panicked), 4 GB RAM, host-only static IP via netplan.
- Installer: `wazuh-install.sh -a -i` (all-in-one, `-i` skips the 2-CPU hardware check).
  Versioned URL required: `https://packages.wazuh.com/4.14/wazuh-install.sh` (version 4.14.10).
- Access: SSH key login from host; dashboard at `https://192.168.56.30` (admin).

## 4. Problems hit and how they were solved
The single-vCPU constraint made the all-in-one install fragile. Four distinct failures, each root-caused:

1. **Manager .deb download timed out** (622 MB over a flaky CDN) → pre-downloaded all component
   packages with a *resumable* `curl -C -` into the apt cache, then re-ran the installer so it used
   the cached files instead of re-downloading.
2. **Out-of-memory during the manager package configure** (4 GB RAM, no swap) → added a **2 GB swap
   file** (`/swapfile`, persisted in `/etc/fstab`).
3. **`dpkg was interrupted`** from the OOM, leaving `wazuh-manager` half-installed with a broken
   pre-removal script (exit 127) → neutralised the package's maintainer scripts in
   `/var/lib/dpkg/info/` and force-purged it, then `dpkg --configure -a` to clear the interrupted state.
4. **`wazuh-manager.service` start-timeout** — the real blocker. On 1 vCPU the manager's daemons start
   too slowly for systemd's ~45 s start timeout, so systemd killed the unit and the installer rolled
   everything back. **Not** a crash or memory issue (peak 275 MB). Fix: pre-place systemd drop-ins
   `/etc/systemd/system/<svc>.service.d/override.conf` with `TimeoutStartSec=900` for manager, indexer
   and dashboard *before* installing, so the slow service starts had room to finish.

After the timeout override, the install completed cleanly (indexer → manager → dashboard all Active).

## 5. Agent enrollment
- Created an agent group **`windows`** on the manager and pushed a shared `agent.conf` to collect the
  extra Windows channels: `Microsoft-Windows-Sysmon/Operational` and
  `Microsoft-Windows-PowerShell/Operational` (Security/System are collected by default).
- Installed the Wazuh Windows agent (MSI `wazuh-agent-4.14.10-1.msi`) on DC01 and SOC-VICTIM-WIN,
  pointed at manager `192.168.56.30`, group `windows`. **Must be run from an elevated PowerShell** or
  the silent MSI install fails and `NET START Wazuh` reports "service name invalid".
- Both agents confirmed **Active** on the manager: ID 001 = DC01, ID 002 = SOC-VICTIM-WIN.
- VirtualBox note: both Windows VMs had a stuck PS/2 mouse; fixed by setting the pointing device to
  **USB Tablet** (`VBoxManage modifyvm "<vm>" --mouse usbtablet`, VM powered off). No Guest Additions,
  so no host↔guest clipboard — installer was delivered via a one-line bootstrap served over HTTP from
  the manager.

## 6. Status / next steps
- ✅ Wazuh stack installed, all services Active, dashboard reachable.
- ✅ DC01 + SOC-VICTIM-WIN agents enrolled and Active in the `windows` group.
- ⏭ Add custom detection rules to `local_rules.xml` (encoded PowerShell, password spray,
  Kerberoasting, DCSync — verify parent rule SIDs in the running version).
- ⏭ Replay incidents INC-001..008 from Kali; capture screenshots of the alerts + MITRE ATT&CK view.

## 7. Reference
- Companion lab: the Splunk detection lab in the `SOC Splunk Lab` folder.
