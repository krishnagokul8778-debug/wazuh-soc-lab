# Wazuh Custom Detection Rules — Walkthrough

> Four custom rules in `/var/ossec/etc/rules/local_rules.xml` (group `soclab`), IDs 100100–100130.
> For each: the attack → the log event it produces → the rule logic → why it works →
> false-positive tuning.

---

## Rule 100100 — Encoded PowerShell  (INC-003 · MITRE T1059.001 / T1027)

**The attack:** an attacker runs PowerShell with a Base64-encoded command, e.g.
`powershell.exe -enc SQBFAFgAKAAuAC4A...` — encoding hides the real command from quick inspection and
basic logging.

**The telemetry:** Sysmon **Event ID 1 (Process Creation)** records the *full command line*, including
the `-enc` flag. (PowerShell **Event 4104** script-block logging additionally records the *decoded*
script — good corroboration.)

**Rule logic:**
```xml
<rule id="100100" level="12">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)powershell(\.exe)?.*\s-(e|enc|encodedcommand)\s</field>
  ...
</rule>
```
- `if_group sysmon_event1` → only evaluate Sysmon process-creation events.
- the regex matches `powershell` followed by the `-e` / `-enc` / `-encodedcommand` flag (case-insensitive).

**Why it works:** legitimate admins almost never launch PowerShell with `-EncodedCommand`; attackers and
malware droppers routinely do, to obfuscate. So the flag itself is a high-signal indicator.

**In short:** *"Sysmon EID 1 gives me the full process command line. Attackers Base64-encode
PowerShell with -EncodedCommand to evade string-based detection, so I alert on that flag. I'd confirm the
intent by pulling the matching Event 4104, which logs the decoded script block."*

**False positives / tuning:** some legitimate management tools use `-enc`; tune by excluding known-good
parent processes or signed scripts.

---

## Rule 100110 — Password Spray  (INC-006 · MITRE T1110.003)

**The attack:** instead of many passwords against one account (which triggers lockout), the attacker tries
**one password against many accounts** — e.g. `kerbrute passwordspray -d soclab.local users.txt 'Autumn2026!'`.

**The telemetry:** many **Event 4625 (failed logon)** records from the **same source IP** but with
**different target usernames**, in a short window.

**Rule logic:**
```xml
<rule id="100110" level="12" frequency="5" timeframe="120">
  <if_matched_sid>60122</if_matched_sid>      <!-- base Windows 4625 failed-logon rule -->
  <same_field>win.eventdata.ipAddress</same_field>
  <different_field>win.eventdata.targetUserName</different_field>
  ...
</rule>
```
- fires when **5** failed logons (`frequency`) occur within **120 s** (`timeframe`)
- where the **source IP is the same** (`same_field`) but the **username differs** (`different_field`).

**Why it works:** this is the exact fingerprint that separates a *spray* (one IP → many users) from a
single-account *brute force* (one IP → one user). The `same_field`/`different_field` correlation is what
makes it spray-specific.

**In short:** *"Spraying is low-and-slow to dodge lockout thresholds — one password across
many accounts. The signature is a burst of 4625 failures sharing a source IP but hitting different
usernames. My correlation rule counts five of those in two minutes with same IP, different user."*

**False positives / tuning:** a broken service account or misconfigured app can generate failures from one
host; adjust the threshold/timeframe and whitelist known service hosts.

---

## Rule 100120 — Kerberoasting  (INC-007 · MITRE T1558.003)

**The attack:** any domain user can request a Kerberos service ticket (TGS) for any account that has an
SPN. The attacker requests tickets for service accounts (e.g. `svc_sql` via `impacket-GetUserSPNs`),
forcing **RC4** encryption, then cracks the ticket **offline** to recover the service account password.

**The telemetry:** Security **Event 4769 (Kerberos service ticket requested)** with **Ticket Encryption
Type 0x17 (RC4-HMAC)** for a **user-account SPN** (not a computer account ending in `$`, not `krbtgt`).

**Rule logic:**
```xml
<rule id="100120" level="12">
  <field name="win.system.eventID">^4769$</field>
  <field name="win.eventdata.ticketEncryptionType">^0x17$</field>
  <field name="win.eventdata.serviceName" negate="yes">\$$|^krbtgt$</field>
  ...
</rule>
```
- `4769` → a service ticket was requested
- `0x17` → RC4 encryption (weak/crackable; modern Kerberos uses AES = 0x11/0x12)
- `serviceName negate` → exclude machine accounts (`…$`) and `krbtgt`, leaving user-SPN services.

**Why it works:** normal domain Kerberos traffic uses AES. A deliberate RC4 ticket request against a
*user* service account is the hallmark of roasting — you're catching the attacker downgrading to a
crackable cipher.

**In short:** *"Kerberoasting abuses the fact that any user can request a service ticket
for an SPN. Attackers force RC4 (0x17) because it's crackable offline. Event 4769 logs the ticket request
and its encryption type, so I alert on 0x17 against user-SPN accounts, excluding machine accounts and
krbtgt to cut noise."*

**False positives / tuning:** legacy apps that still use RC4; baseline which SPNs legitimately request RC4
and whitelist them. **Requires** "Audit Kerberos Service Ticket Operations" enabled on the DC.

---

## Rule 100130 — DCSync  (INC-008 · MITRE T1003.006)   [level 14 — critical]

**The attack:** an attacker with replication rights (or stolen privileged creds) uses the directory
replication API (DRSUAPI) via `impacket-secretsdump` or Mimikatz `lsadump::dcsync` to **pull password
hashes straight from the DC**, impersonating a domain controller — no malware on the DC needed.

**The telemetry:** Security **Event 4662 (operation on a directory object)** whose **Properties** contain
the replication control-access GUIDs — *DS-Replication-Get-Changes* and *-All*
(`1131f6aa-…` / `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`) — performed by an account that is **not** a DC.

**Rule logic:**
```xml
<rule id="100130" level="14">
  <field name="win.system.eventID">^4662$</field>
  <field name="win.eventdata.properties" type="pcre2">(?i)1131f6a[ad]-9c07-11d1-f79f-00c04fc2dcd2</field>
  <field name="win.eventdata.subjectUserName" negate="yes">\$$</field>
  ...
</rule>
```
- `4662` + the **replication GUIDs** → someone invoked directory replication
- `subjectUserName negate \$$` → the actor is a **user**, not a domain-controller machine account.

**Why it works:** *only domain controllers* legitimately replicate directory data. If a **user account**
triggers those replication rights, it's almost certainly DCSync — hence level 14 (critical).

**In short:** *"DCSync impersonates a DC to request secrets over the replication API. It
shows up as Event 4662 referencing the DS-Replication-Get-Changes access rights — those 1131f6aa/ad GUIDs.
Since only DCs should replicate, I fire a critical alert when those GUIDs appear with a non-machine
(user) account as the actor."*

**False positives / tuning:** legitimate replication services like **Azure AD Connect** use these rights —
whitelist their service accounts. **Requires** "Audit Directory Service Access" enabled on the DC.

---

## Dependencies
- Sysmon must be installed on the endpoints (it is) → feeds EID 1 for 100100.
- The DC's **advanced audit policy** must log 4769 (Kerberos TGS) and 4662 (Directory Service Access),
  else 100120/100130 never see events.
- Custom rule IDs start at **100000** (the reserved range for user rules).
- Validate before loading: `sudo /var/ossec/bin/wazuh-analysisd -t`, then restart the manager.
- Test a single event without attacking: `sudo /var/ossec/bin/wazuh-logtest` and paste a sample log.
