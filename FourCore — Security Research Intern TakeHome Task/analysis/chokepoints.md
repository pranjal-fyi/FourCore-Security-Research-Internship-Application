# Part 1.3  Detection Chokepoints

Three moments in this intrusion where detection would have had the highest impact. I'm defining "highest impact" as: earliest, most actionable, and hardest for the attacker to route around without changing their whole approach.

![alt text](Dfir-Image-Report-34936_058-1.png)

## Chokepoint 1: Initial RDP Login + Immediate NetScan Deployment (Day 1, ~T+0:10)

# What the attacker was doing
Within minutes of the initial RDP session, the attacker ran cmd.exe with basic discovery commands (ipconfig, route print, systeminfo) and then dropped SoftPerfect Network Scanner into a folder they created on the desktop. They had a pre-configured netscan.xml with domain admin credentials baked in, custom port ranges, and full-network scanning enabled. They ran it almost immediately.

# Why this was a high-value detection opportunity
This is as early as detection gets. The attacker had barely been in the environment for ten minutes and was already conducting active network reconnaissance. If caught here, none of the downstream activity  DC pivot, account creation, persistence, data theft, ransomware  happens. More importantly, the behavior itself is anomalous in a detectable way: an interactive RDP session spawning cmd.exe and dropping a third-party scanner executable within the same session is not normal user behavior, even for admins.

The netscan deployment also has a specific, observable network fingerprint: high-volume port scanning originating from a single internal host, plus the creation of `delete.me` files on remote SMB shares as NetScan checks write access. These aren't subtle.

### What a defender would need to detect it

**Log source**: Windows Security Event ID 4624 (logon type 10 for RDP) + Sysmon Event ID 1 (process creation) + Sysmon Event ID 11 (file creation)
**Signal**: RDP logon from external IP  within a short time window, cmd.exe spawned under explorer.exe followed by creation of a third-party executable (netscan.exe) on the same host
**Network signal**: Sysmon EID 3 showing high-frequency outbound connections from a single host across broad internal IP ranges and port sweeps shortly after an RDP logon
**Share signal**: Sysmon EID 11 showing creation of `delete.me` files on remote file shares would correlate netscan activity across the estate
**Context needed**: Knowing whether the authenticating account and source IP are expected for that host. An RDP login from an external IP with no prior authentication history to that system should trigger alert review at minimum.


## Chokepoint 2: New Privileged Domain Account Creation (Day 1, ~T+0:15)

# What the attacker was doing
Ten minutes after the initial login, they pivoted to a domain controller via RDP using domain admin credentials and opened Active Directory Users and Computers. They created three new accounts with look-alike names, added two of them to Domain Admins, and set all passwords to never expire. One account was also given Group Policy Creator Owners rights.

# Why this was a high-value detection opportunity
This is the moment the attacker cemented their foothold. If you miss the initial RDP and netscan (chokepoint 1), this is your second chance and arguably more reliable to detect, because adding accounts to Domain Admins is one of the most audited events in a Windows environment. It generates multiple high-fidelity, low-noise security events. Detecting this would have uncovered the intrusion before any data was collected and before persistence (AnyDesk) was established.

The look-alike naming convention also matters  "administratr" is the kind of name that should fail a simple sanity check against a known-good account inventory. It's not clever enough to fool automated monitoring if you're watching for single-character-difference names against existing privileged accounts.

# What a defender would need to detect it

**Log source**: Windows Security Event ID 4720 (user account created) + 4728 (member added to security-enabled global group) + 4732 (member added to security-enabled local group)
**Signal**: New account creation on a domain controller followed immediately by group membership modification adding that account to Domain Admins or other high-privilege groups
**Additional signal**: EID 4738 with the UserAccountControl change showing USER_DONT_EXPIRE_PASSWORD being set on a newly created account is a specific, detectable indicator
**Context needed**: Alerting on any Domain Admin group membership change that isn't part of a documented change request would catch this. The time-of-day context also helps  this happened during a hands-on session, not a scheduled provisioning window.
**Detection enhancement**: Levenshtein distance checks on new account names against existing privileged accounts. A distance of 1 from "administrator" is a trivial rule to write and would catch "administratr" immediately.


## Chokepoint 3: Data Archiving and Exfiltration to temp.sh (Day 6)

# What the attacker was doing
Six days in, the attacker ran 7-Zip from the context menu (7zG.exe, parent process explorer.exe) to archive the contents of multiple network file shares onto the desktop. The archives were then uploaded to temp.sh, a public temporary file-sharing service. This was the double extortion component of the attack data was exfiltrated before ransomware deployment.

# Why this was a high-value detection opportunity
By day six you've missed two earlier opportunities (chokepoints 1 and 2), but the data collection/exfiltration phase is the last moment where stopping the attacker prevents meaningful harm beyond the initial access itself. After this, the remaining "impact" events  backup deletion and ransomware  are fast and hard to reverse. But the data exfiltration is a sustained activity that produces observable artifacts across multiple layers.

Also: if you catch the exfiltration in progress, you still have the data. If you only detect the ransomware, the data is already gone and you're negotiating.

# What a defender would need to detect it

**Log source**: Sysmon EID 1 (7zG.exe spawning with explorer.exe as parent, archiving network paths) + DNS/proxy logs showing connections to temp.sh + Windows Security EID 5145 (file share access at volume)
**Signal**: 7-Zip archiving large volumes of data from UNC paths to a local desktop path, followed by outbound HTTPS connections to temp.sh from the same host
**Network signal**: DNS resolution of temp.sh followed by substantial data transfer over HTTPS to that domain. temp.sh is not a normal business destination and should be blocked or alerted on at the proxy/firewall.
**DLP angle**: File staging behavior  large number of files being read from network shares, compressed, and placed in a user's desktop folder is detectable by endpoint DLP solutions even without knowing the destination
**Context needed**: temp.sh should be on a blocklist. It has no legitimate business use case in most corporate environments, and even if you didn't catch the archiving itself, blocking or alerting on the DNS/HTTP request to temp.sh would have stopped the exfiltration entirely.









