# Part 3 Simulation Scenario: Lynx Ransomware Intrusion (Atomic Red Team)

## Overview

This scenario maps the Lynx ransomware intrusion phases to Atomic Red Team tests. Where ART has applicable tests, the test ID and name are listed. Where it doesn't, I've noted it explicitly with an alternative approach.

### Simulation Table ###

| Phase | ATT&CK Technique | Atomic Red Team Test ID | Test Name | What Control / Detection Is Being Validated |

| Discovery                 | T1046  Network Service Discovery             | T1046-1                                                 | Port Scan using Nmap                                                          | Detects outbound port scanning from an internal host; validates whether network IDS/IPS and Sysmon EID 3 (network connections) alert on broad port sweeps             |
| Discovery                 | T1018  Remote System Discovery               | T1018-1                                                 | Remote System Discovery with Net                                              | Tests whether AD-based host enumeration via `net view` is logged and alerted                                                                                          |
| Discovery                 | T1082  System Information Discovery          | T1082-1                                                 | System Information Discovery                                                  | Validates whether `systeminfo` execution is captured in process creation logs                                                                                         |
| Discovery                 | T1135  Network Share Discovery               | T1135-1                                                 | Network Share Discovery via Net                                               | Tests detection of `net share` and `net view` enumeration; validates EID 5145 share access logging                                                                    |
| Discovery                 | T1057  Process Discovery                     | T1057-1                                                 | Process Discovery via Tasklist                                                | Validates whether tasklist/taskmgr launches from interactive sessions are captured                                                                                    |
| Discovery                 | T1012  Query Registry                        | T1012-1                                                 | Query Registry                                                                | Tests detection of `reg query` commands used to enumerate Hyper-V hostnames and other registry values                                                                 |
| Discovery                 | T1087.002  Account Discovery: Domain Account | T1087-2                                                 | Enumerate Active Directory Accounts with Get-ADUser                           | Validates logging of AD account enumeration; tests whether dsa.msc / ADUC activity generates useful events                                                            |
| Persistence               | T1136.002  Create Account: Domain Account    | T1136-2                                                 | Create Domain Account                                                         | Validates that Security EID 4720 (account created) and EID 4728 (added to privileged group) fire and alert correctly; tests SIEM rule for new domain account creation |
| Persistence               | T1098.007  Additional Group Membership       | T1098-2                                                 | Add User to Local Admin Group via Net                                         | Tests detection of a user being added to Domain Admins or other privileged groups; validates EID 4728/4732 alerting                                                   |
| Persistence               | T1219  Remote Access Software                | T1219-1                                                 | AnyDesk Files Detected Test                                                   | Validates endpoint detection of AnyDesk installation as a service on a domain controller                                                                              |
| Lateral Movement          | T1021.001  RDP Lateral Movement              | T1021-1                                                 | RDP to DomainController                                                       | Tests whether RDP logons from non-standard source IPs to domain controllers generate alerts; validates EID 4624 logon type 10 detection                               |
| Lateral Movement          | T1021.001  RDP via mstsc.exe                 | No specific ART test for mstsc spawned from netscan.exe |                                                                              | See note below                                                                                                                                                        |
| Collection                | T1039  Data from Network Shared Drive        | T1039-1                                                 | Copy Files Using Robocopy from Network Share                                  | Validates detection of bulk file copy from UNC paths; tests DLP and Sysmon file access alerting                                                                       |
| Collection                | T1560.001 Archive via Utility (7-Zip)       | T1560-1 / T1560-2                                       | Data Compressed  nix / Compress Data and Lock with Password for Exfiltration | Tests detection of 7-Zip archiving of sensitive data; validates command-line logging capturing 7zG.exe/7z.exe with archive creation arguments                         |
| Exfiltration              | T1567 Exfiltration Over Web Service         | T1567-2                                                 | Exfiltrate data with curl to File Sharing Service                             | Tests whether outbound HTTP POST to a file-sharing service (temp.sh equivalent) is detected at proxy/firewall; validates DNS alerting on file-share service domains   |
| Impact (Inhibit Recovery) | T1490  Inhibit System Recovery               | T1490-1                                                 | Windows - Delete Volume Shadow Copies                                         | Validates detection of `vssadmin delete shadows`; tests whether backup deletion commands trigger SIEM rules and EDR alerts                                            |
| Impact (Inhibit Recovery) | T1490  Inhibit System Recovery               | T1490-3                                                 | Windows - Disable Windows Recovery Console                                    | Tests `bcdedit /set recoveryenabled no`; validates endpoint detection and process creation logging                                                                    |
| Impact                    | T1486  Data Encrypted for Impact             | T1486-1                                                 | Ransomware  Encrypt Files                                                    | Tests EDR and AV response to ransomware-like file encryption activity; validates whether endpoint protection blocks or detects mass file encryption                   |



## Gaps and Manual Simulation Notes

# Gap 1: mstsc.exe spawned from netscan.exe (Lateral Movement)
ART does not have a test for the specific behavior observed in this intrusion where `mstsc.exe` is launched by `netscan.exe` using the NetScan Remote Desktop hotkey (CTRL+R). This is a very specific process lineage that would stand out in Sysmon data but has no ART equivalent. Manual simulation: Install SoftPerfect NetScan, configure it with domain admin credentials, and use the built-in hotkey to launch RDP sessions. Alternatively, replicate the process creation event synthetically using a custom PowerShell script that spawns mstsc.exe under a non-standard parent process.

# Gap 2: NetScan delete.me write probe (Discovery)
ART has no test that replicates NetScan's share write-access check behavior (creating and deleting `delete.me` on remote shares). This artifact is what my Rule 1 detects. Manual simulation: Write a simple PowerShell or batch script that iterates over a list of UNC share paths, creates a file named `delete.me`, then deletes it. This replicates the network share write-probe pattern without needing the full NetScan binary.

# Gap 3: Security policy export via secedit.exe (Discovery)
No ART test covers `secedit /export /cfg`. Manual simulation: Run `secedit.exe /export /cfg C:\secpol.cfg` from an interactive session, then open the output file in Notepad. This is a single command and very easy to simulate manually  doesn't need a test framework.

### Gap 4: Backup job deletion  wbadmin (Impact)
ART T1490 covers vssadmin and bcdedit well, but the specific `wbadmin delete catalog` or `wbadmin delete backup` commands have limited coverage. Manual simulation: Run `wbadmin delete catalog -quiet` in a lab environment where Windows Server Backup has been configured. Ensure the SIEM is capturing the process creation event with the full command line.


# Expected Gaps Summary

The phases hardest to simulate with ART alone are Discovery and the Lateral Movement pattern specific to this intrusion. ART's discovery tests mostly cover individual commands (systeminfo, net view, tasklist), but the Lynx intrusion's discovery phase was dominated by SoftPerfect NetScan  a GUI-driven, pre-configured third-party tool that doesn't have an ART equivalent. The scan's effects (delete.me artifacts, high-volume Sysmon EID 3 connections, ss.xml export) are hard to reproduce without running the actual tool or writing custom simulation scripts.

The RDP-heavy lateral movement is also tricky for ART because most ART lateral movement tests simulate credential reuse or protocol exploitation  they don't model the specific pattern of an interactive human operator using mstsc.exe across multiple hosts in sequence. ART tests tend to be single-step whereas this intrusion's lateral movement was multi-session, multi-day, and driven by NetScan output. Simulating that level of fidelity probably requires a custom adversary simulation playbook or a purple team exercise using something like VECTR to sequence the ART tests with appropriate timing and intermediate discovery steps.

The Exfiltration phase (temp.sh) is also difficult to fully validate with ART because the built-in tests don't specifically target temp.sh and network controls (proxy/DNS filtering) are environment-dependent. You'd need to either actually attempt an upload to temp.sh (fine for an isolated lab) or set up a mock file-sharing server that replicates the same HTTP endpoint behavior to test the detection without touching a real external service.



