# Part 1.2  MITRE ATT&CK Mapping

**Note:** I went through the report's own ATT&CK list and tried to either expand on under-specified entries or add techniques I thought were missing/implied. Some of these are judgment calls.

| Technique ID | Technique Name | Justification |


| T1078.002    | Valid Accounts: Domain Accounts                                   | Initial RDP access used pre-obtained valid credentials with no failed attempts; domain admin credentials used for lateral movement also appeared pre-compromised                                                     |
| T1133        | External Remote Services                                          | Attacker gained initial access and maintained presence via internet-exposed RDP throughout the intrusion across all nine days                                                                                        |
| T1021.001    | Remote Services: Remote Desktop Protocol                          | RDP was the primary mechanism for lateral movement between beachhead, domain controllers, hypervisors, and backup servers; mstsc.exe observed spawning from explorer.exe and netscan.exe                             |
| T1059.003    | Command and Scripting Interpreter: Windows Command Shell          | cmd.exe spawned immediately after initial access to run ipconfig, route print, systeminfo, net user, and other discovery commands                                                                                    |
| T1059.001    | Command and Scripting Interpreter: PowerShell                     | PowerShell observed during post-compromise hands-on activity per the report's execution section                                                                                                                      |
| T1046        | Network Service Discovery                                         | SoftPerfect Network Scanner deployed with pre-configured custom port ranges and full IP sweep of victim environment; run multiple times across the intrusion                                                         |
| T1018        | Remote System Discovery                                           | netscan.exe performed host discovery across the full internal IP range; NetExec also used to enumerate live SMB hosts                                                                                                |
| T1087.002    | Account Discovery: Domain Account                                 | dsa.msc (ADUC) launched on domain controller to browse AD objects; lusrmgr.msc used on day eight to review local users and groups                                                                                    |
| T1135        | Network Share Discovery                                           | netscan config explicitly enabled share scanning with security info, write access checks, and disk space; threat actor also manually browsed file shares                                                             |
| T1082        | System Information Discovery                                      | systeminfo run repeatedly across multiple hosts throughout the intrusion; secedit.exe used to export local security policy for review                                                                                |
| T1016        | System Network Configuration Discovery                            | ipconfig and route print run immediately after initial access and again on subsequent days                                                                                                                           |
| T1057        | Process Discovery                                                 | Task Manager (taskmgr.exe /4) launched on day six to view running processes                                                                                                                                          |
| T1012        | Query Registry                                                    | reg query against HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters used to identify Hyper-V hostnames on day one and day eight                                                                               |
| T1136.002    | Create Account: Domain Account                                    | Three accounts created via ADUC on the domain controller  "administratr", Lookalike 1, and Lookalike 2  all with passwords set to never expire                                                                     |
| T1098.007    | Account Manipulation: Additional Local or Domain Group Membership | "administratr" and Lookalike 1 added to Domain Admins; "administratr" also added to Group Policy Creator Owners; Lookalike 2 added to a high-privilege domain-specific group                                         |
| T1036.005    | Masquerading: Match Legitimate Name or Location                   | New accounts created with names closely resembling existing legitimate accounts (one character difference) to blend into the environment                                                                             |
| T1078        | Valid Accounts                                                    | Newly created accounts were tested by authenticating to hypervisors on day two; all three accounts used during subsequent operations                                                                                 |
| T1547        | Boot or Logon Autostart Execution                                 | Implied/possible AnyDesk was installed as a service on the domain controller, which would persist across reboots; although never ultimately used, the installation was intended as a persistent access mechanism |
| T1219        | Remote Access Software                                            | AnyDesk installed on the domain controller as a backup persistence mechanism; though it was never observed being used after installation                                                                             |
| T1560.001    | Archive Collected Data: Archive via Utility                       | 7-Zip (7zG.exe) used via right-click context menu to archive contents of targeted file server shares prior to exfiltration                                                                                           |
| T1039        | Data from Network Shared Drive                                    | Threat actor accessed and collected files from multiple network file shares on day six                                                                                                                               |
| T1567        | Exfiltration Over Web Service                                     | Archives exfiltrated to temp.sh, a public temporary file-sharing service  no dedicated infrastructure required                                                                                                      |
| T1567.002    | Exfiltration to Cloud Storage                                     | Under-specified in report but applicable  temp.sh functions as a cloud-hosted exfiltration endpoint; technique maps better here than generic T1048                                                                |
| T1490        | Inhibit System Recovery                                           | Backup jobs deleted from backup servers before ransomware was deployed, ensuring no recovery path was available                                                                                                      |
| T1486        | Data Encrypted for Impact                                         | Lynx ransomware deployed and executed across multiple backup and file servers on day nine                                                                                                                            |
| T1562.001    | Impair Defenses: Disable or Modify Tools                          | Implied deletion of backup jobs constitutes active impairment of defensive/recovery capabilities                                                                                                                 |
| T1071.001    | Application Layer Protocol: Web Protocols                         | exfiltration to temp.sh occurred over HTTP/HTTPS; browser sessions launched from within netscan GUI to access network appliance web portals                                                                          |
| T1083        | File and Directory Discovery                                      | Threat actor manually browsed multiple file shares via Explorer/RDP across multiple days                                                                                                                             |
| T1613        | Container and Resource Discovery                                  | virtmgmt.msc (Hyper-V manager) launched on hypervisors on day eight, indicating enumeration of virtualised infrastructure                                                                                            |
| T1590.005    | Gather Victim Network Information: IP Addresses                   | nslookup, nbtstat, and ping used to resolve and enumerate IP addresses of target systems in additional domain                                                                                                        |


### Techniques I think were under specified in the original report

**T1547 / AnyDesk as service**: The report notes AnyDesk was installed but never used. Its installation as a service is clearly a persistence play and deserves the technique mapping, even if the persistence was never leveraged.

**T1567.002 vs T1048**: Using temp.sh is more precisely cloud storage exfiltration than generic exfiltration over alternative protocol. Worth being specific.

**T1613 (Hyper-V discovery)**: The report focuses on lateral movement to hypervisors but the explicit use of virtmgmt.msc on all three hypervisors looks more like infrastructure enumeration / discovery to me than pure lateral movement.





