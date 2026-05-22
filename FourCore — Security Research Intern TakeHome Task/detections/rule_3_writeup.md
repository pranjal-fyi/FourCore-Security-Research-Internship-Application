# Rule 3  Write-up: Backup Job Deletion Before Ransomware

## What behavior is this targeting and why

This rule covers the inhibit system recovery technique that the Lynx threat actor used on day nine: connecting to backup servers via RDP and deleting existing backup jobs before deploying the ransomware payload. The logic is straightforward  removing backups ensures the victim can't just restore without paying. This is a near-universal step in modern ransomware operations.

I expanded the rule beyond just `wbadmin` to also cover `vssadmin delete shadows` and `bcdedit /set recoveryenabled no`, because these three together form the standard "destroy recovery" playbook. In this specific case the report only mentions backup job deletion (wbadmin-style), but any production environment deploying this rule would want the full pattern covered. The DFIR report's existing detections (as far as I can tell from what's publicly visible) focus on the ransomware binary itself and the RDP lateral movement to backup servers  not on the backup deletion commands that come just before.

Backup deletion is also one of those behaviors where the false positive rate is actually low enough to justify a high severity rating. Outside of authorized backup management tooling, there aren't many legitimate reasons to delete backup catalogs or shadow copies. And when it does happen legitimately, it's predictable it comes from known service accounts, known parent processes, and scheduled times.

## Log source and fields

**Log source**: Windows Security Event ID 4688 (process creation, command line auditing enabled) or Sysmon Event ID 1
**Key fields**: `Image` (wbadmin.exe / vssadmin.exe / bcdedit.exe), `CommandLine` (delete subcommands), `User`, `ParentImage`, `ComputerName`
Ideally deployed on server-class systems (backup servers, domain controllers, file servers) where these commands have the highest impact if run by an attacker

## False positive scope

**Backup rotation scripts**: The most likely false positive is a legitimate scheduled task that rotates old backup sets by deleting them. These typically run as SYSTEM or under a dedicated backup service account, at predictable times (e.g., 2 AM), with cmd.exe or schtasks.exe as the parent. Adding `User` exclusions for known backup service accounts and filtering on `ParentImage` containing task scheduler components would significantly reduce noise.

**Backup software agents**: Products like Veeam, Commvault, and Acronis sometimes invoke wbadmin or vssadmin internally as part of their own backup lifecycle management. Filtering by `ParentImage`  excluding known paths like `C:\Program Files\Veeam\...`  handles most of these.

**The timing and source context matters a lot**: In the Lynx intrusion, the backup deletion happened on day nine of the intrusion, from an RDP session on a backup server, using domain admin credentials. If you correlate this rule's output with: (a) RDP logon from an unusual source on the same host within the past hour, and (b) the same user account having recently performed lateral movement, the confidence jumps dramatically. As a standalone rule it's useful. In a correlation context it's a near-definitive indicator.

I'd deploy this at high severity with a suppression for known backup automation, rather than downgrading the severity to reduce noise.
