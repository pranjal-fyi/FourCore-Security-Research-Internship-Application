# Rule 2  Write-up: Security Policy Export via secedit.exe

## What behavior is this targeting and why

This rule detects the use of `secedit.exe` with the `/export /cfg` flags to dump local security policy to a file. In the Lynx intrusion, the threat actor ran this on day eight as part of a broader infrastructure reconnaissance sweep. The exported file (`secpol.cfg`) was then opened in Notepad for manual review  a clear indicator of a human operator trying to understand the security posture of the system they were on.

I picked this because secedit-based policy export is a LOLBin behavior that doesn't get a lot of attention. Most detection coverage around secedit focuses on using it to weaken security policies (`/configure`), not to read them. But from an attacker perspective, exporting and reading the policy tells you things like password complexity requirements, account lockout thresholds, audit policy settings, and privilege assignments  all useful for planning the final stages of an attack. The fact that the attacker did this on day eight, right before the ransomware deployment on day nine, suggests they were doing a final check on defensive controls.

The rule is not in the DFIR report's existing Sigma detections which (based on what's publicly listed) cover things like NetExec, AnyDesk install, RDP lateral movement, and account creation. secedit export isn't covered.

## Log source and fields

**Log source**: Windows Security Event ID 4688 (process creation with command line logging enabled) or Sysmon Event ID 1 (process creation)
**Key fields**: `Image` (secedit.exe), `CommandLine` (must contain `/export` and `/cfg`), `ParentImage`, `User`, `ComputerName`
 Command line auditing must be enabled via Group Policy or Sysmon for this rule to fire. Without command line logging, you can detect secedit.exe execution but can't distinguish export from configure actions.

## False positive scope

**Security auditing and compliance tooling**: The most common legitimate use of `secedit /export /cfg` is in security baseline comparison scripts  tools like Microsoft Security Compliance Toolkit or custom PowerShell scripts that compare the current policy against a known-good baseline. These would fire this rule. You'd want to filter by the parent process (typically powershell.exe or cmd.exe running from a known admin path) or by user account (a dedicated service account vs. an interactive user session).

**SCCM/Ansible/config management**: Some automated tools export security policy as part of configuration drift detection. These will have consistent, predictable parent processes and run under service accounts, making them distinguishable from interactive sessions.

**The interactive session context matters**: In this intrusion, the secedit export happened inside an interactive RDP session (parent process is cmd.exe or explorer.exe, running under an interactive user account). If your environment only runs secedit from automated tools, any interactive invocation is worth reviewing regardless. Combining this with a check for `notepad.exe` opening a `.cfg` file in the same session window would increase confidence significantly.

Overall I'd rate this medium severity on its own, but high severity if correlated with other indicators in the same session (prior RDP from unusual source IP, account enumeration via lusrmgr.msc, etc.).
