# Rule 1  Write-up: NetScan SMB Write Probe (delete.me)

## What behavior is this targeting and why

This rule targets a specific, lesser-known artifact of SoftPerfect Network Scanner: when the tool is configured to test write access on discovered SMB shares, it creates a file named `delete.me` on each writable share and then removes it. This behavior was explicitly documented in the Lynx intrusion  Sysmon Event ID 11 (FileCreate) events were observed on remote hosts showing creation of `delete.me` files across the environment, and Windows Security EID 5145 entries confirmed the file access from the scanner.

I chose this behavior because it's highly specific to NetScan's share-write-check feature and doesn't have a lot of legitimate overlap. It also hits *multiple* hosts simultaneously  so rather than detecting the scanner on the source host, this rule detects the *effect* of the scan across the estate, which is actually a better vantage point. A single netscan run can generate this artifact on tens or hundreds of hosts, making it easier to correlate.

The existing Sigma rules listed in the DFIR report's Detections section focus on netscan.exe process creation and network scanning behavior from the source host. This rule operates from the *target* host perspective, which is a different detection layer.

## Log source and fields

 **Log source**: Sysmon Event ID 11 (FileCreate), collected on Windows endpoints and forwarded to SIEM
 **Key fields**: `TargetFilename` (should end with `\delete.me` and contain a UNC path indicating a remote share), `Image` (the process writing the file), `User`, `ComputerName`
If Sysmon is not deployed, Windows Security EID 5145 (Detailed File Share  network share object access) can serve as an alternative signal, though it requires object access auditing to be enabled.

## False positive scope

**Legitimate NetScan use**: IT teams sometimes use SoftPerfect NetScan for authorized network auditing. In environments where this is expected, this rule will fire on legitimate scans. Recommended tuning: add an exclusion for known admin hostnames or service accounts that are authorized to run NetScan, or suppress alerts during defined maintenance windows. You could also alert only when the scanning source is outside a known set of authorized admin workstations.

**Custom scripts**: Some homegrown monitoring or backup scripts create test files on shares to verify write access. These would fire this rule. In practice, these scripts usually have predictable, known source processes (e.g., a specific PowerShell script or monitoring agent), which can be filtered via the `Image` field.

**Volume**: In large environments where a legitimate scan is authorized, this rule will generate one alert per writable share per scan run. It's noisy by design in that scenario. The signal is most valuable in environments where no scheduled network scans are expected, or when the source host isn't a known admin system.

In the context of this intrusion, the rule would have generated alerts across many hosts simultaneously, which itself is a useful correlation signal a burst of `delete.me` creations across the estate within a short time window is a strong indicator of automated share enumeration.
