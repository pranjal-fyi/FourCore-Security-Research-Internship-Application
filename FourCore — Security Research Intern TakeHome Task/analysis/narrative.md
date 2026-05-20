# Part 1.1 Attack Chain Narrative

 Lynx Ransomware Intrusion Full Attack Chain

The intrusion started sometime in early March 2025, with what looks like a pretty quiet, unremarkable RDP login. No brute force, no spray attempts, no failed logins before it just a clean, successful authentication to an internet-facing server. That single detail is actually one of the most important things about this case, because it means the attacker already had the credentials before they showed up. Whether those came from an infostealer, a breach database, or an initial access broker (IAB) we can't say for certain, but all signs point toward IAB given that they also had domain admin credentials ready from the start.

Within minutes of logging in, the attacker opened a command prompt and started doing basic local and network recon  ipconfig, route print, systeminfo, a couple of pings. Nothing fancy, but it tells you they're getting oriented. They then dropped SoftPerfect Network Scanner (netscan) into a folder they created on the desktop called "000", which is a small but telling detail it suggests a level of operational routine, like this is a workflow they've done before.

The netscan config they brought with them was pre-configured: domain admin creds baked in, custom port ranges, full IP sweep, share enumeration with write-access checks, workstation info collection. This wasn't a tool someone just downloaded and ran with defaults. The scan produced an XML export of results (ss.xml), which was dropped on the desktop.

Ten minutes after first logging in- ten minutes  the attacker pivoted via RDP to a domain controller using a different account, a domain admin one. This is the second pre-compromised credential in play. On the DC, they opened Active Directory Users and Computers (dsa.msc) and created three new accounts. The naming is worth noting: "administratr" (one letter off from administrator), and two others designed to closely resemble accounts already in the environment. All three were set with passwords that never expire. Two of them "administratr" and Lookalike 1 were added to the Domain Admins group, and "administratr" was also given Group Policy Creator Owners rights. They also installed AnyDesk on the DC as a persistence mechanism, though interestingly it was never actually used again.

After the first day, there's a six-day gap before the attacker returns. When they come back on day six, they're using the same source IP and same hostname as before. They re-run netscan, then pull down NetExec from the internet via Edge and run it to enumerate SMB hosts across the same IP range. After that, they start accessing network file shares  browsing them manually, then using 7-Zip to compress the folders they want. The archives land on the desktop of the compromised user.

The exfiltration itself uses temp.sh, which is a temporary public file-sharing service. Files get uploaded and presumably downloaded from a threat-actor controlled system. This is a clean, low-friction exfiltration method that avoids setting up any dedicated infrastructure.

About nine hours after the data collection wraps up, the attacker returns again  this time from a new IP address, though still tied to the same provider (Railnet LLC / Virtualine, infrastructure associated with criminal networks). They spend day eight doing deeper infrastructure mapping: browsing hypervisors via RDP, running virtmgmt.msc, exporting local security policies with secedit.exe, reviewing them in Notepad, and poking at firewalls and VPN appliances through NetScan's browser integration.

On day nine  the final day  they come back one last time, run netscan again almost like a habit, then RDP into backup servers. On each backup server, they delete the existing backup jobs, then execute Lynx ransomware. The deployment gets repeated across multiple backup and file servers.

The total time-to-ransomware was roughly 178 hours across nine days. The attacker wasn't rushing. They were methodical, they had the credentials they needed from the beginning, and they used almost entirely legitimate tools throughout. No custom malware, no exploits, no fancy lateral movement techniques just RDP, Windows built-ins, and off-the-shelf admin tools. That's actually what makes this intrusion hard to catch.


