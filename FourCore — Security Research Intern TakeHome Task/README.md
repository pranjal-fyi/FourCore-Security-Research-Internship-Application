# FourCore Security Research Intern Take-Home Task

### Overview

This repo is my submission for the FourCore Security Research Internship task. The task was based on the DFIR Report case: *Cat's Got Your Files: Lynx Ransomware* (December 2025).

I went through the full report before starting anything, and tried to structure my analysis around what I thought were the most interesting and defensible decision points rather than just listing everything I could find.


## Structure

├── README.md
├── analysis/
│   ├── narrative.md          # Attack chain in my own words
│   ├── attack_mapping.md     # MITRE ATT&CK table with justifications
│   └── chokepoints.md        # Three high-value detection moments
├── detections/
│   ├── rule_1.yml            # Sigma: NetScan drop + execution
│   ├── rule_1_writeup.md
│   ├── rule_1_evidence.png
│   ├── rule_2.yml            # Sigma: temp.sh exfiltration via curl/browser
│   ├── rule_2_writeup.md
│   ├── rule_2_evidence.png
│   ├── rule_3.yml            # Sigma: Backup job deletion before ransomware
│   ├── rule_3_writeup.md
│   └── rule_3_evidence.png
└── simulation/
    └── scenario.md           # ART scenario table + gaps analysis


## My Approach

**Part 1 (Analysis):** I focused on the attacker's decision-making rather than just summarising what happened. The narrative is written to be readable by someone who hasnt seen the report, while the ATT&CK mapping tries to go beyond the obvious techniques.

**Part 2 (Detection):** I checked the report's existing Sigma rules before choosing targets. My three rules cover: the SoftPerfect NetScan staging behavior, exfiltration to temp.sh, and backup deletion activity pre-ransomware. Each has a full false-positive analysis.

**Part 3 (Simulation):** I tried to be honest about where Atomic Red Team falls short for this specific intrusion  particularly around the use of legitimate tools (NetScan, AnyDesk, 7-Zip) and the RDP-centric lateral movement pattern.

## Notes

- Validation for the Sigma rules was done against simulated Windows Event Log data using a local Elastic stack.
- The intrusion had a TTR of ~178 hours over 9 days, which gave a lot of time where detection could have intervened.
- I found the credential pre-acquisition angle (likely IAB) the most interesting part of the case from a threat intel perspective.

