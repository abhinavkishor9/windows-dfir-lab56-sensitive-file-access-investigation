# Timeline — Lab 56 Sensitive File Access Investigation

## Timeline Purpose

This timeline records the sequence of controlled sensitive-file access, PowerShell activity, local staging, telemetry investigation, and evidence correlation.

Actual timestamps from Event Viewer and PowerShell should be inserted when finalizing the investigation.

## Investigation Timeline

| Order | Source | Activity | Significance |
|---:|---|---|---|
| 1 | File System | `C:\SensitiveFileLab` created | Establishes controlled investigation workspace |
| 2 | File System | `Confidential-Lab56.txt` created | Establishes controlled sensitive test artifact |
| 3 | File System | Baseline metadata collected | Establishes original file state |
| 4 | File System | Baseline SHA-256 collected | Provides artifact identifier |
| 5 | File Explorer | Controlled file opened | Simulates normal GUI access |
| 6 | Event Viewer | Sysmon Event ID 1 observed | Provides process creation evidence |
| 7 | PowerShell | `Get-Content` executed | Simulates programmatic file access |
| 8 | Event Viewer | PowerShell Event ID 4104 observed | Provides script-level evidence |
| 9 | Event Viewer | Security Event ID 4688 observed | Provides additional process evidence |
| 10 | PowerShell | Sysmon Event ID 3 reviewed | Provides network activity context |
| 11 | File System | Staging directory created | Establishes controlled collection location |
| 12 | PowerShell | Sensitive file copied | Demonstrates local staging |
| 13 | File System | Staged file metadata collected | Establishes staging timeline |
| 14 | File System | Staged file SHA-256 calculated | Enables content comparison |
| 15 | Sysmon | Event ID 11 investigated | Direct file-creation telemetry unavailable |
| 16 | DFIR Analysis | Original and staged files compared | Determines relationship between artifacts |
| 17 | DFIR Analysis | Evidence correlated | Builds complete activity chain |
| 18 | DFIR Analysis | Final assessment completed | Distinguishes access, collection, and exfiltration |

## Phase 1 — Preparation

### T+00 — Investigation Started

The Sensitive File Access Investigation was initiated using completely artificial test data.

### T+05 — Investigation Directory Created

The controlled workspace was created:

`C:\SensitiveFileLab`

### T+10 — Sensitive Test File Created

The controlled artifact was created:

`C:\SensitiveFileLab\Confidential-Lab56.txt`

The file contained only simulated sensitive-looking information.

### T+15 — Baseline Metadata Collected

The original file was examined for:

- Name
- Size
- Creation time
- Last write time
- Last access time

### T+20 — Baseline SHA-256 Collected

The original file was hashed and the result recorded.

---

# Phase 2 — File Access

### T+25 — File Opened Through File Explorer

The controlled document was opened through Windows File Explorer.

This represented normal user-driven file access.

### T+30 — Sysmon Event ID 1 Observed

Sysmon Event ID 1 was reviewed for process activity around the file-access timestamp.

### T+35 — PowerShell Access Performed

The file was read using:

    Get-Content "C:\SensitiveFileLab\Confidential-Lab56.txt"

This represented programmatic access to the controlled sensitive file.

### T+40 — PowerShell Event ID 4104 Observed

PowerShell Event ID 4104 was reviewed for script evidence related to the file access.

---

# Phase 3 — Process Correlation

### T+45 — Security Event ID 4688 Observed

Security Event ID 4688 was reviewed for process-creation evidence around the PowerShell activity.

### T+50 — Process Evidence Correlated

Sysmon Event ID 1, Security Event ID 4688, and PowerShell Event ID 4104 were compared using timestamps and process information.

The objective was to determine whether the three sources represented the same controlled activity.

---

# Phase 4 — Local Collection

### T+55 — Staging Directory Created

The controlled staging directory was created:

`C:\SensitiveFileLab\Staging`

### T+60 — Sensitive File Copied

The original file was copied to:

`C:\SensitiveFileLab\Staging\Confidential-Lab56-copy.txt`

This created a controlled local-collection scenario.

### T+65 — Staged File Metadata Collected

The staged copy was examined for:

- Name
- Size
- Creation time
- Last write time
- Last access time

### T+70 — Staged File SHA-256 Calculated

The staged copy was hashed.

The original and staged hashes were then compared.

---

# Phase 5 — File Creation Telemetry

### T+75 — Sysmon Event ID 11 Investigated

Sysmon Event ID 11 was investigated as a possible source of file-creation evidence.

The event was not available on the endpoint.

This was documented as a telemetry limitation.

### T+80 — Alternative Evidence Reviewed

Because Event ID 11 was unavailable, the investigation relied on:

- Filesystem evidence
- File metadata
- SHA-256
- Sysmon Event ID 1
- PowerShell Event ID 4104
- Security Event ID 4688
- Sysmon Event ID 3

---

# Phase 6 — Network Investigation

### T+85 — Sysmon Event ID 3 Reviewed

Sysmon Event ID 3 was obtained through PowerShell.

The event was investigated for network communication occurring around the sensitive-file access and local-staging timeframe.

### T+90 — Network Context Evaluated

Network activity was correlated with process and timestamp information.

No network event was automatically interpreted as proof of exfiltration.

---

# Phase 7 — Evidence Correlation

### T+95 — Original and Staged Files Compared

The original file and staged copy were compared using:

- Filename
- Path
- Size
- Timestamps
- SHA-256

### T+100 — Process Evidence Correlated

The following sources were correlated:

- Sysmon Event ID 1
- PowerShell Event ID 4104
- Security Event ID 4688

### T+105 — File and Network Evidence Correlated

The following were considered together:

- File access
- Staging copy
- Sysmon Event ID 3
- Timestamps

---

# Phase 8 — Final Assessment

### T+110 — File Access Determined

The controlled investigation established access to the sensitive-looking test file.

### T+115 — Local Collection Determined

A controlled copy of the file was created in the staging directory.

### T+120 — Exfiltration Assessment

Network telemetry was reviewed to determine whether the evidence supported external transmission.

The investigation did not equate network connectivity with exfiltration.

### T+125 — Telemetry Limitation Documented

The absence of Sysmon Event ID 11 was documented as an evidence gap.

### T+130 — Investigation Completed

The investigation concluded with a distinction between:

`File Access`

`Local Collection`

and:

`Potential Exfiltration`

---

# Final Timeline Summary

| Phase | Evidence | Assessment |
|---|---|---|
| Preparation | Controlled file created | Baseline established |
| File Access | Explorer / Process telemetry | Access investigated |
| PowerShell | Event ID 4104 | Script activity observed |
| Process | Event ID 4688 | Process creation corroborated |
| Process | Sysmon Event ID 1 | Process context observed |
| Collection | Staged copy created | Local collection demonstrated |
| Network | Sysmon Event ID 3 | Network activity reviewed |
| File Analysis | Metadata and SHA-256 | Original/staged files compared |
| File Telemetry | Event ID 11 | Not available |
| Final Assessment | Correlated evidence | Access and staging established; exfiltration not automatically established |

---

# Investigation Conclusion

The investigation demonstrated how a sensitive-file access event can develop into a local collection scenario and how the different stages can be investigated using Windows telemetry.

Sysmon Event ID 1, PowerShell Event ID 4104, Security Event ID 4688, and Sysmon Event ID 3 provided useful process, script, security, and network context. File metadata and SHA-256 hashes provided evidence for comparing the original and staged artifacts.

Sysmon Event ID 11 was not available, so the investigation relied on alternative evidence sources.

The final assessment must distinguish between:

`Sensitive File Access`

`Local Collection`

and:

`Confirmed Exfiltration`

These are separate forensic conclusions and require different levels of supporting evidence.
```
