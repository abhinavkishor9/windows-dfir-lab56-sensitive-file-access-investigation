# Windows DFIR Lab 56 — Sensitive File Access Investigation

## Overview

This lab investigates access to a sensitive-looking file from a Windows DFIR perspective. The objective is to determine which process accessed the file, when the access occurred, whether the file was modified or copied, and whether surrounding activity provides evidence of possible data collection.

A controlled test document containing completely artificial sensitive-looking information was created inside a dedicated investigation directory. The document was first accessed normally and was then read and copied using PowerShell into a controlled staging directory. The resulting activity was investigated using Sysmon, PowerShell logging, Windows Security auditing, file metadata, and SHA-256 hashing.

Sysmon Event ID 1, PowerShell Event ID 4104, and Windows Security Event ID 4688 were observed through Event Viewer. Sysmon Event ID 3 was obtained through PowerShell. Sysmon Event ID 11 was investigated but was not available on the endpoint.

---

# Executive Summary

The investigation examined a controlled sensitive-file access scenario in which a fake confidential document was opened and subsequently copied to a local staging directory. The purpose was to demonstrate the difference between simply accessing a sensitive file and performing additional collection activity.

Process and script telemetry provided evidence of the applications and PowerShell activity associated with the investigation. Windows Security Event ID 4688 provided an additional process-creation source, while Sysmon Event ID 3 was reviewed for related network activity. File metadata and SHA-256 hashes were used to determine whether the original file was modified and to identify the staged copy.

Sysmon Event ID 11 was not available, so direct Sysmon file-creation telemetry could not be used. The investigation therefore relied on process, PowerShell, Security, filesystem, and network evidence that was actually available on the endpoint.

---

# Lab Objectives

- Investigate access to a controlled sensitive-looking file.
- Identify the process responsible for accessing the file.
- Determine whether PowerShell accessed the file.
- Investigate process creation using Sysmon Event ID 1.
- Correlate process creation with Windows Security Event ID 4688.
- Investigate PowerShell activity using Event ID 4104.
- Review Sysmon Event ID 3 for related network communication.
- Determine whether the original file was modified.
- Identify whether a local copy of the sensitive file was created.
- Use SHA-256 hashing to compare the original and staged files.
- Document the absence of Sysmon Event ID 11.
- Distinguish file access from local collection and potential exfiltration.
- Produce an evidence-based assessment of the observed activity.

---

# Investigation Scenario

A Windows workstation contains a file that holds sensitive-looking information. A SOC analyst receives an alert after the file is accessed and later finds evidence that a copy may have been created elsewhere on the system.

The analyst needs to determine:

- Which user and process accessed the file.
- Whether PowerShell was involved.
- Whether the file was only read or was also copied.
- Whether the original file was modified.
- Whether network activity occurred around the same timeframe.
- Whether the activity is consistent with normal work or possible unauthorized data collection.

The investigation is performed entirely with controlled test data.

---

# Lab Environment

| Component | Details |
|---|---|
| Operating System | Windows |
| Investigation Type | Host-Based DFIR |
| Primary Directory | `C:\SensitiveFileLab` |
| Primary Artifact | `Confidential-Lab56.txt` |
| Staging Directory | `C:\SensitiveFileLab\Staging` |
| Sysmon Event ID 1 | Observed |
| Sysmon Event ID 3 | Observed through PowerShell |
| Sysmon Event ID 11 | Not available |
| PowerShell Event ID 4104 | Observed |
| Security Event ID 4688 | Observed |

---

# Controlled Test Data

The investigation used a fake sensitive-looking document.

Example contents:

    LAB 56 - CONTROLLED SENSITIVE DATA

    Employee: Test User
    Department: Security Operations
    Record ID: LAB56-001
    Classification: CONTROLLED TEST DATA

No real passwords, credentials, API keys, company information, or personal information were used.

---

# Investigation Workflow

1. Create the investigation directory.
2. Create the controlled sensitive test file.
3. Collect baseline metadata.
4. Calculate the baseline SHA-256 hash.
5. Record the initial activity timestamp.
6. Open the file through File Explorer.
7. Investigate Sysmon Event ID 1.
8. Read the file using PowerShell.
9. Investigate PowerShell Event ID 4104.
10. Investigate Windows Security Event ID 4688.
11. Check Sysmon Event ID 3.
12. Copy the test file to a controlled staging directory.
13. Examine the staged copy.
14. Calculate the staged copy's SHA-256 hash.
15. Compare original and staged file state.
16. Investigate Sysmon Event ID 11.
17. Document the Event ID 11 telemetry gap.
18. Correlate the evidence.
19. Determine whether the activity supports access, staging, or possible exfiltration.
20. Clean up the controlled laboratory artifacts.

---

# File Access Investigation

The controlled file was:

`C:\SensitiveFileLab\Confidential-Lab56.txt`

The document was initially opened through File Explorer.

This represented normal GUI-based access.

The investigation then considered which process was responsible for opening the file and what process telemetry was generated around that time.

---

# Sysmon Event ID 1

Sysmon Event ID 1 was observed through Event Viewer.

The event was used to investigate process creation around the sensitive-file access.

Relevant fields included:

- Process Image
- Parent Image
- Command Line
- Process ID
- Parent Process ID
- User
- Timestamp

This allowed the analyst to establish process context around the file access.

---

# PowerShell Event ID 4104

PowerShell was then used to read the controlled file:

    Get-Content "C:\SensitiveFileLab\Confidential-Lab56.txt"

PowerShell Event ID 4104 was observed through Event Viewer.

The event was reviewed for evidence associated with:

- `Get-Content`
- `SensitiveFileLab`
- `Confidential-Lab56.txt`

This provided script-level evidence that complemented process-creation telemetry.

---

# Windows Security Event ID 4688

Security Event ID 4688 was observed through Event Viewer.

The event was used to provide an additional source of process-creation evidence.

Relevant information included:

- New Process Name
- Creator Process Name
- Process ID
- Command Line
- Account
- Timestamp

The event was correlated with Sysmon Event ID 1 and PowerShell Event ID 4104.

---

# Sysmon Event ID 3

Sysmon Event ID 3 was obtained through PowerShell.

The investigation reviewed network connections occurring around the file-access and staging timeframe.

A query was performed against:

    Microsoft-Windows-Sysmon/Operational

with:

    Event ID 3

The investigation considered:

- Process
- Process ID
- Source IP
- Destination IP
- Destination Port
- Protocol
- Timestamp

A network connection was treated as supporting evidence only.

---

# Controlled Local Staging

To demonstrate collection behavior safely, the investigation created:

`C:\SensitiveFileLab\Staging`

The controlled file was copied to:

`C:\SensitiveFileLab\Staging\Confidential-Lab56-copy.txt`

The activity represented:

    Sensitive File
          |
          v
       PowerShell
          |
          v
    Local Staging Copy

This was performed using harmless test data.

---

# File Metadata Analysis

The original file was examined for:

- Name
- Full path
- File size
- Creation time
- Last write time
- Last access time

The staged copy was examined using the same fields.

This allowed the analyst to establish the relationship between the original file and the copied artifact.

---

# SHA-256 Analysis

The original file was hashed using:

    Get-FileHash "C:\SensitiveFileLab\Confidential-Lab56.txt" -Algorithm SHA256

The staged copy was also hashed:

    Get-FileHash "C:\SensitiveFileLab\Staging\Confidential-Lab56-copy.txt" -Algorithm SHA256

If both hashes match, the evidence supports that the staged file contains the same underlying contents as the original controlled file.

This is useful for distinguishing:

- File access
- File copying
- File modification

---

# Sysmon Event ID 11

Sysmon Event ID 11 was investigated as a potential source of file-creation telemetry.

However, Event ID 11 was not available on the endpoint.

This was documented as an evidence limitation.

The investigation therefore relied on:

- Sysmon Event ID 1
- PowerShell Event ID 4104
- Security Event ID 4688
- Sysmon Event ID 3
- Filesystem metadata
- SHA-256 hashing

The absence of Event ID 11 was not interpreted as proof that no file copy occurred.

---

# Evidence Correlation

The investigation followed this model:

    Sensitive File
          |
          v
      File Access
          |
          v
      Process Activity
          |
          +---- Sysmon Event ID 1
          +---- Security Event ID 4688
          +---- PowerShell Event ID 4104
          |
          v
      Local Staging
          |
          +---- File Metadata
          +---- SHA-256
          |
          v
      Network Activity
          |
          +---- Sysmon Event ID 3
          |
          v
      Final Assessment

This allowed the analyst to separate file access from file collection and potential exfiltration.

---

# Investigation Findings

- The controlled sensitive-looking file was successfully accessed.
- Process creation telemetry was available through Sysmon Event ID 1.
- PowerShell Event ID 4104 was available for script-level investigation.
- Windows Security Event ID 4688 was available for process creation correlation.
- Sysmon Event ID 3 was available for network investigation.
- The original file was copied to a controlled staging directory.
- File metadata and SHA-256 could be compared between the original and staged files.
- Sysmon Event ID 11 was not available.
- The absence of Event ID 11 did not prevent the investigation because other evidence sources were available.
- The controlled scenario demonstrated local collection without establishing real-world data theft.

---

# File Access vs Data Collection

The investigation demonstrated three different forensic claims:

### File Access

A process opened or read the sensitive file.

### Local Collection

A copy of the sensitive file was created elsewhere on the system.

### Exfiltration

The sensitive data was transmitted outside the system.

These are not equivalent.

The progression can be represented as:

    File Access
        |
        v
    Local Collection
        |
        v
    Network Transmission
        |
        v
    Possible Exfiltration

The final claim requires stronger evidence than the previous one.

---

# Suspicious Activity Indicators

In a real investigation, concern would increase if the following pattern were observed:

    Sensitive File
         |
         v
    Unexpected Process
         |
         v
    PowerShell
         |
         v
    Local Staging
         |
         v
    Archive Creation
         |
         v
    Suspicious Network Connection

Other indicators could include:

- Unsigned process
- Execution from a user-writable location
- Unusual account
- Unusual working hours
- Large-scale file access
- Multiple sensitive files accessed
- Unexpected archive creation
- External network destination

These indicators require contextual investigation.

---

# Evidence Limitations

Sysmon Event ID 11 was not available on this endpoint.

Therefore, direct Sysmon file-creation telemetry could not be used to prove creation of the staged copy.

The investigation instead relied on:

- Filesystem evidence
- File metadata
- SHA-256 comparison
- Process telemetry
- PowerShell logging
- Security Event ID 4688
- Sysmon Event ID 3

Event availability depends on system configuration, logging policy, and telemetry retention.

---

# MITRE ATT&CK Relevance

Potentially relevant techniques include:

**T1005 — Data from Local System**

This may be relevant when sensitive local files are accessed for collection.

**T1059.001 — PowerShell**

Relevant when PowerShell is used to access or copy sensitive files.

**T1074 — Data Staged**

Relevant when sensitive information is copied into a staging location before potential transmission.

**T1041 — Exfiltration Over C2 Channel**

Relevant only if evidence demonstrates that collected information was transmitted over a command-and-control channel.

ATT&CK mapping should be based on observed evidence.

---

# Conclusion

This investigation demonstrated how sensitive-file access can progress from simple file reading to local staging and potentially to data exfiltration.

Sysmon Event ID 1, PowerShell Event ID 4104, Windows Security Event ID 4688, and Sysmon Event ID 3 provided useful telemetry around the controlled activity. File metadata and SHA-256 hashing provided additional evidence for comparing the original file with the staged copy.

Sysmon Event ID 11 was unavailable, demonstrating an important DFIR limitation: investigators should not rely on a single event source when investigating file access.

The key lesson is:

> Access to a sensitive file is not the same as stealing it.

A defensible conclusion requires correlation of the user, process, file, staging activity, network behavior, and timeline.
