# Troubleshooting Notes 

## 1. Sysmon Event ID 11 Was Not Available

### Problem

The investigation attempted to use Sysmon Event ID 11 as direct file-creation telemetry, but the event was not available on the endpoint.

### Impact

The investigation could not rely on Sysmon to directly confirm creation of the staged copy.

### Resolution

Alternative evidence sources were used:

- Filesystem metadata
- File existence
- SHA-256 hashes
- Sysmon Event ID 1
- PowerShell Event ID 4104
- Windows Security Event ID 4688
- Sysmon Event ID 3

### DFIR Lesson

A missing file-creation event does not prove that a file was not created.

---

## 2. File Access Was Not Automatically Treated as Data Theft

### Observation

The controlled sensitive-looking document was opened and read.

### Incorrect Interpretation

`Sensitive file opened = data stolen`

### Correct Interpretation

The analyst must determine what happened after access.

For example:

    File Access
        ↓
    Local Copy
        ↓
    Archive
        ↓
    Network Transfer

The later stages provide stronger evidence of collection and possible exfiltration.

---

## 3. PowerShell Was Used for Controlled Access

### Observation

PowerShell performed:

    Get-Content "C:\SensitiveFileLab\Confidential-Lab56.txt"

### Potential Misinterpretation

PowerShell itself should not be classified as malicious.

### Resolution

The investigation focused on:

- User
- Parent process
- Command line
- Target file
- Timestamp
- Follow-on activity

### DFIR Lesson

Living-off-the-land tools require behavioral analysis rather than automatic classification.

---

## 4. Sysmon Event ID 1 Was Available

### Observation

Sysmon Event ID 1 was observed through Event Viewer.

### Use

The event was used to identify process execution around the sensitive-file access.

Relevant information included:

- Image
- ParentImage
- CommandLine
- Process ID
- User
- Timestamp

### DFIR Lesson

Process telemetry can establish execution context even when file-specific telemetry is unavailable.

---

## 5. PowerShell Event ID 4104 Was Available

### Observation

PowerShell Event ID 4104 was observed.

### Use

It was used to investigate commands associated with:

- Reading the sensitive file
- Copying the sensitive file
- Creating the staging directory

### DFIR Lesson

Script Block Logging can provide valuable detail about PowerShell behavior.

---

## 6. Security Event ID 4688 Was Available

### Observation

Windows Security Event ID 4688 was observed through Event Viewer.

### Use

It provided an additional process-creation evidence source.

The event was correlated with:

- Sysmon Event ID 1
- PowerShell Event ID 4104

### DFIR Lesson

Independent telemetry sources can improve confidence in process attribution.

---

## 7. Sysmon Event ID 3 Was Obtained Through PowerShell

### Observation

Sysmon Event ID 3 was available through PowerShell.

### Use

It was reviewed for network activity around the sensitive-file access and staging period.

### Important Limitation

A network connection does not establish that the sensitive document was transmitted.

Additional evidence would be required.

---

## 8. Original and Staged Files Had to Be Compared

### Problem

The investigation needed to determine whether the staging copy contained the same content as the original.

### Resolution

SHA-256 hashes were calculated for both files.

Original:

    C:\SensitiveFileLab\Confidential-Lab56.txt

Staged:

    C:\SensitiveFileLab\Staging\Confidential-Lab56-copy.txt

### DFIR Lesson

Hash comparison can help establish whether two artifacts contain identical data.

---

## 9. File Timestamps Need Context

### Problem

Creation and modification times alone do not prove that a user intentionally copied a file.

### Resolution

Timestamps were correlated with:

- Process creation
- PowerShell activity
- Security Event 4688
- Network activity

### DFIR Lesson

Filesystem timestamps become more useful when correlated with process and user activity.

---

## 10. Network Activity Could Be Unrelated

### Problem

Sysmon Event ID 3 may show network connections around the same timeframe.

### Risk

It is easy to assume that the connection represents exfiltration.

### Resolution

The following should be investigated:

- Process responsible
- Destination
- Port
- Protocol
- Timestamp
- Expected application behavior

### DFIR Lesson

Temporal proximity alone does not prove causation.

---

## 11. Staging Copy Was Controlled

### Observation

The copy was created inside:

`C:\SensitiveFileLab\Staging`

### Purpose

This represented controlled local collection.

### DFIR Lesson

A staged copy demonstrates collection behavior in the lab, but does not establish malicious collection in a real environment without additional context.

---

## 12. Event Viewer and PowerShell Provided Different Views

Event Viewer was useful for visually examining:

- Event ID 1
- Event ID 4104
- Event ID 4688

PowerShell was useful for:

- Event ID 3 querying
- Filtering by timestamps
- Searching event messages
- Correlating activity programmatically

Using both methods made the investigation more flexible.

---

# Troubleshooting Summary

| Observation | Resolution |
|---|---|
| Sysmon Event ID 11 unavailable | Used filesystem, hashes, and other telemetry |
| Sensitive file access observed | Investigated process and follow-on behavior |
| PowerShell used | Correlated user, process, command, and timestamp |
| Sysmon Event ID 1 available | Used for process investigation |
| PowerShell Event ID 4104 available | Used for script investigation |
| Security Event ID 4688 available | Used for process correlation |
| Sysmon Event ID 3 available | Used for network investigation |
| Staged file created | Compared metadata and SHA-256 |
| Network activity could be unrelated | Correlated process and destination |
| File access alone insufficient | Distinguished access, staging, and exfiltration |

---

