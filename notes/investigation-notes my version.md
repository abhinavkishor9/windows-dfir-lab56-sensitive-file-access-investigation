# Investigation Notes 

# Investigation Directory

The controlled workspace was:

`C:\SensitiveFileLab`

The primary file was:

`Confidential-Lab56.txt`

A separate staging directory was created:

`C:\SensitiveFileLab\Staging`

---

# Controlled Test Data

The test document contained:

    LAB 56 - CONTROLLED SENSITIVE DATA

    Employee: Test User
    Department: Security Operations
    Record ID: LAB56-001
    Classification: CONTROLLED TEST DATA

No real credentials, company information, or confidential data were used.

---

# Baseline Collection

The original file was examined before access.

Collected fields included:

- Filename
- Full path
- Length
- Creation time
- Last write time
- Last access time

The initial SHA-256 hash was also recorded.

This established the original state of the evidence file.

---

# Normal File Access

The file was first opened using Windows File Explorer.

The purpose was to represent normal user access to a sensitive document.

The investigation then examined process telemetry around the access time.

---

# Sysmon Event ID 1

Sysmon Event ID 1 was observed through Event Viewer.

The event was reviewed to determine which process was involved in the controlled activity.

Relevant fields included:

- Process Image
- Parent Image
- Command Line
- Process ID
- Parent Process ID
- User
- Timestamp

This provided process-level context for the investigation.

---

# PowerShell File Access

The sensitive test file was then read using PowerShell:

    Get-Content "C:\SensitiveFileLab\Confidential-Lab56.txt"

This created the controlled activity:

    Sensitive File
          |
          v
       PowerShell
          |
          v
      File Contents

The operation was benign because the file contained only laboratory test data.

---

# PowerShell Event ID 4104

PowerShell Event ID 4104 was observed in Event Viewer.

The event was reviewed for evidence associated with:

- `Get-Content`
- `SensitiveFileLab`
- `Confidential-Lab56.txt`

This provided script-level evidence of the file access activity.

---

# Windows Security Event ID 4688

Windows Security Event ID 4688 was observed through Event Viewer.

It was used as an additional process creation source.

The investigation considered:

- New Process Name
- Creator Process Name
- Process ID
- Command Line
- User
- Timestamp

The event was compared with Sysmon Event ID 1 and PowerShell Event ID 4104.

---

# Sysmon Event ID 3

Sysmon Event ID 3 was obtained through PowerShell.

The event was investigated for network communication around the file-access and staging timeframe.

Relevant information included:

- Process
- Process ID
- Source IP
- Destination IP
- Destination Port
- Protocol
- Timestamp

The presence of a network event was not treated as proof of exfiltration.

---

# Controlled Local Staging

A staging directory was created:

`C:\SensitiveFileLab\Staging`

The original file was copied to:

`C:\SensitiveFileLab\Staging\Confidential-Lab56-copy.txt`

This created the following controlled collection chain:

    Sensitive File
          |
          v
       PowerShell
          |
          v
    Staged Copy

The copy represented local collection only.

---

# Staged File Metadata

The staged copy was examined for:

- Filename
- Full path
- Length
- Creation time
- Last write time
- Last access time

These values were compared with the original file.

---

# SHA-256 Comparison

The original file was hashed:

    Get-FileHash "C:\SensitiveFileLab\Confidential-Lab56.txt" -Algorithm SHA256

The staged copy was hashed:

    Get-FileHash "C:\SensitiveFileLab\Staging\Confidential-Lab56-copy.txt" -Algorithm SHA256

Matching SHA-256 hashes provide evidence that the staged copy contains the same underlying contents as the original controlled file.

This helped distinguish file copying from content modification.

---

# Sysmon Event ID 11 Investigation

Sysmon Event ID 11 was investigated as a potential source of file-creation evidence.

The event was not available on the endpoint.

This created an evidence gap.

The investigation therefore did not depend on Event ID 11 and instead relied on:

- File metadata
- File existence
- SHA-256
- Sysmon Event ID 1
- PowerShell Event ID 4104
- Security Event ID 4688
- Sysmon Event ID 3

---

# Evidence Correlation

The investigation combined:

| Evidence | Purpose |
|---|---|
| File metadata | Establish file timeline |
| SHA-256 | Compare original and staged contents |
| Sysmon Event ID 1 | Process creation |
| PowerShell Event ID 4104 | Script-level activity |
| Security Event ID 4688 | Independent process creation |
| Sysmon Event ID 3 | Network activity |
| Filesystem | Confirm local staging |

The main sequence was:

    Sensitive File
          |
          v
      File Access
          |
          v
       Process
          |
          v
      Local Staging
          |
          v
    Network Review
          |
          v
    Final Assessment

---

