# Timeline 
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

