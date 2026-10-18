# PowerShell repeated-failure detector
## Scope
A first-version local log analysis tool. Groups records by account and source IP and reports at least five failures within an inclusive five-minute rolling window. This is not a continuously running service or proof of malicious activity.

## Files and usage
From this folder in elevated Windows PowerShell:
```powershell
. .\Find-RepeatedFailures.ps1
$records = @(.\Read-LabFailedLogons.ps1 -Hours 24)
$alerts = @(Find-RepeatedFailures -Records $records)
$alerts | Format-Table -AutoSize
```
Reader defaults to the lab test account. Explicitly set -Account to investigate another authorised account. If Get-WinEvent reports no matching events, check time range and audit policy; access failures must not be treated as zero detections.

Optional export:
```powershell
$folder = Join-Path $env:USERPROFILE 'SOC-Lab-Reports'
New-Item -ItemType Directory -Path $folder -Force | Out-Null
$records | Export-Csv (Join-Path $folder 'lab-failed-logons.csv') -NoTypeInformation -Encoding UTF8
```

## User-observed validation, 18 October 2026
Results below were supplied as PowerShell console transcripts. They were not independently executed by the repository maintainer's automation. The detector function was exercised interactively; the packaged reader adds Hours and Account parameters around the demonstrated XML extraction logic and has not yet been rerun as a standalone file.

| Case | Observed alerts | Expected | Outcome |
|---|---:|---:|---|
| Five synthetic failures within two minutes | 1 | 1 | Pass |
| Four synthetic failures | 0 | 0 | Pass |
| Two actual Windows test events | 0 | 0 | Pass |
| Five synthetic failures spanning exactly 300 seconds | 1 | 1 | Pass |
| Fifth synthetic event at 301 seconds | 0 | 0 | Pass |
| Five synthetic events split 3/2 between source IPs | 0 | 0 | Pass |

CSV validation: Test-Path returned True; Import-Csv displayed both test records. This confirms local export/reimport based on the supplied transcript; the original CSV file was not uploaded.

Actual event fields reported:
| Time UTC | Record ID | Account | Source | Type | Status | Substatus |
|---|---|---|---|---|---|---|
| 2026-10-18T08:18:19.3299718Z | 1832673 | SOC_Lab_Test_User | 127.0.0.1 | 3 | 0xc000006d | 0xc0000064 |
| 2026-10-18T08:17:57.6746270Z | 1832671 | SOC_Lab_Test_User | 127.0.0.1 | 3 | 0xc000006d | 0xc0000064 |

Synthetic test IPs 192.0.2.10 and 192.0.2.20 are documentation addresses. Synthetic timestamps were generated test values, not observed attack times.

## Limitations
- One alert per account/source pair per invocation; no persistent suppression between runs.
- Assumes valid, unique input records and consistently UTC timestamps. Imported CSV timestamps must retain their UTC designation.
- Does not include account domain or destination host in its grouping key; restrict this version to one local host/domain.
- Missing source IPs, duplicate records, malformed inputs, cross-account isolation, and mixed timezones are not covered by the six checks.
- Scans each window repeatedly; intended for small lab datasets, not production-scale telemetry.
- The configured threshold is illustrative and needs environment-specific tuning.
- No production SIEM alert, live five-failure attack, containment, or automated blocking was demonstrated.

## Next steps
Rerun the packaged files on Windows, add automated assertions and input validation, then extend grouping to domain and destination host before multi-host use.
