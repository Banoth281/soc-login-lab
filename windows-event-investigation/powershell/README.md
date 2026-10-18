# Windows failed-logon detection - schema v2

Group repeated failures by **destination computer, account domain, account name, and source IP**. Validate and deduplicate records before detection or reporting. This is an offline lab tool, not continuous monitoring or a confirmed-attack classifier.

[![Windows tests](https://github.com/Banoth281/soc-login-lab/actions/workflows/powershell-tests.yml/badge.svg)](https://github.com/Banoth281/soc-login-lab/actions/workflows/powershell-tests.yml)

## What changed
| Area | v1 | v2 |
|---|---|---|
| Grouping | Account and source IP | Computer, domain, account and canonical source IP |
| Duplicate handling | Assumed unique records | Identity-based deduplication; conflicting copies rejected |
| Validation | Minimal | Required fields, timezone, IP, record ID, channel/event type |
| Window scan | Repeated full scans | Sorted groups with two moving window indices |
| Alert evidence | Counts and times | Context, counts, times, and contributing record IDs |
| Report | Imported count | Imported/unique counts, removed duplicates, context and alerts |
| Tests | 8 original synthetic cases | 30 regression cases including report integration |

## Collection and detection
Download all four .ps1 files together. In elevated Windows PowerShell:
```powershell
. ./Find-RepeatedFailures.ps1
$records = @(./Read-LabFailedLogons.ps1 -Hours 24)
$alerts = @(Find-RepeatedFailures -Records $records)
$alerts | Format-List
```
The collector reads Security Event 4625 and defaults to SOC_Lab_Test_User. Use -Account for another authorised account. It does not alter audit policy. Missing events/access failures are errors, not a successful zero-alert run.

## Schema and validation
Required fields: TimeUTC, RecordID, Computer, Channel, EventID, Domain, Account, SourceIP.
- Channel must be Security and EventID 4625.
- RecordID must be a positive integer.
- String timestamps must be ISO 8601 with an explicit timezone; they are normalised to UTC.
- SourceIP must parse as an IP address; canonical IPv6 forms group together.
- Windows computer/domain/account keys compare case-insensitively.
- Missing domain is recorded as "-" by the collector when Windows does not provide it. It is unknown context, not a verified domain.
- Events with absent/unparseable source IP are rejected by this network-source rule and need separate analysis.
- Null or invalid records stop processing, preventing silent partial analysis.

Optional reporting fields: LogonType, Status, SubStatus.

## Duplicate identity
Computer + channel + positive record ID + UTC timestamp identifies a record within the supplied dataset. Timestamp is included to avoid merging reused IDs after log reset. Identical copies are counted once. A repeated identity with conflicting account/domain/IP or authentication details is rejected. Event IDs alone are never used as unique identifiers.

This is a practical lab identity, not a cryptographic provenance guarantee. Different collection sources, log restoration, or genuinely ambiguous IDs require further provenance controls.

## Detection behaviour
Default: at least 5 failures within an inclusive 5-minute window. Threshold and WindowMinutes are configurable. Each group emits at most one alert per invocation, containing every event in its earliest qualifying window. RecordIDs lists the contributing IDs; Computer supplies their host context.

There is no persistent suppression between runs. Multi-account password spraying is outside this per-account rule's scope.

## Migration from the old CSV
Older CSVs lack Computer, Domain, Channel, and EventID. **Recollect with the v2 reader; do not invent these values.** Keep the old CSV privately as historical evidence:
```powershell
$folder = Join-Path $env:USERPROFILE 'SOC-Lab-Reports'
$records | Export-Csv (Join-Path $folder 'lab-failed-logons-v2.csv') -NoTypeInformation -Encoding UTF8
./New-InvestigationReport.ps1 -CsvPath (Join-Path $folder 'lab-failed-logons-v2.csv') -OutputPath (Join-Path $folder 'investigation-report-v2.html')
```
The report validates and deduplicates input, shows unique and imported counts, and refuses to overwrite the input CSV. Inputs are not changed. Source records and alerts are encoded as HTML tables.

## Automated validation
```powershell
./Test-RepeatedFailures.ps1
```
No log access, admin rights, or login attempts are required. Thirty cases retain the original threshold/window/account/source checks and add host/domain separation, duplicate/conflict handling, timezone and IPv6 normalisation, required-field rejection, configurable settings, later-window detection, and report integration.

Hosted v2 verification: **30/30 regression cases passed** on Windows in [run 39117628101](https://github.com/Banoth281/soc-login-lab/actions/runs/39117628101), testing commit 4e8f40eb252d95aff25c9bbde221a039821a6206. This includes duplicate handling, context isolation, validation, and report integration. No local v2 PowerShell run has been claimed in the authoring environment.

## Evidence and provenance
[Historical v1 validation](VALIDATION-V1.md) preserves the two actual user-observed test events, eight original tests, successful v1 packaged run, and reviewed v1 HTML screenshot. Those are historical results, not proof that v2 has been run against the user's machine. The v2 suite uses synthetic records and temporary CSV/HTML files.

## Limits and next steps
- Validate v2 collection against the user's actual Windows log after upgrading all scripts.
- Add collector-specific integration tests and stress/performance benchmarks.
- Unknown domain "-" values cannot establish account namespace separation.
- The detector combines logon types within each group; tune or extend keys for a specific environment.
- Inputs and reports may contain machine/account identifiers; review before sharing.
- Hard-link aliases are not explicitly checked by the report's input/output path guard.
- There is no SIEM deployment, live above-threshold attack, or containment claim.
