# Case study: Windows failed-logon investigation and detection
**Author:** Santhosh Banoth | **Completed:** 18 October 2026  
**Environment:** Personal Windows computer, 8 GB RAM, Windows PowerShell

## Problem
Build a practical SOC portfolio exercise without cloud costs or a resource-heavy SIEM. The objective was to collect actual Windows authentication evidence, explain a failed logon, and build a small, testable analysis workflow.

## Approach
Verified the Audit Logon policy, reviewed Security events in Event Viewer, and used an authorised loopback authentication test against a nonexistent local account. Extracted named XML fields with PowerShell, built a rolling-window detector, exported CSV, and generated an HTML report.

## Investigation
The initial audit query lacked privileges. Elevating the prompt resolved the error and confirmed Success and Failure auditing. The runas method could not acquire password input, so a loopback IPC$ test was used. It returned error 1326.

The supplied XML identifies Event 4625, record 1832673, at 2026-10-18T08:18:19.3299718Z. Logon Type 3 indicates network authentication; source 127.0.0.1 matches the local test. Status 0xC000006D is generic authentication failure; substatus 0xC0000064 identifies an unrecognised account. PowerShell subsequently read two matching test-account events.

## Detection design
Group records by account and source IP. Alert when at least five failures occur within an inclusive five-minute rolling window. Emit at most one alert per pair per invocation. This rule identifies repeated failures for one account/source pair; it is not a password spray detector.

## Results
| Evidence category | Outcome |
|---|---|
| Actual Windows records | Two failed-logon records read; IDs 1832673 and 1832671 |
| Actual-data detector outcome | Zero alerts, correctly below the threshold |
| Synthetic automated suite | 8/8 checks passed in user-executed Windows PowerShell |
| CSV report | Export existence and reimport confirmed in supplied transcript |
| HTML report | Two events and zero alerts; readable layout confirmed from supplied screenshot |
| GitHub Actions | Windows test job succeeded in [run 39113190608](https://github.com/Banoth281/soc-login-lab/actions/runs/39113190608) |

## Test coverage
Positive threshold, below threshold, inclusive 300-second boundary, exclusion at 301 seconds, separate sources, separate accounts, unsorted input, and empty input. Positive cases also check account, source, and failure count.

## What this demonstrates
Windows Security event interpretation, named-field XML parsing, evidence-based triage, PowerShell scripting, boundary testing, CSV/HTML reporting, and continuous integration.

## Evidence and reproducibility
- [Investigation walkthrough](README.md)
- [Sanitised event evidence](evidence/05-controlled-logon-result.txt)
- [Scripts, usage, and validation history](powershell/README.md)
- [Automated workflow](../.github/workflows/powershell-tests.yml)

Local evidence comes from user-supplied event text, XML, console transcripts, and screenshots. A raw EVTX file was not supplied. Computer identifiers were redacted from published evidence; screenshots remain unpublished. The HTML report is generated locally rather than hosted publicly.

## Limitations and next improvements
The lab does not demonstrate a production deployment, malicious intrusion, a live five-failure alert, or containment. The detector assumes valid, unique, single-host/domain records and needs stronger validation and scalable window processing for larger datasets. Further work could add multi-host grouping, malformed-input tests, and report-generation tests.

## References
- [Microsoft Event 4625](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625)
- [Microsoft auditpol](https://learn.microsoft.com/windows-server/administration/windows-commands/auditpol)

## Advanced v2 follow-up
The collector and detector now separate destination host, domain, account and source IP; validate required event fields; and deduplicate event identities before analysis. A two-index scan replaces repeated full-window scans. Alert evidence includes contributing record IDs.

The user ran 30/30 original v2 tests and collected two actual Windows records with host/domain context: 2 unique events and 0 alerts. The corrected generator produced a local report showing 0 duplicates. SHA-256 checks confirmed that the CSV and HTML matched their saved manifest. The path-resolution regression brings the hosted suite to 31/31 passing cases. See [local v2 validation](evidence/LOCAL-V2-VALIDATION.md) for provenance, hashes, and limits. No raw CSV or HTML was uploaded.
