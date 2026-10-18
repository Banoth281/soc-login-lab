# Case study: Offline phishing email investigation
**Santhosh Banoth | Personal lab | 18 October 2026**

## Objective
Create a reproducible phishing investigation that separates extracted evidence from analyst judgment, preserves the original sample, and produces a readable report without accessing live URLs.

## Scenario
A synthetic plain-text email impersonates IT Support, threatens account disablement within 30 minutes, links to a different domain, and explicitly asks the recipient to reply with a username and password. All email domains are reserved .invalid examples. Authentication-Results values are deliberately authored fixture text.

## Workflow
1. Save the sample and calculate SHA-256.
2. Extract headers, unfold continuation lines, and collect unique body URLs with PowerShell.
3. Save extracted evidence to JSON without automatically assigning a verdict.
4. Record a separate analyst verdict with supporting observations and proposed responses.
5. Generate Markdown and HTML reports.
6. Test the extractor and report generator on a GitHub-hosted Windows runner.

## Findings
| Observation | Assessment |
|---|---|
| Explicit request for username and password | Primary evidence of the fixture's credential-phishing intent |
| Threat of account disablement within 30 minutes | Urgency intended to pressure the recipient |
| From and Reply-To domains differ | Supporting anomaly; not conclusive by itself |
| Verification URL uses another domain | Additional context requiring investigation |
| Embedded SPF fail / DKIM none / DMARC fail | Synthetic, unverified header text; no real authentication validation |

**Analyst verdict:** credential-phishing training scenario. This is a manual assessment of a known fixture, not an automated classifier result.

## Sample integrity
```text
SHA256 A8B936DA03CF64F34DC185DD23DF89424BA6D372B0F3690EBF227B6E62565CEB
```
Uploaded sample bytes independently matched the recorded hash. All five submitted files matched their ZIP entries. Original files were published byte for byte; Git attributes protect the sample against newline conversion.

## Validation and results
| Component | Evidence and outcome |
|---|---|
| Local extractor execution | User supplied output with expected hash, headers, and one URL |
| Local assertions | Three checks passed: hash, Reply-To, exact URL |
| Extractor CI | Ten checks passed on Windows in [run 39115587909](https://github.com/Banoth281/soc-login-lab/actions/runs/39115587909) |
| Report CI | Extraction and HTML generation checks passed in [run 39115864024](https://github.com/Banoth281/soc-login-lab/actions/runs/39115864024) |
| HTML output | User supplied report text showing evidence, analyst verdict, proposed responses, and generation time 2026-10-18 09:35:14Z |
| Visual layout | Not verified from a browser screenshot |

Report tests check evidence presence, HTML encoding, verdict display, and absence of clickable anchors. Temporary test folders prevent overwriting original evidence.

## Troubleshooting
An initial script file accidentally included its creation commands and an unfinished here-string wrapper. The script section was recovered, syntax-checked with the PowerShell parser, and backed up before saving. Subsequent execution succeeded. A session-scoped execution policy allowed reviewed local scripts without a permanent machine-wide change.

## Proposed response
For a real incident, preserve the original message, verify through a known support channel, search authorised delivery telemetry, assess user interaction, and follow containment procedures if exposure is established. No blocking, credential reset, or containment was performed in this synthetic exercise.

## Skills demonstrated
Email header inspection, evidence hashing, PowerShell parsing, JSON reporting, analyst reasoning, HTML encoding, negative-input testing, and continuous integration.

## Limits
This parser supports the simple plain-text fixture; it is not a general MIME parser. No attachments, live delivery, reputation checks, DNS checks, or independent SPF/DKIM/DMARC validation were involved. Report hash matching associates two JSON records but does not rehash the email. Automated checks validate the covered examples rather than production detection effectiveness.

## Explore the evidence
- [Project guide](README.md)
- [Original synthetic sample](sample-phishing.eml)
- [Extractor](Extract-LabEmail.ps1)
- [Extracted JSON](extracted-evidence.json)
- [Analyst assessment](analysis.json)
- [Investigation report](investigation-report.md)
- [Validation history](VALIDATION.md)
