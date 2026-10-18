# Phishing Email Investigation Lab

[![Phishing extractor tests](https://github.com/Banoth281/soc-login-lab/actions/workflows/phishing-tests.yml/badge.svg)](https://github.com/Banoth281/soc-login-lab/actions/workflows/phishing-tests.yml)
**Author:** Santhosh Banoth | **Lab date:** 18 October 2026

An offline investigation of a synthetic credential-phishing email using Windows PowerShell. Includes the exact uploaded sample, a reusable extractor, machine-readable evidence, and analyst findings.

[Read the case study](CASE-STUDY.md) - concise investigation, findings, validation, and limitations.

## Results
| Check | Result | Evidence source |
|---|---|---|
| Sample identification | SHA-256 verified independently against uploaded bytes | Host-side hash verification |
| Archive consistency | All five individual files match their ZIP entries byte for byte | Host-side comparison |
| Header extraction | From, Reply-To, Subject, and folded Authentication-Results extracted | Supplied console output and uploaded JSON |
| URL extraction | One expected URL extracted | Uploaded JSON and user-executed assertion |
| Packaged extractor | Executed successfully after repairing an accidental here-string wrapper | User-supplied console output |
| Three assertions | Hash, Reply-To, and exact URL checks passed | User-supplied console output |
| Analyst report | Credential-phishing training scenario documented | [Investigation report](investigation-report.md) |

## Sample identity
```text
A8B936DA03CF64F34DC185DD23DF89424BA6D372B0F3690EBF227B6E62565CEB
```
The sample is preserved byte for byte, including BOM and original line endings. Editing it or allowing Git to normalise its line endings changes the hash. The email Date header is fictional fixture data, not a verified collection timestamp.

## Files
| File | Purpose |
|---|---|
| [sample-phishing.eml](sample-phishing.eml) | Synthetic plain-text email; reserved .invalid domains |
| [Extract-LabEmail.ps1](Extract-LabEmail.ps1) | Local header/URL extraction and SHA-256 calculation |
| [extracted-evidence.json](extracted-evidence.json) | Actual submitted extractor output; no automated verdict |
| [analysis.json](analysis.json) | Separate analyst-assigned verdict and rationale |
| [investigation-report.md](investigation-report.md) | Findings, proposed responses, and limitations |
| [VALIDATION.md](VALIDATION.md) | Validation provenance and observed outcomes |

## Run
Download the files together, then open Windows PowerShell in this folder:
```powershell
Get-FileHash './sample-phishing.eml' -Algorithm SHA256
./Extract-LabEmail.ps1 | Format-List
Get-Content './extracted-evidence.json' -Raw | ConvertFrom-Json | Format-List
```
The extractor reads a local file, makes no network requests, and overwrites extracted-evidence.json next to the script. It does not overwrite analysis.json. Administrator access is unnecessary. If local execution policy prevents running a reviewed script, process-scoped RemoteSigned can be used on a personal lab machine; organisational policies should be respected.

## Analyst reasoning
The explicit request to reply with a username and password is the primary credential-phishing indicator. Urgency, differing sender/reply destinations, and the third-domain link provide supporting context. Domain differences alone are insufficient to classify an email as malicious.

Authentication-Results is deliberately embedded fixture text. The extractor does not validate SPF, DKIM, DMARC, DNS, or the authenticity of that header. The analyst verdict and proposed containment actions are not automatic extractor outputs.

## Limits
This is a simple plain-text fixture parser, not a complete MIME or forensic email-processing library. It does not decode attachments, base64/quoted-printable bodies, encoded headers, or multipart messages. Repeated headers and unusual URL punctuation require additional handling. No live email, malicious attachment, reputation lookup, delivery investigation, credential exposure, or containment was involved. The initial three assertions were run interactively. A subsequent ten-check automated suite covers this exact fixture plus rejection of a missing header/body separator; it does not establish support for general MIME email.

## Further work
Extend negative cases, add robust MIME parsing, and develop safe report generation before applying this approach to more complex samples.

## Automated tests
Run `./Test-LabEmail.ps1` from Windows PowerShell. It checks sample hash, sender, Reply-To, subject, folded header, exact URL, unverified authentication status, analyst-review verdict, JSON roundtrip, and malformed-input rejection. Execution happens in a temporary directory that is removed afterward; original evidence files are not overwritten.

The GitHub workflow runs on relevant pushes and pull requests with read-only repository access. Hosted execution status is available through the badge above.

## HTML investigation report
Run `./New-PhishingReport.ps1` next to analysis.json and extracted-evidence.json, then open phishing-report.html in a browser. No administrator access is needed. The generator leaves JSON inputs unchanged and writes only its HTML output.

The report combines extracted headers and hash with the separate analyst assessment. All dynamic text is HTML-encoded; extracted URLs are plain text. The observations and response guidance are specific to this synthetic fixture. A matching valid hash is required across both JSON inputs.

`./Test-PhishingReport.ps1` validates report generation, key evidence, encoded markup, verdict display, and absence of anchor links using a temporary directory. GitHub CI runs this check alongside the ten extraction checks. Report generation is confirmed by user-supplied output dated 18 October 2026 (generated 09:35:14Z). Browser visual verification remains pending.
