# Windows Failed-Logon Investigation
**Author:** Santhosh Banoth  
**Lab date:** 18 October 2026  
**Status:** In progress — audit configuration verified; Event 4625 capture pending.

A free local SOC investigation exercise using Windows Event Viewer and auditpol on an 8 GB RAM Windows computer. This folder records the actual work completed during the session. The repository's other simulated-data exercises are separate; their results do not validate this live Windows test.

## Objective
Generate one controlled failed logon against a nonexistent local test account, find Event 4625, interpret the failure fields, and document the outcome. No Azure, Sentinel, Wazuh deployment, production incident, or successful detection is claimed.

## Confirmed actions and evidence
| Action | Observed result | Evidence |
|---|---|---|
| Check hardware | 8 GB RAM; about 6.5 GB in use | User-provided screenshot; withheld from public repository |
| Open Windows Security log | Log accessible; selected event was 4672 | User-provided screenshot; withheld from public repository |
| Filter for 4625 | Filter applied; matching list empty at capture time | User-provided screenshot; withheld from public repository |
| Query audit policy without elevation | Error 0x00000522: required privilege not held | [User-provided command transcript](evidence/04-command-transcript.txt) |
| Retry from elevated command prompt | Logon policy reports Success and Failure | [User-provided command transcript](evidence/04-command-transcript.txt) |
| Attempt controlled failed logon with runas | Unable to acquire user password; authentication attempt not established | [User-provided command transcript](evidence/04-command-transcript.txt) |

Screenshots are original user-provided captures. The transcript is a transcription of command output supplied by the user, not an independently captured terminal log. No EVTX file has been supplied. An empty filtered view does not establish that the computer has never had failed logons.

## Evidence availability
The three original screenshots were reviewed during the session but are not included in this public repository. Public upload was blocked by automatic approval review pending explicit approval for those images. The sanitised command transcript is included. No raw Windows event logs are published.

## Reproduction and next steps
Use your own authorised lab computer.
1. Open Command Prompt as administrator.
2. Check policy:
   `auditpol /get /subcategory:"Logon"`
3. The observed result was `Success and Failure`; no audit policy change was needed.
4. Confirm the test account does not exist. Attempt once:
   `runas /user:.\\SOC_Lab_Test_User "cmd.exe"`
5. At the password prompt, manually enter a made-up, nonempty test password. Input is hidden. Do not use an actual account password.
6. Record the exact runas outcome. An input-acquisition error is not proof of authentication failure.
7. In Event Viewer, open Windows Logs > Security, filter Event ID 4625, and refresh.
8. If an event appears, record timestamp and timezone, event record ID, Failure Reason, Status, Sub Status, and Logon Type. Confirm the target matches the lab account.
9. Retain original event evidence privately. Publish only reviewed, sanitised evidence and explain any redactions.

## Troubleshooting
- **0x00000522:** initial command lacked the required privilege. Retrying elevated successfully returned the audit policy.
- **Unable to acquire user password:** observed twice in the supplied transcript. Manual nonempty password input was suggested; its result has not yet been supplied.
- **Empty 4625 results:** no matching events visible at the screenshot time. Verify time range, refresh, and confirm a test authentication was actually attempted before diagnosing logging failure.

## Success criteria
- [x] Choose a lab approach suitable for available hardware.
- [x] Access Security log and apply Event ID filter.
- [x] Resolve privilege issue for audit policy query.
- [x] Verify Logon success and failure auditing is enabled.
- [ ] Complete a controlled authentication attempt.
- [ ] Capture matching Event 4625.
- [ ] Interpret status/substatus and logon type.
- [ ] Preserve sanitised event evidence and write final findings.

## Current finding
Audit readiness has been verified. End-to-end failed-logon detection remains unvalidated. No malicious activity, successful login, containment, or remediation outcome has been demonstrated.

## References
- [Microsoft: Event 4625](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625)
- [Microsoft: auditpol get](https://learn.microsoft.com/windows-server/administration/windows-commands/auditpol-get)
- [Microsoft: runas](https://learn.microsoft.com/windows-server/administration/windows-commands/runas)
