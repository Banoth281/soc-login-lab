# Windows Failed-Logon Investigation
**Author:** Santhosh Banoth  
**Lab date:** 18 October 2026  
**Status:** Completed for the single-event lab scope using user-supplied event text and XML. Original EVTX export has not been supplied.

A free local SOC investigation exercise using Windows Event Viewer and auditpol on an 8 GB RAM Windows computer. This folder records the actual work completed during the session. The repository's other simulated-data exercises are separate; their results do not validate this live Windows test.

[Read the case study](CASE-STUDY.md) · [Explore PowerShell tools and tests](powershell/README.md)

## Objective
Generate one controlled failed logon against a nonexistent local test account, find Event 4625, interpret the failure fields, and document the outcome. No Azure, Sentinel, Wazuh deployment, or production incident is claimed. Local event recording was demonstrated through user-supplied text; no SIEM alert was tested.

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

## Validated local test outcome
After runas repeatedly failed to acquire password input, a single loopback IPC$ authentication test returned error 1326. The user then supplied failed-logon event text for SOC_Lab_Test_User with Logon Type 3, Status 0xC000006D, Sub Status 0xC0000064, and source 127.0.0.1.

This supports an expected network authentication failure for an unrecognised account. It is authorised lab activity, not evidence of intrusion. See [sanitised command and event evidence](evidence/05-controlled-logon-result.txt).

The subsequent supplied XML confirms EventID **4625**, EventRecordID **1832673**, and UTC time **2026-10-18T08:18:19.3299718Z** (displayed local time **18 October 2026, 13:48:19**, consistent with UTC+05:30). Account, source address, source port, and failure fields match the earlier event text. This is verification within user-supplied evidence, not independent access to the machine.

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
7. The working alternative on this machine was `net use \\127.0.0.1\IPC$ /user:%COMPUTERNAME%\SOC_Lab_Test_User *`. Enter a made-up password once. Error 1326 was observed.
8. In Event Viewer, open Windows Logs > Security, filter Event ID 4625, and refresh.
9. If an event appears, record timestamp and timezone, event record ID, Failure Reason, Status, Sub Status, and Logon Type. Confirm the target matches the lab account.
10. Retain original event evidence privately. Publish only reviewed, sanitised evidence and explain any redactions.

## Troubleshooting
- **0x00000522:** initial command lacked the required privilege. Retrying elevated successfully returned the audit policy.
- **Unable to acquire user password:** observed twice in the supplied transcript. Further retry returned the same error. A loopback net use test subsequently produced the expected credential rejection.
- **Empty 4625 results:** no matching events visible at the screenshot time. Verify time range, refresh, and confirm a test authentication was actually attempted before diagnosing logging failure.

## Success criteria
- [x] Choose a lab approach suitable for available hardware.
- [x] Access Security log and apply Event ID filter.
- [x] Resolve privilege issue for audit policy query.
- [x] Verify Logon success and failure auditing is enabled.
- [x] Complete a controlled authentication attempt (error 1326).
- [x] Obtain matching failed-logon General-tab text from the user (Event 4625 context).
- [x] Interpret status/substatus and logon type.
- [x] Publish sanitised event transcription and findings.
- [x] Obtain timestamp, EventRecordID, and explicit System/EventID confirmation from supplied XML.
- [ ] Optional evidence-preservation follow-up: retain the original EVTX privately.

## Current finding
The controlled local test produced a credential rejection and matching user-supplied failed-logon text. Status 0xC000006D indicates authentication failure; Sub Status 0xC0000064 narrows the cause to an unrecognised username. Logon Type 3 and 127.0.0.1 are consistent with the loopback network test. No malicious activity, successful login, SIEM alert, containment, or remediation outcome has been demonstrated. Event identifier, timestamp, and record ID are now documented from supplied XML. Original EVTX evidence and an independent command timestamp have not been supplied. The single-event investigation is complete within this evidence scope; live above-threshold detection and response actions were not tested. The subsequent [PowerShell extension](powershell/README.md) validates repeated-failure logic with synthetic tests and automated CI.

## References
- [Microsoft: Event 4625](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625)
- [Microsoft: auditpol get](https://learn.microsoft.com/windows-server/administration/windows-commands/auditpol-get)
- [Microsoft: runas](https://learn.microsoft.com/windows-server/administration/windows-commands/runas)
