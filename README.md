# Suspicious Login Detection and Investigation

A beginner SOC portfolio lab using Python to detect suspicious login sequences and document investigation decisions.

## Purpose

Detect five or more failed logins followed by a successful login for the same account and source IP within five minutes.

An alert indicates activity to investigate, not proof of compromise.

## Tools

- Python standard library
- CSV login records
- Windows Command Prompt

No additional Python packages are required.

## Files

- `login_logs.csv` — 15 synthetic login records
- `detect_logins.py` — detection script and CSV report export
- `alerts.csv` — generated alert report
- `investigation_notes.txt` — evidence, fictional follow-up scenarios and proposed responses

## Run

From the project folder:

```shell
python detect_logins.py
```

On Windows, you can also use:

```cmd
py detect_logins.py
```

Each run replaces `alerts.csv` with the latest results.

## Sample Results

The supplied dataset produces two alerts:

| Account | Failed attempts | Time until success |
|---------|-----------------|--------------------|
| charlie | 5 | 2 minutes 30 seconds |
| diana | 5 | 2 minutes 30 seconds |

Alice and Bob do not meet the alert threshold.

## Investigation Practice

Charlie's fictional follow-up scenario illustrates suspected account compromise and proposed escalation and containment.

Diana's fictional follow-up scenario illustrates likely benign activity and the importance of checking context.

Follow-up details are explicitly labelled as assumptions in the investigation notes. They are not contained in the CSV.

## Detection Behaviour

The script sorts events by timestamp and tracks failures separately for each account and source IP. Failures older than five minutes are excluded. A successful login resets that group's failure history.

## Limitations

- Uses synthetic data and documentation-only IP addresses.
- Not connected to a live identity system or SIEM.
- Does not detect password spraying or attacks across multiple IPs.
- Assumes valid CSV fields and timestamps.
- No real containment actions were performed.

## Skills Demonstrated

Log analysis, Python scripting, rule-based detection, CSV reporting, alert triage and investigation documentation.
