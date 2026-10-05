import csv
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

folder = Path(__file__).resolve().parent
window = timedelta(minutes=5)
failures = defaultdict(deque)
alerts = []

with (folder / "login_logs.csv").open(
    newline="", encoding="utf-8-sig"
) as file:
    events = list(csv.DictReader(file))

for event in events:
    event["time"] = datetime.fromisoformat(
        event["timestamp"].replace("Z", "+00:00")
    )

events.sort(key=lambda event: event["time"])

for event in events:
    key = (event["user"], event["source_ip"])
    recent = failures[key]
    now = event["time"]

    # Keep only failures within the last five minutes.
    while recent and now - recent[0] > window:
        recent.popleft()

    if event["event"] == "login_failure":
        recent.append(now)

    elif event["event"] == "login_success":
        if len(recent) >= 5:
            alerts.append({
                "user": event["user"],
                "source_ip": event["source_ip"],
                "failed_attempts": len(recent),
                "first_failure": recent[0].isoformat(),
                "successful_login": now.isoformat(),
            })

        # Start a new sequence after a successful login.
        recent.clear()

print(f"Analysed {len(events)} login records.")
print(f"Suspicious login alerts: {len(alerts)}")

for alert in alerts:
    print(
        f"\nALERT: {alert['user']} from {alert['source_ip']}"
        f"\n  Failed attempts: {alert['failed_attempts']}"
        f"\n  First failure: {alert['first_failure']}"
        f"\n  Successful login: {alert['successful_login']}"
    )

print("\nAlerts require investigation; they do not prove compromise.")
report_path = folder / "alerts.csv"

with report_path.open("w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(
        file,
        fieldnames=[
            "user",
            "source_ip",
            "failed_attempts",
            "first_failure",
            "successful_login",
        ],
    )
    writer.writeheader()
    writer.writerows(alerts)

print(f"\nAlert report saved to: {report_path}")