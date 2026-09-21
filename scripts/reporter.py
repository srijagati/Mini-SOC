"""Write alerts, incident tickets and a Markdown security report."""
import json
from collections import Counter
from pathlib import Path

from detector import failed_logins


def write_json(items, path):
    Path(path).write_text(json.dumps([i.to_dict() for i in items], indent=2))


def build_report(events, alerts, incidents):
    fails = failed_logins(events)
    successes = [e for e in events if e.event_id == 4624]
    sev = Counter(a.severity for a in alerts)
    top_ips = Counter(e.ip for e in fails).most_common(5)
    top_users = Counter(e.user for e in fails).most_common(5)

    L = []
    L.append("# Mini SOC Security Report\n")
    L.append("Period: %s to %s\n" % (events[0].time, events[-1].time))
    L.append("## Summary\n")
    L.append("| Metric | Value |\n|---|---|")
    L.append("| Events analyzed | %d |" % len(events))
    L.append("| Successful logons (4624) | %d |" % len(successes))
    L.append("| Failed logons (4625) | %d |" % len(fails))
    L.append("| Alerts | %d (Critical %d, High %d, Medium %d, Low %d) |" % (
        len(alerts), sev["Critical"], sev["High"], sev["Medium"], sev["Low"]))
    L.append("| Open incidents | %d |\n" % len(incidents))

    L.append("## Top sources of failed logins\n")
    L.append("| IP | Failures |\n|---|---|")
    L += ["| %s | %d |" % t for t in top_ips]
    L.append("\n## Most targeted accounts\n")
    L.append("| Account | Failures |\n|---|---|")
    L += ["| %s | %d |" % t for t in top_users]

    L.append("\n## Incidents\n")
    for inc in incidents:
        L.append("### %s [%s] %s\n" % (inc.incident_id, inc.severity, inc.title))
        L.append("- Status: %s" % inc.status)
        L.append("- Window: %s to %s" % (inc.first_seen, inc.last_seen))
        L.append("- Accounts involved: %s" % ", ".join(inc.users))
        L.append("- Alerts: %s" % ", ".join(inc.alert_ids))
        L.append("- Recommended actions:")
        L += ["  - %s" % step for step in inc.actions]
        L.append("")

    L.append("## Alerts\n")
    L.append("| ID | Severity | Rule | MITRE ATT&CK | Description |\n|---|---|---|---|---|")
    for a in alerts:
        L.append("| %s | %s | %s | %s | %s |" % (
            a.alert_id, a.severity, a.rule, a.technique, a.description))
    return "\n".join(L) + "\n"
