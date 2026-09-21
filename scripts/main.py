"""Mini SOC: generate logs -> detect threats -> raise alerts -> open incidents -> report.

Usage:  python scripts/main.py [--seed 42] [--log data/windows_events.csv] [--out output]
        Add --use-existing-log to analyze a log file you already have instead of generating one.
"""
import argparse
from pathlib import Path

import detector
import incidents
import log_generator
import reporter


def main():
    p = argparse.ArgumentParser(description="Mini security operations center")
    p.add_argument("--seed", type=int, default=42, help="seed for synthetic log generation")
    p.add_argument("--log", default="data/windows_events.csv", help="event log CSV path")
    p.add_argument("--out", default="output", help="directory for alerts, incidents and report")
    p.add_argument("--use-existing-log", action="store_true",
                   help="analyze --log as-is instead of generating a new one")
    args = p.parse_args()

    log_path, out = Path(args.log), Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    if not args.use_existing_log:
        n = log_generator.write_csv(log_generator.generate_events(seed=args.seed), log_path)
        print("[1/4] Generated %d synthetic events -> %s" % (n, log_path))
    else:
        print("[1/4] Using existing log %s" % log_path)

    events = detector.load_events(log_path)
    print("[2/4] Loaded %d events (%d failed logons)" % (
        len(events), len(detector.failed_logins(events))))

    alerts = detector.run_detections(events)
    print("[3/4] Raised %d alerts" % len(alerts))
    for a in alerts:
        print("      %s  %-8s %-22s %s" % (a.alert_id, a.severity, a.rule, a.description))

    tickets = incidents.create_incidents(alerts)
    reporter.write_json(alerts, out / "alerts.json")
    reporter.write_json(tickets, out / "incidents.json")
    (out / "report.md").write_text(reporter.build_report(events, alerts, tickets))
    print("[4/4] Opened %d incident tickets -> %s/{alerts.json,incidents.json,report.md}"
          % (len(tickets), out))
    for t in tickets:
        print("      %s  %-8s %s" % (t.incident_id, t.severity, t.title))


if __name__ == "__main__":
    main()
