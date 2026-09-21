"""Load Windows event logs and run detection rules over them."""
import csv
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List

# Tunable thresholds
BURST_GAP = timedelta(minutes=5)          # events further apart than this start a new burst
BRUTE_FORCE_MIN_FAILURES = 10             # failures from one IP in one burst
SPRAY_MIN_DISTINCT_USERS = 8              # distinct accounts hit by one IP in one burst
REPEATED_FAIL_MIN = 5                     # failures against one account in one burst
SUCCESS_AFTER_WINDOW = timedelta(minutes=10)

TECHNIQUES = {
    "BRUTE_FORCE": "T1110.001 Password Guessing",
    "PASSWORD_SPRAY": "T1110.003 Password Spraying",
    "REPEATED_FAILED_LOGIN": "T1110 Brute Force",
    "ACCOUNT_LOCKOUT": "T1110 Brute Force",
    "COMPROMISED_ACCOUNT": "T1078 Valid Accounts",
}


@dataclass
class Event:
    time: datetime
    event_id: int
    computer: str
    user: str
    ip: str
    logon_type: str
    sub_status: str


@dataclass
class Alert:
    rule: str
    severity: str
    description: str
    src_ip: str
    users: List[str]
    count: int
    first_seen: datetime
    last_seen: datetime
    technique: str = ""
    alert_id: str = ""

    def __post_init__(self):
        self.technique = self.technique or TECHNIQUES.get(self.rule, "")

    def to_dict(self):
        d = self.__dict__.copy()
        d["first_seen"] = self.first_seen.isoformat(sep=" ")
        d["last_seen"] = self.last_seen.isoformat(sep=" ")
        return d


def load_events(path) -> List[Event]:
    events = []
    with open(path, newline="") as fh:
        for row in csv.DictReader(fh):
            events.append(Event(
                time=datetime.fromisoformat(row["TimeCreated"]),
                event_id=int(row["EventID"]),
                computer=row["Computer"],
                user=row["TargetUserName"],
                ip=row["IpAddress"],
                logon_type=row["LogonType"],
                sub_status=row["SubStatus"],
            ))
    events.sort(key=lambda e: e.time)
    return events


def failed_logins(events):
    """Event 4625: every failed logon."""
    return [e for e in events if e.event_id == 4625]


def _bursts(events, gap=BURST_GAP):
    """Split time-sorted events into bursts separated by quiet periods > gap."""
    burst = []
    for e in sorted(events, key=lambda e: e.time):
        if burst and e.time - burst[-1].time > gap:
            yield burst
            burst = []
        burst.append(e)
    if burst:
        yield burst


def _group(events, key):
    groups = {}
    for e in events:
        groups.setdefault(key(e), []).append(e)
    return groups


def _users(burst):
    return sorted({e.user for e in burst})


def detect_brute_force(events):
    """Many failures from one IP in a short burst. Returns (alerts, covered events)."""
    alerts, covered = [], set()
    for ip, evs in _group(failed_logins(events), lambda e: e.ip).items():
        for burst in _bursts(evs):
            users = _users(burst)
            if len(users) >= SPRAY_MIN_DISTINCT_USERS:
                rule, sev = "PASSWORD_SPRAY", "High"
                desc = "%d failed logins across %d accounts from %s" % (len(burst), len(users), ip)
            elif len(burst) >= BRUTE_FORCE_MIN_FAILURES:
                rule, sev = "BRUTE_FORCE", "High"
                desc = "%d failed logins against %s from %s" % (len(burst), ", ".join(users), ip)
            else:
                continue
            covered.update(id(e) for e in burst)
            alerts.append(Alert(rule, sev, desc, ip, users, len(burst),
                                burst[0].time, burst[-1].time))
    return alerts, covered


def detect_repeated_failures(events, covered):
    """Several failures against one account that are not already part of an attack alert."""
    alerts = []
    remaining = [e for e in failed_logins(events) if id(e) not in covered]
    for user, evs in _group(remaining, lambda e: e.user).items():
        for burst in _bursts(evs):
            if len(burst) < REPEATED_FAIL_MIN:
                continue
            ip = Counter(e.ip for e in burst).most_common(1)[0][0]
            sev = "Medium" if len(burst) >= BRUTE_FORCE_MIN_FAILURES else "Low"
            alerts.append(Alert(
                "REPEATED_FAILED_LOGIN", sev,
                "%d failed logins against %s from %s" % (len(burst), user, ip),
                ip, [user], len(burst), burst[0].time, burst[-1].time))
    return alerts


def detect_lockouts(events):
    return [Alert("ACCOUNT_LOCKOUT", "Medium",
                  "Account %s was locked out" % e.user,
                  e.ip, [e.user], 1, e.time, e.time)
            for e in events if e.event_id == 4740]


def detect_compromise(events, attack_alerts):
    """A successful logon from an attacking IP right after its failures."""
    alerts = []
    successes = [e for e in events if e.event_id == 4624]
    for a in attack_alerts:
        for s in successes:
            if (s.ip == a.src_ip and s.user in a.users
                    and a.first_seen <= s.time <= a.last_seen + SUCCESS_AFTER_WINDOW):
                alerts.append(Alert(
                    "COMPROMISED_ACCOUNT", "Critical",
                    "Successful logon to %s from %s after %d failed attempts - "
                    "account likely compromised" % (s.user, s.ip, a.count),
                    s.ip, [s.user], a.count, a.first_seen, s.time))
                break
    return alerts


def run_detections(events) -> List[Alert]:
    attacks, covered = detect_brute_force(events)
    alerts = (attacks
              + detect_repeated_failures(events, covered)
              + detect_lockouts(events)
              + detect_compromise(events, attacks))
    alerts.sort(key=lambda a: (a.first_seen, a.rule))
    for i, a in enumerate(alerts, 1):
        a.alert_id = "ALT-%04d" % i
    return alerts
