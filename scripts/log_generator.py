"""Generate synthetic Windows Security event logs (CSV).

Event IDs used (same meaning as on a real Windows host):
    4624  An account was successfully logged on
    4625  An account failed to log on
    4740  A user account was locked out

Sub-status codes on 4625 events:
    0xC000006A  correct user name, wrong password
    0xC0000064  user name does not exist
"""
import csv
import random
from datetime import datetime, timedelta

FIELDS = ["TimeCreated", "EventID", "Computer", "TargetUserName",
          "IpAddress", "LogonType", "SubStatus"]

WRONG_PASSWORD = "0xC000006A"
NO_SUCH_USER = "0xC0000064"

USERS = ["jsmith", "mwilson", "apatel", "rlee", "tgarcia", "kbrown",
         "dnguyen", "lchen", "svc_backup", "Administrator"]
WORKSTATIONS = ["WKS-01", "WKS-02", "WKS-03", "WKS-04", "WKS-05"]
SERVERS = ["DC01", "FILESRV01"]
GUESSED_USERS = ["admin", "test", "guest", "root", "oracle", "sqlsvc", "backup"]


def _event(ts, event_id, computer, user, ip, logon_type="", sub_status=""):
    return {
        "TimeCreated": ts.isoformat(sep=" "),
        "EventID": event_id,
        "Computer": computer,
        "TargetUserName": user,
        "IpAddress": ip,
        "LogonType": logon_type,
        "SubStatus": sub_status,
    }


def _normal_activity(rng, start, hours):
    """Regular staff logging in during working hours, with the odd typo."""
    events = []
    ips = {u: "10.0.0.%d" % (10 + i) for i, u in enumerate(USERS)}
    for day in range(max(1, hours // 24)):
        base = start + timedelta(days=day)
        for user in USERS:
            for _ in range(rng.randint(2, 4)):
                ts = base + timedelta(hours=rng.randint(8, 17),
                                      minutes=rng.randint(0, 59),
                                      seconds=rng.randint(0, 59))
                host = rng.choice(WORKSTATIONS + SERVERS)
                if rng.random() < 0.12:  # mistyped password once or twice
                    for i in range(rng.randint(1, 2)):
                        events.append(_event(ts - timedelta(seconds=10 * (i + 1)), 4625, host,
                                             user, ips[user], 2, WRONG_PASSWORD))
                events.append(_event(ts, 4624, host, user, ips[user], rng.choice([2, 3, 10])))
    return events


def _brute_force(start):
    """Attacker hammers Administrator from the internet, never gets in."""
    ip, t0 = "185.220.101.47", start + timedelta(hours=2, minutes=14)
    return [_event(t0 + timedelta(seconds=2 * i), 4625, "DC01", "Administrator",
                   ip, 3, WRONG_PASSWORD) for i in range(60)]


def _successful_brute_force(start):
    """Attacker guesses the svc_backup password after 25 tries."""
    ip, t0 = "45.155.205.233", start + timedelta(hours=13, minutes=40)
    events = [_event(t0 + timedelta(seconds=3 * i), 4625, "FILESRV01", "svc_backup",
                     ip, 3, WRONG_PASSWORD) for i in range(25)]
    events.append(_event(t0 + timedelta(seconds=3 * 25 + 4), 4624, "FILESRV01",
                         "svc_backup", ip, 3))
    return events


def _password_spray(rng, start):
    """One IP tries a few common passwords against many accounts."""
    ip, t0 = "194.26.29.102", start + timedelta(hours=22, minutes=5)
    targets = USERS[:8] + GUESSED_USERS
    events, t = [], t0
    for user in targets:
        status = WRONG_PASSWORD if user in USERS else NO_SUCH_USER
        for _ in range(rng.randint(1, 2)):
            events.append(_event(t, 4625, "DC01", user, ip, 3, status))
            t += timedelta(seconds=rng.randint(8, 20))
    return events


def _lockout(start):
    """Insider / misconfigured device keeps failing until the account locks."""
    ip, t0 = "10.0.0.57", start + timedelta(hours=10, minutes=30)
    events = [_event(t0 + timedelta(seconds=10 * i), 4625, "DC01", "mwilson",
                     ip, 2, WRONG_PASSWORD) for i in range(6)]
    events.append(_event(t0 + timedelta(seconds=65), 4740, "DC01", "mwilson", ip))
    return events


def generate_events(seed=42, start=None, hours=24):
    rng = random.Random(seed)
    start = start or datetime(2026, 9, 1)
    events = _normal_activity(rng, start, hours)
    events += _brute_force(start)
    events += _successful_brute_force(start)
    events += _password_spray(rng, start)
    events += _lockout(start)
    events.sort(key=lambda e: e["TimeCreated"])
    return events


def write_csv(events, path):
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(events)
    return len(events)
