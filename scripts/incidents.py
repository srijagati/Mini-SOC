"""Turn alerts into incident tickets (one ticket per attacking source)."""
from dataclasses import dataclass, field
from typing import List

SEVERITY_ORDER = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}

PLAYBOOK = {
    "BRUTE_FORCE": ["Block the source IP at the firewall",
                    "Enforce MFA and review the targeted account's password policy"],
    "PASSWORD_SPRAY": ["Block the source IP at the firewall",
                       "Force password resets for any account that was targeted",
                       "Enable smart lockout / MFA on all external logons"],
    "REPEATED_FAILED_LOGIN": ["Contact the user to confirm they were mistyping",
                              "Check the source device for stale saved credentials"],
    "ACCOUNT_LOCKOUT": ["Verify the lockout with the user before unlocking the account"],
    "COMPROMISED_ACCOUNT": ["Disable the account and reset its credentials immediately",
                            "Terminate active sessions and hunt for activity after the logon time",
                            "Escalate to the incident response lead"],
}


@dataclass
class Incident:
    incident_id: str
    title: str
    severity: str
    status: str
    src_ip: str
    users: List[str]
    first_seen: object
    last_seen: object
    alert_ids: List[str]
    rules: List[str]
    actions: List[str] = field(default_factory=list)

    def to_dict(self):
        d = self.__dict__.copy()
        d["first_seen"] = self.first_seen.isoformat(sep=" ")
        d["last_seen"] = self.last_seen.isoformat(sep=" ")
        return d


def _is_internal(ip):
    return ip.startswith("10.") or ip.startswith("192.168.")


def create_incidents(alerts) -> List[Incident]:
    groups = {}
    for a in alerts:
        groups.setdefault(a.src_ip, []).append(a)

    incidents = []
    for ip, group in groups.items():
        top = max(group, key=lambda a: SEVERITY_ORDER[a.severity])
        actions = []
        for a in group:
            for step in PLAYBOOK.get(a.rule, []):
                if step not in actions:
                    actions.append(step)
        where = "internal host" if _is_internal(ip) else "external IP"
        incidents.append(Incident(
            incident_id="",
            title="%s from %s %s" % (top.rule.replace("_", " ").title(), where, ip),
            severity=top.severity,
            status="Open",
            src_ip=ip,
            users=sorted({u for a in group for u in a.users}),
            first_seen=min(a.first_seen for a in group),
            last_seen=max(a.last_seen for a in group),
            alert_ids=[a.alert_id for a in group],
            rules=sorted({a.rule for a in group}),
            actions=actions,
        ))
    incidents.sort(key=lambda i: (-SEVERITY_ORDER[i.severity], i.first_seen))
    for n, inc in enumerate(incidents, 1):
        inc.incident_id = "INC-%04d" % n
    return incidents
