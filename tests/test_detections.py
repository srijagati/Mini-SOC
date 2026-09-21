import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import detector
import incidents
import log_generator
from detector import Event

T0 = datetime(2026, 9, 1, 12, 0, 0)


def fail(i, user="bob", ip="1.2.3.4", gap=2):
    return Event(T0 + timedelta(seconds=gap * i), 4625, "DC01", user, ip, "3", "0xC000006A")


def ok(seconds, user="bob", ip="1.2.3.4"):
    return Event(T0 + timedelta(seconds=seconds), 4624, "DC01", user, ip, "3", "")


class DetectionTests(unittest.TestCase):
    def rules(self, events):
        return [a.rule for a in detector.run_detections(events)]

    def test_brute_force_detected(self):
        self.assertIn("BRUTE_FORCE", self.rules([fail(i) for i in range(12)]))

    def test_few_failures_not_brute_force(self):
        self.assertNotIn("BRUTE_FORCE", self.rules([fail(i) for i in range(4)]))

    def test_repeated_failures_low_alert(self):
        self.assertEqual(self.rules([fail(i, ip="10.0.0.5") for i in range(6)]),
                         ["REPEATED_FAILED_LOGIN"])

    def test_password_spray(self):
        events = [fail(i, user="u%d" % i) for i in range(9)]
        self.assertIn("PASSWORD_SPRAY", self.rules(events))

    def test_slow_failures_split_into_separate_bursts(self):
        events = [fail(i, gap=600) for i in range(12)]  # 10 minutes apart
        self.assertEqual(self.rules(events), [])

    def test_success_after_brute_force_is_critical(self):
        events = [fail(i) for i in range(12)] + [ok(60)]
        alerts = detector.run_detections(events)
        self.assertIn("Critical", [a.severity for a in alerts])

    def test_lockout_alert(self):
        e = Event(T0, 4740, "DC01", "bob", "10.0.0.9", "", "")
        self.assertEqual(self.rules([e]), ["ACCOUNT_LOCKOUT"])

    def test_incident_grouping_and_severity(self):
        events = [fail(i) for i in range(12)] + [ok(60)]
        tickets = incidents.create_incidents(detector.run_detections(events))
        self.assertEqual(len(tickets), 1)
        self.assertEqual(tickets[0].severity, "Critical")
        self.assertEqual(tickets[0].incident_id, "INC-0001")


class EndToEndTests(unittest.TestCase):
    def test_synthetic_data_finds_all_planted_attacks(self):
        events = log_generator.generate_events(seed=42)
        # round-trip through CSV like the real pipeline does
        import tempfile, os
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "log.csv")
            log_generator.write_csv(events, path)
            loaded = detector.load_events(path)
        rules = [a.rule for a in detector.run_detections(loaded)]
        for expected in ("BRUTE_FORCE", "PASSWORD_SPRAY", "COMPROMISED_ACCOUNT", "ACCOUNT_LOCKOUT"):
            self.assertIn(expected, rules)

    def test_normal_activity_raises_no_alerts(self):
        import random
        events = log_generator._normal_activity(random.Random(7), datetime(2026, 9, 1), 24)
        with_typos = [e for e in events if e["EventID"] == 4625]
        self.assertTrue(with_typos)  # the baseline really contains typo failures
        import tempfile, os
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "normal.csv")
            log_generator.write_csv(events, path)
            self.assertEqual(detector.run_detections(detector.load_events(path)), [])


if __name__ == "__main__":
    unittest.main()
