"""Run with: python -m unittest -v"""
import unittest
from datetime import datetime, timedelta

from detector import Config, V1_RULES, detect, parse_lines

T0 = datetime(2026, 10, 10, 12, 0, 0)


def fail_line(ts, user, ip, invalid=False):
    stamp = f"{ts.strftime('%b')} {ts.day:2d} {ts.strftime('%H:%M:%S')}"
    who = f"invalid user {user}" if invalid else user
    return f"{stamp} web01 sshd[100]: Failed password for {who} from {ip} port 5000 ssh2"


def ok_line(ts, user, ip):
    stamp = f"{ts.strftime('%b')} {ts.day:2d} {ts.strftime('%H:%M:%S')}"
    return f"{stamp} web01 sshd[100]: Accepted password for {user} from {ip} port 5000 ssh2"


def run(lines, **kw):
    events, _ = parse_lines(lines, 2026)
    return detect(events, Config(**kw))


class ParserTests(unittest.TestCase):
    def test_parses_failed_accepted_and_ignores_the_rest(self):
        lines = [
            fail_line(T0, "root", "203.0.113.1"),
            fail_line(T0, "admin", "203.0.113.1", invalid=True),
            ok_line(T0, "alice", "198.51.100.1"),
            "Oct 10 12:00:00 web01 sshd[1]: Invalid user admin from 203.0.113.1 port 5000",
            "Oct 10 12:00:00 web01 CRON[2]: pam_unix(cron:session): session opened",
            "garbage line",
        ]
        events, stats = parse_lines(lines, 2026)
        self.assertEqual(len(events), 3)
        self.assertEqual(stats["unparseable_lines"], 2)          # CRON line + garbage
        self.assertEqual(stats["ignored_sshd_lines"], 1)         # the "Invalid user" line
        self.assertTrue(events[1].invalid_user)
        self.assertTrue(events[2].success)

    def test_single_digit_day_padding(self):
        events, _ = parse_lines(["Oct  5 03:04:05 web01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"], 2026)
        self.assertEqual(events[0].ts, datetime(2026, 10, 5, 3, 4, 5))


class RuleTests(unittest.TestCase):
    def test_brute_force_fires_at_threshold_not_below(self):
        ip = "203.0.113.1"
        four = [fail_line(T0 + timedelta(seconds=i), "root", ip) for i in range(4)]
        five = [fail_line(T0 + timedelta(seconds=i), "root", ip) for i in range(5)]
        self.assertEqual([a for a in run(four) if a.rule == "brute_force"], [])
        self.assertEqual(len([a for a in run(five) if a.rule == "brute_force"]), 1)

    def test_failures_spread_outside_window_do_not_trigger_brute_force(self):
        ip = "203.0.113.1"
        lines = [fail_line(T0 + timedelta(seconds=70 * i), "root", ip) for i in range(10)]
        self.assertEqual([a for a in run(lines) if a.rule == "brute_force"], [])

    def test_user_spray(self):
        ip = "203.0.113.2"
        lines = [fail_line(T0 + timedelta(seconds=30 * i), f"user{i}", ip, invalid=True) for i in range(10)]
        rules = {a.rule for a in run(lines)}
        self.assertIn("user_spray", rules)
        self.assertNotIn("brute_force", rules)   # only 2 per minute

    def test_typo_then_success_is_benign(self):
        ip = "198.51.100.5"
        lines = [fail_line(T0, "alice", ip), fail_line(T0 + timedelta(seconds=4), "alice", ip),
                 ok_line(T0 + timedelta(seconds=9), "alice", ip)]
        self.assertEqual(run(lines), [])

    def test_success_after_failures_is_critical(self):
        ip = "203.0.113.3"
        lines = [fail_line(T0 + timedelta(seconds=i), "alice", ip) for i in range(6)]
        lines.append(ok_line(T0 + timedelta(seconds=10), "alice", ip))
        crit = [a for a in run(lines) if a.severity == "critical"]
        self.assertEqual(len(crit), 1)
        self.assertEqual(crit[0].rule, "success_after_failures")

    def test_allowlist_suppresses_alerts(self):
        ip = "198.51.100.50"
        lines = [fail_line(T0 + timedelta(seconds=i), "backup", ip) for i in range(30)]
        self.assertTrue(run(lines))
        self.assertEqual(run(lines, allowlist=frozenset({ip})), [])

    def test_persistent_low_rate_catches_what_v1_misses(self):
        ip = "203.0.113.9"
        lines = [fail_line(T0.replace(hour=0) + timedelta(hours=2 * i), "root", ip) for i in range(12)]
        self.assertEqual(run(lines, rules=V1_RULES), [])
        self.assertEqual([a.rule for a in run(lines)], ["persistent_low_rate"])


if __name__ == "__main__":
    unittest.main()
