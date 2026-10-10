"""
SSH brute-force detector for OpenSSH auth.log-style logs. Standard library only.

Rules:
  brute_force            >= N failed logins from one IP inside a short window (default 5 in 60s)
  user_spray             one IP tries >= M distinct usernames inside a window (default 8 in 10 min)
  slow_brute             >= N failures from one IP inside a long window (default 40 in 24h)
  success_after_failures a successful login from an IP that just failed >= K times (likely compromise)
  persistent_low_rate    (v2) a low-volume attacker that keeps coming back: >= F failures spread
                         over >= H distinct clock-hours. Added after the evasive attacker in the
                         synthetic data slipped past all four v1 rules.

Usage:
  python detector.py data/auth.log --year 2026
  python detector.py data/auth.log --year 2026 --allow 198.51.100.50 --json alerts.json --blocklist block.txt
"""
import argparse
import json
import re
import sys
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime

LINE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"sshd(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
# "Invalid user X from ..." lines are ignored on purpose: real logs also emit a
# "Failed password for invalid user X" line for the same attempt, so counting both would double-count.
FAILED = re.compile(
    r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+) port \d+"
)
ACCEPTED = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+"
)

V1_RULES = frozenset({"brute_force", "user_spray", "slow_brute", "success_after_failures"})
V2_RULES = V1_RULES | {"persistent_low_rate"}


@dataclass(frozen=True)
class Event:
    ts: datetime
    host: str
    ip: str
    user: str
    success: bool
    invalid_user: bool


@dataclass(frozen=True)
class Alert:
    rule: str
    severity: str
    ip: str
    first_seen: str
    count: int
    detail: str


@dataclass(frozen=True)
class Config:
    brute_threshold: int = 5
    brute_window: int = 60
    spray_users: int = 8
    spray_window: int = 600
    slow_threshold: int = 40
    slow_window: int = 86400
    compromise_fails: int = 5
    compromise_window: int = 600
    persist_fails: int = 8
    persist_hours: int = 6
    allowlist: frozenset = frozenset()
    rules: frozenset = V2_RULES


# ---------------------------------------------------------------- parsing

def parse_lines(lines, year):
    """Return (events, stats). Lines that are not sshd login results are counted as ignored."""
    events, ignored, bad = [], 0, 0
    for raw in lines:
        m = LINE.match(raw.rstrip("\n"))
        if not m:
            bad += 1
            continue
        msg = m.group("msg")
        f = FAILED.match(msg)
        a = None if f else ACCEPTED.match(msg)
        if not (f or a):
            ignored += 1
            continue
        try:
            ts = datetime.strptime(f"{year} {' '.join(m.group('ts').split())}", "%Y %b %d %H:%M:%S")
        except ValueError:
            bad += 1
            continue
        g = f or a
        events.append(Event(ts, m.group("host"), g.group("ip"), g.group("user"),
                            success=bool(a), invalid_user=bool(f and f.group("invalid"))))
    events.sort(key=lambda e: e.ts)
    return events, {"events": len(events), "ignored_sshd_lines": ignored, "unparseable_lines": bad}


# ---------------------------------------------------------------- window helpers

def count_window(times, window, threshold):
    """(first_trigger_time, peak_count) if any `window`-second span holds >= threshold events."""
    dq, peak, first = deque(), 0, None
    for t in times:
        dq.append(t)
        while (t - dq[0]).total_seconds() > window:
            dq.popleft()
        peak = max(peak, len(dq))
        if first is None and len(dq) >= threshold:
            first = t
    return (first, peak) if first else None


def distinct_window(items, window, threshold):
    """Same idea, but counts DISTINCT values (usernames) inside the window."""
    dq, cnt, peak, first = deque(), Counter(), 0, None
    for t, u in items:
        dq.append((t, u))
        cnt[u] += 1
        while (t - dq[0][0]).total_seconds() > window:
            _, old = dq.popleft()
            cnt[old] -= 1
            if cnt[old] == 0:
                del cnt[old]
        peak = max(peak, len(cnt))
        if first is None and len(cnt) >= threshold:
            first = t
    return (first, peak) if first else None


# ---------------------------------------------------------------- detection

def detect(events, cfg=Config()):
    by_ip = defaultdict(list)
    for e in events:
        by_ip[e.ip].append(e)

    alerts = []
    for ip, evs in by_ip.items():
        if ip in cfg.allowlist:
            continue
        evs.sort(key=lambda e: e.ts)
        fails = [e for e in evs if not e.success]
        fail_times = [e.ts for e in fails]

        if "brute_force" in cfg.rules and fails:
            hit = count_window(fail_times, cfg.brute_window, cfg.brute_threshold)
            if hit:
                alerts.append(Alert("brute_force", "high", ip, hit[0].isoformat(), hit[1],
                                    f"{hit[1]} failures within {cfg.brute_window}s"))

        if "user_spray" in cfg.rules and fails:
            hit = distinct_window([(e.ts, e.user) for e in fails], cfg.spray_window, cfg.spray_users)
            if hit:
                alerts.append(Alert("user_spray", "medium", ip, hit[0].isoformat(), hit[1],
                                    f"{hit[1]} distinct usernames within {cfg.spray_window}s"))

        if "slow_brute" in cfg.rules and fails:
            hit = count_window(fail_times, cfg.slow_window, cfg.slow_threshold)
            if hit:
                alerts.append(Alert("slow_brute", "medium", ip, hit[0].isoformat(), hit[1],
                                    f"{hit[1]} failures within {cfg.slow_window // 3600}h"))

        if "persistent_low_rate" in cfg.rules and fails:
            hours = {t.replace(minute=0, second=0, microsecond=0) for t in fail_times}
            if len(fail_times) >= cfg.persist_fails and len(hours) >= cfg.persist_hours:
                alerts.append(Alert("persistent_low_rate", "medium", ip, fail_times[0].isoformat(),
                                    len(fail_times),
                                    f"{len(fail_times)} failures spread over {len(hours)} distinct hours"))

        if "success_after_failures" in cfg.rules:
            for s in (e for e in evs if e.success):
                recent = [t for t in fail_times
                          if 0 <= (s.ts - t).total_seconds() <= cfg.compromise_window]
                if len(recent) >= cfg.compromise_fails:
                    alerts.append(Alert("success_after_failures", "critical", ip, s.ts.isoformat(),
                                        len(recent),
                                        f"login as '{s.user}' succeeded after {len(recent)} recent failures"))
                    break

    alerts.sort(key=lambda a: a.first_seen)
    return alerts


# ---------------------------------------------------------------- CLI

def main(argv=None):
    p = argparse.ArgumentParser(description="SSH brute-force detector (auth.log style)")
    p.add_argument("logfile")
    p.add_argument("--year", type=int, default=datetime.now().year,
                   help="syslog timestamps carry no year; default is the current year")
    p.add_argument("--allow", action="append", default=[], help="IP to never alert on (repeatable)")
    p.add_argument("--v1", action="store_true", help="disable the v2 persistent_low_rate rule")
    p.add_argument("--json", help="write alerts to this JSON file")
    p.add_argument("--blocklist", help="write one flagged IP per line to this file")
    a = p.parse_args(argv)

    with open(a.logfile, encoding="utf-8", errors="replace") as fh:
        events, stats = parse_lines(fh, a.year)
    cfg = Config(allowlist=frozenset(a.allow), rules=V1_RULES if a.v1 else V2_RULES)
    alerts = detect(events, cfg)

    print(f"Parsed {stats['events']} login events "
          f"({stats['ignored_sshd_lines']} other sshd lines ignored, {stats['unparseable_lines']} unparseable)")
    print(f"{len(alerts)} alerts from {len({x.ip for x in alerts})} IPs\n")
    print(f"{'severity':<9} {'rule':<24} {'ip':<16} {'first seen':<20} detail")
    for x in alerts:
        print(f"{x.severity:<9} {x.rule:<24} {x.ip:<16} {x.first_seen:<20} {x.detail}")

    if a.json:
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump([asdict(x) for x in alerts], fh, indent=2)
    if a.blocklist:
        with open(a.blocklist, "w", encoding="utf-8") as fh:
            fh.write("\n".join(sorted({x.ip for x in alerts})) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
