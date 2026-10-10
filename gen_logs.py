"""
Generate a synthetic OpenSSH auth.log plus labeled ground truth (per source IP).

Everything is fake: IPs come from the RFC 5737 documentation ranges (never routable),
hostnames and users are invented. The point is to test a DETECTOR against known patterns.

Usage: python gen_logs.py [--seed 42] [--out data]
Writes: data/auth.log, data/ground_truth.json
"""
import argparse
import json
import pathlib
import random
from datetime import datetime, timedelta

HOST = "web01"
DAY = datetime(2026, 10, 10)
VALID_USERS = {"root", "alice", "bob", "carol", "dave", "backup"}
COMMON_NAMES = ["admin", "ubuntu", "test", "oracle", "postgres", "git", "ftp", "pi", "user", "guest",
                "mysql", "jenkins", "deploy", "ansible", "hadoop", "nagios", "tomcat", "www", "mail",
                "support", "info", "dev", "demo", "web", "steam", "minecraft", "teamspeak", "redis",
                "elastic", "kafka", "vagrant", "docker", "zabbix", "svn", "backup1", "ec2-user",
                "centos", "debian", "operator", "default"]


class Gen:
    def __init__(self, seed):
        self.rng = random.Random(seed)
        self.rows = []     # (ts, line)
        self.truth = {}    # ip -> {label, scenario, expected_rules}

    def label(self, ip, label, scenario, expected_rules=()):
        self.truth[ip] = {"label": label, "scenario": scenario, "expected_rules": list(expected_rules)}

    def _emit(self, ts, msg):
        pid = self.rng.randint(1000, 32000)
        stamp = f"{ts.strftime('%b')} {ts.day:2d} {ts.strftime('%H:%M:%S')}"
        self.rows.append((ts, f"{stamp} {HOST} sshd[{pid}]: {msg}"))

    def fail(self, ts, user, ip):
        port = self.rng.randint(32768, 60999)
        if user not in VALID_USERS:
            self._emit(ts, f"Invalid user {user} from {ip} port {port}")
            self._emit(ts, f"Failed password for invalid user {user} from {ip} port {port} ssh2")
        else:
            self._emit(ts, f"Failed password for {user} from {ip} port {port} ssh2")

    def accept(self, ts, user, ip):
        port = self.rng.randint(32768, 60999)
        method = self.rng.choice(["password", "publickey"])
        self._emit(ts, f"Accepted {method} for {user} from {ip} port {port} ssh2")

    def noise(self, ts):
        # other sshd chatter the parser must ignore
        self._emit(ts, f"Connection closed by authenticating user root 192.0.2.250 port 40001 [preauth]")


def generate(seed=42):
    g = Gen(seed)
    r = g.rng

    # ---- benign: normal users, occasional typos before a successful login
    for i, user in enumerate(["alice", "bob", "carol", "dave"]):
        ip = f"198.51.100.{10 + i}"
        g.label(ip, "benign", "normal_user")
        for _ in range(r.randint(3, 6)):
            t = DAY + timedelta(seconds=r.randint(7 * 3600, 19 * 3600))
            if r.random() < 0.3:
                for _ in range(r.randint(1, 2)):
                    g.fail(t, user, ip)
                    t += timedelta(seconds=r.randint(3, 8))
            g.accept(t, user, ip)

    # ---- benign but noisy: cron job with a stale password retrying every 10s for 10 min
    ip = "198.51.100.50"
    g.label(ip, "benign", "stale_service_credentials")
    for k in range(61):
        g.fail(DAY + timedelta(hours=2, seconds=10 * k), "backup", ip)

    # ---- benign: internet background noise, 1-2 failed attempts per IP
    for n in range(15):
        ip = f"192.0.2.{100 + n}"
        g.label(ip, "benign", "background_noise")
        for _ in range(r.randint(1, 2)):
            g.fail(DAY + timedelta(seconds=r.randint(0, 86399)), r.choice(["root", "admin", "test"]), ip)

    # ---- attackers
    ip = "203.0.113.5"   # fast brute force: 150 attempts in 2 minutes
    g.label(ip, "attacker", "fast_brute", ["brute_force"])
    start = DAY + timedelta(hours=3, minutes=14)
    names = ["root", "admin", "ubuntu", "test", "oracle"]
    for k in range(150):
        g.fail(start + timedelta(seconds=k * 120 / 150), names[k % len(names)], ip)

    ip = "203.0.113.6"   # shorter fast brute force against root
    g.label(ip, "attacker", "fast_brute", ["brute_force"])
    start = DAY + timedelta(hours=11, minutes=40)
    for k in range(40):
        g.fail(start + timedelta(seconds=k * 50 / 40), "root", ip)

    ip = "203.0.113.7"   # password spraying: 30 different usernames, one try each, 3 per minute
    g.label(ip, "attacker", "user_spray", ["user_spray"])
    start = DAY + timedelta(hours=5, minutes=30)
    for k, name in enumerate(r.sample(COMMON_NAMES, 30)):
        g.fail(start + timedelta(seconds=20 * k), name, ip)

    ip = "203.0.113.8"   # slow brute force: 1 attempt every ~4 min for 8 hours
    g.label(ip, "attacker", "slow_brute", ["slow_brute"])
    start = DAY + timedelta(hours=9)
    for k in range(120):
        g.fail(start + timedelta(seconds=240 * k + r.randint(-20, 20)), "root", ip)

    ip = "203.0.113.9"   # evasive: 1 attempt every 2 hours (12/day), under every v1 threshold
    g.label(ip, "attacker", "evasive_low_rate", ["persistent_low_rate"])
    for k in range(12):
        g.fail(DAY + timedelta(minutes=30, hours=2 * k, seconds=r.randint(0, 120)), "root", ip)

    ip = "203.0.113.10"  # successful compromise: 25 fast failures on alice, then a login works
    g.label(ip, "attacker", "compromise", ["brute_force", "success_after_failures"])
    start = DAY + timedelta(hours=16, minutes=20)
    for k in range(25):
        g.fail(start + timedelta(seconds=k * 45 / 25), "alice", ip)
    g.accept(start + timedelta(seconds=50), "alice", ip)

    # sshd lines the parser should ignore
    for _ in range(20):
        g.noise(DAY + timedelta(seconds=r.randint(0, 86399)))

    g.rows.sort(key=lambda x: x[0])
    return [line for _, line in g.rows], g.truth


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--out", default="data")
    a = p.parse_args()
    lines, truth = generate(a.seed)
    out = pathlib.Path(a.out)
    out.mkdir(exist_ok=True)
    (out / "auth.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (out / "ground_truth.json").write_text(json.dumps(truth, indent=2), encoding="utf-8")
    n_att = sum(1 for v in truth.values() if v["label"] == "attacker")
    print(f"Wrote {len(lines)} log lines, {len(truth)} source IPs ({n_att} attackers) to {out}/")


if __name__ == "__main__":
    main()
