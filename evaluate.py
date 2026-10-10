"""
Score the detector against the labeled synthetic logs.
Usage: python gen_logs.py && python evaluate.py
Writes results/results.md and prints the same tables.

Scoring is per source IP: an IP is "flagged" if any enabled rule alerts on it.
  TP = attacker IP flagged      FN = attacker IP not flagged
  FP = benign IP flagged        TN = benign IP not flagged
"""
import json
import pathlib
import sys
from collections import defaultdict
from dataclasses import replace

from detector import Config, V1_RULES, V2_RULES, detect, parse_lines

YEAR = 2026
STALE_CRON_IP = "198.51.100.50"   # the known-good service host an operator would allowlist
ALL_RULES = ["brute_force", "user_spray", "slow_brute", "success_after_failures", "persistent_low_rate"]


def load(data_dir="data"):
    d = pathlib.Path(data_dir)
    if not (d / "auth.log").exists():
        sys.exit("data/auth.log not found. Run: python gen_logs.py")
    with open(d / "auth.log", encoding="utf-8") as fh:
        events, _ = parse_lines(fh, YEAR)
    truth = json.loads((d / "ground_truth.json").read_text(encoding="utf-8"))
    return events, truth


def score(alerts, truth):
    flagged = {a.ip for a in alerts}
    tp = sum(1 for ip, v in truth.items() if v["label"] == "attacker" and ip in flagged)
    fn = sum(1 for ip, v in truth.items() if v["label"] == "attacker" and ip not in flagged)
    fp = sum(1 for ip, v in truth.items() if v["label"] == "benign" and ip in flagged)
    tn = sum(1 for ip, v in truth.items() if v["label"] == "benign" and ip not in flagged)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, precision=prec, recall=rec, f1=f1)


def md_table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def main():
    events, truth = load()
    n_att = sum(1 for v in truth.values() if v["label"] == "attacker")
    sections = [f"Synthetic day of logs: {len(events)} login events, {len(truth)} source IPs "
                f"({n_att} attackers, {len(truth) - n_att} benign). Scored per source IP.\n"]

    # ---- 1. overall: v1 vs v2, with and without the allowlist
    configs = [
        ("v1 rules", Config(rules=V1_RULES)),
        ("v1 rules + allowlist", Config(rules=V1_RULES, allowlist=frozenset({STALE_CRON_IP}))),
        ("v2 rules (+persistent_low_rate)", Config(rules=V2_RULES)),
        ("v2 rules + allowlist", Config(rules=V2_RULES, allowlist=frozenset({STALE_CRON_IP}))),
    ]
    rows = []
    for name, cfg in configs:
        s = score(detect(events, cfg), truth)
        rows.append([name, s["tp"], s["fp"], s["fn"], s["tn"],
                     f"{s['precision']:.2f}", f"{s['recall']:.2f}", f"{s['f1']:.2f}"])
    sections.append("## Overall detection (per IP)\n\n" +
                    md_table(["Config", "TP", "FP", "FN", "TN", "Precision", "Recall", "F1"], rows))

    # ---- 2. which rule catches which scenario (v2, no allowlist)
    alerts = detect(events, Config(rules=V2_RULES))
    caught = defaultdict(set)
    for a in alerts:
        caught[a.ip].add(a.rule)
    by_scn = defaultdict(list)
    for ip, v in truth.items():
        by_scn[(v["label"], v["scenario"])].append(ip)
    rows = []
    for (label, scn), ips in sorted(by_scn.items()):
        marks = []
        for rule in ALL_RULES:
            n = sum(1 for ip in ips if rule in caught[ip])
            marks.append("-" if n == 0 else f"{n}/{len(ips)}")
        flagged = sum(1 for ip in ips if caught[ip])
        rows.append([scn, label, len(ips)] + marks + [f"{flagged}/{len(ips)}"])
    sections.append("## Which rule fires on which scenario (v2, no allowlist)\n\n"
                    "Cells show IPs flagged by that rule / IPs in the scenario.\n\n" +
                    md_table(["Scenario", "Label", "IPs"] + ALL_RULES + ["Any rule"], rows))

    # ---- 3. threshold sensitivity for brute_force alone
    rows = []
    for thr in [3, 5, 10, 20, 50, 100]:
        cfg = Config(rules=frozenset({"brute_force"}), brute_threshold=thr)
        s = score(detect(events, cfg), truth)
        rows.append([thr, s["tp"], s["fp"], s["fn"], f"{s['precision']:.2f}", f"{s['recall']:.2f}"])
    sections.append("## brute_force threshold sensitivity (60s window, this rule only, no allowlist)\n\n" +
                    md_table(["Failures in 60s", "TP", "FP", "FN", "Precision", "Recall"], rows))

    # ---- 4. what is still missed / still false-alarming
    final = detect(events, Config(rules=V2_RULES, allowlist=frozenset({STALE_CRON_IP})))
    flagged = {a.ip for a in final}
    missed = [ip for ip, v in truth.items() if v["label"] == "attacker" and ip not in flagged]
    false_pos = [ip for ip, v in truth.items() if v["label"] == "benign" and ip in flagged]
    sections.append("## Remaining errors (v2 + allowlist)\n\n"
                    f"- Missed attackers: {missed or 'none'}\n"
                    f"- False positives: {false_pos or 'none'}\n"
                    "- Note: scores on synthetic data show the rules work as designed, not how they "
                    "would perform on real traffic.")

    report = "\n\n".join(sections) + "\n"
    out = pathlib.Path("results")
    out.mkdir(exist_ok=True)
    (out / "results.md").write_text(report, encoding="utf-8")
    print(report)


if __name__ == "__main__":
    main()
