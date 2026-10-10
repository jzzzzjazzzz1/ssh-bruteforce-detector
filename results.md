Synthetic day of logs: 487 login events, 26 source IPs (6 attackers, 20 benign). Scored per source IP.


## Overall detection (per IP)

| Config | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| v1 rules | 5 | 1 | 1 | 19 | 0.83 | 0.83 | 0.83 |
| v1 rules + allowlist | 5 | 0 | 1 | 20 | 1.00 | 0.83 | 0.91 |
| v2 rules (+persistent_low_rate) | 6 | 1 | 0 | 19 | 0.86 | 1.00 | 0.92 |
| v2 rules + allowlist | 6 | 0 | 0 | 20 | 1.00 | 1.00 | 1.00 |

## Which rule fires on which scenario (v2, no allowlist)

Cells show IPs flagged by that rule / IPs in the scenario.

| Scenario | Label | IPs | brute_force | user_spray | slow_brute | success_after_failures | persistent_low_rate | Any rule |
|---|---|---|---|---|---|---|---|---|
| compromise | attacker | 1 | 1/1 | - | - | 1/1 | - | 1/1 |
| evasive_low_rate | attacker | 1 | - | - | - | - | 1/1 | 1/1 |
| fast_brute | attacker | 2 | 2/2 | - | 2/2 | - | - | 2/2 |
| slow_brute | attacker | 1 | - | - | 1/1 | - | 1/1 | 1/1 |
| user_spray | attacker | 1 | - | 1/1 | - | - | - | 1/1 |
| background_noise | benign | 15 | - | - | - | - | - | 0/15 |
| normal_user | benign | 4 | - | - | - | - | - | 0/4 |
| stale_service_credentials | benign | 1 | 1/1 | - | 1/1 | - | - | 1/1 |

## brute_force threshold sensitivity (60s window, this rule only, no allowlist)

| Failures in 60s | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| 3 | 4 | 1 | 2 | 0.80 | 0.67 |
| 5 | 3 | 1 | 3 | 0.75 | 0.50 |
| 10 | 3 | 0 | 3 | 1.00 | 0.50 |
| 20 | 3 | 0 | 3 | 1.00 | 0.50 |
| 50 | 1 | 0 | 5 | 1.00 | 0.17 |
| 100 | 0 | 0 | 6 | 0.00 | 0.00 |

## Remaining errors (v2 + allowlist)

- Missed attackers: none
- False positives: none
- Note: scores on synthetic data show the rules work as designed, not how they would perform on real traffic.
