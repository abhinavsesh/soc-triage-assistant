# Risk Scoring and MITRE ATT&CK Mapping: Design, Results and Limitations

## 1. Pipeline

detector output -> incident (entity + signals + evidence) -> risk score (additive, with breakdown) -> MITRE tags (with confidence)

Detections are grouped into one incident per entity, so one attacker produces one alert instead of one per window.

## 2. Risk score

- Additive points per signal, capped at 100.
- Severity bands: 70 and above is high, 40 to 69 is medium, below 40 is low.
- Every alert carries a per-signal breakdown, so an analyst can see exactly why it scored what it did.
- Unknown signal names raise an error, so a typo cannot silently score 0.

| Signal | Points |
|---|---|
| flow_rule_hit | 40 |
| flow_volume_3x_threshold | 20 |
| flow_sustained_5plus_windows | 15 |
| auth_s1_bruteforce | 30 |
| auth_s2_spraying | 30 |
| auth_s3_success_after_failures | 40 |
| new_source_ip | 15 |
| off_hours | 10 |
| multi_scenario_correlation | 20 |

## 3. Verified results

Run: `python scripts/phase5.py` on `data/sample/auth_sample.csv` and `data/raw/tuesday.csv`. All 19 tests passed at this point.

| Score | Severity | Entity | Signals | Techniques |
|---|---|---|---|---|
| 100 | high | user:bob | S1 (30), S3 (40), new IP (15), correlation (20) = 105, capped at 100 | T1110.001, T1078 |
| 75 | high | ip:172.16.0.1:port:21 | rule hit (40), volume 3x (20), sustained (15) | T1110 |
| 75 | high | ip:172.16.0.1:port:22 | rule hit (40), volume 3x (20), sustained (15) | T1110 |
| 40 | medium | ip:198.51.100.23 | spraying (30), off-hours (10) | T1110.003 |

- Alice's typo (one failure, then success from her usual IP) produces no incident, as intended.
- The auth results come from a synthetic 18-row file, so they show the logic works as designed, not that it works on real traffic.
- The flow thresholds come from a per-service rule (2 x benign maximum) whose baseline uses labels to find benign windows.

## 4. Limitations of the risk score

- Weights are judgement, not tuned. They should be calibrated against analyst dispositions (true or false positive) once the dashboard collects them.
- The score is a prioritisation aid. It is not a probability of compromise.
- The cap at 100 hides differences between very severe incidents (bob at 105 and a hypothetical 130 both show 100).
- Signals can overlap. S3 already requires a new IP, so new_source_ip is not added for S3 to avoid double counting.
- S1 and S3 count failures per (user, source IP). Failures from different IPs are not combined, so a distributed attack against one account can fall below every threshold.
- Evidence is kept as a list of observations per scenario. The LLM packet shows at most 5 per scenario and records the total.
- Incidents are grouped per entity without splitting on time gaps, so a long campaign becomes one incident.
- Off-hours is not used for flow data because CICIDS timestamps have no AM/PM marker.
- An attacker who knows the rules can keep the score low: stay under thresholds, spread attempts across IPs, log in from an IP already in the user's history, or flood a victim with noise to bury real alerts.

## 5. MITRE ATT&CK mapping

ATT&CK version checked: <FILL IN: version shown on attack.mitre.org>
Date checked: <FILL IN>

| Signal | Technique | Tactic | Confidence |
|---|---|---|---|
| auth_s1_bruteforce | T1110.001 Brute Force: Password Guessing | Credential Access | medium |
| auth_s2_spraying | T1110.003 Brute Force: Password Spraying | Credential Access | medium |
| auth_s3_success_after_failures | T1078 Valid Accounts | Initial Access, Persistence, Privilege Escalation, Defense Evasion (called Stealth in newer ATT&CK versions) | low |
| flow_rule_hit | T1110 Brute Force | Credential Access | low |

Notes:
- Sub-techniques are used only when the evidence supports them. Flow data cannot show how credentials were guessed, so it maps to the broader T1110.
- T1078 appears under several tactics because valid credentials are useful at several stages of an attack. Tactic names were checked on <FILL IN: date>. If the version above differs from the one used when this table was written, recheck them.
- Confidence records that each mapping is a hypothesis.

## 6. Limitations of rule-based mapping

1. A mapping is a hypothesis. The same behaviour can fit several techniques: many flows to port 22 could be password guessing, scanning or a misbehaving client.
2. Flow data has no usernames or login results, so it supports only the broad T1110, with low confidence.
3. Success after failures does not prove misuse of a valid account. T1078 is the likely explanation, not a confirmed one.
4. Coverage is four mappings. A missing tag means "not mapped", not "not an attack".
5. A false positive is mapped as confidently as a true positive, so downstream text (including the LLM in Phase 6) must say "consistent with" and never "confirmed".
6. ATT&CK changes between versions (IDs, tactic names and tactic structure), so the mapping must be versioned and reviewed.
7. If an attacker evades the underlying rule (slow attempts, many IPs, a known IP), no technique is tagged at all.
8. The mapping is static. It does not learn from analyst feedback.
