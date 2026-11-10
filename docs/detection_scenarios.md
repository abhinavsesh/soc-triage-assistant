# Detection Scenarios

Each scenario is a testable hypothesis: entity, signal, window and threshold, benign lookalike, and what would prove it wrong. Thresholds are starting points to be tuned during evaluation (Phase 4), not final values.

Two data sources are used, and the README must say so openly:

- **CICIDS2017 Tuesday (`data/raw/tuesday.csv`):** real labelled network flows. No usernames or login results, so only flow-level brute force can be measured.
- **Synthetic auth log (`data/sample/auth_sample.csv`):** has usernames, timestamps and success/failure, so all login-level scenarios can be demonstrated. Because it is synthetic, it proves the logic works, not that it works on real traffic.

---

## Part A: Login-level scenarios (synthetic auth log)

### Scenario S1: Brute force

- **MITRE ATT&CK:** T1110.001 Brute Force: Password Guessing
- **Log source:** authentication logs
- **Entity:** (user, source IP) pair
- **Signal:** count of failed logins
- **Window and threshold:** 5 or more failures within 5 minutes
- **Benign lookalike:** a user who forgot their password, or a service retrying with an expired password
- **Falsified if:** the rule alerts on single typos from known users, or misses the bob story at 13:02
- **Known evasion:** a slow attack (one attempt every 10 minutes) stays under the threshold

### Scenario S2: Password spraying

- **MITRE ATT&CK:** T1110.003 Brute Force: Password Spraying
- **Log source:** authentication logs
- **Entity:** source IP (not user, because each account sees only one or two failures)
- **Signal:** number of distinct usernames with failed logins from the same IP
- **Window and threshold:** 3 or more distinct users within 10 minutes, with each user having 2 or fewer failures
- **Benign lookalike:** a shared NAT or office gateway where several colleagues mistype passwords at the start of the day
- **Falsified if:** it alerts on the corporate NAT during the morning login rush, or misses the 02:10 story
- **Known evasion:** spreading attempts across many source IPs (botnet) or over many hours

### Scenario S3: Suspicious success after failures

- **MITRE ATT&CK:** T1078 Valid Accounts (result of a successful credential attack)
- **Log source:** authentication logs
- **Entity:** user
- **Signal:** a successful login preceded by failures for the same user, from a source IP the user has not successfully logged in from before
- **Window and threshold:** 3 or more failures in the 10 minutes before the success, AND the success IP is not in the user's history of previous successful logins
- **Benign lookalike:** a user typing their password wrong twice, then succeeding from their usual IP (the new-IP condition suppresses this)
- **Falsified if:** it alerts on alice's typo at 09:30, or misses bob's success at 13:03:44
- **Known evasion:** the attacker logs in from an IP already in the user's history (for example, through a compromised internal host), or succeeds on the first try with stolen credentials (no failures at all)

### Expected alerts on the sample file (derived by hand)

Source: `data/sample/auth_sample.csv` (18 rows).

| Rows (timestamp) | Expected alert | Reason |
|---|---|---|
| 13:02:10 to 13:03:20, bob from 203.0.113.45 (6 failures) | S1 | 6 failures in 70 seconds from one (user, IP) pair |
| 02:10:01 to 02:11:40, 4 users from 198.51.100.23 | S2 | 4 distinct users from one IP in under 2 minutes, 1 failure each |
| 13:03:44, bob success from 203.0.113.45 | S3 | 6 failures just before, and the IP is new (bob's history is 10.0.0.7) |

Rows that must NOT alert:

| Rows | Why not |
|---|---|
| 09:30:15 and 09:30:25, alice from 10.0.0.5 | One failure then success from her usual IP: a typo. Below every threshold, and the IP is known |
| Spraying rows, for S1 | Each (user, IP) pair has only 1 failure |
| Bob's 13:02 rows, for S2 | Only one distinct user from that IP |
| All other success rows | Normal logins from known IPs, with no preceding failures |

Cold-start caveat: "known IP" is computed from earlier successful logins in the data. The first event for a user has no history, so new-IP logic needs a baseline period. This is a real limitation for production.

---

## Part B: Flow-level scenarios (CICIDS2017 Tuesday, real labels)

There are no usernames or login results, so we detect the behaviour of brute forcing: many short connections to an authentication service.

### Scenario T1: FTP brute force (flow-level)

- **MITRE ATT&CK:** T1110.001 Brute Force: Password Guessing
- **Log source:** network flows (CICFlowMeter output)
- **Entity:** (source IP, destination port 21)
- **Signal:** number of flows in the window
- **Window and threshold:** 10 or more flows within 1 minute (provisional, see measurements below)
- **Benign lookalike:** a backup job or monitoring tool opening many short FTP connections
- **Falsified if:** benign FTP clients exceed the threshold as often as the attacker does
- **Known evasion:** slowing the attack to stay under the threshold, or distributing it across many source IPs

### Scenario T2: SSH brute force (flow-level)

- **MITRE ATT&CK:** T1110.001 Brute Force: Password Guessing
- **Entity:** (source IP, destination port 22)
- **Signal:** number of flows in the window, plus short flow duration and small, uniform packet counts per flow
- **Window and threshold:** 10 or more flows within 1 minute (provisional, to be tuned separately from T1)
- **Benign lookalike:** automation or configuration-management tools (for example Ansible) opening many SSH sessions
- **Falsified if:** it alerts on a legitimate admin automation host, or misses the labelled SSH-Patator period
- **Known evasion:** same as T1

### Scenario T3: Anomaly detection on flow features (ML)

- **Technique:** Isolation Forest, unsupervised
- **Input:** flow features such as duration, packet counts, bytes, and per-window counts. Labels are NOT used for training and only for evaluation.
- **Hypothesis:** brute-force flows are statistically unusual relative to benign traffic, so they receive higher anomaly scores
- **Falsified if:** precision and recall are no better than the threshold rule from T1 and T2
- **Known limitation:** an anomaly is not necessarily an attack, and a benign scan or backup can also score high

### Measured on Tuesday.csv (EDA findings)

- Labels: FTP-Patator 7,938 flows, SSH-Patator 5,897 flows. All attacks come from 172.16.0.1 to 192.168.10.50. One FTP-Patator flow targets port 80 (labelling quirk, outside the port 21/22 filter).
- Definitions: one row is one flow (one summarised connection). A window is one (source IP, destination port, minute) group. An attack window is a window containing at least one non-BENIGN flow.
- Flows per window on ports 21 and 22:

| | Windows | Mean | Median | Min | 75% | Max |
|---|---|---|---|---|---|---|
| Benign | 1,072 | 2.98 | 3 | 1 | 4 | 6 |
| Attack | 126 | 109.8 | 106 | 1 | 130.75 | 146 |

- Provisional threshold for T1 and T2: 10 flows per minute, chosen by looking at the table above.

### Baseline check at threshold 10 (window level)

- 1 of 126 attack windows is below the threshold (172.16.0.1, port 21, 09:17, 1 flow), probably the first partial minute of the attack.
- 0 of 1,072 benign windows reach the threshold.
- Implied result: TP 125, FN 1, FP 0, TN 1,072. Precision 1.00, recall about 0.992.
- Caveat: the threshold was chosen on the same data it is evaluated on, so this is optimistic. Phase 4 will tune on one part of the data and evaluate on another.
- Caveat: the separation is cleaner than real traffic, because the attacker is scripted and comes from a single IP.

### Dataset caveats specific to this file

- Every attack comes from one source IP, so a rule or model that uses source IP as a feature scores perfectly and means nothing. **Source IP, destination IP and Flow ID must not be model features.** They are used only for grouping.
- It is lab traffic with scripted attacks, so real attackers are noisier and slower. Results show the method works, not that thresholds transfer to production.
- The file has NaN and infinite values, duplicates and padded column names, handled in Phase 3.
- CICIDS timestamps have no AM/PM marker, so afternoon times can appear as morning. Window counts are unaffected because only ordering matters.

---

## Which scenario can be measured on which dataset

| Scenario | CICIDS Tuesday (real labels) | Synthetic auth log |
|---|---|---|
| T1/T2 flow-level brute force | Yes | n/a |
| T3 anomaly detection | Yes | n/a |
| S1 brute force (logins) | No (no usernames) | Yes |
| S2 password spraying | No | Yes |
| S3 success after failures | No | Yes |

Only flow-level brute force is evaluated against real labels. S2 and S3 are demonstrated on synthetic data, which proves the logic works but not that it works on real traffic.
