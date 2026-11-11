# Phase 4 Evaluation Notes (CICIDS2017 Tuesday, window level)

## Setup

- Data: `data/raw/tuesday.csv`, FTP-Patator and SSH-Patator against 192.168.10.50, all attacks from 172.16.0.1.
- Unit of evaluation: one window = (Source IP, Destination Port, minute), ports 21 and 22 only. One alert per window.
- Window counts: port 21 has 564 windows (63 attack, prevalence 0.112). Port 22 has 634 windows (63 attack, prevalence 0.099).
- Features: flow_count, mean_duration, mean_fwd_packets. Source IP, Destination Port and Label are never model inputs.
- Metrics: precision, recall, F1, false-positive rate, ROC-AUC, PR-AUC. Accuracy is not used because of class imbalance.

## Experiment 1: train/tune on FTP (port 21), test on SSH (port 22)

| Detector | Alerts | TP | FP | FN | TN | Precision | Recall | F1 | FPR | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|---|---|---|---|---|
| A: threshold rule (flows >= 5) | 110 | 63 | 47 | 0 | 524 | 0.573 | 1.00 | 0.728 | 0.082 | 1.000 | 1.000 |
| B: Isolation Forest, all features | 634 | 63 | 571 | 0 | 0 | 0.099 | 1.00 | 0.181 | 1.000 | 0.972 | 0.662 |
| C: Isolation Forest, no flow_count | 634 | 63 | 571 | 0 | 0 | 0.099 | 1.00 | 0.181 | 1.000 | 0.849 | 0.269 |

Findings:
- flow_count ranks SSH windows perfectly (AUC 1.0). The problem was the threshold, not the signal.
- The threshold of 5 was chosen on FTP, where benign windows reach at most 4 flows. SSH benign windows reach 6, so the rule raised 47 false positives. The false positives were internal hosts (192.168.10.12 and 192.168.10.14) with 5-6 flows per window, regular timing and near-identical durations. This looks like scheduled or automated SSH activity, which is likely but not confirmed.
- B and C alerted on every window (634 of 634). Recall of 1.0 is meaningless when everything alerts, and precision equals the attack prevalence.
- The Isolation Forest ranking was good (B AUC 0.972) but the threshold, chosen using training labels on FTP, was far too low for SSH scores.
- Without flow_count the ranking degrades (PR-AUC 0.662 to 0.269, against prevalence 0.099). Behavioural features carry some signal, but volume carries most of it.
- Training data contained 11% attack windows, which weakens the assumption that anomalies are rare.

## Diagnostics

flow_count by service and class:

| Port | Class | Windows | Mean | Max |
|---|---|---|---|---|
| 21 | benign | 501 | 2.1 | 4 |
| 21 | attack | 63 | 126.0 | 146 |
| 22 | benign | 571 | 3.7 | 6 |
| 22 | attack | 63 | 93.6 | 110 |

Isolation Forest scores (higher = more anomalous):
- Train (FTP): ROC-AUC 0.954, PR-AUC 0.568. Benign median -0.153, attack median 0.052.
- Test (SSH): ROC-AUC 0.972, PR-AUC 0.662. Benign median 0.204, attack median 0.239.
- Even benign SSH windows score high (median 0.204) compared with benign FTP (-0.153). SSH traffic looks unusual to a model fitted on FTP, which is distribution shift between services.
- Correction to an earlier hypothesis: attacks did look anomalous on FTP training data, so "attacks look normal because they are dense" was wrong for this run. The failures were threshold selection and cross-service shift.

## Experiment 2: benign-only baseline, percentile threshold, both directions

The Isolation Forest is fitted on benign windows only of the training service. The threshold is a percentile of the benign training scores, not chosen with labels.

| Direction | Quantile | TP | FP | FN | TN | Precision | Recall | FPR | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|---|---|---|---|
| FTP -> SSH | 0.95 | 63 | 562 | 0 | 9 | 0.101 | 1.0 | 0.984 | 0.373 | 0.086 |
| FTP -> SSH | 0.99 | 63 | 510 | 0 | 61 | 0.110 | 1.0 | 0.893 | 0.373 | 0.086 |
| SSH -> FTP | 0.95 | 63 | 426 | 0 | 75 | 0.129 | 1.0 | 0.850 | 0.998 | 0.968 |
| SSH -> FTP | 0.99 | 63 | 1 | 0 | 500 | 0.984 | 1.0 | 0.002 | 0.998 | 0.968 |

Findings:
- Results depend on direction. FTP -> SSH has ROC-AUC 0.373, which is worse than random. SSH -> FTP has 0.998.
- A model trained only on benign FTP sees benign SSH as highly unusual and the SSH attacks as relatively ordinary.
- Baselines and thresholds must be per service (per entity). A percentile threshold only controls the false-alarm rate when the baseline matches the target environment.
- A single train/test split must never be reported alone.

## Experiment 3: per-service evaluation with 5-fold cross-validation

Isolation Forest: fitted per service on the benign windows of the training folds, threshold at the 99th percentile of benign training scores.

| Detector | Service | TP | FP | FN | TN | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|---|
| Isolation Forest, q=0.99 | FTP | 63 | 5 | 0 | 496 | 0.926 | 1.0 | 0.962 | 0.010 |
| Isolation Forest, q=0.99 | SSH | 63 | 6 | 0 | 565 | 0.913 | 1.0 | 0.955 | 0.011 |
| Rule, threshold = 2 x benign max | FTP | 62 | 0 | 1 | 501 | 1.0 | 0.984 | 0.992 | 0.0 |
| Rule, threshold = 2 x benign max | SSH | 63 | 0 | 0 | 571 | 1.0 | 1.0 | 1.000 | 0.0 |

Findings:
- Per-service baselines remove the cross-service failure seen in Experiments 1 and 2.
- The rule has no false positives. The Isolation Forest has 5-6 false positives per service but catches all attack windows.
- The single FTP rule miss is a low-volume attack window (below the threshold of 8). It is probably the 1-flow window at the start of the attack seen during EDA. This has not been confirmed by printing the row, and it has not been checked whether the Isolation Forest scores that window above its threshold.
- Invalid test, kept for the record: a "first half / second half" rule evaluation produced tp=0, fn=0 because rows are ordered by Source IP, so every attack window sorted into the first half and the held-out half had no attacks. It was replaced by the cross-validated rule above.

## Conclusions

- On this lab data, a per-service count threshold is the strongest and simplest detector. It is cheap, explainable and has no false positives.
- Isolation Forest adds value mainly for low-volume windows, at the cost of a few extra false alarms. Whether that trade is worthwhile depends on analyst capacity.
- Thresholds and baselines are local to a service. A single global threshold or model does not transfer.
- The first saved model (`iforest_v1`, threshold 0.003) alerted on every window and was deleted. A per-service model has not been saved yet.

## Limitations

- One scripted attacker and one source IP. Results are optimistic compared with real traffic. Real attackers can be slow, distributed and noisy.
- Attack volume is very different from benign volume, so the problem is easier than real brute force.
- Cross-validation folds are random, not time-ordered, so neighbouring minutes can appear in both train and test. Benign leakage makes the Isolation Forest numbers optimistic.
- Labels were used only to select benign rows for the baseline (and, in Experiment 1, to pick thresholds). The system is therefore not purely unsupervised.
- The multiplier of 2 in the rule and the 0.99 percentile were chosen by judgement, not tuned.
- Window-level metrics, not event-level. A slow or distributed attack would evade all three detectors.
- The date ambiguity (d/m/Y) was fixed in loading, and CICIDS timestamps have no AM/PM marker, so afternoon times can appear as morning.
- A supervised classifier (T19) was skipped. With one scripted attacker and a feature that separates the classes almost perfectly, it would score near 100% and add no insight.
