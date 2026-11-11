
## Results: first run (train on FTP port 21, test on SSH port 22)

| Detector | Alerts | Precision | Recall | F1 | FPR | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|---|
| A threshold rule (flows >= 5) | 110 | 0.573 | 1.00 | 0.728 | 0.082 | 1.000 | 1.000 |
| B Isolation Forest, all features | 634 | 0.099 | 1.00 | 0.181 | 1.00 | 0.972 | 0.662 |
| C Isolation Forest, no flow_count | 634 | 0.099 | 1.00 | 0.181 | 1.00 | 0.849 | 0.269 |

Findings:
- flow_count ranks SSH windows perfectly (AUC 1.0), but the threshold tuned on FTP (5) transferred badly, giving 47 false positives. SSH has a busier benign baseline.
- The Isolation Forest scores rank well (AUC 0.972) but the label-tuned threshold flagged every window, so precision equals prevalence. Recall of 1.0 is meaningless when everything alerts.
- Without flow_count the ranking degrades (PR-AUC 0.269), so volume carries most of the signal on this data.
- The false positives for the rule were internal hosts making regular, scripted-looking SSH connections.
- The model was trained on data containing 11% attack windows, which violates the assumption that anomalies are rare.

Action: retrain on a benign-only baseline with a label-free percentile threshold (phase4b), and test in both directions.
