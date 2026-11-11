import numpy as np
import pandas as pd
from sklearn.model_selection import KFold

from soc_triage.detection.evaluation import evaluate
from soc_triage.detection.iforest import FEATURES, anomaly_score, fit_iforest
from soc_triage.features.windows import flow_window_features
from soc_triage.ingestion.loaders import clean_flows, load_flows

f = flow_window_features(clean_flows(load_flows("data/raw/tuesday.csv")))
rows = {}

for port in (21, 22):
    d = f[f["Destination Port"] == port].reset_index(drop=True)
    y = d["is_attack"].astype(int)

    # Rule: threshold = 2 x the max benign flow_count seen in the baseline half
    # (fit on first half in index order, evaluate on second half)
    half = len(d) // 2
    base = d.iloc[:half]
    thr = 2 * base[~base["is_attack"]]["flow_count"].max()
    test = d.iloc[half:]
    rows[f"port {port} rule (thr={thr}) 2nd half"] = evaluate(
        test["is_attack"].astype(int), (test["flow_count"] >= thr).astype(int)
    )

    # Isolation Forest within one service, 5-fold CV, benign-only baseline,
    # threshold = 99th percentile of benign training scores
    pred = np.zeros(len(d), dtype=int)
    for tr_idx, te_idx in KFold(5, shuffle=True, random_state=0).split(d):
        tr, te = d.iloc[tr_idx], d.iloc[te_idx]
        bl = tr[~tr["is_attack"]]
        model, med = fit_iforest(bl, FEATURES)
        t = np.quantile(anomaly_score(model, med, bl, FEATURES), 0.99)
        pred[te_idx] = (anomaly_score(model, med, te, FEATURES) >= t).astype(int)
    rows[f"port {port} iforest 5-fold CV q=0.99"] = evaluate(y, pred)

print(pd.DataFrame(rows).T[["tp", "fp", "fn", "tn", "precision", "recall", "f1", "fpr"]].round(3).to_string())
