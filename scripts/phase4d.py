import numpy as np
import pandas as pd
from sklearn.model_selection import KFold

from soc_triage.detection.evaluation import evaluate
from soc_triage.features.windows import flow_window_features
from soc_triage.ingestion.loaders import clean_flows, load_flows

f = flow_window_features(clean_flows(load_flows("data/raw/tuesday.csv")))
rows = {}
for port in (21, 22):
    d = f[f["Destination Port"] == port].reset_index(drop=True)
    y = d["is_attack"].astype(int)
    pred = np.zeros(len(d), dtype=int)
    for tr_idx, te_idx in KFold(5, shuffle=True, random_state=0).split(d):
        tr, te = d.iloc[tr_idx], d.iloc[te_idx]
        thr = 2 * tr[~tr["is_attack"]]["flow_count"].max()  # from benign train only
        pred[te_idx] = (te["flow_count"] >= thr).astype(int)
    rows[f"port {port} rule (2 x benign max) 5-fold CV"] = evaluate(y, pred)

print(pd.DataFrame(rows).T[["tp", "fp", "fn", "tn", "precision", "recall", "f1", "fpr"]].round(3).to_string())
