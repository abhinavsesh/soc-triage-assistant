import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from soc_triage.detection.evaluation import evaluate
from soc_triage.detection.iforest import FEATURES, anomaly_score, fit_iforest
from soc_triage.features.windows import flow_window_features
from soc_triage.ingestion.loaders import clean_flows, load_flows

f = flow_window_features(clean_flows(load_flows("data/raw/tuesday.csv")))


def run(train_port, test_port, quantile):
    train = f[f["Destination Port"] == train_port].reset_index(drop=True)
    test = f[f["Destination Port"] == test_port].reset_index(drop=True)
    baseline = train[~train["is_attack"]]  # clean baseline: benign windows only
    model, med = fit_iforest(baseline, FEATURES)
    thr = np.quantile(anomaly_score(model, med, baseline, FEATURES), quantile)
    s = anomaly_score(model, med, test, FEATURES)
    y = test["is_attack"].astype(int)
    m = evaluate(y, (s >= thr).astype(int))
    m.update(roc_auc=roc_auc_score(y, s), pr_auc=average_precision_score(y, s), thr=round(float(thr), 3))
    return m


rows = {}
for tr, te in [(21, 22), (22, 21)]:
    for q in (0.95, 0.99):
        rows[f"train {tr} -> test {te}, q={q}"] = run(tr, te, q)
print(pd.DataFrame(rows).T.round(3).to_string())
