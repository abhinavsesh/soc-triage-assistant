import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from soc_triage.detection.evaluation import best_threshold, evaluate
from soc_triage.detection.iforest import FEATURES, anomaly_score, fit_iforest, save_model
from soc_triage.detection.rules import threshold_rule
from soc_triage.features.windows import flow_window_features
from soc_triage.ingestion.loaders import clean_flows, load_flows

f = flow_window_features(clean_flows(load_flows("data/raw/tuesday.csv")))
train = f[f["Destination Port"] == 21].reset_index(drop=True)
test = f[f["Destination Port"] == 22].reset_index(drop=True)
y_tr = train["is_attack"].astype(int)
y_te = test["is_attack"].astype(int)
print("train:", len(train), "attack:", y_tr.sum(), "| test:", len(test), "attack:", y_te.sum())

rows = {}

# A. threshold rule: tune on train, evaluate on test
t, _ = best_threshold(train["flow_count"], y_tr, range(1, 60))
pred_rule = threshold_rule(test, t)
rows["A rule"] = evaluate(y_te, pred_rule) | {
    "threshold": t,
    "roc_auc": roc_auc_score(y_te, test["flow_count"]),
    "pr_auc": average_precision_score(y_te, test["flow_count"]),
}


def run_iforest(name, features):
    model, med = fit_iforest(train, features)
    s_tr = anomaly_score(model, med, train, features)
    s_te = anomaly_score(model, med, test, features)
    thr, _ = best_threshold(s_tr, y_tr, np.unique(s_tr))
    pred = (s_te >= thr).astype(int)
    rows[name] = evaluate(y_te, pred) | {
        "threshold": round(float(thr), 4),
        "roc_auc": roc_auc_score(y_te, s_te),
        "pr_auc": average_precision_score(y_te, s_te),
    }
    return model, med, thr, pred


model, med, thr, pred_if = run_iforest("B IForest all", FEATURES)
run_iforest("C IForest no flow_count", [c for c in FEATURES if c != "flow_count"])

print(pd.DataFrame(rows).T.round(3).to_string())

# Error analysis (rule and IForest B)
for name, pred in [("RULE", pred_rule), ("IFOREST B", pred_if)]:
    fp = test[(pred == 1) & (y_te == 0)]
    fn = test[(pred == 0) & (y_te == 1)]
    print(f"\n{name} false positives: {len(fp)}\n", fp.head(10).to_string())
    print(f"\n{name} false negatives: {len(fn)}\n", fn.head(10).to_string())

# Analyst workload: alerts raised on the test set
print("\nIForest B alerts:", int(pred_if.sum()), "of", len(test), "windows")
print("Rule alerts:", int(pred_rule.sum()), "of", len(test), "windows")

# Save the IForest B model
save_model(model, med, FEATURES, thr, len(train), "models/iforest_v1.joblib")
print("\nsaved models/iforest_v1.joblib")
