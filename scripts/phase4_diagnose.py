from sklearn.metrics import average_precision_score, roc_auc_score

from soc_triage.detection.iforest import FEATURES, anomaly_score, fit_iforest
from soc_triage.features.windows import flow_window_features
from soc_triage.ingestion.loaders import clean_flows, load_flows

f = flow_window_features(clean_flows(load_flows("data/raw/tuesday.csv")))
train = f[f["Destination Port"] == 21].reset_index(drop=True)
test = f[f["Destination Port"] == 22].reset_index(drop=True)

print("flow_count by port and class")
print(f.groupby(["Destination Port", "is_attack"]).flow_count.describe().round(1))

model, med = fit_iforest(train, FEATURES)
for name, df in [("train (FTP)", train), ("test (SSH)", test)]:
    s = anomaly_score(model, med, df, FEATURES)
    y = df["is_attack"].astype(int)
    print(f"\n{name}: roc_auc={roc_auc_score(y, s):.3f} pr_auc={average_precision_score(y, s):.3f} prevalence={y.mean():.3f}")
    print(df.assign(score=s).groupby("is_attack").score.describe().round(3))
