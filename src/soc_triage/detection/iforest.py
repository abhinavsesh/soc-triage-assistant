import json
import platform
from datetime import datetime, timezone

import joblib
import sklearn
from sklearn.ensemble import IsolationForest

FEATURES = ["flow_count", "mean_duration", "mean_fwd_packets"]


def fit_iforest(train, features=FEATURES, seed=42):
    """Fit on feature columns only. Labels are never passed in."""
    medians = train[features].median()
    model = IsolationForest(n_estimators=200, random_state=seed)
    model.fit(train[features].fillna(medians))
    return model, medians


def anomaly_score(model, medians, df, features=FEATURES):
    """Higher = more anomalous (sklearn's decision_function is higher = more normal)."""
    return -model.decision_function(df[features].fillna(medians))


def save_model(model, medians, features, threshold, train_rows, path):
    bundle = {
        "model": model,
        "medians": medians,
        "features": features,
        "threshold": float(threshold),
        "meta": {
            "sklearn_version": sklearn.__version__,
            "python_version": platform.python_version(),
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "train_rows": int(train_rows),
            "train_data": "CICIDS2017 Tuesday, port 21 windows",
        },
    }
    joblib.dump(bundle, path)
    with open(str(path).replace(".joblib", ".json"), "w") as fh:
        json.dump({**bundle["meta"], "features": features, "threshold": float(threshold)}, fh, indent=2)
