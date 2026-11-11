import json

from soc_triage.detection.incidents import detect_auth, detect_flows
from soc_triage.features.windows import flow_window_features
from soc_triage.ingestion.loaders import clean_flows, load_auth, load_flows
from soc_triage.scoring.alerts import build_alerts

incidents = detect_auth(load_auth("data/sample/auth_sample.csv"))
incidents += detect_flows(flow_window_features(clean_flows(load_flows("data/raw/tuesday.csv"))))
alerts = build_alerts(incidents)

for a in alerts:
    print(a["risk_score"], a["severity"], a["entity"], a["signals"], [m["id"] for m in a["mitre"]])

print()
print(json.dumps(alerts[0], indent=2, default=str))
