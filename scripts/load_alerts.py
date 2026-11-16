from soc_triage.api.db import connect, init_db, store_alerts
from soc_triage.detection.incidents import detect_auth, detect_flows
from soc_triage.features.windows import flow_window_features
from soc_triage.ingestion.loaders import clean_flows, load_auth, load_flows
from soc_triage.logging_setup import setup_logging
from soc_triage.scoring.alerts import build_alerts


def main():
    setup_logging()
    auth = load_auth("data/sample/auth_sample.csv")
    incidents = detect_auth(auth)
    incidents += detect_flows(flow_window_features(clean_flows(load_flows("data/raw/tuesday.csv"))))
    alerts = build_alerts(incidents)
    conn = connect()
    init_db(conn)
    created, duplicates = store_alerts(conn, alerts, "load_script", len(auth))
    print(f"alerts: {len(alerts)} | new: {created} | duplicates skipped: {duplicates}")


if __name__ == "__main__":
    main()
