from soc_triage.features.windows import (
    add_new_ip_flag,
    auth_failures_rolling,
    distinct_users_per_ip,
)


def is_off_hours(ts, start=22, end=6):
    return ts.hour >= start or ts.hour < end


def _incident(store, key, kind, ts):
    inc = store.setdefault(
        key,
        {"entity": key, "kind": kind, "signals": set(), "evidence": {}, "first_seen": str(ts)},
    )
    inc["first_seen"] = min(inc["first_seen"], str(ts))
    return inc


def detect_auth(df, s1_min=5, s2_min=3, s3_min=3):
    """Scenarios S1, S2, S3 from docs/detection_scenarios.md. One incident per entity."""
    df = auth_failures_rolling(df, "5min")
    df = auth_failures_rolling(df, "10min")
    df = add_new_ip_flag(df)
    store = {}

    # S1: brute force. Note: failures are counted per user (all IPs), a simplification.
    s1 = df[(df["is_failure"] == 1) & (df["failures_5min"] >= s1_min)]
    for (user, ip), g in s1.groupby(["user", "src_ip"]):
        ts = g["timestamp"].min()
        inc = _incident(store, f"user:{user}", "auth", ts)
        inc["signals"].add("auth_s1_bruteforce")
        inc["evidence"]["s1"] = {"src_ip": ip, "peak_failures_5min": int(g["failures_5min"].max())}
        if g["is_new_ip"].any():
            inc["signals"].add("new_source_ip")
        if is_off_hours(ts):
            inc["signals"].add("off_hours")

    # S3: success after failures from a new IP (new IP is part of the rule itself,
    # so it is not added again as a separate signal, to avoid double counting).
    s3 = df[(df["is_failure"] == 0) & (df["failures_10min"] >= s3_min) & (df["is_new_ip"])]
    for user, g in s3.groupby("user"):
        ts = g["timestamp"].min()
        inc = _incident(store, f"user:{user}", "auth", ts)
        inc["signals"].add("auth_s3_success_after_failures")
        inc["evidence"]["s3"] = {
            "success_ip": g["src_ip"].iloc[0],
            "success_at": str(ts),
            "failures_10min": int(g["failures_10min"].max()),
        }
        if is_off_hours(ts):
            inc["signals"].add("off_hours")

    # S2: password spraying, entity is the source IP
    sp = distinct_users_per_ip(df)
    for _, r in sp[sp["distinct_users"] >= s2_min].iterrows():
        inc = _incident(store, f"ip:{r['src_ip']}", "auth", r["bucket"])
        inc["signals"].add("auth_s2_spraying")
        inc["evidence"]["s2"] = {"distinct_users": int(r["distinct_users"]), "failures": int(r["failures"])}
        if is_off_hours(r["bucket"]):
            inc["signals"].add("off_hours")

    # Correlation: the same user shows brute force AND a suspicious success
    for inc in store.values():
        if {"auth_s1_bruteforce", "auth_s3_success_after_failures"} <= inc["signals"]:
            inc["signals"].add("multi_scenario_correlation")
    return list(store.values())


def detect_flows(f, multiplier=2):
    """Per-service rule from Phase 4: threshold = multiplier x benign max of that port.

    Labels are used ONLY to find the benign baseline. In production the baseline
    would come from a known-clean period. Off-hours is not used for flows because
    CICIDS timestamps have no AM/PM marker.
    """
    out = []
    for port, d in f.groupby("Destination Port"):
        benign = d.loc[~d["is_attack"], "flow_count"]
        if benign.empty:
            continue
        thr = multiplier * benign.max()
        hits = d[d["flow_count"] >= thr]
        for ip, g in hits.groupby("Source IP"):
            signals = {"flow_rule_hit"}
            if g["flow_count"].max() >= 3 * thr:
                signals.add("flow_volume_3x_threshold")
            if len(g) >= 5:
                signals.add("flow_sustained_5plus_windows")
            out.append({
                "entity": f"ip:{ip}:port:{port}",
                "kind": "flow",
                "signals": signals,
                "evidence": {
                    "threshold": int(thr),
                    "peak_flow_count": int(g["flow_count"].max()),
                    "alerting_windows": int(len(g)),
                    "first_minute": str(g["minute"].min()),
                    "last_minute": str(g["minute"].max()),
                },
                "first_seen": str(g["minute"].min()),
            })
    return out
