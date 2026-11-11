from soc_triage.features.windows import (
    add_new_ip_flag,
    auth_failures_rolling,
    distinct_users_per_ip,
)

C5 = "failures_5min_user_src_ip"
C10 = "failures_10min_user_src_ip"


def is_off_hours(ts, start=22, end=6):
    return ts.hour >= start or ts.hour < end


def _incident(store, key, kind, ts):
    inc = store.setdefault(
        key,
        {"entity": key, "kind": kind, "signals": set(), "evidence": {}, "first_seen": str(ts)},
    )
    inc["first_seen"] = min(inc["first_seen"], str(ts))
    return inc


def _observe(inc, scenario, observation):
    """Accumulate evidence. Never replace an earlier observation."""
    inc["evidence"].setdefault(scenario, []).append(observation)


def detect_auth(df, s1_min=5, s2_min=3, s3_min=3):
    """Scenarios S1, S2, S3 from docs/detection_scenarios.md. One incident per entity.

    S1 and S3 count failures per (user, source IP), matching the documented entity.
    """
    by_pair = ("user", "src_ip")
    df = auth_failures_rolling(df, "5min", by=by_pair)
    df = auth_failures_rolling(df, "10min", by=by_pair)
    df = add_new_ip_flag(df)
    store = {}

    # S1: brute force from one IP against one user
    s1 = df[(df["is_failure"] == 1) & (df[C5] >= s1_min)]
    for (user, ip), g in s1.groupby(["user", "src_ip"]):
        ts = g["timestamp"].min()
        inc = _incident(store, f"user:{user}", "auth", ts)
        inc["signals"].add("auth_s1_bruteforce")
        _observe(inc, "s1", {
            "src_ip": ip,
            "peak_failures_5min": int(g[C5].max()),
            "first_failure_at": str(ts),
        })
        if g["is_new_ip"].any():
            inc["signals"].add("new_source_ip")
        if is_off_hours(ts):
            inc["signals"].add("off_hours")

    # S3: success from a NEW IP after failures from that SAME IP. New IP is part of
    # the rule itself, so it is not added again as a signal (no double counting).
    s3 = df[(df["is_failure"] == 0) & (df[C10] >= s3_min) & (df["is_new_ip"])]
    for (user, ip), g in s3.groupby(["user", "src_ip"]):
        ts = g["timestamp"].min()
        inc = _incident(store, f"user:{user}", "auth", ts)
        inc["signals"].add("auth_s3_success_after_failures")
        _observe(inc, "s3", {
            "success_ip": ip,
            "success_at": str(ts),
            "failures_10min_same_ip": int(g[C10].max()),
        })
        if is_off_hours(ts):
            inc["signals"].add("off_hours")

    # S2: password spraying, entity is the source IP. One observation per bucket.
    sp = distinct_users_per_ip(df)
    for _, r in sp[sp["distinct_users"] >= s2_min].iterrows():
        inc = _incident(store, f"ip:{r['src_ip']}", "auth", r["bucket"])
        inc["signals"].add("auth_s2_spraying")
        _observe(inc, "s2", {
            "bucket_start": str(r["bucket"]),
            "distinct_users": int(r["distinct_users"]),
            "failures": int(r["failures"]),
        })
        if is_off_hours(r["bucket"]):
            inc["signals"].add("off_hours")

    # Correlation: brute force and a suspicious success involving the SAME IP
    for inc in store.values():
        s1_ips = {o["src_ip"] for o in inc["evidence"].get("s1", [])}
        s3_ips = {o["success_ip"] for o in inc["evidence"].get("s3", [])}
        if s1_ips & s3_ips:
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
                "evidence": {"flow": [{
                    "threshold": int(thr),
                    "peak_flow_count": int(g["flow_count"].max()),
                    "alerting_windows": int(len(g)),
                    "first_minute": str(g["minute"].min()),
                    "last_minute": str(g["minute"].max()),
                }]},
                "first_seen": str(g["minute"].min()),
            })
    return out
