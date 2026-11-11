import pandas as pd

FLOW_PORTS = [21, 22]


def flow_window_features(df, ports=FLOW_PORTS):
    """One row per (Source IP, Destination Port, minute) on the given ports.

    Source IP and Destination Port are grouping keys only, never model features.
    is_attack is ground truth for evaluation only, never a model feature.
    """
    d = df[df["Destination Port"].isin(ports)].copy()
    d["minute"] = d["Timestamp"].dt.floor("min")
    d["_attack_flow"] = d["Label"] != "BENIGN"
    out = (
        d.groupby(["Source IP", "Destination Port", "minute"])
        .agg(
            flow_count=("Label", "size"),
            mean_duration=("Flow Duration", "mean"),
            mean_fwd_packets=("Total Fwd Packets", "mean"),
            is_attack=("_attack_flow", "any"),
        )
        .reset_index()
    )
    return out


def auth_failures_rolling(df, window="10min", by=("user",)):
    """Failures in the window ending at each event, counted per group in `by`.

    by=("user",) counts across all IPs. by=("user", "src_ip") counts only
    failures from the same IP, which is what S1 and S3 need.
    """
    by = list(by)
    col = f"failures_{window}" if by == ["user"] else f"failures_{window}_{'_'.join(by)}"
    df = df.copy().sort_values("timestamp", kind="stable").reset_index(drop=True)
    if df.empty:
        df[col] = pd.Series(dtype=int)
        return df

    parts = []
    for _, g in df.groupby(by):
        s = g.set_index("timestamp")["is_failure"].rolling(window).sum()
        parts.append(pd.Series(s.values, index=g.index))
    df[col] = pd.concat(parts).astype(int)
    return df


def distinct_users_per_ip(df, window="10min"):
    """Distinct users with failed logins per source IP, in tumbling buckets."""
    cols = ["src_ip", "bucket", "distinct_users", "failures"]
    f = df[df["is_failure"] == 1].copy()
    if f.empty:
        return pd.DataFrame(columns=cols)
    f["bucket"] = f["timestamp"].dt.floor(window)
    return (
        f.groupby(["src_ip", "bucket"])
        .agg(distinct_users=("user", "nunique"), failures=("user", "size"))
        .reset_index()
    )


def add_new_ip_flag(df):
    """is_new_ip is True if the user has no EARLIER successful login from this IP.

    The first success from an IP counts as new. A user's very first login
    is therefore always new (cold start).
    """
    df = df.copy().sort_values("timestamp", kind="stable").reset_index(drop=True)
    if df.empty:
        df["is_new_ip"] = pd.Series(dtype=bool)
        return df

    first_success = (
        df[df["is_failure"] == 0]
        .groupby(["user", "src_ip"])["timestamp"]
        .min()
        .rename("_first_success")
        .reset_index()
    )
    df = df.merge(first_success, on=["user", "src_ip"], how="left")
    df["is_new_ip"] = df["_first_success"].isna() | (df["timestamp"] <= df["_first_success"])
    return df.drop(columns="_first_success")
