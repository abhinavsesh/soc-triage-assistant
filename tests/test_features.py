import pandas as pd

from soc_triage.features.windows import (
    add_new_ip_flag,
    auth_failures_rolling,
    distinct_users_per_ip,
)


def make_df(rows):
    """rows: list of (timestamp, user, src_ip, is_failure)."""
    df = pd.DataFrame(rows, columns=["timestamp", "user", "src_ip", "is_failure"])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def test_six_failures_counted():
    times = ["13:02:10", "13:02:22", "13:02:35", "13:02:51", "13:03:08", "13:03:20"]
    df = make_df([(f"2026-11-10 {t}", "bob", "203.0.113.45", 1) for t in times])
    out = auth_failures_rolling(df)
    assert out["failures_10min"].iloc[-1] == 6


def test_old_failure_expires():
    df = make_df([
        ("2026-11-10 13:00:00", "bob", "1.1.1.1", 1),
        ("2026-11-10 13:11:00", "bob", "1.1.1.1", 1),
    ])
    out = auth_failures_rolling(df)
    assert out["failures_10min"].iloc[-1] == 1  # the 11-minute-old failure is gone


def test_users_are_isolated():
    df = make_df([
        ("2026-11-10 13:02:00", "alice", "1.1.1.1", 1),
        ("2026-11-10 13:02:10", "bob", "2.2.2.2", 1),
    ])
    out = auth_failures_rolling(df)
    assert out[out["user"] == "bob"]["failures_10min"].iloc[-1] == 1


def test_unsorted_input_same_result():
    df = make_df([
        ("2026-11-10 13:02:10", "bob", "1.1.1.1", 1),
        ("2026-11-10 13:02:20", "bob", "1.1.1.1", 1),
        ("2026-11-10 13:02:30", "bob", "1.1.1.1", 1),
    ])
    shuffled = df.sample(frac=1, random_state=0)
    a = auth_failures_rolling(df)["failures_10min"].tolist()
    b = auth_failures_rolling(shuffled)["failures_10min"].tolist()
    assert a == b == [1, 2, 3]


def test_empty_dataframe_does_not_crash():
    df = make_df([])
    assert len(auth_failures_rolling(df)) == 0
    assert len(distinct_users_per_ip(df)) == 0
    assert len(add_new_ip_flag(df)) == 0


def test_new_ip_flag():
    df = make_df([
        ("2026-11-10 09:00:01", "alice", "10.0.0.5", 0),
        ("2026-11-10 09:30:15", "alice", "10.0.0.5", 1),
        ("2026-11-10 09:30:25", "alice", "10.0.0.5", 0),
        ("2026-11-10 13:03:44", "alice", "203.0.113.45", 0),
    ])
    out = add_new_ip_flag(df)
    assert out["is_new_ip"].tolist() == [True, False, False, True]


def test_input_not_mutated():
    df = make_df([
        ("2026-11-10 13:02:10", "bob", "1.1.1.1", 1),
        ("2026-11-10 13:02:20", "bob", "1.1.1.1", 0),
    ])
    before = df.copy()
    auth_failures_rolling(df)
    distinct_users_per_ip(df)
    add_new_ip_flag(df)
    pd.testing.assert_frame_equal(df, before)


def test_spraying_distinct_users():
    df = make_df([
        ("2026-11-10 02:10:01", "alice", "198.51.100.23", 1),
        ("2026-11-10 02:10:30", "bob", "198.51.100.23", 1),
        ("2026-11-10 02:11:02", "carol", "198.51.100.23", 1),
        ("2026-11-10 02:11:40", "dave", "198.51.100.23", 1),
    ])
    out = distinct_users_per_ip(df)
    assert out["distinct_users"].iloc[0] == 4
