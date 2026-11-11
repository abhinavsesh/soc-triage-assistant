import pandas as pd

from soc_triage.detection.incidents import detect_auth


def df_from(rows):
    df = pd.DataFrame(rows, columns=["timestamp", "user", "src_ip", "is_failure"])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def fails(user, ip, hhmm, n):
    return [(f"2026-11-10 {hhmm}:{i:02d}", user, ip, 1) for i in range(n)]


def by_entity(df):
    return {i["entity"]: i for i in detect_auth(df)}


def test_s1_keeps_evidence_from_both_ips():
    rows = fails("alice", "1.1.1.1", "10:00", 7) + fails("alice", "2.2.2.2", "11:00", 9)
    inc = by_entity(df_from(rows))["user:alice"]
    assert {o["src_ip"] for o in inc["evidence"]["s1"]} == {"1.1.1.1", "2.2.2.2"}


def test_s1_ignores_low_volume_ip_of_a_busy_user():
    rows = fails("alice", "1.1.1.1", "10:00", 6) + [("2026-11-10 10:01:00", "alice", "3.3.3.3", 1)]
    inc = by_entity(df_from(rows))["user:alice"]
    assert {o["src_ip"] for o in inc["evidence"]["s1"]} == {"1.1.1.1"}


def test_s2_keeps_evidence_from_every_bucket():
    rows = [(f"2026-11-10 02:00:{i * 10:02d}", f"u{i}", "9.9.9.9", 1) for i in range(3)]
    rows += [(f"2026-11-10 03:00:{i * 10:02d}", f"v{i}", "9.9.9.9", 1) for i in range(3)]
    inc = by_entity(df_from(rows))["ip:9.9.9.9"]
    assert len(inc["evidence"]["s2"]) == 2


def test_s3_requires_failures_from_the_success_ip():
    rows = fails("carol", "1.1.1.1", "13:00", 5) + [("2026-11-10 13:02:00", "carol", "2.2.2.2", 0)]
    inc = by_entity(df_from(rows))["user:carol"]
    assert "auth_s3_success_after_failures" not in inc["signals"]


def test_correlation_requires_same_ip():
    rows = fails("dave", "1.1.1.1", "10:00", 7)
    rows += fails("dave", "2.2.2.2", "10:02", 3) + [("2026-11-10 10:02:20", "dave", "2.2.2.2", 0)]
    inc = by_entity(df_from(rows))["user:dave"]
    assert {"auth_s1_bruteforce", "auth_s3_success_after_failures"} <= inc["signals"]
    assert "multi_scenario_correlation" not in inc["signals"]
