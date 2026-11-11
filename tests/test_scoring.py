import pandas as pd
import pytest

from soc_triage.detection.incidents import detect_auth
from soc_triage.mitre.mapping import map_signals
from soc_triage.scoring.risk import score_alert, severity


def auth_story():
    rows = [
        ("2026-11-10 09:12:40", "bob", "10.0.0.7", 0),
        ("2026-11-10 09:00:01", "alice", "10.0.0.5", 0),
        ("2026-11-10 09:30:15", "alice", "10.0.0.5", 1),
        ("2026-11-10 09:30:25", "alice", "10.0.0.5", 0),
    ]
    for t, u in [("02:10:01", "alice"), ("02:10:30", "bob"), ("02:11:02", "carol"), ("02:11:40", "dave")]:
        rows.append((f"2026-11-10 {t}", u, "198.51.100.23", 1))
    for t in ["13:02:10", "13:02:22", "13:02:35", "13:02:51", "13:03:08", "13:03:20"]:
        rows.append((f"2026-11-10 {t}", "bob", "203.0.113.45", 1))
    rows.append(("2026-11-10 13:03:44", "bob", "203.0.113.45", 0))
    df = pd.DataFrame(rows, columns=["timestamp", "user", "src_ip", "is_failure"])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def test_score_is_additive():
    assert score_alert({"auth_s1_bruteforce", "new_source_ip"})["score"] == 45


def test_score_capped_at_100():
    everything = {"auth_s1_bruteforce", "auth_s3_success_after_failures", "new_source_ip",
                  "off_hours", "multi_scenario_correlation"}
    assert score_alert(everything)["score"] == 100


def test_unknown_signal_raises():
    with pytest.raises(ValueError):
        score_alert({"auth_s1_brutforce"})


def test_severity_bands():
    assert (severity(0), severity(39), severity(40), severity(69), severity(70)) == (
        "low", "low", "medium", "medium", "high")


def test_map_signals():
    ids = [m["id"] for m in map_signals({"auth_s2_spraying", "off_hours"})]
    assert ids == ["T1110.003"]  # off_hours has no technique and is ignored


def test_auth_story_incidents():
    inc = {i["entity"]: i for i in detect_auth(auth_story())}
    assert set(inc) == {"user:bob", "ip:198.51.100.23"}
    assert {"auth_s1_bruteforce", "auth_s3_success_after_failures",
            "multi_scenario_correlation"} <= inc["user:bob"]["signals"]
    assert "auth_s2_spraying" in inc["ip:198.51.100.23"]["signals"]


def test_alice_typo_raises_nothing():
    inc = detect_auth(auth_story())
    assert not any(i["entity"] == "user:alice" for i in inc)
