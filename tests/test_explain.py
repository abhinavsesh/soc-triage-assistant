import json

from soc_triage.llm.explain import explain_alert

ALERT = {
    "entity": "user:bob", "kind": "auth", "first_seen": "2026-11-10 13:03:08",
    "risk_score": 100, "severity": "high",
    "signals": ["auth_s1_bruteforce"], "score_breakdown": {"auth_s1_bruteforce": 30},
    "mitre": [{"id": "T1110.001", "name": "Password Guessing", "confidence": "medium", "tactic": "x"}],
    "evidence": {"s1": [{"src_ip": "203.0.113.45", "peak_failures_5min": 6}]},
}
GOOD = {
    "summary": "user_1 had 6 failures from ip_1.",
    "evidence_cited": [{"field": "src_ip", "value": "ip_1"}],
    "mitre_hypotheses": [{"id": "T1110.001", "reasoning": "consistent with guessing"}],
    "investigation_steps": ["Review history", "Compare locations", "Check other accounts"],
    "proposed_actions": ["PROPOSAL: consider a password reset"],
    "uncertainty": "Source of ip_1 unknown.",
}


def test_explain_ok_and_restores_names():
    r = explain_alert(ALERT, call=lambda s, u: json.dumps(GOOD))
    assert r["ok"] and r["problems"] == []
    shown = json.dumps(r["explanation"])
    assert "bob" in shown and "203.0.113.45" in shown   # restored for display
    assert "bob" not in json.dumps(r["explanation_raw"])  # model only ever saw placeholders


def test_explain_flags_bad_output():
    bad = {**GOOD, "summary": "This is benign."}
    r = explain_alert(ALERT, call=lambda s, u: json.dumps(bad))
    assert not r["ok"] and r["problems"]


def test_explain_handles_unparseable_output():
    r = explain_alert(ALERT, call=lambda s, u: "not json at all")
    assert not r["ok"] and r["problems"] == ["unparseable output"]
