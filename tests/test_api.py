import logging

import pytest
from fastapi.testclient import TestClient

from soc_triage.api.main import app, get_explainer
from soc_triage.llm.client import LLMError

KEY1, KEY2 = "test-key-one", "test-key-two"
H1, H2 = {"X-API-Key": KEY1}, {"X-API-Key": KEY2}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.setenv("ANALYST_KEYS", f"{KEY1}:analyst_1,{KEY2}:analyst_2")
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def bruteforce_events(user="bob"):
    ev = [{"timestamp": f"2026-11-10T13:02:{i * 10:02d}", "user": user,
           "src_ip": "203.0.113.45", "result": "failure"} for i in range(6)]
    ev.append({"timestamp": "2026-11-10T13:03:10", "user": user,
               "src_ip": "203.0.113.45", "result": "success"})
    return ev


def spraying_events():
    times = ["02:10:01", "02:10:30", "02:11:02", "02:11:40"]
    return [{"timestamp": f"2026-11-10T{t}", "user": u, "src_ip": "198.51.100.23", "result": "failure"}
            for t, u in zip(times, ["alice", "bob", "carol", "dave"])]


def ingest_one(client):
    r = client.post("/ingest/auth", json={"events": bruteforce_events()}, headers=H1)
    assert r.status_code == 200
    return client.get("/alerts", headers=H1).json()[0]["id"]


def use_explainer(fn):
    app.dependency_overrides[get_explainer] = lambda: fn


# ---------- authentication ----------
def test_health_needs_no_key(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_missing_key_rejected(client):
    assert client.get("/alerts").status_code == 401


def test_wrong_key_rejected(client):
    assert client.get("/alerts", headers={"X-API-Key": "nope"}).status_code == 401


def test_auth_not_configured_fails_closed(client, monkeypatch):
    monkeypatch.setenv("ANALYST_KEYS", "")
    assert client.get("/alerts", headers=H1).status_code == 503


# ---------- ingest ----------
def test_ingest_creates_one_alert(client):
    r = client.post("/ingest/auth", json={"events": bruteforce_events()}, headers=H1)
    assert r.json() == {"events": 7, "alerts_created": 1, "alerts_duplicate": 0}
    alerts = client.get("/alerts", headers=H1).json()
    assert len(alerts) == 1
    assert alerts[0]["entity"] == "user:bob" and alerts[0]["risk_score"] == 100
    assert alerts[0]["severity"] == "high" and alerts[0]["status"] == "new"


def test_ingest_twice_is_deduplicated(client):
    body = {"events": bruteforce_events()}
    client.post("/ingest/auth", json=body, headers=H1)
    r = client.post("/ingest/auth", json=body, headers=H1)
    assert r.json()["alerts_created"] == 0 and r.json()["alerts_duplicate"] == 1
    assert len(client.get("/alerts", headers=H1).json()) == 1


def test_ingest_validation_errors(client):
    good = bruteforce_events()[0]
    cases = [
        {**good, "src_ip": "not-an-ip"},
        {**good, "result": "maybe"},
        {**good, "extra_field": 1},
        {**good, "timestamp": "yesterday-ish"},
        {**good, "user": ""},
    ]
    for bad in cases:
        assert client.post("/ingest/auth", json={"events": [bad]}, headers=H1).status_code == 422
    assert client.post("/ingest/auth", json={"events": []}, headers=H1).status_code == 422


def test_ingest_rejects_oversized_batch(client):
    ev = bruteforce_events()[0]
    r = client.post("/ingest/auth", json={"events": [ev] * 5001}, headers=H1)
    assert r.status_code == 422


def test_hostile_username_is_stored_as_data(client):
    hostile = "evil\nforged log line; DROP TABLE alerts"
    r = client.post("/ingest/auth", json={"events": bruteforce_events(hostile)}, headers=H1)
    assert r.json()["alerts_created"] == 1
    alerts = client.get("/alerts", headers=H1).json()  # table still exists
    assert "\n" not in alerts[0]["entity"] and "DROP TABLE" in alerts[0]["entity"]


def test_logs_do_not_contain_usernames(client, caplog):
    with caplog.at_level(logging.INFO):
        client.post("/ingest/auth", json={"events": bruteforce_events("secret_user_name")}, headers=H1)
        client.get("/alerts", headers=H1)
    assert "secret_user_name" not in caplog.text


# ---------- listing and detail ----------
def test_list_filters_and_order(client):
    client.post("/ingest/auth", json={"events": bruteforce_events() + spraying_events()}, headers=H1)
    alerts = client.get("/alerts", headers=H1).json()
    assert [a["risk_score"] for a in alerts] == [100, 40]
    assert [a["entity"] for a in client.get("/alerts?severity=medium", headers=H1).json()] == ["ip:198.51.100.23"]
    assert [a["entity"] for a in client.get("/alerts?min_score=50", headers=H1).json()] == ["user:bob"]
    assert client.get("/alerts?status=closed", headers=H1).json() == []


def test_list_parameter_validation(client):
    for q in ("limit=0", "limit=201", "offset=-1", "min_score=101", "status=' OR 1=1 --", "severity=critical"):
        assert client.get(f"/alerts?{q}", headers=H1).status_code == 422


def test_detail_and_404(client):
    aid = ingest_one(client)
    d = client.get(f"/alerts/{aid}", headers=H1).json()
    assert d["entity"] == "user:bob" and "s1" in d["evidence"] and d["mitre"] and d["explanation"] is None
    assert client.get("/alerts/999", headers=H1).status_code == 404


def test_alert_id_must_be_integer(client):
    assert client.get("/alerts/abc", headers=H1).status_code == 422


# ---------- status ----------
def test_status_update_and_history(client):
    aid = ingest_one(client)
    r = client.patch(f"/alerts/{aid}/status", json={"status": "investigating", "note": "looking"}, headers=H1)
    assert r.status_code == 200 and r.json()["status"] == "investigating"
    hist = client.get(f"/alerts/{aid}", headers=H1).json()["history"]
    assert hist[-1]["actor"] == "analyst_1" and hist[-1]["action"] == "status_change"
    assert hist[-1]["detail"].startswith("new -> investigating")


def test_invalid_transition_returns_409(client):
    aid = ingest_one(client)
    r = client.patch(f"/alerts/{aid}/status", json={"status": "closed"}, headers=H1)
    assert r.status_code == 409


def test_unknown_status_returns_422(client):
    aid = ingest_one(client)
    assert client.patch(f"/alerts/{aid}/status", json={"status": "deleted"}, headers=H1).status_code == 422


def test_status_note_too_long(client):
    aid = ingest_one(client)
    r = client.patch(f"/alerts/{aid}/status", json={"status": "investigating", "note": "x" * 501}, headers=H1)
    assert r.status_code == 422


# ---------- explanations ----------
def test_explain_stores_and_caches(client):
    aid = ingest_one(client)
    calls = []

    def fake(alert):
        calls.append(alert)
        return {"ok": True, "problems": [], "explanation": {"summary": "ok"}, "seconds": 1.2}

    use_explainer(fake)
    r = client.post(f"/alerts/{aid}/explain", headers=H1)
    assert r.status_code == 200 and r.json()["ok"] and r.json()["explanation"]["summary"] == "ok"
    assert "history" not in calls[0] and "status" not in calls[0]  # the model gets a whitelist
    client.post(f"/alerts/{aid}/explain", headers=H1)
    assert len(calls) == 1  # cached
    client.post(f"/alerts/{aid}/explain?refresh=true", headers=H1)
    assert len(calls) == 2
    assert client.get(f"/alerts/{aid}", headers=H1).json()["explanation"]["requested_by"] == "analyst_1"


def test_explain_model_down_returns_503(client):
    aid = ingest_one(client)

    def fake(alert):
        raise LLMError("connection refused at localhost:11434")

    use_explainer(fake)
    r = client.post(f"/alerts/{aid}/explain", headers=H1)
    assert r.status_code == 503 and "localhost" not in r.text
    assert client.get(f"/alerts/{aid}", headers=H1).json()["explanation"] is None


def test_explain_unknown_alert_404(client):
    use_explainer(lambda alert: {})
    assert client.post("/alerts/999/explain", headers=H1).status_code == 404


def test_unhandled_error_returns_generic_500(client):
    aid = ingest_one(client)

    def fake(alert):
        raise RuntimeError("secret internal detail")

    use_explainer(fake)
    r = client.post(f"/alerts/{aid}/explain", headers=H1)
    assert r.status_code == 500 and "secret" not in r.text and "request_id" in r.json()


def test_request_id_header(client):
    assert "x-request-id" in client.get("/health").headers


# ---------- approvals ----------
def test_action_four_eyes_flow(client):
    aid = ingest_one(client)
    body = {"action": "block_ip", "target": "203.0.113.45", "reason": "brute force then success"}
    r = client.post(f"/alerts/{aid}/actions", json=body, headers=H1)
    assert r.status_code == 201 and r.json()["status"] == "pending" and r.json()["proposed_by"] == "analyst_1"
    act = r.json()["id"]
    assert client.post(f"/actions/{act}/execute", headers=H1).status_code == 403          # not approved
    assert client.post(f"/actions/{act}/decision", json={"decision": "approve"}, headers=H1).status_code == 403  # proposer
    r = client.post(f"/actions/{act}/decision", json={"decision": "approve"}, headers=H2)
    assert r.status_code == 200 and r.json()["status"] == "approved" and r.json()["decided_by"] == "analyst_2"
    r = client.post(f"/actions/{act}/execute", headers=H2)
    assert r.status_code == 200 and r.json()["status"] == "executed" and r.json()["dry_run"] is True
    assert client.post(f"/actions/{act}/execute", headers=H2).status_code == 403          # no double execution
    assert client.post(f"/actions/{act}/decision", json={"decision": "approve"}, headers=H2).status_code == 409


def test_action_validation(client):
    aid = ingest_one(client)
    bad_target = {"action": "block_ip", "target": "not-an-ip", "reason": "r"}
    assert client.post(f"/alerts/{aid}/actions", json=bad_target, headers=H1).status_code == 400
    bad_action = {"action": "format_disk", "target": "bob", "reason": "r"}
    assert client.post(f"/alerts/{aid}/actions", json=bad_action, headers=H1).status_code == 422
    ok = {"action": "block_ip", "target": "203.0.113.45", "reason": "r"}
    assert client.post("/alerts/999/actions", json=ok, headers=H1).status_code == 404


def test_actions_require_key(client):
    aid = ingest_one(client)
    ok = {"action": "block_ip", "target": "203.0.113.45", "reason": "r"}
    assert client.post(f"/alerts/{aid}/actions", json=ok).status_code == 401
    assert client.get("/actions").status_code == 401


def test_rejected_action_cannot_execute(client):
    aid = ingest_one(client)
    ok = {"action": "block_ip", "target": "203.0.113.45", "reason": "r"}
    act = client.post(f"/alerts/{aid}/actions", json=ok, headers=H1).json()["id"]
    client.post(f"/actions/{act}/decision", json={"decision": "reject"}, headers=H2)
    assert client.post(f"/actions/{act}/execute", headers=H2).status_code == 403
    assert len(client.get("/actions?status=rejected", headers=H1).json()) == 1


def test_me_returns_identity(client):
    assert client.get("/me", headers=H2).json() == {"analyst": "analyst_2"}


def test_me_requires_key(client):
    assert client.get("/me").status_code == 401


def test_sample_file_end_to_end(client):
    """The 18-row sample must produce exactly the alerts derived by hand in docs/detection_scenarios.md."""
    import csv
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "data" / "sample" / "auth_sample.csv"
    with open(path, newline="") as fh:
        events = [{"timestamp": r["timestamp"].replace(" ", "T"), "user": r["user"],
                   "src_ip": r["src_ip"], "result": r["result"]} for r in csv.DictReader(fh)]
    r = client.post("/ingest/auth", json={"events": events}, headers=H1)
    assert r.json() == {"events": 18, "alerts_created": 2, "alerts_duplicate": 0}
    alerts = client.get("/alerts", headers=H1).json()
    assert [(a["entity"], a["risk_score"], a["severity"]) for a in alerts] == [
        ("user:bob", 100, "high"), ("ip:198.51.100.23", 40, "medium")]
    assert not any(a["entity"] == "user:alice" for a in alerts)  # the typo must not alert
