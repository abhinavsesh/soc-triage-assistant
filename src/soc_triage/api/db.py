"""SQLite storage layer: plain sqlite3, parameterised queries only, one connection per request."""
import json
import logging
import os
import sqlite3
from datetime import datetime, timezone

from soc_triage import config  # noqa: F401  (importing it loads .env)
from soc_triage.agent.approvals import (
    ProposedAction,
    check_decider,
    dry_run_executor,
    validate_proposal,
)

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
TRANSITIONS = {
    "new": {"investigating", "false_positive", "escalated"},
    "investigating": {"false_positive", "escalated", "closed"},
    "escalated": {"investigating", "closed"},
    "false_positive": {"investigating"},
    "closed": {"investigating"},
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dedup_key TEXT NOT NULL UNIQUE,
    entity TEXT NOT NULL,
    kind TEXT NOT NULL,
    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
    first_seen TEXT NOT NULL,
    signals TEXT NOT NULL,
    evidence TEXT NOT NULL,
    score_breakdown TEXT NOT NULL,
    mitre TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'new'
        CHECK (status IN ('new', 'investigating', 'false_positive', 'escalated', 'closed')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_status_score ON alerts (status, risk_score DESC);

CREATE TABLE IF NOT EXISTS explanations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL REFERENCES alerts (id),
    ok INTEGER NOT NULL,
    problems TEXT NOT NULL,
    explanation TEXT,
    seconds REAL NOT NULL,
    model TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL REFERENCES alerts (id),
    action TEXT NOT NULL CHECK (action IN ('block_ip', 'reset_password', 'disable_account')),
    target TEXT NOT NULL,
    reason TEXT NOT NULL,
    proposed_by TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'executed')),
    decided_by TEXT,
    decided_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    actor TEXT NOT NULL,
    alert_id INTEGER,
    action TEXT NOT NULL,
    detail TEXT NOT NULL
);
"""


class StoreError(Exception):
    """Base class for errors the API turns into specific status codes."""


class NotFoundError(StoreError):
    pass


class ConflictError(StoreError):
    pass


class BadRequestError(StoreError):
    pass


class ForbiddenError(StoreError):
    pass


def db_path():
    url = os.getenv("DATABASE_URL", "sqlite:///./soc_triage.db")
    if not url.startswith("sqlite:///"):
        raise ValueError("only sqlite:/// URLs are supported")
    return url[len("sqlite:///"):]


def connect():
    # check_same_thread=False: FastAPI may open and close a request's connection on
    # different worker threads. Each request still gets its own connection.
    conn = sqlite3.connect(db_path(), check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db(conn):
    conn.executescript(SCHEMA)
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")  # a real project would use migrations
    conn.commit()


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _dump(obj):
    return json.dumps(obj, default=str)


def _audit(conn, actor, action, alert_id=None, detail=""):
    """Call only inside a `with conn:` block. Details must be our own text, never raw log text."""
    conn.execute(
        "INSERT INTO audit_log (at, actor, alert_id, action, detail) VALUES (?, ?, ?, ?, ?)",
        (_now(), actor, alert_id, action, detail[:500]),
    )


# ---------- alerts ----------
def store_alerts(conn, alerts, actor, n_events):
    """Insert alerts in one transaction. A repeated alert (same entity, kind, first_seen) is skipped."""
    created = duplicates = 0
    now = _now()
    with conn:
        for a in alerts:
            key = f"{a['entity']}|{a['kind']}|{a['first_seen']}"
            cur = conn.execute(
                "INSERT OR IGNORE INTO alerts (dedup_key, entity, kind, risk_score, severity, first_seen,"
                " signals, evidence, score_breakdown, mitre, created_at, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (key, a["entity"], a["kind"], int(a["risk_score"]), a["severity"], a["first_seen"],
                 _dump(a["signals"]), _dump(a["evidence"]), _dump(a["score_breakdown"]),
                 _dump(a["mitre"]), now, now),
            )
            if cur.rowcount == 1:
                created += 1
            else:
                duplicates += 1
        _audit(conn, actor, "ingest", None,
               f"{n_events} events, {created} new alerts, {duplicates} duplicates")
    return created, duplicates


def _alert_from_row(r):
    return {
        "id": r["id"], "entity": r["entity"], "kind": r["kind"], "risk_score": r["risk_score"],
        "severity": r["severity"], "first_seen": r["first_seen"], "status": r["status"],
        "signals": json.loads(r["signals"]), "evidence": json.loads(r["evidence"]),
        "score_breakdown": json.loads(r["score_breakdown"]), "mitre": json.loads(r["mitre"]),
        "created_at": r["created_at"], "updated_at": r["updated_at"],
    }


def list_alerts(conn, status=None, severity=None, min_score=0, limit=50, offset=0):
    # Only fixed SQL fragments are concatenated. Every value goes through a placeholder.
    where, params = ["risk_score >= ?"], [min_score]
    if status:
        where.append("status = ?")
        params.append(status)
    if severity:
        where.append("severity = ?")
        params.append(severity)
    sql = ("SELECT * FROM alerts WHERE " + " AND ".join(where)
           + " ORDER BY risk_score DESC, id ASC LIMIT ? OFFSET ?")
    return [_alert_from_row(r) for r in conn.execute(sql, [*params, limit, offset]).fetchall()]


def get_alert(conn, alert_id):
    row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if row is None:
        raise NotFoundError("alert not found")
    alert = _alert_from_row(row)
    alert["explanation"] = latest_explanation(conn, alert_id)
    alert["history"] = [dict(r) for r in conn.execute(
        "SELECT at, actor, action, detail FROM audit_log WHERE alert_id = ? ORDER BY id", (alert_id,))]
    return alert


def update_status(conn, alert_id, new_status, actor, note=None):
    with conn:
        row = conn.execute("SELECT status FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if row is None:
            raise NotFoundError("alert not found")
        old = row["status"]
        if new_status not in TRANSITIONS[old]:
            raise ConflictError(f"cannot move from {old} to {new_status}")
        # Optimistic concurrency: only update if nobody changed the status since we read it.
        cur = conn.execute(
            "UPDATE alerts SET status = ?, updated_at = ? WHERE id = ? AND status = ?",
            (new_status, _now(), alert_id, old))
        if cur.rowcount != 1:
            raise ConflictError("status was changed by someone else, reload and retry")
        _audit(conn, actor, "status_change", alert_id,
               f"{old} -> {new_status}" + (f" | {note}" if note else ""))
    return _alert_from_row(conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone())


# ---------- explanations ----------
def latest_explanation(conn, alert_id):
    r = conn.execute("SELECT * FROM explanations WHERE alert_id = ? ORDER BY id DESC LIMIT 1",
                     (alert_id,)).fetchone()
    if r is None:
        return None
    return {"id": r["id"], "created_at": r["created_at"], "ok": bool(r["ok"]),
            "problems": json.loads(r["problems"]),
            "explanation": json.loads(r["explanation"]) if r["explanation"] else None,
            "seconds": r["seconds"], "model": r["model"], "requested_by": r["requested_by"]}


def save_explanation(conn, alert_id, result, model, actor):
    with conn:
        if conn.execute("SELECT 1 FROM alerts WHERE id = ?", (alert_id,)).fetchone() is None:
            raise NotFoundError("alert not found")
        conn.execute(
            "INSERT INTO explanations (alert_id, ok, problems, explanation, seconds, model,"
            " requested_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (alert_id, int(bool(result["ok"])), _dump(result["problems"]),
             _dump(result["explanation"]) if result.get("explanation") else None,
             float(result["seconds"]), model, actor, _now()))
        _audit(conn, actor, "explanation_requested", alert_id,
               f"ok={bool(result['ok'])}, problems={len(result['problems'])}")
    return latest_explanation(conn, alert_id)


# ---------- approvals ----------
def get_action(conn, action_id):
    row = conn.execute("SELECT * FROM approvals WHERE id = ?", (action_id,)).fetchone()
    if row is None:
        raise NotFoundError("action not found")
    return dict(row)


def list_actions(conn, status=None):
    if status:
        rows = conn.execute("SELECT * FROM approvals WHERE status = ? ORDER BY id", (status,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM approvals ORDER BY id").fetchall()
    return [dict(r) for r in rows]


def propose_action(conn, alert_id, action, target, reason, proposed_by):
    try:
        target = validate_proposal(action, target)
    except ValueError as e:
        raise BadRequestError(str(e)) from None
    who = str(proposed_by).strip().lower()
    with conn:
        if conn.execute("SELECT 1 FROM alerts WHERE id = ?", (alert_id,)).fetchone() is None:
            raise NotFoundError("alert not found")
        cur = conn.execute(
            "INSERT INTO approvals (alert_id, action, target, reason, proposed_by, status, created_at)"
            " VALUES (?, ?, ?, ?, ?, 'pending', ?)",
            (alert_id, action, target, reason, who, _now()))
        _audit(conn, who, "action_proposed", alert_id, f"{action} #{cur.lastrowid}")
    return get_action(conn, cur.lastrowid)


def decide_action(conn, action_id, analyst, decision):
    status = "approved" if decision == "approve" else "rejected"
    with conn:
        row = conn.execute("SELECT * FROM approvals WHERE id = ?", (action_id,)).fetchone()
        if row is None:
            raise NotFoundError("action not found")
        try:
            who = check_decider(analyst, row["proposed_by"])
        except PermissionError as e:
            raise ForbiddenError(str(e)) from None
        cur = conn.execute(
            "UPDATE approvals SET status = ?, decided_by = ?, decided_at = ? WHERE id = ? AND status = 'pending'",
            (status, who, _now(), action_id))
        if cur.rowcount != 1:
            raise ConflictError(f"action is already {row['status']}")
        _audit(conn, who, f"action_{status}", row["alert_id"], f"#{action_id}")
    return get_action(conn, action_id)


def execute_action(conn, action_id, actor, executor=dry_run_executor):
    """Run an approved action. The status flip is atomic, so a double click cannot execute twice.
    A real executor would also need failure handling; the default one only logs."""
    with conn:
        row = conn.execute("SELECT * FROM approvals WHERE id = ?", (action_id,)).fetchone()
        if row is None:
            raise NotFoundError("action not found")
        if row["status"] != "approved":
            raise ForbiddenError(f"action is {row['status']}, not approved")
        cur = conn.execute("UPDATE approvals SET status = 'executed' WHERE id = ? AND status = 'approved'",
                           (action_id,))
        if cur.rowcount != 1:
            raise ConflictError("action was already executed")
        entity = conn.execute("SELECT entity FROM alerts WHERE id = ?", (row["alert_id"],)).fetchone()["entity"]
        executor(ProposedAction(
            id=row["id"], entity=entity, action=row["action"], target=row["target"],
            reason=row["reason"], proposed_by=row["proposed_by"], status="approved",
            decided_by=row["decided_by"] or "", decided_at=row["decided_at"] or ""))
        _audit(conn, actor, "action_executed", row["alert_id"], f"#{action_id} (dry run)")
    return get_action(conn, action_id)
