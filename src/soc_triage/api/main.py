"""FastAPI application. Handlers are plain `def`, so FastAPI runs them in a thread pool and a
slow model call does not block other requests."""
import logging
import sqlite3
import time
import uuid
from collections.abc import Callable
from contextlib import asynccontextmanager, closing
from typing import Annotated

import pandas as pd
from fastapi import APIRouter, Depends, FastAPI, Query, Request
from fastapi.responses import JSONResponse

from soc_triage.api.auth import current_analyst
from soc_triage.api.db import (
    BadRequestError, ConflictError, ForbiddenError, NotFoundError,
    connect, decide_action, execute_action, get_alert, init_db, list_actions, list_alerts,
    propose_action, save_explanation, store_alerts, update_status,
)
from soc_triage.api.schemas import (
    ActionOut, ActionProposal, ActionStatus, AlertDetail, AlertSummary, AuthIngest, Decision,
    ExplanationOut, IngestResult, SeverityName, StatusName, StatusUpdate,
)
from soc_triage.config import OLLAMA_MODEL
from soc_triage.detection.incidents import detect_auth
from soc_triage.llm.client import LLMError
from soc_triage.llm.explain import explain_alert
from soc_triage.logging_setup import setup_logging
from soc_triage.scoring.alerts import build_alerts

logger = logging.getLogger(__name__)

LLM_KEYS = ("entity", "kind", "first_seen", "risk_score", "severity", "signals",
            "score_breakdown", "mitre", "evidence")


@asynccontextmanager
async def lifespan(app):
    setup_logging()
    with closing(connect()) as conn:
        init_db(conn)
    logger.info("API started")
    yield


app = FastAPI(title="SOC Alert Triage Assistant", lifespan=lifespan)


# ---------- logging and error handling ----------
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log method, path, status and timing. Never bodies or query strings (they can hold log text)."""
    rid = uuid.uuid4().hex[:12]
    t0 = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        logger.exception("request %s failed: %s %s", rid, request.method, request.url.path)
        return JSONResponse({"detail": "internal error", "request_id": rid}, status_code=500)
    response.headers["X-Request-ID"] = rid
    logger.info("request %s %s %s -> %d in %.0f ms", rid, request.method, request.url.path,
                response.status_code, (time.perf_counter() - t0) * 1000)
    return response


def _error(status, detail):
    return JSONResponse({"detail": detail}, status_code=status)


@app.exception_handler(NotFoundError)
async def _not_found(request, exc):
    return _error(404, str(exc))


@app.exception_handler(ConflictError)
async def _conflict(request, exc):
    return _error(409, str(exc))


@app.exception_handler(BadRequestError)
async def _bad_request(request, exc):
    return _error(400, str(exc))


@app.exception_handler(ForbiddenError)
async def _forbidden(request, exc):
    return _error(403, str(exc))


@app.exception_handler(LLMError)
async def _llm_down(request, exc):
    logger.warning("model server unavailable")
    return _error(503, "model server unavailable")  # no internal details in the response


# ---------- dependencies ----------
def get_conn():
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()


def get_explainer():
    return explain_alert  # tests override this so they need no model


Conn = Annotated[sqlite3.Connection, Depends(get_conn)]
Analyst = Annotated[str, Depends(current_analyst)]
Explainer = Annotated[Callable[[dict], dict], Depends(get_explainer)]

router = APIRouter(dependencies=[Depends(current_analyst)])  # every route here needs a valid key


@app.get("/health")
def health():
    return {"status": "ok"}


# ---------- ingest ----------
@router.post("/ingest/auth", response_model=IngestResult)
def ingest_auth(body: AuthIngest, conn: Conn, analyst: Analyst):
    """Analyse one batch of auth events and store the alerts. Events themselves are not stored,
    and the new-IP baseline comes from this batch only."""
    df = pd.DataFrame({
        "timestamp": pd.to_datetime([e.timestamp for e in body.events], utc=True).tz_localize(None),
        "user": [e.user for e in body.events],
        "src_ip": [str(e.src_ip) for e in body.events],
        "is_failure": [int(e.result == "failure") for e in body.events],
    })
    alerts = build_alerts(detect_auth(df))
    created, duplicates = store_alerts(conn, alerts, analyst, len(df))
    return {"events": len(df), "alerts_created": created, "alerts_duplicate": duplicates}


# ---------- alerts ----------
@router.get("/alerts", response_model=list[AlertSummary])
def alerts(
    conn: Conn,
    status: StatusName | None = None,
    severity: SeverityName | None = None,
    min_score: Annotated[int, Query(ge=0, le=100)] = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    return list_alerts(conn, status, severity, min_score, limit, offset)


@router.get("/alerts/{alert_id}", response_model=AlertDetail)
def alert_detail(alert_id: int, conn: Conn):
    return get_alert(conn, alert_id)


@router.patch("/alerts/{alert_id}/status", response_model=AlertSummary)
def change_status(alert_id: int, body: StatusUpdate, conn: Conn, analyst: Analyst):
    return update_status(conn, alert_id, body.status, analyst, body.note)


@router.post("/alerts/{alert_id}/explain", response_model=ExplanationOut)
def explain(alert_id: int, conn: Conn, analyst: Analyst, explainer: Explainer, refresh: bool = False):
    """Explain an alert with the local model (about 20 s). The latest explanation is cached."""
    alert = get_alert(conn, alert_id)
    if alert["explanation"] and not refresh:
        return alert["explanation"]
    result = explainer({k: alert[k] for k in LLM_KEYS})
    return save_explanation(conn, alert_id, result, OLLAMA_MODEL, analyst)


# ---------- approvals ----------
@router.post("/alerts/{alert_id}/actions", response_model=ActionOut, status_code=201)
def propose(alert_id: int, body: ActionProposal, conn: Conn, analyst: Analyst):
    return propose_action(conn, alert_id, body.action, body.target, body.reason, analyst)


@router.get("/actions", response_model=list[ActionOut])
def actions(conn: Conn, status: ActionStatus | None = None):
    return list_actions(conn, status)


@router.post("/actions/{action_id}/decision", response_model=ActionOut)
def decision(action_id: int, body: Decision, conn: Conn, analyst: Analyst):
    return decide_action(conn, action_id, analyst, body.decision)


@router.post("/actions/{action_id}/execute", response_model=ActionOut)
def execute(action_id: int, conn: Conn, analyst: Analyst):
    """Dry run only. Nothing in this project changes a real system."""
    return execute_action(conn, action_id, analyst)


app.include_router(router)
