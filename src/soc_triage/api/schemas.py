"""Request and response models. Requests are validated strictly; responses are an output whitelist."""
import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator

CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

StatusName = Literal["new", "investigating", "false_positive", "escalated", "closed"]
SeverityName = Literal["low", "medium", "high"]
ActionName = Literal["block_ip", "reset_password", "disable_account"]
ActionStatus = Literal["pending", "approved", "rejected", "executed"]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")  # unknown fields are an error


class AuthEvent(Strict):
    timestamp: datetime
    user: str
    src_ip: IPvAnyAddress
    result: Literal["success", "failure"]

    @field_validator("user", mode="before")
    @classmethod
    def clean_user(cls, v):
        # Truncate and neutralise instead of rejecting: one hostile username must not
        # be able to make a whole batch (and the attack inside it) disappear.
        if not isinstance(v, str):
            raise ValueError("user must be a string")
        v = CONTROL_RE.sub("?", v)[:128].strip()
        if not v:
            raise ValueError("user must not be empty")
        return v


class AuthIngest(Strict):
    events: list[AuthEvent] = Field(min_length=1, max_length=5000)


class StatusUpdate(Strict):
    status: StatusName
    note: str | None = Field(default=None, max_length=500)


class ActionProposal(Strict):
    action: ActionName
    target: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=500)


class Decision(Strict):
    decision: Literal["approve", "reject"]


class IngestResult(BaseModel):
    events: int
    alerts_created: int
    alerts_duplicate: int


class AlertSummary(BaseModel):
    id: int
    entity: str
    kind: str
    risk_score: int
    severity: SeverityName
    status: StatusName
    first_seen: str
    signals: list[str]
    created_at: str
    updated_at: str


class HistoryItem(BaseModel):
    at: str
    actor: str
    action: str
    detail: str


class ExplanationOut(BaseModel):
    id: int
    created_at: str
    ok: bool
    problems: list[str]
    explanation: dict | None = None
    seconds: float
    model: str
    requested_by: str


class AlertDetail(AlertSummary):
    evidence: dict
    score_breakdown: dict[str, int]
    mitre: list[dict]
    explanation: ExplanationOut | None = None
    history: list[HistoryItem]


class ActionOut(BaseModel):
    id: int
    alert_id: int
    action: str
    target: str
    reason: str
    proposed_by: str
    status: ActionStatus
    decided_by: str | None = None
    decided_at: str | None = None
    created_at: str
    dry_run: bool = True  # nothing in this project changes a real system
