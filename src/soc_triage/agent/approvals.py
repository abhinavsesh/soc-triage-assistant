"""Human-approval gate. The model can only PROPOSE. Nothing in this project changes a real
system: the default executor only writes a log line. The rules live in two helper functions
so the in-memory queue and the database version cannot drift apart."""
import ipaddress
import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from soc_triage.agent.tools import USER_RE
from soc_triage.llm.evidence import sanitise

logger = logging.getLogger(__name__)

ACTION_TYPES = {"block_ip", "reset_password", "disable_account"}
MODEL_IDENTITIES = {"", "llm", "model", "assistant", "system", "ai"}


@dataclass
class ProposedAction:
    id: int
    entity: str
    action: str
    target: str
    reason: str
    proposed_by: str
    status: str = "pending"   # pending -> approved or rejected -> executed
    decided_by: str = ""
    decided_at: str = ""


def validate_proposal(action, target):
    """Return the cleaned target, or raise ValueError."""
    if action not in ACTION_TYPES:
        raise ValueError(f"unknown action type: {sanitise(action)}")
    target = str(target)
    if action == "block_ip":
        try:
            ipaddress.ip_address(target)
        except ValueError:
            raise ValueError("block_ip target must be a valid IP address") from None
    elif not USER_RE.match(target):
        raise ValueError("target must be a valid username")
    return target


def check_decider(analyst, proposed_by):
    """Return the normalised decider name, or raise PermissionError."""
    who = str(analyst).strip().lower()
    if who in MODEL_IDENTITIES or who == str(proposed_by).strip().lower():
        raise PermissionError("a human other than the proposer must decide")
    return who


def dry_run_executor(item):
    logger.info("DRY RUN: would %s on %s (approved by %s). No system was changed.",
                item.action, item.target, item.decided_by)


class ApprovalQueue:
    def __init__(self):
        self._items = {}
        self._next = 1

    def propose(self, entity, action, target, reason, proposed_by="llm"):
        target = validate_proposal(action, target)
        item = ProposedAction(self._next, sanitise(entity), action, target,
                              sanitise(reason), str(proposed_by).strip().lower())
        self._items[item.id] = item
        self._next += 1
        logger.info("action %d proposed: %s on %s by %s", item.id, action, target, item.proposed_by)
        return item

    def _decide(self, action_id, analyst, status):
        item = self._items[action_id]
        who = check_decider(analyst, item.proposed_by)
        if item.status != "pending":
            raise ValueError(f"action is already {item.status}")
        item.status, item.decided_by = status, who
        item.decided_at = datetime.now(timezone.utc).isoformat()
        logger.info("action %d %s by %s", item.id, status, who)
        return item

    def approve(self, action_id, analyst):
        return self._decide(action_id, analyst, "approved")

    def reject(self, action_id, analyst):
        return self._decide(action_id, analyst, "rejected")

    def execute(self, action_id, executor=dry_run_executor):
        item = self._items[action_id]
        if item.status != "approved":
            raise PermissionError(f"action is {item.status}, not approved")
        executor(item)
        item.status = "executed"
        return item

    def pending(self):
        return [i for i in self._items.values() if i.status == "pending"]
