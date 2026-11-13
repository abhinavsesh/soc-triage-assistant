"""Human-approval gate. The model can only PROPOSE. Nothing in this project changes a real
system: the default executor only writes a log line."""
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


def dry_run_executor(item):
    logger.info("DRY RUN: would %s on %s (approved by %s). No system was changed.",
                item.action, item.target, item.decided_by)


class ApprovalQueue:
    def __init__(self):
        self._items = {}
        self._next = 1

    def propose(self, entity, action, target, reason, proposed_by="llm"):
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
        item = ProposedAction(self._next, sanitise(entity), action, target,
                              sanitise(reason), str(proposed_by).strip().lower())
        self._items[item.id] = item
        self._next += 1
        logger.info("action %d proposed: %s on %s by %s", item.id, action, target, item.proposed_by)
        return item

    def _decide(self, action_id, analyst, status):
        item = self._items[action_id]
        who = str(analyst).strip().lower()
        if who in MODEL_IDENTITIES or who == item.proposed_by:
            raise PermissionError("a human other than the proposer must decide")
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
