"""Argument-bound, single-use, expiring approvals (control C4).

When the policy says "ask", the owner approves one *exact* action: the approval stores a SHA-256
digest of the tool name and its validated arguments. Executing anything else (a different
recipient, a changed body, another tool) fails, as does reusing or outliving the approval.
"""

import hashlib
import hmac
import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from bastion.common import canonical_json, utc_now
from bastion.tools.base import RiskTier, ToolArgs

DEFAULT_TTL = timedelta(minutes=10)
_RETENTION = timedelta(hours=1)


class ApprovalError(Exception):
    """An approval is missing, expired, already used, or does not match the action."""


class _Status(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    USED = "used"


@dataclass(frozen=True)
class ApprovalRequest:
    id: str
    tool: str
    tier: RiskTier
    arguments_json: str
    digest: str
    summary: str
    reason: str
    step_up: bool
    created_at: datetime
    expires_at: datetime


def action_digest(tool: str, args: ToolArgs) -> str:
    payload = canonical_json({"tool": tool, "args": args.model_dump(mode="json")})
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ApprovalService:
    def __init__(
        self, clock: Callable[[], datetime] = utc_now, ttl: timedelta = DEFAULT_TTL
    ) -> None:
        self._clock = clock
        self._ttl = ttl
        self._requests: dict[str, ApprovalRequest] = {}
        self._status: dict[str, _Status] = {}

    def create(
        self,
        *,
        tool: str,
        tier: RiskTier,
        args: ToolArgs,
        summary: str,
        reason: str,
        step_up: bool,
    ) -> ApprovalRequest:
        self._prune()
        now = self._clock()
        request = ApprovalRequest(
            id=secrets.token_urlsafe(16),
            tool=tool,
            tier=tier,
            arguments_json=json.dumps(args.model_dump(mode="json"), indent=2, ensure_ascii=False),
            digest=action_digest(tool, args),
            summary=summary,
            reason=reason,
            step_up=step_up,
            created_at=now,
            expires_at=now + self._ttl,
        )
        self._requests[request.id] = request
        self._status[request.id] = _Status.PENDING
        return request

    def _lookup(self, request_id: str) -> ApprovalRequest:
        request = self._requests.get(request_id)
        if request is None:
            raise ApprovalError("unknown approval request")
        return request

    def _expired(self, request: ApprovalRequest) -> bool:
        return self._clock() >= request.expires_at

    def record_decision(self, request_id: str, *, approved: bool) -> None:
        request = self._lookup(request_id)
        if self._status[request_id] is not _Status.PENDING:
            raise ApprovalError("approval request already decided")
        if self._expired(request):
            raise ApprovalError("approval request expired")
        self._status[request_id] = _Status.APPROVED if approved else _Status.DENIED

    def consume(self, request_id: str, tool: str, args: ToolArgs) -> None:
        """Atomically check an approval against the action about to run, then burn it."""
        request = self._lookup(request_id)
        status = self._status[request_id]
        if status is _Status.USED:
            raise ApprovalError("approval already used")
        if status is not _Status.APPROVED:
            raise ApprovalError("action was not approved")
        if self._expired(request):
            raise ApprovalError("approval expired")
        matches = tool == request.tool and hmac.compare_digest(
            request.digest, action_digest(tool, args)
        )
        if not matches:
            raise ApprovalError("arguments do not match the approved action")
        self._status[request_id] = _Status.USED

    def _prune(self) -> None:
        cutoff = self._clock() - _RETENTION
        stale = [rid for rid, req in self._requests.items() if req.expires_at < cutoff]
        for request_id in stale:
            del self._requests[request_id]
            del self._status[request_id]
