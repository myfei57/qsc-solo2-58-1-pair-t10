"""One audit line: a record in the hash-chained ledger."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

KIND_LIVE = "live"
KIND_BACKFILL = "backfill"
KIND_MIGRATED = "migrated"
KINDS = (KIND_LIVE, KIND_BACKFILL, KIND_MIGRATED)


@dataclass(frozen=True)
class AuditEntry:
    """One link in the audit chain.

    ``at`` is always the moment the record was appended.  A backfill keeps
    the historical moment it describes in ``occurred_at`` and the
    justification in ``reason``; both are hashed into the chain, so a late
    record can never pose as a contemporaneous one.
    """

    seq: int
    at: str
    event: str
    detail: str
    kind: str = KIND_LIVE
    occurred_at: str = ""
    reason: str = ""
    prev: str = ""
    hash: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: object) -> "AuditEntry | None":
        if not isinstance(payload, dict):
            return None
        at = payload.get("at")
        event = payload.get("event")
        detail = payload.get("detail")
        if not all(isinstance(item, str) for item in (at, event, detail)):
            return None
        seq = payload.get("seq", 0)
        if isinstance(seq, bool) or not isinstance(seq, int):
            return None
        kind = payload.get("kind", KIND_LIVE)
        occurred_at = payload.get("occurred_at", "")
        reason = payload.get("reason", "")
        prev = payload.get("prev", "")
        digest = payload.get("hash", "")
        if not all(isinstance(item, str) for item in (kind, occurred_at, reason, prev, digest)):
            return None
        return cls(
            seq=seq,
            at=at,
            event=event,
            detail=detail,
            kind=kind,
            occurred_at=occurred_at,
            reason=reason,
            prev=prev,
            hash=digest,
        )
