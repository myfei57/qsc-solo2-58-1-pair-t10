"""One audit line, bound to its predecessor."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from typing import Any

from portpower.audit.chain import GENESIS, digest_of


@dataclass(frozen=True)
class Backfill:
    """Why a historical event was recorded after the fact.

    A backfill never rewrites history: the entry keeps the wall-clock time it
    was appended, and the historical moment lives only in this annotation.
    """

    original_at: str
    reason: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: object) -> "Backfill | None":
        if not isinstance(payload, dict):
            return None
        original_at = payload.get("original_at")
        reason = payload.get("reason")
        if not isinstance(original_at, str) or not isinstance(reason, str):
            return None
        return cls(original_at=original_at, reason=reason)


@dataclass(frozen=True)
class AuditEntry:
    at: str
    event: str
    detail: str
    seq: int = 0
    prev: str = GENESIS
    digest: str = ""
    backfill: Backfill | None = None

    def signing_payload(self) -> dict[str, Any]:
        """Everything the digest commits to, in canonical form."""

        return {
            "seq": self.seq,
            "at": self.at,
            "event": self.event,
            "detail": self.detail,
            "backfill": None if self.backfill is None else self.backfill.as_dict(),
            "prev": self.prev,
        }

    def sign(self) -> "AuditEntry":
        """Return a copy whose digest commits to every other field."""

        return replace(self, digest=digest_of(self.signing_payload()))

    def digest_matches(self) -> bool:
        return self.digest == digest_of(self.signing_payload())

    def as_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "at": self.at,
            "event": self.event,
            "detail": self.detail,
            "prev": self.prev,
            "digest": self.digest,
            "backfill": None if self.backfill is None else self.backfill.as_dict(),
        }

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
        prev = payload.get("prev", GENESIS)
        digest = payload.get("digest", "")
        if not isinstance(seq, int) or isinstance(seq, bool):
            return None
        if not isinstance(prev, str) or not isinstance(digest, str):
            return None
        backfill_raw = payload.get("backfill")
        backfill = Backfill.from_dict(backfill_raw) if backfill_raw is not None else None
        if backfill_raw is not None and backfill is None:
            return None
        return cls(
            at=at,
            event=event,
            detail=detail,
            seq=seq,
            prev=prev,
            digest=digest,
            backfill=backfill,
        )
