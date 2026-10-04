"""Verification outcomes for the chained ledger."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ChainBreak:
    """The first place the chain fails to prove itself."""

    layer: str  # "entry" | "head" | "volume" | "link"
    seq: int
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {"layer": self.layer, "seq": self.seq, "reason": self.reason}


@dataclass(frozen=True)
class VerifyReport:
    ok: bool
    checked_entries: int
    checked_volumes: int
    head_seq: int
    head_digest: str | None
    active_volume: int
    orphans: tuple[int, ...]
    first_break: ChainBreak | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "checked_entries": self.checked_entries,
            "checked_volumes": self.checked_volumes,
            "head_seq": self.head_seq,
            "head_digest": self.head_digest,
            "active_volume": self.active_volume,
            "orphans": list(self.orphans),
            "first_break": None if self.first_break is None else self.first_break.as_dict(),
        }
