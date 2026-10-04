"""Append-only, hash-chained audit ledger."""

from __future__ import annotations

from portpower.audit.chain import HashChain, Verification, VolumeInfo
from portpower.audit.entry import KIND_BACKFILL, KIND_MIGRATED, AuditEntry
from portpower.store.kvstore import RecordStore

LEDGER_KEY = "audit.log"


class Ledger:
    """Facade used by the console: append, backfill, verify, seal."""

    def __init__(self, store: RecordStore) -> None:
        self._store = store
        self._chain = HashChain(store.directory / "audit-chain")
        self._chain.open()
        self._migrate_legacy()

    def append(self, event: str, detail: str) -> AuditEntry:
        return self._chain.append(event, detail)

    def backfill(self, event: str, detail: str, *, occurred_at: str, reason: str) -> AuditEntry:
        """Record a historical event, explicitly marked as a late entry.

        The record lands at the tail of the chain with the true append time;
        ``occurred_at`` states the moment it describes and ``reason`` why it
        was recorded late.  Both are hashed in, so a backfill can never pose
        as a contemporaneous record.
        """

        return self._chain.append(
            event,
            detail,
            kind=KIND_BACKFILL,
            occurred_at=occurred_at,
            reason=reason,
        )

    def entries(self) -> list[AuditEntry]:
        return self._chain.records()

    def latest(self) -> AuditEntry | None:
        records = self._chain.records()
        return records[-1] if records else None

    def count(self) -> int:
        return len(self._chain.records())

    def verify(self) -> Verification:
        return self._chain.verify()

    def seal(self) -> VolumeInfo:
        return self._chain.seal()

    def volumes(self) -> list[VolumeInfo]:
        return self._chain.volumes()

    def close(self) -> None:
        self._chain.close()

    def _migrate_legacy(self) -> None:
        """Fold the pre-chain ``audit.log`` document into the chain once.

        Migrated records keep their original timestamps and are marked
        ``migrated``.  Already-migrated lines are skipped, so a crash
        between the chain write and the legacy delete is harmless.
        """

        document = self._store.get_json(LEDGER_KEY)
        if document is None:
            return
        if not isinstance(document, list):
            return  # not a ledger document; leave it untouched
        migrated = {
            (entry.at, entry.event, entry.detail)
            for entry in self._chain.records()
            if entry.kind == KIND_MIGRATED
        }
        for item in document:
            entry = AuditEntry.from_dict(item)
            if entry is None:
                continue
            key = (entry.at, entry.event, entry.detail)
            if key in migrated:
                continue
            self._chain.append(entry.event, entry.detail, kind=KIND_MIGRATED, at=entry.at)
            migrated.add(key)
        self._store.delete(LEDGER_KEY)
