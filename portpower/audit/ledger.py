"""Append-only hash-chained audit ledger with sealable archive volumes.

Storage layout (one key per record, never a whole-log rewrite):

- ``audit.chain.<seq>``  one immutable entry per key; each write is a single
  atomic file replace, so a power cut loses at most the in-flight entry and
  the gap is visible to :meth:`Ledger.verify`.
- ``audit.head``         the chain tip and active-volume pointer; written
  last, so it is the commit point of every append and seal.
- ``audit.volume.<n>``   one sealed manifest per archived volume.

Appends and seals share one atomic read-modify-write on ``audit.head``, so a
seal can never split an append and vice versa.  Verification only performs
short reads against immutable records and never holds the store lock across
the walk, so it does not stall business writes.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from portpower.audit.chain import GENESIS
from portpower.audit.entry import AuditEntry, Backfill
from portpower.audit.verify import ChainBreak, VerifyReport
from portpower.audit.volume import VolumeManifest
from portpower.store.kvstore import RecordStore
from portpower.store.query import keys_with_prefix

HEAD_KEY = "audit.head"
LEGACY_KEY = "audit.log"
ENTRY_PREFIX = "audit.chain."
VOLUME_PREFIX = "audit.volume."
LEGACY_REASON = "imported from legacy audit.log during upgrade"


class LedgerCorrupt(RuntimeError):
    """Raised when the chain head or a sealed manifest cannot be trusted."""


class Ledger:
    def __init__(self, store: RecordStore) -> None:
        self._store = store

    # ------------------------------------------------------------------
    # writes
    # ------------------------------------------------------------------

    def append(self, event: str, detail: str) -> AuditEntry:
        return self._commit(event, detail, backfill=None)

    def append_backfill(
        self, event: str, detail: str, original_at: str, reason: str
    ) -> AuditEntry:
        """Record a historical event without disguising it as current.

        The entry is appended now, in chain order; the historical moment is
        only carried by the mandatory backfill annotation.
        """

        if not original_at.strip() or not reason.strip():
            raise ValueError("backfill requires original_at and reason")
        backfill = Backfill(original_at=original_at, reason=reason)
        return self._commit(event, detail, backfill=backfill)

    def seal(self) -> VolumeManifest | None:
        """Seal the active volume and open a fresh one.

        Returns ``None`` when the active volume is still empty.  The work is
        O(1): the manifest is derived from the head document, so sealing never
        walks entries and never blocks appends longer than one head update.
        """

        self._guard_head_readable()
        sealed_at = _timestamp()

        def mutate(head: object) -> tuple[object, VolumeManifest | None]:
            current = _normalize_head(head)
            first_seq = current["volume_first_seq"]
            last_seq = current["seq"]
            if last_seq < first_seq:
                return None, None
            volume = current["volume"]
            prev_volume_head = GENESIS
            if volume > 1:
                previous = self._read_volume(volume - 1)
                if previous is None:
                    raise LedgerCorrupt(
                        f"previous volume manifest {volume - 1} is missing"
                    )
                prev_volume_head = previous.head_digest
            manifest = VolumeManifest(
                volume=volume,
                first_seq=first_seq,
                last_seq=last_seq,
                count=last_seq - first_seq + 1,
                first_digest=current["volume_first_digest"],
                head_digest=current["digest"],
                prev_volume_head=prev_volume_head,
                sealed_at=sealed_at,
            ).sign()
            self._store.put_json(_volume_key(volume), manifest.as_dict())
            new_head = {
                "seq": last_seq,
                "digest": current["digest"],
                "volume": volume + 1,
                "volume_first_seq": last_seq + 1,
                "volume_first_digest": "",
            }
            return new_head, manifest

        return self._store.update_json(HEAD_KEY, mutate)

    # ------------------------------------------------------------------
    # reads
    # ------------------------------------------------------------------

    def entries(self) -> list[AuditEntry]:
        head = self._head()
        if head is None:
            return []
        entries: list[AuditEntry] = []
        for seq in range(1, head["seq"] + 1):
            entry = self._read_entry(seq)
            if entry is not None:
                entries.append(entry)
        return entries

    def latest(self) -> AuditEntry | None:
        head = self._head()
        if head is None:
            return None
        return self._read_entry(head["seq"])

    def count(self) -> int:
        head = self._head()
        return 0 if head is None else head["seq"]

    def volumes(self) -> list[VolumeManifest]:
        head = self._head()
        if head is None:
            return []
        manifests: list[VolumeManifest] = []
        for volume in range(1, head["volume"]):
            manifest = self._read_volume(volume)
            if manifest is not None:
                manifests.append(manifest)
        return manifests

    # ------------------------------------------------------------------
    # verification
    # ------------------------------------------------------------------

    def verify(self) -> VerifyReport:
        """Replay the chain and report the first place it fails to prove itself."""

        head = self._head()
        if head is None:
            orphans = self._orphan_seqs(0)
            first_break = None
            if orphans:
                first_break = ChainBreak("entry", orphans[0], "entry without chain head")
            return VerifyReport(
                ok=not orphans,
                checked_entries=0,
                checked_volumes=0,
                head_seq=0,
                head_digest=None,
                active_volume=1,
                orphans=orphans,
                first_break=first_break,
            )

        entries: dict[int, AuditEntry] = {}
        prev_digest = GENESIS
        first_break: ChainBreak | None = None
        for seq in range(1, head["seq"] + 1):
            entry = self._read_entry(seq)
            if entry is None:
                first_break = ChainBreak("entry", seq, "entry record missing")
                break
            if entry.seq != seq:
                first_break = ChainBreak(
                    "entry", seq, f"stored under seq {seq} but declares {entry.seq}"
                )
                break
            if not entry.digest_matches():
                first_break = ChainBreak("entry", seq, "digest does not match content")
                break
            if entry.prev != prev_digest:
                first_break = ChainBreak(
                    "entry", seq, "prev link does not match predecessor"
                )
                break
            prev_digest = entry.digest
            entries[seq] = entry

        if first_break is None and prev_digest != head["digest"]:
            first_break = ChainBreak(
                "head", head["seq"], "head digest does not match chain tip"
            )

        checked_volumes = 0
        if first_break is None:
            checked_volumes, first_break = self._verify_volumes(head, entries)

        orphans = self._orphan_seqs(head["seq"])
        return VerifyReport(
            ok=first_break is None and not orphans,
            checked_entries=len(entries),
            checked_volumes=checked_volumes,
            head_seq=head["seq"],
            head_digest=head["digest"],
            active_volume=head["volume"],
            orphans=orphans,
            first_break=first_break,
        )

    def _verify_volumes(
        self, head: dict[str, Any], entries: dict[int, AuditEntry]
    ) -> tuple[int, ChainBreak | None]:
        """Check sealed manifests against the entries and against each other."""

        checked = 0
        prev_volume_head = GENESIS
        for volume in range(1, head["volume"]):
            manifest = self._read_volume(volume)
            if manifest is None:
                return checked, ChainBreak("volume", volume, "manifest missing")
            if not manifest.digest_matches():
                return checked, ChainBreak(
                    "volume", volume, "manifest digest does not match content"
                )
            if manifest.prev_volume_head != prev_volume_head:
                return checked, ChainBreak(
                    "volume", volume, "volume does not chain to previous volume"
                )
            first = entries.get(manifest.first_seq)
            last = entries.get(manifest.last_seq)
            if (
                first is None
                or last is None
                or manifest.count != manifest.last_seq - manifest.first_seq + 1
                or first.digest != manifest.first_digest
                or last.digest != manifest.head_digest
            ):
                return checked, ChainBreak(
                    "volume", volume, "manifest does not match archived entries"
                )
            if first.prev != manifest.prev_volume_head:
                return checked, ChainBreak(
                    "link",
                    manifest.first_seq,
                    "archived range does not continue previous volume",
                )
            prev_volume_head = manifest.head_digest
            checked += 1

        first_seq = head["volume_first_seq"]
        if head["volume"] > 1 and head["seq"] >= first_seq:
            first = entries.get(first_seq)
            if first is None or first.prev != prev_volume_head:
                return checked, ChainBreak(
                    "link", first_seq, "active volume does not continue sealed archive"
                )
        return checked, None

    # ------------------------------------------------------------------
    # legacy import
    # ------------------------------------------------------------------

    def migrate_legacy(self) -> int:
        """Import the pre-chain ``audit.log`` document as marked backfills.

        Runs only when the chain has not started yet; the legacy document is
        left in place as evidence of where the imported entries came from.
        """

        if self._head() is not None:
            return 0
        document = self._store.get_json(LEGACY_KEY)
        if not isinstance(document, list) or not document:
            return 0
        legacy: list[AuditEntry] = []
        for item in document:
            entry = AuditEntry.from_dict(item)
            if entry is not None:
                legacy.append(entry)
        legacy.sort(key=lambda item: item.at)
        for item in legacy:
            self.append_backfill(
                item.event,
                item.detail,
                original_at=item.at,
                reason=LEGACY_REASON,
            )
        return len(legacy)

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _commit(
        self, event: str, detail: str, backfill: Backfill | None
    ) -> AuditEntry:
        self._guard_head_readable()
        at = _timestamp()

        def mutate(head: object) -> tuple[object, AuditEntry]:
            current = _normalize_head(head)
            seq = current["seq"] + 1
            entry = AuditEntry(
                at=at,
                event=event,
                detail=detail,
                seq=seq,
                prev=current["digest"],
                backfill=backfill,
            ).sign()
            # The entry record lands before the head pointer, so the head is
            # the commit point: a crash here leaves an orphan that the next
            # append overwrites and that verify() reports.
            self._store.put_json(_entry_key(seq), entry.as_dict())
            first_digest = current["volume_first_digest"]
            if seq == current["volume_first_seq"]:
                first_digest = entry.digest
            new_head = {
                "seq": seq,
                "digest": entry.digest,
                "volume": current["volume"],
                "volume_first_seq": current["volume_first_seq"],
                "volume_first_digest": first_digest,
            }
            return new_head, entry

        return self._store.update_json(HEAD_KEY, mutate)

    def _head(self) -> dict[str, Any] | None:
        self._guard_head_readable()
        document = self._store.get_json(HEAD_KEY)
        if document is None:
            return None
        return _normalize_head(document)

    def _guard_head_readable(self) -> None:
        raw = self._store.get(HEAD_KEY)
        if raw is not None and self._store.get_json(HEAD_KEY) is None:
            raise LedgerCorrupt("audit head exists but is not readable")

    def _read_entry(self, seq: int) -> AuditEntry | None:
        return AuditEntry.from_dict(self._store.get_json(_entry_key(seq)))

    def _read_volume(self, volume: int) -> VolumeManifest | None:
        return VolumeManifest.from_dict(self._store.get_json(_volume_key(volume)))

    def _orphan_seqs(self, head_seq: int) -> tuple[int, ...]:
        orphans: list[int] = []
        for key in keys_with_prefix(self._store, ENTRY_PREFIX):
            suffix = key[len(ENTRY_PREFIX) :]
            if suffix.isdigit() and int(suffix) > head_seq:
                orphans.append(int(suffix))
        return tuple(sorted(orphans))


def _normalize_head(document: object) -> dict[str, Any]:
    if document is None:
        return {
            "seq": 0,
            "digest": GENESIS,
            "volume": 1,
            "volume_first_seq": 1,
            "volume_first_digest": "",
        }
    if not isinstance(document, dict):
        raise LedgerCorrupt("audit head is not a document")
    seq = document.get("seq")
    volume = document.get("volume")
    volume_first_seq = document.get("volume_first_seq")
    integers = (seq, volume, volume_first_seq)
    if not all(isinstance(item, int) and not isinstance(item, bool) for item in integers):
        raise LedgerCorrupt("audit head has invalid counters")
    digest = document.get("digest")
    volume_first_digest = document.get("volume_first_digest")
    if not isinstance(digest, str) or not isinstance(volume_first_digest, str):
        raise LedgerCorrupt("audit head has invalid digests")
    return {
        "seq": seq,
        "digest": digest,
        "volume": volume,
        "volume_first_seq": volume_first_seq,
        "volume_first_digest": volume_first_digest,
    }


def _entry_key(seq: int) -> str:
    return f"{ENTRY_PREFIX}{seq:012d}"


def _volume_key(volume: int) -> str:
    return f"{VOLUME_PREFIX}{volume:06d}"


def _timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
