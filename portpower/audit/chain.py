"""Hash-chained, append-only audit segments with sealed volumes.

Layout inside the chain directory::

    seg-000001.sealed.jsonl   immutable volume, never modified after sealing
    seg-000002.active.jsonl   the only segment that accepts appends
    manifest.json             one entry per sealed volume, with its SHA-256

Every record carries the SHA-256 of its predecessor, so the whole history -
across volume boundaries - is a single hash chain.  Sealing only renames the
active segment and registers it in the manifest; business writes continue on
the next segment while the volume digest is computed outside the lock.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

from portpower.audit.entry import KIND_BACKFILL, KIND_MIGRATED, KINDS, AuditEntry

GENESIS_HASH = "0" * 64

_ACTIVE_SUFFIX = ".active.jsonl"
_SEALED_SUFFIX = ".sealed.jsonl"
_MANIFEST_NAME = "manifest.json"
_CHUNK = 65536


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def content_hash(entry: AuditEntry) -> str:
    """SHA-256 over the canonical form of everything a record states."""

    payload = {
        "seq": entry.seq,
        "at": entry.at,
        "event": entry.event,
        "detail": entry.detail,
        "kind": entry.kind,
        "occurred_at": entry.occurred_at,
        "reason": entry.reason,
        "prev": entry.prev,
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def verify_records(records: list[AuditEntry]) -> "ChainFault | None":
    """Walk a record sequence and return the first break, if any."""

    prev_hash = GENESIS_HASH
    for position, record in enumerate(records, start=1):
        if record.seq != position:
            return ChainFault(
                "seq_gap",
                position,
                f"chain position {position} holds a record claiming seq {record.seq}",
                expected=str(position),
                actual=str(record.seq),
            )
        if record.prev != prev_hash:
            return ChainFault(
                "prev_mismatch",
                record.seq,
                f"record seq {record.seq} does not bind to its predecessor",
                expected=prev_hash,
                actual=record.prev,
            )
        digest = content_hash(record)
        if digest != record.hash:
            return ChainFault(
                "hash_mismatch",
                record.seq,
                f"record seq {record.seq} content was altered after recording",
                expected=digest,
                actual=record.hash,
            )
        if record.kind not in KINDS:
            return ChainFault(
                "unknown_kind",
                record.seq,
                f"record seq {record.seq} has unknown kind {record.kind!r}",
            )
        if record.kind == KIND_BACKFILL and (not record.occurred_at or not record.reason):
            return ChainFault(
                "backfill_incomplete",
                record.seq,
                f"backfill seq {record.seq} lacks occurred_at or reason",
            )
        prev_hash = record.hash
    return None


@dataclass(frozen=True)
class ChainFault:
    """The first break found while walking the chain."""

    reason: str
    seq: int | None
    detail: str
    expected: str = ""
    actual: str = ""

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class Verification:
    """Outcome of one chain walk, pinned to the head it observed."""

    ok: bool
    checked: int
    volumes: int
    head_seq: int
    head_hash: str
    fault: ChainFault | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "checked": self.checked,
            "volumes": self.volumes,
            "head_seq": self.head_seq,
            "head_hash": self.head_hash,
            "fault": self.fault.as_dict() if self.fault is not None else None,
        }


@dataclass(frozen=True)
class VolumeInfo:
    """Manifest entry for one sealed volume."""

    volume: int
    file: str
    first_seq: int
    last_seq: int
    entry_count: int
    prev_hash: str
    head_hash: str
    sealed_at: str
    sha256: str

    def as_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: object) -> "VolumeInfo | None":
        if not isinstance(payload, dict):
            return None
        volume = payload.get("volume")
        first_seq = payload.get("first_seq")
        last_seq = payload.get("last_seq")
        entry_count = payload.get("entry_count")
        integers = (volume, first_seq, last_seq, entry_count)
        if any(isinstance(item, bool) or not isinstance(item, int) for item in integers):
            return None
        file = payload.get("file")
        prev_hash = payload.get("prev_hash")
        head_hash = payload.get("head_hash")
        sealed_at = payload.get("sealed_at")
        sha256 = payload.get("sha256")
        strings = (file, prev_hash, head_hash, sealed_at, sha256)
        if not all(isinstance(item, str) for item in strings):
            return None
        return cls(
            volume=volume,
            file=file,
            first_seq=first_seq,
            last_seq=last_seq,
            entry_count=entry_count,
            prev_hash=prev_hash,
            head_hash=head_hash,
            sealed_at=sealed_at,
            sha256=sha256,
        )


class ChainCorruptionError(Exception):
    """Raised when the persisted chain fails structural checks."""

    def __init__(self, fault: ChainFault) -> None:
        self.fault = fault
        super().__init__(fault.detail)


class NothingToSealError(Exception):
    """Raised when sealing is requested but the active segment is empty."""


class HashChain:
    """Append-only record segments linked into one hash chain."""

    def __init__(self, directory: str | os.PathLike[str]) -> None:
        self._dir = Path(directory)
        self._lock = threading.RLock()
        self._manifest_lock = threading.Lock()
        self._records: list[AuditEntry] = []
        self._active_index = 1
        self._active_count = 0
        self._handle: object | None = None

    # -- lifecycle --------------------------------------------------

    def open(self) -> None:
        """Load segments, repair a torn tail, reconcile the manifest."""

        with self._lock:
            self._dir.mkdir(parents=True, exist_ok=True)
            sealed = self._segments(_SEALED_SUFFIX)
            actives = self._segments(_ACTIVE_SUFFIX)
            if len(actives) > 1:
                names = ", ".join(path.name for _, path in actives)
                raise ChainCorruptionError(
                    ChainFault("multiple_active_segments", None, f"more than one active segment: {names}")
                )

            records: list[AuditEntry] = []
            segment_records: dict[int, list[AuditEntry]] = {}
            digests: dict[int, str] = {}
            for index, path in sealed:
                segment, _ = self._read_segment(path, allow_torn_tail=False)
                if not segment:
                    raise ChainCorruptionError(
                        ChainFault("empty_volume", None, f"sealed segment {path.name} holds no records")
                    )
                segment_records[index] = segment
                digests[index] = _sha256_file(path)
                records.extend(segment)

            if actives:
                self._active_index = actives[0][0]
            else:
                self._active_index = sealed[-1][0] + 1 if sealed else 1
            active_path = self._dir / _segment_name(self._active_index, _ACTIVE_SUFFIX)
            active_records, torn_at = self._read_segment(active_path, allow_torn_tail=True, missing_ok=True)
            if torn_at is not None:
                # The process died mid-append: only the unterminated tail is
                # lost, every record before it is intact.
                self._truncate(active_path, torn_at)
            records.extend(active_records)

            fault = verify_records(records)
            if fault is not None:
                raise ChainCorruptionError(fault)

            self._records = records
            self._active_count = len(active_records)
            self._handle = open(active_path, "ab")
            self._reconcile_manifest(sealed, segment_records, digests)

    def close(self) -> None:
        with self._lock:
            if self._handle is not None:
                self._handle.close()
                self._handle = None

    # -- appending ----------------------------------------------------

    def append(
        self,
        event: str,
        detail: str,
        *,
        kind: str = "live",
        occurred_at: str = "",
        reason: str = "",
        at: str | None = None,
    ) -> AuditEntry:
        """Append one record; it is durable once this call returns."""

        if kind not in KINDS:
            raise ValueError(f"unknown record kind: {kind!r}")
        if kind == KIND_BACKFILL and (not occurred_at.strip() or not reason.strip()):
            raise ValueError("backfill records require occurred_at and reason")
        if kind != KIND_BACKFILL and (occurred_at or reason):
            raise ValueError("only backfill records carry occurred_at and reason")
        if at is not None and kind != KIND_MIGRATED:
            raise ValueError("only migrated records may keep a historical timestamp")

        with self._lock:
            seq = self._records[-1].seq + 1 if self._records else 1
            prev = self._records[-1].hash if self._records else GENESIS_HASH
            entry = AuditEntry(
                seq=seq,
                at=at if at is not None else _utc_now(),
                event=event,
                detail=detail,
                kind=kind,
                occurred_at=occurred_at,
                reason=reason,
                prev=prev,
                hash="",
            )
            entry = replace(entry, hash=content_hash(entry))
            line = json.dumps(entry.as_dict(), ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
            self._handle.write(line)
            self._handle.flush()
            os.fsync(self._handle.fileno())
            self._records.append(entry)
            self._active_count += 1
            return entry

    # -- sealing ------------------------------------------------------

    def seal(self) -> VolumeInfo:
        """Freeze the active segment into an immutable volume.

        The rotation itself is a rename inside the lock; the digest and the
        manifest update happen after the lock is released, so business
        appends are only paused for the rename.
        """

        with self._lock:
            if self._active_count == 0:
                raise NothingToSealError("active segment is empty")
            first = self._records[-self._active_count]
            last = self._records[-1]
            index = self._active_index
            self._handle.flush()
            os.fsync(self._handle.fileno())
            self._handle.close()
            sealed_path = self._dir / _segment_name(index, _SEALED_SUFFIX)
            os.replace(self._dir / _segment_name(index, _ACTIVE_SUFFIX), sealed_path)
            self._active_index = index + 1
            self._active_count = 0
            self._handle = open(self._dir / _segment_name(self._active_index, _ACTIVE_SUFFIX), "ab")

        digest = _sha256_file(sealed_path)
        info = VolumeInfo(
            volume=index,
            file=sealed_path.name,
            first_seq=first.seq,
            last_seq=last.seq,
            entry_count=last.seq - first.seq + 1,
            prev_hash=first.prev,
            head_hash=last.hash,
            sealed_at=_utc_now(),
            sha256=digest,
        )
        with self._manifest_lock:
            manifest = self._read_manifest()
            manifest.append(info)
            self._write_manifest(manifest)
        return info

    # -- verification -------------------------------------------------

    def verify(self) -> Verification:
        """Re-walk the persisted chain without pausing appends.

        Only the head snapshot is taken under the lock; the files are then
        read outside it.  Records appended after the snapshot are ignored.
        """

        with self._lock:
            head_seq = self._records[-1].seq if self._records else 0
            head_hash = self._records[-1].hash if self._records else GENESIS_HASH
            active_index = self._active_index

        try:
            manifest = self._read_manifest()
        except ChainCorruptionError as exc:
            return Verification(False, 0, 0, head_seq, head_hash, exc.fault)

        records: list[AuditEntry] = []
        try:
            for index in range(1, active_index):
                path = self._dir / _segment_name(index, _SEALED_SUFFIX)
                segment, _ = self._read_segment(path, allow_torn_tail=False)
                records.extend(segment)
            active_path = self._dir / _segment_name(active_index, _ACTIVE_SUFFIX)
            if not active_path.exists():
                # A seal rotated the segment after the snapshot; the bytes
                # are identical, only the name changed.
                active_path = self._dir / _segment_name(active_index, _SEALED_SUFFIX)
            segment, _ = self._read_segment(active_path, allow_torn_tail=True, missing_ok=True)
            records.extend(segment)
        except FileNotFoundError as exc:
            fault = ChainFault("missing_segment", None, f"segment file is missing: {exc.filename}")
            return Verification(False, len(records), 0, head_seq, head_hash, fault)
        except ChainCorruptionError as exc:
            return Verification(False, len(records), 0, head_seq, head_hash, exc.fault)

        records = [record for record in records if record.seq <= head_seq]
        fault = verify_records(records)
        if fault is not None:
            return Verification(False, len(records), 0, head_seq, head_hash, fault)

        volumes_ok = 0
        expected_prev = GENESIS_HASH
        for info in manifest:
            path = self._dir / info.file
            if not path.exists():
                fault = ChainFault(
                    "missing_volume", None, f"volume {info.volume} file {info.file} is missing"
                )
                return Verification(False, len(records), volumes_ok, head_seq, head_hash, fault)
            digest = _sha256_file(path)
            if digest != info.sha256:
                fault = ChainFault(
                    "digest_mismatch",
                    None,
                    f"volume {info.volume} file changed after sealing",
                    expected=info.sha256,
                    actual=digest,
                )
                return Verification(False, len(records), volumes_ok, head_seq, head_hash, fault)
            if info.prev_hash != expected_prev:
                fault = ChainFault(
                    "volume_link_mismatch",
                    None,
                    f"volume {info.volume} does not continue the previous volume",
                    expected=expected_prev,
                    actual=info.prev_hash,
                )
                return Verification(False, len(records), volumes_ok, head_seq, head_hash, fault)
            expected_prev = info.head_hash
            volumes_ok += 1
        return Verification(True, len(records), volumes_ok, head_seq, head_hash)

    # -- queries ------------------------------------------------------

    def records(self) -> list[AuditEntry]:
        with self._lock:
            return list(self._records)

    def volumes(self) -> list[VolumeInfo]:
        with self._manifest_lock:
            return self._read_manifest()

    # -- internals ----------------------------------------------------

    def _segments(self, suffix: str) -> list[tuple[int, Path]]:
        found: list[tuple[int, Path]] = []
        for path in self._dir.glob(f"seg-*{suffix}"):
            index = _segment_index(path.name, suffix)
            if index is not None:
                found.append((index, path))
        found.sort(key=lambda item: item[0])
        return found

    def _read_segment(
        self,
        path: Path,
        *,
        allow_torn_tail: bool,
        missing_ok: bool = False,
    ) -> tuple[list[AuditEntry], int | None]:
        """Parse a segment file; return (records, torn_tail_offset)."""

        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            if missing_ok:
                return [], None
            raise
        records: list[AuditEntry] = []
        pos = 0
        torn_at: int | None = None
        while pos < len(raw):
            newline = raw.find(b"\n", pos)
            if newline == -1:
                torn_at = pos
                break
            record = _parse_line(raw[pos:newline])
            if record is None:
                raise ChainCorruptionError(
                    ChainFault(
                        "unparseable_record",
                        None,
                        f"{path.name}: line {len(records) + 1} is not a valid record",
                    )
                )
            records.append(record)
            pos = newline + 1
        if torn_at is not None and not allow_torn_tail:
            raise ChainCorruptionError(
                ChainFault("torn_sealed_segment", None, f"{path.name}: sealed segment ends mid-record")
            )
        return records, torn_at

    def _reconcile_manifest(
        self,
        sealed: list[tuple[int, Path]],
        segment_records: dict[int, list[AuditEntry]],
        digests: dict[int, str],
    ) -> None:
        """Register volumes sealed before a crash; refuse mismatches."""

        with self._manifest_lock:
            manifest = self._read_manifest()
            by_volume = {info.volume: info for info in manifest}
            changed = False
            for index, path in sealed:
                records = segment_records[index]
                actual = VolumeInfo(
                    volume=index,
                    file=path.name,
                    first_seq=records[0].seq,
                    last_seq=records[-1].seq,
                    entry_count=len(records),
                    prev_hash=records[0].prev,
                    head_hash=records[-1].hash,
                    sealed_at="",
                    sha256=digests[index],
                )
                known = by_volume.get(index)
                if known is None:
                    # Sealed but never registered: the process died between
                    # the rename and the manifest write.
                    manifest.append(replace(actual, sealed_at=_utc_now()))
                    changed = True
                    continue
                for field_name in ("file", "first_seq", "last_seq", "entry_count", "prev_hash", "head_hash", "sha256"):
                    if getattr(known, field_name) != getattr(actual, field_name):
                        raise ChainCorruptionError(
                            ChainFault(
                                "manifest_mismatch",
                                None,
                                f"volume {index} manifest entry disagrees with the sealed segment",
                                expected=str(getattr(known, field_name)),
                                actual=str(getattr(actual, field_name)),
                            )
                        )
            on_disk = {index for index, _ in sealed}
            for info in manifest:
                if info.volume not in on_disk:
                    raise ChainCorruptionError(
                        ChainFault(
                            "missing_volume",
                            None,
                            f"manifest lists volume {info.volume} but {info.file} is gone",
                        )
                    )
            if changed:
                manifest.sort(key=lambda info: info.volume)
                self._write_manifest(manifest)

    def _read_manifest(self) -> list[VolumeInfo]:
        path = self._dir / _MANIFEST_NAME
        try:
            document = json.loads(path.read_bytes().decode("utf-8"))
        except FileNotFoundError:
            return []
        except (ValueError, UnicodeDecodeError) as exc:
            raise ChainCorruptionError(
                ChainFault("manifest_unreadable", None, f"manifest.json is not valid JSON: {exc}")
            ) from exc
        if not isinstance(document, dict) or not isinstance(document.get("volumes"), list):
            raise ChainCorruptionError(
                ChainFault("manifest_unreadable", None, "manifest.json has no volumes list")
            )
        volumes: list[VolumeInfo] = []
        for item in document["volumes"]:
            info = VolumeInfo.from_dict(item)
            if info is None:
                raise ChainCorruptionError(
                    ChainFault("manifest_unreadable", None, "manifest.json holds a malformed volume entry")
                )
            volumes.append(info)
        volumes.sort(key=lambda info: info.volume)
        return volumes

    def _write_manifest(self, volumes: list[VolumeInfo]) -> None:
        blob = json.dumps(
            {"volumes": [info.as_dict() for info in volumes]},
            ensure_ascii=False,
            indent=2,
        ).encode("utf-8")
        tmp = self._dir / f"{_MANIFEST_NAME}.tmp"
        with open(tmp, "wb") as handle:
            handle.write(blob)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, self._dir / _MANIFEST_NAME)

    @staticmethod
    def _truncate(path: Path, offset: int) -> None:
        with open(path, "r+b") as handle:
            handle.truncate(offset)
            handle.flush()
            os.fsync(handle.fileno())


def _segment_name(index: int, suffix: str) -> str:
    return f"seg-{index:06d}{suffix}"


def _segment_index(name: str, suffix: str) -> int | None:
    if not name.startswith("seg-") or not name.endswith(suffix):
        return None
    digits = name[len("seg-") : -len(suffix)]
    if not digits.isdigit():
        return None
    return int(digits)


def _parse_line(line: bytes) -> AuditEntry | None:
    try:
        payload = json.loads(line.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return AuditEntry.from_dict(payload)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()
