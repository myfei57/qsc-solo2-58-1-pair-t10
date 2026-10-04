"""Immutable manifests that seal a finished range of the chain."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from portpower.audit.chain import digest_of


@dataclass(frozen=True)
class VolumeManifest:
    """Seals ``[first_seq, last_seq]`` into an immutable archive volume.

    Because every entry digest commits to its predecessor, ``head_digest``
    commits to the whole range; ``prev_volume_head`` chains the volumes
    themselves, so an archive can be checked against the live chain.
    """

    volume: int
    first_seq: int
    last_seq: int
    count: int
    first_digest: str
    head_digest: str
    prev_volume_head: str
    sealed_at: str
    digest: str = ""

    def signing_payload(self) -> dict[str, Any]:
        return {
            "volume": self.volume,
            "first_seq": self.first_seq,
            "last_seq": self.last_seq,
            "count": self.count,
            "first_digest": self.first_digest,
            "head_digest": self.head_digest,
            "prev_volume_head": self.prev_volume_head,
            "sealed_at": self.sealed_at,
        }

    def sign(self) -> "VolumeManifest":
        return replace(self, digest=digest_of(self.signing_payload()))

    def digest_matches(self) -> bool:
        return self.digest == digest_of(self.signing_payload())

    def as_dict(self) -> dict[str, Any]:
        payload = self.signing_payload()
        payload["digest"] = self.digest
        return payload

    @classmethod
    def from_dict(cls, payload: object) -> "VolumeManifest | None":
        if not isinstance(payload, dict):
            return None
        volume = payload.get("volume")
        first_seq = payload.get("first_seq")
        last_seq = payload.get("last_seq")
        count = payload.get("count")
        integers = (volume, first_seq, last_seq, count)
        if not all(isinstance(item, int) and not isinstance(item, bool) for item in integers):
            return None
        first_digest = payload.get("first_digest")
        head_digest = payload.get("head_digest")
        prev_volume_head = payload.get("prev_volume_head")
        sealed_at = payload.get("sealed_at")
        digest = payload.get("digest")
        strings = (first_digest, head_digest, prev_volume_head, sealed_at, digest)
        if not all(isinstance(item, str) for item in strings):
            return None
        return cls(
            volume=volume,
            first_seq=first_seq,
            last_seq=last_seq,
            count=count,
            first_digest=first_digest,
            head_digest=head_digest,
            prev_volume_head=prev_volume_head,
            sealed_at=sealed_at,
            digest=digest,
        )
