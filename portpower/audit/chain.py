"""Hash primitives that turn the audit log into a tamper-evident chain."""

from __future__ import annotations

import hashlib
import json
from typing import Any

GENESIS = "0" * 64


def canonical(payload: Any) -> bytes:
    """Stable encoding so a digest commits to exactly one document."""

    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def digest_of(payload: Any) -> str:
    return hashlib.sha256(canonical(payload)).hexdigest()
