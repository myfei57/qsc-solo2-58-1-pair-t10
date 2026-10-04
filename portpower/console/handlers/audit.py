"""Audit ledger query, backfill, verification and sealing endpoints."""

from __future__ import annotations

from portpower.audit.filter import by_event, events, tail
from portpower.audit.ledger import LedgerCorrupt
from portpower.audit.summary import summarize
from portpower.console.http import BadRequest, Request, Response
from portpower.console.validation import optional_text, require_text

DEFAULT_TAIL = 10


def audit_list(runtime, request: Request) -> Response:
    event = request.query_one("event")
    if event:
        entries = by_event(runtime.ledger, event)
    else:
        entries = runtime.ledger.entries()
    return Response.json(
        200,
        {
            "count": len(entries),
            "events": events(runtime.ledger),
            "entries": [entry.as_dict() for entry in entries],
        },
    )


def audit_latest(runtime, request: Request) -> Response:
    latest = runtime.ledger.latest()
    if latest is None:
        return Response.json(404, {"error": "no audit entries"})
    return Response.json(200, latest.as_dict())


def audit_summary(runtime, request: Request) -> Response:
    return Response.json(200, summarize(runtime.ledger).as_dict())


def audit_tail(runtime, request: Request) -> Response:
    raw = request.query_one("limit")
    if raw is None:
        limit = DEFAULT_TAIL
    else:
        try:
            limit = int(raw)
        except ValueError as exc:
            raise BadRequest("limit must be an integer") from exc
    entries = tail(runtime.ledger, limit)
    return Response.json(
        200,
        {"limit": limit, "count": len(entries), "entries": [e.as_dict() for e in entries]},
    )


def audit_backfill(runtime, request: Request) -> Response:
    payload = request.json_object()
    event = require_text(payload, "event")
    detail = optional_text(payload, "detail", "")
    original_at = require_text(payload, "original_at")
    reason = require_text(payload, "reason")
    try:
        entry = runtime.ledger.append_backfill(
            event, detail, original_at=original_at, reason=reason
        )
    except ValueError as exc:
        raise BadRequest(str(exc)) from exc
    return Response.json(201, entry.as_dict())


def audit_verify(runtime, request: Request) -> Response:
    report = runtime.ledger.verify()
    return Response.json(200 if report.ok else 409, report.as_dict())


def audit_seal(runtime, request: Request) -> Response:
    try:
        manifest = runtime.ledger.seal()
    except LedgerCorrupt as exc:
        return Response.json(409, {"error": str(exc)})
    if manifest is None:
        return Response.json(409, {"error": "active volume is empty"})
    return Response.json(201, manifest.as_dict())


def audit_volumes(runtime, request: Request) -> Response:
    manifests = runtime.ledger.volumes()
    return Response.json(
        200,
        {"count": len(manifests), "volumes": [item.as_dict() for item in manifests]},
    )
