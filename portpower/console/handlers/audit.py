"""Audit ledger query endpoints."""

from __future__ import annotations

from portpower.audit.chain import NothingToSealError
from portpower.audit.filter import by_event, events, tail
from portpower.audit.summary import summarize
from portpower.console.http import BadRequest, Request, Response
from portpower.console.validation import require_text

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
    detail = require_text(payload, "detail")
    occurred_at = require_text(payload, "occurred_at")
    reason = require_text(payload, "reason")
    entry = runtime.ledger.backfill(
        event,
        detail,
        occurred_at=occurred_at,
        reason=reason,
    )
    return Response.json(201, entry.as_dict())


def audit_verify(runtime, request: Request) -> Response:
    return Response.json(200, runtime.ledger.verify().as_dict())


def audit_seal(runtime, request: Request) -> Response:
    try:
        info = runtime.ledger.seal()
    except NothingToSealError:
        return Response.json(409, {"error": "active segment is empty, nothing to seal"})
    return Response.json(201, info.as_dict())


def audit_volumes(runtime, request: Request) -> Response:
    volumes = runtime.ledger.volumes()
    return Response.json(
        200,
        {"count": len(volumes), "volumes": [info.as_dict() for info in volumes]},
    )
