"""Synthetic typed mock tools (MASTERPLAN section 11).

Six operations: ``ticket.read``, ``ticket.update``, ``report.read``, ``report.publish_mock``,
``artifact.read``, ``artifact.write_mock``. Every handler reads or writes the local ``lab_records``
table on the connection it is given, inside the gateway's transaction. There is no network,
filesystem, shell or clock access, and no real side effect of any kind.

Handlers run only *after* authorization. They are never exposed to agent code directly.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, StrictStr

from ananke.domain import canonical_bytes, validate_text
from ananke.domain.models import ShortText, StrictModel

Title = Annotated[StrictStr, AfterValidator(lambda v: validate_text(v, max_len=80))]
Body = Annotated[StrictStr, AfterValidator(lambda v: validate_text(v, max_len=500))]


class NoArgs(StrictModel):
    pass


class TicketUpdateArgs(StrictModel):
    status: Literal["open", "pending", "closed"]
    note: ShortText = ""


class PublishArgs(StrictModel):
    title: Title


class ArtifactWriteArgs(StrictModel):
    content: Body


class ToolError(RuntimeError):
    """A post-authorization tool failure. The gateway rolls back and denies."""


Handler = Callable[[sqlite3.Connection, str, BaseModel, int], dict[str, Any] | None]


@dataclass(frozen=True, slots=True)
class OperationSpec:
    args_model: type[StrictModel]
    handler: Handler
    discloses: bool  # returns record content to the caller


@dataclass(frozen=True, slots=True)
class ToolSpec:
    tool_id: str
    namespace: str
    operations: Mapping[str, OperationSpec]


# ----------------------------------------------------------------------------- lab state access


def _load(conn: sqlite3.Connection, resource: str) -> tuple[dict[str, Any], int] | None:
    row = conn.execute(
        "SELECT body, version FROM lab_records WHERE resource = ?", (resource,)
    ).fetchone()
    if row is None:
        return None
    return json.loads(row[0]), int(row[1])


def _store(conn: sqlite3.Connection, resource: str, body: dict[str, Any], version: int) -> None:
    blob = canonical_bytes(body)
    if version == 1:
        conn.execute(
            "INSERT INTO lab_records(resource, body, version) VALUES (?, ?, 1)", (resource, blob)
        )
    else:
        cur = conn.execute(
            "UPDATE lab_records SET body = ?, version = ? WHERE resource = ? AND version = ?",
            (blob, version, resource, version - 1),
        )
        if cur.rowcount != 1:
            raise ToolError("concurrent modification of lab record")


def seed_records(conn: sqlite3.Connection, records: Mapping[str, dict[str, Any]]) -> None:
    """Trusted scenario-controller setup of synthetic fixture state (not an agent path)."""
    for resource, body in sorted(records.items()):
        _store(conn, resource, dict(body), 1)


def read_record(conn: sqlite3.Connection, resource: str) -> dict[str, Any] | None:
    loaded = _load(conn, resource)
    return None if loaded is None else loaded[0]


# ----------------------------------------------------------------------------- handlers


def _read(conn: sqlite3.Connection, resource: str, _args: BaseModel, _now: int) -> dict[str, Any]:
    loaded = _load(conn, resource)
    if loaded is None:
        return {"resource": resource, "exists": False}
    return {"resource": resource, "exists": True, "record": loaded[0]}


def _ticket_update(
    conn: sqlite3.Connection, resource: str, args: BaseModel, now: int
) -> dict[str, Any]:
    if not isinstance(args, TicketUpdateArgs):  # defensive: dispatcher bug must fail closed
        raise ToolError("argument model mismatch")
    loaded = _load(conn, resource)
    if loaded is None:
        raise ToolError("ticket does not exist")
    body, version = loaded
    body = {**body, "status": args.status, "last_note": args.note, "updated_at": now}
    _store(conn, resource, body, version + 1)
    return {"resource": resource, "version": version + 1}


def _publish(conn: sqlite3.Connection, resource: str, args: BaseModel, now: int) -> dict[str, Any]:
    if not isinstance(args, PublishArgs):
        raise ToolError("argument model mismatch")
    loaded = _load(conn, resource)
    if loaded is None:
        raise ToolError("report does not exist")
    body, version = loaded
    published = [*body.get("published_titles", []), args.title]
    _store(
        conn, resource, {**body, "published_titles": published, "published_at": now}, version + 1
    )
    return {"resource": resource, "published": True, "version": version + 1}


def _artifact_write(
    conn: sqlite3.Connection, resource: str, args: BaseModel, now: int
) -> dict[str, Any]:
    if not isinstance(args, ArtifactWriteArgs):
        raise ToolError("argument model mismatch")
    loaded = _load(conn, resource)
    if loaded is None:
        _store(conn, resource, {"content": args.content, "written_at": now}, 1)
        return {"resource": resource, "version": 1}
    body, version = loaded
    _store(conn, resource, {**body, "content": args.content, "written_at": now}, version + 1)
    return {"resource": resource, "version": version + 1}


def _ops(**ops: OperationSpec) -> Mapping[str, OperationSpec]:
    return MappingProxyType(dict(ops))


REGISTRY: Mapping[str, ToolSpec] = MappingProxyType(
    {
        "ticket": ToolSpec(
            "ticket",
            "ticket",
            _ops(
                read=OperationSpec(NoArgs, _read, discloses=True),
                update=OperationSpec(TicketUpdateArgs, _ticket_update, discloses=False),
            ),
        ),
        "report": ToolSpec(
            "report",
            "report",
            _ops(
                read=OperationSpec(NoArgs, _read, discloses=True),
                publish_mock=OperationSpec(PublishArgs, _publish, discloses=False),
            ),
        ),
        "artifact": ToolSpec(
            "artifact",
            "artifact",
            _ops(
                read=OperationSpec(NoArgs, _read, discloses=True),
                write_mock=OperationSpec(ArtifactWriteArgs, _artifact_write, discloses=False),
            ),
        ),
    }
)
