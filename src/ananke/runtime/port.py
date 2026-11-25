"""AgentPort: the single, narrow capability handed to agent/model code.

The port binds identity. The principal and session come from the channel the proposal arrives on,
never from the proposal itself, so a model cannot impersonate another principal. The port exposes
nothing except :meth:`propose`. No ledger, clock, database or operator handle is reachable from it.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from ananke.domain import (
    ActionCore,
    ActionRequest,
    DecisionReceipt,
    Proposal,
    ReasonCode,
    validate_identifier,
)
from ananke.ledger.store import IdFactory, uuid4_factory
from ananke.runtime.gateway import Gateway


class AgentPort:
    __slots__ = ("__gateway", "__ids", "__principal_id", "__session_id")

    def __init__(
        self,
        gateway: Gateway,
        *,
        principal_id: str,
        session_id: str,
        id_factory: IdFactory = uuid4_factory,
    ) -> None:
        self.__gateway = gateway
        self.__principal_id = validate_identifier(principal_id, "principal_id")
        self.__session_id = validate_identifier(session_id, "session_id")
        self.__ids = id_factory

    @property
    def principal_id(self) -> str:
        return self.__principal_id

    @property
    def session_id(self) -> str:
        return self.__session_id

    def propose(self, proposal: Mapping[str, Any] | str | bytes) -> DecisionReceipt:
        """Submit an untrusted proposal. Malformed input is denied and recorded."""
        try:
            if isinstance(proposal, str | bytes):
                parsed = Proposal.model_validate_json(proposal)
            elif isinstance(proposal, Mapping):
                parsed = Proposal.model_validate(dict(proposal))
            else:
                raise TypeError("proposal must be a mapping or JSON text")
        except (ValidationError, TypeError, ValueError):
            return self.__gateway.reject(
                session_id=self.__session_id,
                principal_id=self.__principal_id,
                reason=ReasonCode.INVALID_ARGUMENTS,
            )
        request = ActionRequest(
            request_id=self.__ids(),
            action=ActionCore(
                principal_id=self.__principal_id,
                session_id=self.__session_id,
                tool_id=parsed.tool_id,
                operation=parsed.operation,
                resource=parsed.resource,
                arguments=parsed.arguments,
            ),
            idempotency_key=parsed.idempotency_key,
            approval_id=parsed.approval_id,
            observed_epoch=parsed.observed_epoch,
        )
        return self.__gateway.submit(request)
