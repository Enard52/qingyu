"""Unsigned transport projections; none of these fields is a trust certificate."""
from dataclasses import dataclass

from ._r1_validation_stream import RegistrySlice


@dataclass(frozen=True, slots=True)
class AuthorityCaller:
    runtime_principal: str
    session_id: str
    policy_digest: str
    inventory_digest: str


@dataclass(frozen=True, slots=True)
class AuthorityReply:
    state: str
    request_wire: bytes | None
    authority: RegistrySlice
    ack_wire: bytes | None = None
    acceptance_wire: bytes | None = None
    terminal_wire: bytes | None = None
