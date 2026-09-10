from typing import Literal

from pydantic import field_validator

from .common import Alias, ContractModel, NonNegativeInt, OpaqueUUID4


class IdentityContinuityEnvelope(ContractModel):
    """The shared Core identity/continuity fields carried by future APIs."""

    contract_version: Literal["core-identity-v1"] = "core-identity-v1"
    qingyu_identity_id: OpaqueUUID4
    continuity_id: OpaqueUUID4
    continuity_alias: Alias
    continuity_epoch: NonNegativeInt = 0
    state_version: NonNegativeInt = 0

    @field_validator("continuity_alias")
    @classmethod
    def alias_is_not_a_uuid(cls, value: str) -> str:
        # An alias is a lookup label, never a disguised canonical identifier.
        import uuid

        try:
            uuid.UUID(value)
        except ValueError:
            return value
        raise ValueError("continuity_alias must not be a UUID identifier")
