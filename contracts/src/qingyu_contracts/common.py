from typing import Annotated
import uuid

from pydantic import AfterValidator, BaseModel, ConfigDict, Field
from pydantic.types import StringConstraints


def _require_uuid4(value: uuid.UUID) -> uuid.UUID:
    if value.version != 4:
        raise ValueError("value must be an opaque UUIDv4")
    return value


OpaqueUUID4 = Annotated[uuid.UUID, AfterValidator(_require_uuid4)]
Fingerprint = Annotated[
    str,
    StringConstraints(
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-fA-F]{64}$",
    ),
]
Alias = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=128),
]
OpaqueCursor = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=4096),
]


class ContractModel(BaseModel):
    """All public contracts reject fields not explicitly in the contract."""

    model_config = ConfigDict(extra="forbid", frozen=True)


NonNegativeInt = Annotated[int, Field(ge=0)]
