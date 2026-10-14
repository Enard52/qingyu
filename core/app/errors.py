from __future__ import annotations

from dataclasses import dataclass


ERROR_HTTP_STATUS: dict[str, int] = {
    "EPOCH_REQUIRED": 409,
    "EPOCH_STALE": 409,
    "EPOCH_NOT_ISSUED": 409,
    "LEASE_REQUIRED": 409,
    "LEASE_FENCED": 409,
    "GENESIS_NOT_INITIALIZED": 409,
    "GENESIS_ALREADY_EXISTS": 409,
    "GENESIS_CONFLICT": 409,
    "GENESIS_STORAGE_NOT_CLAIMED": 409,
    "GENESIS_ANCHOR_MISMATCH": 409,
    "GENESIS_OUTCOME_UNKNOWN": 503,
    "OWNER_TRANSFER_CONFLICT": 409,
    "OWNER_VERSION_STALE": 409,
    "RESTORE_IDENTITY_MISMATCH": 409,
    "RESTORE_INITIAL_OWNER_MISMATCH": 409,
    "RESTORE_OWNER_UNPROVEN": 503,
    "RESTORE_AUTHORIZATION_INVALID": 403,
    "RESTORE_AUTHORIZATION_SCOPE_MISMATCH": 403,
    "RESTORE_STATE_GAP": 409,
    "RESTORE_FENCE_UNPROVEN": 503,
    "AUDIT_CHAIN_INVALID": 409,
    "AUDIT_HIGH_WATER_UNPROVEN": 503,
    "CONTROL_PLANE_RECOVERY_CLAIM_CONFLICT": 409,
    "CONTROL_PLANE_WITNESS_QUORUM_UNAVAILABLE": 503,
}


@dataclass(slots=True)
class CoreError(RuntimeError):
    code: str
    message: str | None = None

    @property
    def status_code(self) -> int:
        return ERROR_HTTP_STATUS.get(self.code, 409)

    def __str__(self) -> str:
        return self.message or self.code


def fail(code: str, message: str | None = None) -> CoreError:
    return CoreError(code, message)

