from __future__ import annotations

from enum import StrEnum


class Capability(StrEnum):
    MIGRATION_ADMIN = "core_migration_admin"
    APPLICATION = "core_application"
    GOVERNANCE = "core_governance"
    WRITER = "core_writer"
    GATEWAY_EVIDENCE_READ = "gateway_evidence_read"
    RUNTIME = "core_runtime_reserved"


CAPABILITY_BOUNDARIES = {
    Capability.MIGRATION_ADMIN: {"migration"},
    Capability.APPLICATION: {"read_status"},
    Capability.GOVERNANCE: {"genesis", "ownership_transfer", "restore_activate"},
    Capability.WRITER: {"governed_mutation"},
    Capability.GATEWAY_EVIDENCE_READ: {"gateway_get"},
    Capability.RUNTIME: set(),
}

