from __future__ import annotations

from datetime import datetime, timezone
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from .canonical import sha256_hex
from .errors import CoreError
from .models import AuditLedger, CoreMetadata


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def append_audit(
    session: Session,
    *,
    trust_domain_id: uuid.UUID,
    continuity_id: uuid.UUID | None,
    continuity_epoch: int,
    state_version: int,
    operation_type: str,
    actor_principal_id: str,
    capability: str,
    request_id: str,
    mutation_id: str | None,
    result_code: str,
    payload: object,
) -> AuditLedger:
    metadata = session.execute(
        select(CoreMetadata).where(CoreMetadata.id == 1).with_for_update()
    ).scalar_one()
    next_seq = metadata.audit_seq + 1
    previous = metadata.audit_head_hash
    payload_hash = sha256_hex(payload)
    canonical_record = {
        "audit_seq": next_seq,
        "trust_domain_id": str(trust_domain_id),
        "continuity_id": str(continuity_id) if continuity_id else None,
        "continuity_epoch": continuity_epoch,
        "state_version": state_version,
        "operation_type": operation_type,
        "actor_principal_id": actor_principal_id,
        "capability": capability,
        "request_id": request_id,
        "mutation_id": mutation_id,
        "result_code": result_code,
        "payload_hash": payload_hash,
        "previous_record_hash": previous,
        "created_at": _utc_iso(),
    }
    record_hash = sha256_hex(canonical_record)
    row = AuditLedger(
        audit_seq=next_seq,
        trust_domain_id=trust_domain_id,
        continuity_id=continuity_id,
        continuity_epoch=continuity_epoch,
        state_version=state_version,
        operation_type=operation_type,
        actor_principal_id=actor_principal_id,
        capability=capability,
        request_id=request_id,
        mutation_id=mutation_id,
        result_code=result_code,
        payload_hash=payload_hash,
        previous_record_hash=previous,
        record_hash=record_hash,
        canonical_record=canonical_record,
    )
    session.add(row)
    metadata.audit_seq = next_seq
    metadata.audit_head_hash = record_hash
    return row


def verify_audit_row(row: AuditLedger | None) -> AuditLedger:
    """Bind every persisted audit projection field to its canonical hash."""
    if row is None:
        raise CoreError("AUDIT_CHAIN_INVALID")
    canonical = row.canonical_record
    expected = {
        "audit_seq": row.audit_seq,
        "trust_domain_id": str(row.trust_domain_id),
        "continuity_id": str(row.continuity_id) if row.continuity_id else None,
        "continuity_epoch": row.continuity_epoch,
        "state_version": row.state_version,
        "operation_type": row.operation_type,
        "actor_principal_id": row.actor_principal_id,
        "capability": row.capability,
        "request_id": row.request_id,
        "mutation_id": row.mutation_id,
        "result_code": row.result_code,
        "payload_hash": row.payload_hash,
        "previous_record_hash": row.previous_record_hash,
    }
    if any(canonical.get(key) != value for key, value in expected.items()) or sha256_hex(canonical) != row.record_hash:
        raise CoreError("AUDIT_CHAIN_INVALID")
    return row


def verify_audit_chain(session: Session, *, refresh: bool = False) -> dict[str, object]:
    """Check the chain, optionally reloading locked persisted rows at a gate.

    Gate callers use refresh only at persisted transaction boundaries. The
    default preserves ordinary callers' unflushed local projection changes.
    """
    metadata_query = select(CoreMetadata).where(CoreMetadata.id == 1)
    audit_query = select(AuditLedger).order_by(AuditLedger.audit_seq)
    if refresh:
        metadata_query = metadata_query.with_for_update().execution_options(populate_existing=True)
        audit_query = audit_query.with_for_update().execution_options(populate_existing=True)
    metadata = session.execute(
        metadata_query
    ).scalar_one()
    rows = list(session.scalars(audit_query))
    expected_previous: str | None = None
    for expected_seq, row in enumerate(rows, start=1):
        if row.audit_seq != expected_seq:
            raise CoreError("AUDIT_CHAIN_INVALID")
        if row.previous_record_hash != expected_previous:
            raise CoreError("AUDIT_CHAIN_INVALID")
        verify_audit_row(row)
        expected_previous = row.record_hash
    if metadata.audit_seq != len(rows) or metadata.audit_head_hash != expected_previous:
        raise CoreError("AUDIT_HIGH_WATER_UNPROVEN")
    return {
        "audit_seq": metadata.audit_seq,
        "audit_head_hash": metadata.audit_head_hash,
        "entries": len(rows),
    }

