from __future__ import annotations

from typing import Any, Literal, Protocol

from pydantic import Field, field_validator

from .canonical import sha256_hex
from .errors import CoreError
from .schemas import CoreModel, CoreReadModel


AssertionKind = Literal["USER_STATED", "DERIVED", "INFERRED"]
DerivedAssertionKind = Literal["DERIVED", "INFERRED"]
ProjectionStatus = Literal["COMPLETE", "DEGRADED", "AMBIGUOUS", "NOT_FOUND"]

MEMORY_DERIVATION_VERSION = "memory-derivation-v2"
CONTEXT_PROJECTION_VERSION = "context-projection-v2"
HERMES_PROJECTION_VERSION = "hermes-projection-v2"
VALUE_CHAIN_VERSION = "value-poc-read-chain-v2"
RECALL_ALGORITHM_VERSION = "memory-recall-v1"
CONTEXT_SELECTION_VERSION = "context-selection-v1"
MAX_CONTEXT_RECORDS = 128


class ProvenanceRef(CoreModel):
    source_type: Literal["core_read_model", "gateway_evidence", "memory_record", "context_projection"]
    source_id: str
    digest: str
    state_version: int | None = None


class GatewayEvidence(CoreModel):
    schema_version: str = "gateway-evidence-normalized-v1"
    evidence_id: str = Field(min_length=1, max_length=128)
    evidence_hash: str = Field(min_length=64, max_length=64)
    core_read_model_hash: str = Field(min_length=64, max_length=64)
    core_state_version: int | None = None
    continuity_id: str | None = None
    source_epistemic_status: AssertionKind = "USER_STATED"
    source_reference: dict[str, Any] = Field(default_factory=dict)
    facts: list[dict[str, Any]] = Field(default_factory=list)

    @field_validator("core_state_version")
    @classmethod
    def state_version_nonnegative(cls, value: int | None) -> int | None:
        if value is not None and value < 0:
            raise ValueError("core_state_version must be non-negative")
        return value


class MemoryRecord(CoreModel):
    schema_version: str = "memory-record-v1"
    record_id: str
    memory_hash: str
    domain: str
    proposition: str
    assertion_kind: DerivedAssertionKind
    source_epistemic_status: AssertionKind
    value: dict[str, Any]
    confidence: float | None = None
    core_state_version: int
    derivation_version: str = MEMORY_DERIVATION_VERSION
    inference_rule: str | None = None
    supersedes: list[str] = Field(default_factory=list)
    conflict_key: str | None = None
    lifecycle: Literal["rebuilt", "created"] = "rebuilt"
    provenance: list[ProvenanceRef]
    rebuildable: bool = True

    @field_validator("confidence")
    @classmethod
    def confidence_range(cls, value: float | None) -> float | None:
        if value is not None and not (0 <= value <= 1):
            raise ValueError("confidence must be between 0 and 1")
        return value


class MemoryRecallQuery(CoreModel):
    schema_version: str = "memory-recall-query-v1"
    query_id: str = Field(min_length=1, max_length=128)
    recall_algorithm_version: str = RECALL_ALGORITHM_VERSION
    core_state_version: int
    proposition: str | None = None
    subject: str | None = None
    memory_id: str | None = None
    evidence_id: str | None = None
    assertion_kind: DerivedAssertionKind | None = None
    derivation_version: str | None = None
    provenance_source_type: str | None = None
    include_superseded: bool = False
    max_results: int = Field(default=8, ge=1, le=MAX_CONTEXT_RECORDS)


class RecallResult(CoreModel):
    schema_version: str = "memory-recall-result-v1"
    query_hash: str
    recall_algorithm_version: str
    result_status: ProjectionStatus
    memory_ref: ProvenanceRef | None = None
    proposition: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    epistemic_type: DerivedAssertionKind | None = None
    provenance: list[ProvenanceRef] = Field(default_factory=list)
    core_state_version: int
    supersession_status: Literal["CURRENT", "SUPERSEDED", "CONFLICTING", "NONE"] = "NONE"
    inference_rule: str | None = None
    confidence: float | None = None
    selection_reason: str
    omitted_reason: str | None = None


class ContextIntent(CoreModel):
    schema_version: str = "context-intent-v1"
    intent_id: str = Field(min_length=1, max_length=128)
    subject: str | None = None
    max_memory_items: int = Field(default=8, ge=1, le=MAX_CONTEXT_RECORDS)
    max_payload_bytes: int = Field(default=8192, ge=128)


class ContextProjection(CoreModel):
    schema_version: str = "context-projection-v1"
    projection_id: str
    core_state_version: int
    records: list[MemoryRecord]
    canonical_hash: str
    status: ProjectionStatus = "COMPLETE"
    degraded_reasons: list[str] = Field(default_factory=list)
    recall_results: list[RecallResult] = Field(default_factory=list)
    selected_memory_refs: list[ProvenanceRef] = Field(default_factory=list)
    omitted_reasons: dict[str, str] = Field(default_factory=dict)
    truncated: bool = False
    selection_version: str = CONTEXT_SELECTION_VERSION
    provenance: list[ProvenanceRef]
    rebuildable: bool = True


class HermesProfileProjection(CoreModel):
    schema_version: str = "hermes-profile-projection-v1"
    profile_id: str
    context_projection_id: str
    core_state_version: int
    identity_authority: Literal["core_read_model"]
    content: dict[str, Any]
    canonical_hash: str
    status: ProjectionStatus = "COMPLETE"
    degraded_reasons: list[str] = Field(default_factory=list)
    provenance: list[ProvenanceRef]
    rebuildable: bool = True


class ValueChainResult(CoreModel):
    schema_version: str = "value-chain-result-v1"
    memory_records: list[MemoryRecord]
    context: ContextProjection
    hermes: HermesProfileProjection
    canonical_hash: str
    status: ProjectionStatus = "COMPLETE"
    degraded_reasons: list[str] = Field(default_factory=list)
    runtime_metadata: dict[str, Any] = Field(default_factory=dict)


class MemoryAdapter(Protocol):
    def derive(self, read_model: CoreReadModel, evidence: GatewayEvidence) -> list[MemoryRecord]:
        ...


class CoreReadModelReader(Protocol):
    def read(self) -> CoreReadModel:
        ...


class GatewayEvidenceReader(Protocol):
    def read_value_evidence(self, *, limit: int = 1) -> GatewayEvidence:
        ...


def reject_direct_core_database_uri(uri: str | None) -> None:
    if uri:
        raise CoreError("VALUE_POC_DIRECT_CORE_DB_FORBIDDEN")


def reject_direct_gateway_database_uri(uri: str | None) -> None:
    if uri:
        raise CoreError("VALUE_POC_DIRECT_GATEWAY_DB_FORBIDDEN")


def _state_version(read_model: CoreReadModel) -> int:
    version = read_model.generation.get("state_version")
    if not isinstance(version, int) or version < 0:
        raise CoreError("VALUE_POC_CORE_STATE_VERSION_INVALID")
    return version


def _core_ref(read_model: CoreReadModel) -> ProvenanceRef:
    return ProvenanceRef(
        source_type="core_read_model",
        source_id=str(read_model.identity_reference["continuity_id"]),
        digest=read_model.read_model_hash,
        state_version=_state_version(read_model),
    )


def _evidence_ref(evidence: GatewayEvidence) -> ProvenanceRef:
    return ProvenanceRef(
        source_type="gateway_evidence",
        source_id=evidence.evidence_id,
        digest=evidence.evidence_hash,
        state_version=evidence.core_state_version,
    )


def _fact_proposition(value: dict[str, Any]) -> str:
    explicit = value.get("proposition")
    if explicit is not None:
        return str(explicit)
    domain = str(value.get("domain", "general"))
    content = value.get("value", value)
    return f"{domain}:{sha256_hex(content)[:16]}"


def _validate_evidence(read_model: CoreReadModel, evidence: GatewayEvidence) -> int:
    version = _state_version(read_model)
    if evidence.schema_version != "gateway-evidence-normalized-v1":
        raise CoreError("VALUE_POC_EVIDENCE_SCHEMA_UNSUPPORTED")
    if evidence.core_read_model_hash != read_model.read_model_hash:
        raise CoreError("VALUE_POC_PROVENANCE_MISMATCH")
    if evidence.core_state_version is not None and evidence.core_state_version != version:
        raise CoreError("VALUE_POC_CORE_STATE_VERSION_MISMATCH")
    continuity_id = str(read_model.identity_reference["continuity_id"])
    if evidence.continuity_id is not None and evidence.continuity_id != continuity_id:
        raise CoreError("VALUE_POC_CONTINUITY_MISMATCH")
    if not evidence.facts:
        raise CoreError("VALUE_POC_EVIDENCE_FACTS_REQUIRED")
    return version


class ReadOnlyMemoryAdapter:
    def __init__(self, *, derivation_version: str = MEMORY_DERIVATION_VERSION) -> None:
        self.derivation_version = derivation_version

    def derive(self, read_model: CoreReadModel, evidence: GatewayEvidence) -> list[MemoryRecord]:
        return self.derive_many(read_model, [evidence])

    def derive_many(self, read_model: CoreReadModel, evidence_items: list[GatewayEvidence]) -> list[MemoryRecord]:
        if not evidence_items:
            raise CoreError("VALUE_POC_EVIDENCE_REQUIRED")
        version = _state_version(read_model)
        core_ref = _core_ref(read_model)
        records: list[MemoryRecord] = []
        derived_by_domain: dict[str, list[MemoryRecord]] = {}
        for evidence in sorted(evidence_items, key=lambda item: item.evidence_id):
            checked_version = _validate_evidence(read_model, evidence)
            if checked_version != version:
                raise CoreError("VALUE_POC_CORE_STATE_VERSION_MISMATCH")
            evidence_ref = _evidence_ref(evidence)
            for index, fact in enumerate(evidence.facts):
                kind = fact.get("assertion_kind", "DERIVED")
                if kind == "USER_STATED":
                    raise CoreError("VALUE_POC_USER_STATED_REQUIRES_EXPLICIT_USER_SOURCE")
                if kind not in {"DERIVED", "INFERRED"}:
                    raise CoreError("VALUE_POC_ASSERTION_KIND_INVALID")
                value = {k: v for k, v in fact.items() if k != "assertion_kind"}
                domain = str(value.get("domain", "general"))
                proposition = _fact_proposition(value)
                confidence = value.get("confidence") if kind == "INFERRED" else value.get("confidence")
                inference_rule = value.get("inference_rule") if kind == "INFERRED" else None
                if kind == "INFERRED" and not inference_rule:
                    raise CoreError("VALUE_POC_INFERENCE_RULE_REQUIRED")
                supersedes = [str(item) for item in value.get("supersedes", [])]
                conflict_key = str(value.get("conflict_key", proposition))
                memory_hash = sha256_hex({
                    "derivation_version": self.derivation_version,
                    "core": read_model.read_model_hash,
                    "core_state_version": version,
                    "evidence": evidence.evidence_hash,
                    "evidence_id": evidence.evidence_id,
                    "source_epistemic_status": evidence.source_epistemic_status,
                    "index": index,
                    "domain": domain,
                    "proposition": proposition,
                    "value": value,
                    "assertion_kind": kind,
                    "inference_rule": inference_rule,
                    "supersedes": supersedes,
                })
                record = MemoryRecord(
                    record_id=f"mem-{memory_hash[:24]}",
                    memory_hash=memory_hash,
                    domain=domain,
                    proposition=proposition,
                    assertion_kind=kind,
                    source_epistemic_status=evidence.source_epistemic_status,
                    value=value,
                    confidence=confidence,
                    core_state_version=version,
                    derivation_version=self.derivation_version,
                    inference_rule=inference_rule,
                    supersedes=supersedes,
                    conflict_key=conflict_key,
                    provenance=[core_ref, evidence_ref],
                )
                records.append(record)
                if kind == "DERIVED":
                    derived_by_domain.setdefault(domain, []).append(record)
        records.extend(self._infer_from_derived(read_model, core_ref, derived_by_domain))
        return sorted(records, key=lambda record: record.record_id)

    def _infer_from_derived(
        self,
        read_model: CoreReadModel,
        core_ref: ProvenanceRef,
        derived_by_domain: dict[str, list[MemoryRecord]],
    ) -> list[MemoryRecord]:
        inferred: list[MemoryRecord] = []
        version = _state_version(read_model)
        for domain, records in sorted(derived_by_domain.items()):
            unique = {record.proposition: record for record in records}
            if len(unique) < 2:
                continue
            source_records = sorted(unique.values(), key=lambda item: item.record_id)
            provenance = [core_ref] + [
                ProvenanceRef(source_type="memory_record", source_id=record.record_id, digest=record.memory_hash, state_version=record.core_state_version)
                for record in source_records
            ]
            memory_hash = sha256_hex({
                "derivation_version": self.derivation_version,
                "inference_rule": "multi-evidence-domain-corroboration-v1",
                "core": read_model.read_model_hash,
                "core_state_version": version,
                "domain": domain,
                "sources": [record.memory_hash for record in source_records],
            })
            inferred.append(MemoryRecord(
                record_id=f"mem-{memory_hash[:24]}",
                memory_hash=memory_hash,
                domain=domain,
                proposition=f"{domain}:multiple-evidence-observed",
                assertion_kind="INFERRED",
                source_epistemic_status="INFERRED",
                value={
                    "domain": domain,
                    "proposition": f"{domain}:multiple-evidence-observed",
                    "source_record_ids": [record.record_id for record in source_records],
                },
                confidence=min(0.95, 0.5 + 0.1 * len(source_records)),
                core_state_version=version,
                derivation_version=self.derivation_version,
                inference_rule="multi-evidence-domain-corroboration-v1",
                conflict_key=f"{domain}:inferred",
                provenance=provenance,
            ))
        return inferred


def _query_hash(query: MemoryRecallQuery) -> str:
    return sha256_hex(query.model_dump(mode="json"))


def _superseded_ids(records: list[MemoryRecord]) -> set[str]:
    return {item for record in records for item in record.supersedes}


def _matches_query(record: MemoryRecord, query: MemoryRecallQuery) -> bool:
    if query.schema_version != "memory-recall-query-v1":
        raise CoreError("VALUE_POC_RECALL_QUERY_SCHEMA_UNSUPPORTED")
    if query.recall_algorithm_version != RECALL_ALGORITHM_VERSION:
        raise CoreError("VALUE_POC_RECALL_ALGORITHM_UNSUPPORTED")
    if record.core_state_version != query.core_state_version:
        return False
    if query.memory_id and record.record_id != query.memory_id:
        return False
    if query.proposition and record.proposition != query.proposition:
        return False
    if query.subject and record.domain != query.subject and record.conflict_key != query.subject and query.subject not in record.proposition:
        return False
    if query.assertion_kind and record.assertion_kind != query.assertion_kind:
        return False
    if query.derivation_version and record.derivation_version != query.derivation_version:
        return False
    if query.evidence_id and not any(ref.source_type == "gateway_evidence" and ref.source_id == query.evidence_id for ref in record.provenance):
        return False
    if query.provenance_source_type and not any(ref.source_type == query.provenance_source_type for ref in record.provenance):
        return False
    return True


def recall_memory(records: list[MemoryRecord], query: MemoryRecallQuery) -> list[RecallResult]:
    qh = _query_hash(query)
    if not records:
        return [RecallResult(query_hash=qh, recall_algorithm_version=query.recall_algorithm_version, result_status="NOT_FOUND", core_state_version=query.core_state_version, selection_reason="no memory available")]
    versions = {record.core_state_version for record in records}
    if len(versions) != 1 or query.core_state_version not in versions:
        raise CoreError("VALUE_POC_RECALL_STATE_VERSION_MISMATCH")
    for record in records:
        if not record.provenance:
            raise CoreError("VALUE_POC_RECALL_PROVENANCE_REQUIRED")
    superseded = _superseded_ids(records)
    matched = [record for record in records if _matches_query(record, query)]
    if not query.include_superseded:
        matched = [record for record in matched if record.record_id not in superseded]
    matched = sorted(matched, key=lambda record: (
        0 if record.record_id not in superseded else 1,
        0 if query.proposition and record.proposition == query.proposition else 1,
        0 if record.assertion_kind == "DERIVED" else 1,
        record.record_id,
    ))
    if not matched:
        return [RecallResult(query_hash=qh, recall_algorithm_version=query.recall_algorithm_version, result_status="NOT_FOUND", core_state_version=query.core_state_version, selection_reason="no matching memory")]
    active_by_key: dict[str, set[str]] = {}
    for record in records:
        if record.record_id not in superseded:
            active_by_key.setdefault(record.conflict_key or record.domain, set()).add(record.proposition)
    conflict_keys = {key for key, propositions in active_by_key.items() if len(propositions) > 1}
    results: list[RecallResult] = []
    for record in matched[: query.max_results]:
        supersession_status = "SUPERSEDED" if record.record_id in superseded else "CURRENT"
        status: ProjectionStatus = "COMPLETE"
        reason = "current deterministic match"
        key = record.conflict_key or record.domain
        if key in conflict_keys and record.record_id not in superseded:
            supersession_status = "CONFLICTING"
            status = "AMBIGUOUS"
            reason = "unresolved conflict; no arbitrary winner selected"
        elif record.record_id in superseded:
            reason = "historical superseded match"
        results.append(RecallResult(
            query_hash=qh,
            recall_algorithm_version=query.recall_algorithm_version,
            result_status=status,
            memory_ref=ProvenanceRef(source_type="memory_record", source_id=record.record_id, digest=record.memory_hash, state_version=record.core_state_version),
            proposition=record.proposition,
            payload=record.value,
            epistemic_type=record.assertion_kind,
            provenance=list(record.provenance),
            core_state_version=record.core_state_version,
            supersession_status=supersession_status,
            inference_rule=record.inference_rule,
            confidence=record.confidence,
            selection_reason=reason,
        ))
    return results


def select_context(read_model: CoreReadModel, recall_results: list[RecallResult], intent: ContextIntent) -> ContextProjection:
    version = _state_version(read_model)
    if intent.schema_version != "context-intent-v1":
        raise CoreError("VALUE_POC_CONTEXT_INTENT_SCHEMA_UNSUPPORTED")
    if not recall_results:
        raise CoreError("VALUE_POC_RECALL_REQUIRED")
    if any(result.core_state_version != version for result in recall_results):
        raise CoreError("VALUE_POC_CONTEXT_RECALL_STALE")
    selected = [result for result in recall_results if result.memory_ref is not None and result.result_status == "COMPLETE"]
    ambiguous = [result for result in recall_results if result.result_status == "AMBIGUOUS"]
    not_found = all(result.result_status == "NOT_FOUND" for result in recall_results)
    if ambiguous:
        selected = []
    selected = sorted(selected, key=lambda result: (0 if result.epistemic_type == "DERIVED" else 1, result.memory_ref.source_id if result.memory_ref else ""))
    omitted: dict[str, str] = {}
    truncated = False
    if len(selected) > intent.max_memory_items:
        for result in selected[intent.max_memory_items:]:
            omitted[result.memory_ref.source_id] = "budget:max_memory_items"
        selected = selected[: intent.max_memory_items]
        truncated = True
    payload_bytes = 0
    bounded: list[RecallResult] = []
    for result in selected:
        size = len(str(result.payload).encode("utf-8"))
        if payload_bytes + size > intent.max_payload_bytes:
            omitted[result.memory_ref.source_id] = "budget:max_payload_bytes"
            truncated = True
            continue
        payload_bytes += size
        bounded.append(result)
    selected = bounded
    status: ProjectionStatus = "COMPLETE"
    degraded: list[str] = []
    if ambiguous:
        status = "AMBIGUOUS"
        degraded.append("ambiguous_recall")
    elif not_found or not selected:
        status = "NOT_FOUND"
        degraded.append("no_selected_memory")
    elif truncated:
        status = "DEGRADED"
        degraded.append("context_budget_truncated")
    refs = [result.memory_ref for result in selected if result.memory_ref is not None]
    canonical_hash = sha256_hex({
        "context_selection_version": CONTEXT_SELECTION_VERSION,
        "intent": intent.model_dump(mode="json"),
        "selected": [result.model_dump(mode="json") for result in selected],
        "ambiguous": [result.model_dump(mode="json") for result in ambiguous],
        "omitted": omitted,
        "status": status,
        "degraded_reasons": degraded,
        "core": read_model.read_model_hash,
    })
    return ContextProjection(
        projection_id=f"context-{canonical_hash[:24]}",
        core_state_version=version,
        records=[],
        canonical_hash=canonical_hash,
        status=status,
        degraded_reasons=degraded,
        recall_results=[*selected, *ambiguous] if not not_found else recall_results,
        selected_memory_refs=refs,
        omitted_reasons=omitted,
        truncated=truncated,
        provenance=[_core_ref(read_model), *refs],
    )


def project_context(records: list[MemoryRecord], *, max_records: int = MAX_CONTEXT_RECORDS) -> ContextProjection:
    if not records:
        raise CoreError("VALUE_POC_MEMORY_REQUIRED")
    if len(records) > max_records:
        raise CoreError("VALUE_POC_CONTEXT_INPUT_LIMIT_EXCEEDED")
    versions = {record.core_state_version for record in records}
    if len(versions) != 1:
        raise CoreError("VALUE_POC_CONTEXT_STATE_VERSION_MIXED")
    unique = {record.record_id: record for record in records}
    ordered = sorted(unique.values(), key=lambda record: record.record_id)
    for record in ordered:
        if record.schema_version != "memory-record-v1" or not record.provenance or record.assertion_kind == "USER_STATED":
            raise CoreError("VALUE_POC_MEMORY_PROVENANCE_REQUIRED")

    degraded_reasons: list[str] = []
    by_conflict: dict[str, list[MemoryRecord]] = {}
    for record in ordered:
        by_conflict.setdefault(record.conflict_key or record.domain, []).append(record)
    for key, group in sorted(by_conflict.items()):
        propositions = {record.proposition for record in group if not record.supersedes}
        superseded = {item for record in group for item in record.supersedes}
        active = [record for record in group if record.record_id not in superseded]
        if len({record.proposition for record in active}) > 1:
            degraded_reasons.append(f"conflict:{key}")
    canonical_records = [record.model_dump(mode="json") for record in ordered]
    status: ProjectionStatus = "DEGRADED" if degraded_reasons else "COMPLETE"
    canonical_hash = sha256_hex({
        "context_projection_version": CONTEXT_PROJECTION_VERSION,
        "records": canonical_records,
        "status": status,
        "degraded_reasons": degraded_reasons,
    })
    return ContextProjection(
        projection_id=f"context-{canonical_hash[:24]}",
        core_state_version=next(iter(versions)),
        records=ordered,
        canonical_hash=canonical_hash,
        status=status,
        degraded_reasons=degraded_reasons,
        provenance=[
            ProvenanceRef(source_type="memory_record", source_id=r.record_id, digest=r.memory_hash, state_version=r.core_state_version)
            for r in ordered
        ],
    )


def project_hermes(context: ContextProjection, read_model: CoreReadModel) -> HermesProfileProjection:
    version = _state_version(read_model)
    if context.core_state_version != version:
        raise CoreError("VALUE_POC_HERMES_STATE_VERSION_MISMATCH")
    content = {
        "continuity_id": read_model.identity_reference["continuity_id"],
        "state_version": version,
        "memory_record_count": len(context.records) or len(context.selected_memory_refs),
        "context_status": context.status,
        "selected_epistemic_types": [result.epistemic_type for result in context.recall_results if result.epistemic_type],
    }
    canonical_hash = sha256_hex({
        "hermes_projection_version": HERMES_PROJECTION_VERSION,
        "context": context.canonical_hash,
        "core": read_model.read_model_hash,
        "content": content,
        "status": context.status,
        "degraded_reasons": context.degraded_reasons,
    })
    return HermesProfileProjection(
        profile_id=f"hermes-{canonical_hash[:24]}",
        context_projection_id=context.projection_id,
        core_state_version=version,
        identity_authority="core_read_model",
        content=content,
        canonical_hash=canonical_hash,
        status=context.status,
        degraded_reasons=list(context.degraded_reasons),
        provenance=[
            _core_ref(read_model),
            ProvenanceRef(source_type="context_projection", source_id=context.projection_id, digest=context.canonical_hash, state_version=context.core_state_version),
            *context.provenance,
        ],
    )


class InMemoryDerivedStateStore:
    """Ephemeral PoC store for derived state; never stores Core or Gateway truth."""

    def __init__(self) -> None:
        self.memory_records: list[MemoryRecord] = []
        self.context: ContextProjection | None = None
        self.hermes: HermesProfileProjection | None = None

    def save(self, result: ValueChainResult) -> None:
        self.memory_records = list(result.memory_records)
        self.context = result.context
        self.hermes = result.hermes

    def delete_all(self) -> None:
        self.memory_records = []
        self.context = None
        self.hermes = None


class ValuePocReadChain:
    def __init__(
        self,
        *,
        core: CoreReadModelReader,
        gateway: GatewayEvidenceReader,
        memory: MemoryAdapter | None = None,
        store: InMemoryDerivedStateStore | None = None,
    ):
        self.core = core
        self.gateway = gateway
        self.memory = memory or ReadOnlyMemoryAdapter()
        self.store = store or InMemoryDerivedStateStore()

    def run(self) -> ValueChainResult:
        read_model = self.core.read()
        evidence_items = self._read_evidence_items()
        if hasattr(self.memory, "derive_many"):
            records = self.memory.derive_many(read_model, evidence_items)  # type: ignore[attr-defined]
        else:
            records = []
            for evidence in evidence_items:
                records.extend(self.memory.derive(read_model, evidence))
        context = project_context(records)
        hermes = project_hermes(context, read_model)
        canonical_hash = sha256_hex({
            "value_chain_version": VALUE_CHAIN_VERSION,
            "memory": [record.model_dump(mode="json") for record in records],
            "context": context.canonical_hash,
            "hermes": hermes.canonical_hash,
            "status": hermes.status,
            "degraded_reasons": hermes.degraded_reasons,
        })
        result = ValueChainResult(
            memory_records=records,
            context=context,
            hermes=hermes,
            canonical_hash=canonical_hash,
            status=hermes.status,
            degraded_reasons=list(hermes.degraded_reasons),
            runtime_metadata={"derived_state_persistence": "ephemeral-poc-store"},
        )
        self.store.save(result)
        return result

    def _read_evidence_items(self) -> list[GatewayEvidence]:
        reader = getattr(self.gateway, "read_value_evidence_set", None)
        if callable(reader):
            items = reader(limit=MAX_CONTEXT_RECORDS)
            if not isinstance(items, list) or not items:
                raise CoreError("VALUE_POC_EVIDENCE_REQUIRED")
            return items
        return [self.gateway.read_value_evidence(limit=1)]

    def delete_derived_state(self) -> None:
        self.store.delete_all()


def trace_value_chain(result: ValueChainResult) -> dict[str, Any]:
    memory = {
        record.record_id: {
            "memory_hash": record.memory_hash,
            "assertion_kind": record.assertion_kind,
            "core_state_version": record.core_state_version,
            "provenance": [ref.model_dump(mode="json") for ref in record.provenance],
        }
        for record in result.memory_records
    }
    return {
        "schema_version": "value-chain-trace-v1",
        "result_hash": result.canonical_hash,
        "status": result.status,
        "context": {
            "projection_id": result.context.projection_id,
            "canonical_hash": result.context.canonical_hash,
            "core_state_version": result.context.core_state_version,
            "status": result.context.status,
            "selected_memory_refs": [ref.model_dump(mode="json") for ref in result.context.selected_memory_refs],
            "omitted_reasons": result.context.omitted_reasons,
            "truncated": result.context.truncated,
            "provenance": [ref.model_dump(mode="json") for ref in result.context.provenance],
        },
        "recall": [
            {
                "query_hash": recall.query_hash,
                "recall_algorithm_version": recall.recall_algorithm_version,
                "result_status": recall.result_status,
                "selection_reason": recall.selection_reason,
                "memory_ref": recall.memory_ref.model_dump(mode="json") if recall.memory_ref else None,
                "core_state_version": recall.core_state_version,
            }
            for recall in result.context.recall_results
        ],
        "hermes": {
            "profile_id": result.hermes.profile_id,
            "canonical_hash": result.hermes.canonical_hash,
            "identity_authority": result.hermes.identity_authority,
            "provenance": [ref.model_dump(mode="json") for ref in result.hermes.provenance],
        },
        "memory": memory,
        "secret_values_omitted": True,
    }


