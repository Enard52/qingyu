"""Internal bounded replay of original records, never a new trust certificate.

Each window contains original canonical object bytes and original absolute event
positions. Persistent callers must retain those facts and rebuild this disposable
state from them after restart. No API accepts a serialized state or verified flag.
The public whole-history verifier and its 64-operation limit are unchanged.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass

from . import _r1_validation_semantics as sem
from ._r1_validation_chain import ChainBoundary, MAX_OPERATIONS, decode_boundary
from .r1_validation_codec import (SCHEMA, STRUCT, RECORD, ContractError, c2, decode,
                                 h2, match, obj, require, validate, validate_fields)
from .r1_validation_crypto import FixedTrust, verify_signed


@dataclass(frozen=True, slots=True)
class RegistrySlice:
    header_wire: bytes
    event_wires: tuple[bytes, ...]
    record_wires: tuple[tuple[str, bytes], ...]


@dataclass(frozen=True, slots=True)
class WindowEvidence:
    request_wires: tuple[bytes, ...]
    authority: RegistrySlice
    cores: tuple[tuple[str, RegistrySlice], ...]
    source_admission_wires: tuple[bytes, ...] = ()
    context_wires: tuple[bytes, ...] = ()


def registry_slice(registry) -> RegistrySlice:
    """Split an already materialized registry without re-numbering any event."""
    require(type(registry) is dict and set(registry) == {"header", "events", "records"},
            "registry exact fields")
    return RegistrySlice(c2(registry["header"]), tuple(c2(e) for e in registry["events"]),
                         tuple((d, c2(v)) for d, v in registry["records"].items()))


def from_history(evidence) -> WindowEvidence:
    from .r1_validation import HistoryEvidence
    require(type(evidence) is HistoryEvidence, "original HistoryEvidence required")
    return WindowEvidence(evidence.request_wires, registry_slice(decode(evidence.authority_history)),
        tuple((core.runtime_principal, registry_slice(decode(core.raw))) for core in evidence.core_histories),
        evidence.source_admission_wires, evidence.context_wires)


class BoundedHistory:
    """Private implementation state rooted in explicit fixed trust and boundary.

    Attributes are implementation data for the controlled local service, not an
    authenticated caller interface. ``fork`` stages work without mutating the
    committed cache; only original evidence is persisted. Failed instances may
    not be reused. SQLite still has to recheck its own current committed facts.
    """
    def __init__(self, trust, deployments, chain_boundary: ChainBoundary, *, restore_evidence=()):
        require(type(trust) is FixedTrust, "independent fixed trust required")
        require(type(deployments) is tuple and 0 < len(deployments) <= 32, "deployment bounds")
        self.trust, self.deployments = trust, deployments
        self.pin = decode(trust.pin_wire)
        validate(self.pin)
        self.materials = {}
        for material in deployments:
            require(type(material) is sem.DeploymentEvidence, "deployment type")
            sem.validate_pin_material(self.pin, material)
            require(material.runtime_principal not in self.materials, "duplicate deployment principal")
            self.materials[material.runtime_principal] = material
        self.boundary = chain_boundary
        self.identity, self.initial_checkpoint, self.expected_initial_end = decode_boundary(chain_boundary)
        self.authority = {"header": sem.header(self.pin), "events": [], "records": {}}
        self.cores = {}
        self.requests, self.request_wires, self.admissions = {}, {}, {}
        self.mutation_ids, self.local_commit_ids = {}, {}
        self.authority_state = sem.empty_state()
        self.core_states, self.core_checkpoints, self.core_started = {}, {}, set()
        self.authority_checkpoint = deepcopy(self.initial_checkpoint)
        self.pending = None
        self.chain_checkpoints = {c2(self.initial_checkpoint)}
        self.authority_facts = {}
        self.contexts, self.restore_results = {}, []
        self._verified_signatures = set()
        self._failed, self._windows = False, 0
        self.revision = 0
        self._global_records = {}
        require(type(restore_evidence) is tuple and len(restore_evidence) <= 16, "restore proof bounds")
        if restore_evidence:
            from ._r1_validation_restore import verify_restore_evidence
            from .r1_validation import validate_evidence
            for proof in restore_evidence:
                result = verify_restore_evidence(proof, trust, deployments, validate_evidence)
                context = result.context
                self._object(context)
                require(h2(context) not in self.contexts, "duplicate restoration context")
                self.contexts[h2(context)] = context
                self.restore_results.append(result)

    def fork(self):
        require(not self._failed, "failed verification state must be discarded")
        # FixedTrust retains a cryptography public-key implementation object.
        # It is immutable and cannot be deepcopy/pickled; every derived mutable
        # relation is copied. A fork cannot accept state from request bytes.
        memo = {id(self.trust): self.trust}
        return deepcopy(self, memo)

    clone = fork

    def registry(self, runtime_principal=None):
        require(not self._failed, "failed verification state must be discarded")
        return self.authority if runtime_principal is None else self.cores[runtime_principal]

    def _object(self, value):
        require(type(value) is dict, "registry original record must be object")
        if "type" in value:
            require(value["type"] in SCHEMA, "unknown protocol record type")
            validate(value)
            if "receipt_signature" in value or "root_signature" in value:
                digest = h2(value)
                if digest not in self._verified_signatures:
                    verify_signed(value, self.trust)
                    self._verified_signatures.add(digest)
        else:
            require("receipt_signature" not in value and "root_signature" not in value,
                    "signature on unregistered record type")

    def _restore_declared(self, value):
        declared = value.get("restoration_context_digest")
        enrollment = value.get("enrollment")
        if type(enrollment) is dict:
            declared = enrollment.get("restoration_context_digest")
            require(enrollment.get("context_kind") != "MANUAL_RESTORE_ADMITTED" or declared is not None,
                    "restore enrollment requires original context")
        if value.get("type") == "restoration_context":
            declared = h2(value)
        if value.get("context_kind") == "MANUAL_RESTORE_ADMITTED" and declared is None:
            policy = sem.record_by(self.authority, value.get("policy_digest"))
            require(policy.get("type") == "recovery_policy", "restore protection policy type")
            declared = policy["restoration_context_digest"]
            require(declared is not None, "restore protection requires original context")
        require(declared is None or declared in self.contexts, "complete restore source/archive/backup proof required")

    def _merge(self, part, registry, material=None):
        require(type(part) is RegistrySlice, "RegistrySlice required")
        require(type(part.event_wires) is tuple and len(part.event_wires) <= 4096
                and type(part.record_wires) is tuple and len(part.record_wires) <= 4096, "registry slice bounds")
        header = decode(part.header_wire)
        validate_fields(header, RECORD["registry_header"])
        require(header == registry["header"] == sem.header(self.pin, material), "registry source/header mismatch")
        new_records = []
        for entry in part.record_wires:
            require(type(entry) is tuple and len(entry) == 2, "record pair shape")
            digest, raw = entry
            match(digest, "hash")
            value = decode(raw)
            self._object(value)
            allowed = {sem.rawhash(value), h2(value)} if value.get("type") in SCHEMA else {sem.rawhash(value)}
            require(digest in allowed, "record key does not hash original bytes")
            require(digest not in self._global_records or self._global_records[digest] == raw,
                    "cross-registry original record conflict")
            self._global_records[digest] = raw
            if digest in registry["records"]:
                require(c2(registry["records"][digest]) == raw, "historical original record replaced")
            else:
                registry["records"][digest] = value
                new_records.append(value)
        start = len(registry["events"])
        previous_supplied = 0
        for raw in part.event_wires:
            event = decode(raw)
            validate_fields(event, RECORD["registry_event"])
            number = event["position"]["event_sequence"]
            require(number > previous_supplied, "slice event order/duplicate position")
            previous_supplied = number
            require(event["position"] == sem.position(registry, number), "absolute registry position mismatch")
            if number <= len(registry["events"]):
                require(c2(registry["events"][number - 1]) == raw, "historical event overlap conflict")
                continue
            require(number == len(registry["events"]) + 1, "registry event gap")
            kinds = sem.A_KINDS if material is None else sem.C_KINDS
            require(event["event_kind"] in kinds, "registry event kind")
            require(not registry["events"] or event["recorded_at"] >= registry["events"][-1]["recorded_at"],
                    "registry time backdating")
            require(event["input_digest"] in registry["records"], "missing event input")
            require(sem.rawhash(registry["records"][event["input_digest"]]) == event["input_digest"],
                    "event original input domain mismatch")
            if event["output_digest"] is not None:
                output = sem.record_by(registry, event["output_digest"])
                require(output is not None, "missing event output")
            registry["events"].append(event)
        return start, new_records

    def _request(self, raw):
        request = decode(raw)
        validate(request)
        require(request["type"] == "mutation_request", "mutation request required")
        sem.verify_request(request, self.pin, request["intent"]["scope"]["actor_identity"])
        intent, scope = request["intent"], request["intent"]["scope"]
        op = intent["operation_id"]
        require(op not in self.request_wires or self.request_wires[op] == raw, "historical operation content conflict")
        require(intent["identity"] == self.identity, "chain identity/continuity mismatch")
        sem.eq_fields(scope, {"actor_identity": self.boundary.owner_identity,
            **{key: getattr(self.boundary, key) for key in ("owner_version", "continuity_epoch",
                "storage_generation_id", "control_plane_generation_id", "trust_domain_id")}},
            "chain external governance scope mismatch")
        for key, index in (("mutation_id", self.mutation_ids), ("local_commit_id", self.local_commit_ids)):
            require(intent[key] not in index or index[intent[key]] == op, "historical mutation/local commit identity conflict")
            index[intent[key]] = op
        self.requests[op], self.request_wires[op] = request, raw
        return op

    def _chain_authority(self, event):
        kind = event["event_kind"]
        if kind not in ("PREPARE", "FIX_ACCEPTED", "TERMINAL"):
            return
        snapshot = self.authority["records"][event["input_digest"]]
        op = snapshot["operation_id"]
        request = self.requests[op]
        require(sem.before_checkpoint(request) == self.authority_checkpoint, "Authority original predecessor mismatch")
        require(self.pending is None or self.pending == op, "overlapping unresolved mutation")
        if kind == "PREPARE":
            require(self.pending is None, "duplicate chain PREPARE")
            self.pending = op
        elif kind == "FIX_ACCEPTED":
            require(self.pending == op, "FIX without original chain PREPARE")
        else:
            require(self.pending == op, "terminal without original chain PREPARE")
            receipt = self.authority["records"][event["output_digest"]]
            previous = self.authority_checkpoint["authority_ref"]
            require(previous["wire_version"] == 2 and previous["authority_generation"] == receipt["authority_generation"],
                    "mutation cannot open a version/generation")
            require(receipt["previous_authority_ref"] == previous
                    and receipt["authority_sequence"] == previous["authority_sequence"] + 1,
                    "Authority receipt predecessor/sequence mismatch")
            candidate = request[receipt["decision"].lower()]["audit_candidate"]
            require(candidate["previous_audit_ref"] == self.authority_checkpoint["audit_ref"]
                    and candidate["audit_sequence"] == self.authority_checkpoint["audit_ref"]["audit_sequence"] + 1,
                    "Audit predecessor/sequence mismatch")
            require(receipt["state_before"] == self.authority_checkpoint["state_version"]
                    and receipt["state_after"] == receipt["state_before"] + (receipt["decision"] == "COMMIT"),
                    "COMMIT/ABORT state progression mismatch")
            audit = obj("audit_record", candidate=candidate, receipt_digest=h2(receipt))
            self.authority_checkpoint = sem.after_checkpoint(receipt, audit)
            self.chain_checkpoints.add(c2(self.authority_checkpoint))
            self.pending = None

    def _facts(self, event):
        kind = event["event_kind"]
        value = self.authority["records"][event["input_digest"]]
        state, facts = self.authority_state, {}
        if kind == "POLICY_REGISTER":
            digest = h2(value)
            facts = {"policies": {digest: value}, "policy_active": {digest: state["policy_active"][digest]}}
        elif kind == "INVENTORY_ACCEPT":
            facts = {"inventories": {h2(value): value}}
        elif kind == "PREPARE":
            op = value["operation_id"]
            facts = {"acks": {op: state["acks"][op]}}
        elif kind == "FIX_ACCEPTED":
            output = self.authority["records"][event["output_digest"]]
            key = (value["operation_id"], output["kind"])
            facts = {"fixes": {key: state["fixes"][key]}}
        self.authority_facts[event["position"]["event_sequence"]] = facts

    def _chain_core(self, principal, event):
        if event["event_kind"] not in ("PROPOSAL", "PUBLICATION", "APPLY"):
            return
        core = self.cores[principal]
        snap = core["records"][event["input_digest"]]
        policy = sem.record_by(self.authority, snap["policy_digest"])
        context = self.contexts.get(policy["restoration_context_digest"])
        if principal not in self.core_started:
            if context is not None:
                start = context["restore_start_checkpoint"]
                require(c2(start) in self.chain_checkpoints, "restore start is not an original chain checkpoint")
                self.core_checkpoints[principal] = start
            self.core_started.add(principal)
        before = self.core_checkpoints[principal]
        request = self.requests[snap["operation_id"]]
        require(sem.before_checkpoint(request) == before, "Core missing APPLY or predecessor mismatch")
        if event["event_kind"] == "APPLY":
            receipt = self.authority_state["terminals"][snap["operation_id"]]
            completion = core["records"][event["output_digest"]]
            audit = obj("audit_record", candidate=request[receipt["decision"].lower()]["audit_candidate"],
                        receipt_digest=h2(receipt))
            after = sem.after_checkpoint(receipt, audit)
            require(completion["before_checkpoint"] == before and completion["after_checkpoint"] == after,
                    "Core original completion checkpoint mismatch")
            self.core_checkpoints[principal] = after

    def append(self, window: WindowEvidence, *, operation="TERMINAL_HISTORY"):
        require(not self._failed, "failed verification state must be discarded")
        try:
            return self._append(window, operation)
        except ContractError:
            self._failed = True
            raise
        except (ValueError, TypeError, KeyError, IndexError, RecursionError) as exc:
            self._failed = True
            raise ContractError("malformed or incomplete bounded original evidence") from exc
        except BaseException:
            self._failed = True
            raise

    def _append(self, window, operation):
        old_footprint = self._footprint()
        require(type(window) is WindowEvidence, "WindowEvidence required")
        require(operation in ("REGISTRY_RELATIONS", "TERMINAL_HISTORY", "COMPLETION_HISTORY"), "validation operation")
        require(type(window.request_wires) is tuple and len(window.request_wires) <= 128, "request wire resource limit")
        requested = {self._request(raw) for raw in window.request_wires}
        require(len(requested) <= MAX_OPERATIONS, "operation chain resource limit")
        require(requested or operation == "REGISTRY_RELATIONS", "request wires required")
        require(type(window.cores) is tuple and len(window.cores) <= 16, "Core history resource limit")
        require(type(window.context_wires) is tuple and len(window.context_wires) <= 16, "context bounds")
        for raw in window.context_wires:
            context = decode(raw)
            self._object(context)
            require(context.get("type") == "restoration_context" and self.contexts.get(h2(context)) == context,
                    "restore context lacks complete original proof")
        start_a, values = self._merge(window.authority, self.authority)
        starts = {}
        for principal, part in window.cores:
            require(principal in self.materials and principal not in starts, "unknown/duplicate Core deployment")
            if principal not in self.cores:
                self.cores[principal] = {"header": sem.header(self.pin, self.materials[principal]), "events": [], "records": {}}
                state = sem.empty_state()
                state.update(protection={}, proposals={}, publications={}, completions={}, observed={})
                self.core_states[principal] = state
                self.core_checkpoints[principal] = deepcopy(self.initial_checkpoint)
            start, found = self._merge(part, self.cores[principal], self.materials[principal])
            starts[principal] = start
            values.extend(found)
        for value in values:
            self._restore_declared(value)
        touched = set(requested)
        for registry, start in [(self.authority, start_a)] + [(self.cores[p], n) for p, n in starts.items()]:
            for event in registry["events"][start:]:
                for digest in (event["input_digest"], event["output_digest"]):
                    if digest is not None:
                        value = registry["records"][digest]
                        if "operation_id" in value:
                            touched.add(value["operation_id"])
                        observed = value.get("object_digest")
                        if observed is not None and observed in self.authority["records"]:
                            related = self.authority["records"][observed]
                            if "operation_id" in related:
                                touched.add(related["operation_id"])
        require(len(touched) <= MAX_OPERATIONS, "operation chain resource limit for actual window events")
        require(touched <= self.requests.keys(), "window event lacks original request")
        for event in self.authority["events"][start_a:]:
            sem._authority_event(self.authority, event, self.authority_state, self.pin,
                                 self.materials, self.requests, self.contexts)
            self._chain_authority(event)
            self._facts(event)
        require(type(window.source_admission_wires) is tuple and len(window.source_admission_wires) <= 128,
                "original source admission bounds")
        for raw in window.source_admission_wires:
            admission = decode(raw)
            validate_fields(admission, RECORD["source_admission"])
            op = admission["operation_id"]
            require(op in self.requests and (op not in self.admissions or c2(self.admissions[op]) == raw),
                    "original source admission missing/conflicting request")
            self.admissions[op] = admission
        for op in touched:
            require(op in self.admissions, "original source admission required")
            admission, request = self.admissions[op], self.requests[op]
            ack = self.authority_state["acks"].get(op)
            if ack is not None:
                snap = sem.record_by(self.authority, ack["prepare_execution_digest"], "execution_snapshot")
                policy = self.authority_state["policies"][snap["policy_digest"]]
                material = self.materials[policy["runtime_principal"]]
            else:
                scope = request["intent"]["scope"]
                matches = [m for m in self.deployments if m.core_installation_id == admission["core_installation_id"]
                    and m.storage_generation_id == scope["storage_generation_id"]
                    and m.control_plane_generation_id == scope["control_plane_generation_id"]
                    and sem.sha(m.component_bytes) == admission["component_artifact_digest"]
                    and sem.sha(m.deployment_bytes) == admission["deployment_admission_digest"]]
                require(len(matches) == 1, "source deployment missing or ambiguous")
                material = matches[0]
            sem.verify_source_admission(admission, request, self.pin, material)
        for principal, start in starts.items():
            for event in self.cores[principal]["events"][start:]:
                sem._core_event(self.cores[principal], self.authority, event, self.core_states[principal],
                    self.pin, self.materials[principal], self.materials, self.requests, self.contexts,
                    lambda n: self.authority_facts[n], self.authority_state)
                self._chain_core(principal, event)
        # The graph covers all accepted original positions, not only this window.
        # No serialization of the accumulated graph/history enters the old wire API.
        if self._footprint()[2:] != old_footprint[2:]:
            sem.verify_causality(self.authority, self.cores.values())
        for result in self.restore_results:
            original = result.source_authority
            require(self.authority["header"] == original["header"]
                    and self.authority["events"][:len(original["events"])] == original["events"],
                    "restore source is not the original Authority prefix")
            for op in result.allowed_operations:
                require(op in self.requests, "restore approved operation missing")
                receipts = [original["records"][event["output_digest"]] for event in original["events"]
                    if event["event_kind"] == "TERMINAL"
                    and original["records"][event["output_digest"]]["operation_id"] == op]
                require(len(receipts) == 1 and self.authority_state["terminals"].get(op) == receipts[0],
                        "restore original terminal differs")
            for permit in self.authority_state["permits"].values():
                if permit["restoration_context_digest"] == h2(result.context):
                    require(permit["operation_id"] in result.allowed_operations, "restore permit outside approved tail")
        for op in requested:
            terminal = self.authority_state["terminals"].get(op)
            if operation != "REGISTRY_RELATIONS":
                require(terminal is not None, "complete terminal history required")
                key = (op, terminal["authorization_kind"])
                require(sum(key in state["publications"] for state in self.core_states.values()) == 1,
                        "terminal requires one original Core publication")
            if operation == "COMPLETION_HISTORY":
                require(any(op in state["completions"] for state in self.core_states.values()),
                        "original completed use required")
        if operation == "COMPLETION_HISTORY":
            for result in self.restore_results:
                context = result.context
                relevant = requested.intersection(result.allowed_operations)
                if not relevant:
                    continue
                targets = [self.core_states[principal] for principal, material in self.materials.items()
                    if principal in self.core_states
                    and material.core_installation_id == context["target_core_installation_id"]
                    and material.storage_generation_id == context["target_storage_generation_id"]
                    and material.control_plane_generation_id == context["target_control_plane_generation_id"]]
                require(len(targets) == 1, "one actual restoration target Core history required")
                for op in relevant:
                    completion = targets[0]["completions"].get(op)
                    require(completion is not None, "restoration target has not completed the requested tail")
                    permit = self.authority_state["permits"][completion["permit_digest"]]
                    require(permit["restoration_context_digest"] == h2(context),
                            "restoration completion used a different context")
        self._windows += 1
        footprint = self._footprint()
        if footprint != old_footprint:
            self.revision += 1
        return {"window": self._windows, "distinct_operation_count": len(touched),
                "revision": self.revision,
                "operation_ids": tuple(sorted(touched)), "request_operation_ids": tuple(sorted(requested)),
                "authority_positions": (start_a + 1, len(self.authority["events"])),
                "core_positions": {p: (start + 1, len(self.cores[p]["events"])) for p, start in starts.items()},
                "cumulative_requests": len(self.requests),
                "authority_checkpoint_wire": c2(self.authority_checkpoint),
                "core_checkpoint_wires": {p: c2(value) for p, value in self.core_checkpoints.items()},
                "continuation_source": "EXPLICIT_INITIAL_BOUNDARY" if self._windows == 1 else "REPLAYED_ORIGINAL_FACTS"}

    def _footprint(self):
        return (len(self.requests), len(self.admissions), len(self.cores),
                len(self.authority["records"]), len(self.authority["events"]),
                sum(len(reg["records"]) for reg in self.cores.values()),
                sum(len(reg["events"]) for reg in self.cores.values()))
