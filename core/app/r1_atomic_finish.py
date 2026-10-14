"""Explicit Scoped V2 local finish, backed by new file-only SQLite stores.

The injected source is an authenticated, protected registry/time adapter, not
request data. No production source is installed here. Original evidence remains
conditional until this boundary supplies it. The V1 consumer is unchanged.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, fields, is_dataclass, replace
import json

from ._r1_scoped_sqlite import ScopedSQLiteStore
from .control_plane import r1_validation as kernel
from .control_plane import _r1_validation_semantics as sem
from .control_plane.r1_validation_codec import ContractError, c2, decode, h2, require, obj, record, match


@dataclass(frozen=True)
class FinishInput:
    operation_id: str
    evidence: kernel.HistoryEvidence
    permit_digest: str
    chain_boundary: kernel.ChainBoundary | None = None
    restore_evidence: tuple = ()


@dataclass(frozen=True)
class TrustedLocalContext:
    authority_history: bytes
    core_history: bytes
    runtime_principal: str
    session_id: str
    policy_digest: str
    inventory_digest: str
    checked_at: int


@dataclass(frozen=True)
class LocalFinishResult:
    applied: bool
    operation_id: str
    result_wire: bytes
    audit_wire: bytes
    terminal_wire: bytes
    completion_wire: bytes
    checkpoint_wire: bytes


# This is an internal storage envelope, NOT a protocol canonicalization. Every
# protocol byte string is stored unchanged. Only explicit public proof types
# may be reconstructed; no pickle, import-by-name, or executable objects.
def _proof_types():
    from .control_plane import _r1_validation_restore as restoration
    from .control_plane import _r1_validation_legacy as legacy
    from .control_plane import r1_validation_crypto as crypto
    from .control_plane.r1_protocol import ExpectedIntent
    from .control_plane.r1_provisioning import ObservedProvisionedTarget
    from .control_plane._r1_validation_stream import RegistrySlice, WindowEvidence
    names = (FinishInput, kernel.HistoryEvidence, kernel.CoreHistory,
             kernel.ChainBoundary, sem.DeploymentEvidence, crypto.FixedTrust,
             restoration.ArchiveMember, restoration.SourceDeploymentObservation,
             restoration.SourceFencingObservation, restoration.OpeningEvidence,
             restoration.SourceEvidence, restoration.RestoreEvidence,
             legacy.LegacyGenesisEvidence, ExpectedIntent, ObservedProvisionedTarget, RegistrySlice, WindowEvidence)
    return {t.__name__: t for t in names}


def _pack(value):
    types = _proof_types()
    def encode(v, depth=0):
        require(depth < 96, "stored proof nesting limit")
        if type(v) is bytes:
            return {"bytes": v.hex()}
        if type(v) is tuple:
            return {"tuple": [encode(x, depth + 1) for x in v]}
        if type(v) is dict:
            require(all(type(k) is str for k in v), "stored proof mapping key")
            return {"mapping": {k: encode(x, depth + 1) for k, x in v.items()}}
        if is_dataclass(v) and types.get(type(v).__name__) is type(v):
            return {"class": type(v).__name__, "fields": {
                f.name: encode(getattr(v, f.name), depth + 1) for f in fields(v) if f.init}}
        require(v is None or type(v) in (str, int, bool), "unsupported stored proof value")
        return v
    raw = json.dumps(encode(value), sort_keys=True, separators=(",", ":")).encode("utf-8")
    require(len(raw) <= 128 * 1024 * 1024, "stored proof resource limit")
    return raw


def _unpack(raw):
    require(type(raw) is bytes and len(raw) <= 128 * 1024 * 1024, "stored proof resource limit")
    types = _proof_types()
    def decode_value(v, depth=0):
        require(depth < 96, "stored proof nesting limit")
        if type(v) is dict:
            if set(v) == {"bytes"}:
                return bytes.fromhex(v["bytes"])
            if set(v) == {"tuple"}:
                return tuple(decode_value(x, depth + 1) for x in v["tuple"])
            if set(v) == {"mapping"}:
                require(type(v["mapping"]) is dict, "stored proof mapping")
                return {k: decode_value(x, depth + 1) for k, x in v["mapping"].items()}
            require(set(v) == {"class", "fields"} and v["class"] in types, "stored proof type")
            cls = types[v["class"]]
            require(set(v["fields"]) == {f.name for f in fields(cls) if f.init}, "stored proof fields")
            return cls(**{k: decode_value(x, depth + 1) for k, x in v["fields"].items()})
        require(v is None or type(v) in (str, int, bool), "stored proof scalar")
        return v
    try:
        result = decode_value(json.loads(raw))
        require(type(result) is FinishInput and _pack(result) == raw, "stored proof exact encoding")
        return result
    except (ValueError, KeyError, TypeError, RecursionError) as exc:
        raise ContractError("invalid stored original evidence") from exc


class _Advanced(Exception):
    def __init__(self, context):
        self.context = context


class ScopedCoreFinisher:
    """Explicitly configured write entry; absent authenticated source denies.

    SQLite serializes the actual local predecessor and all effect/proof writes.
    It does not freeze the remote Authority. Permission is evaluated at the
    observed local execution position under the conservative permit deadline.
    """
    def __init__(self, store, *, trust, deployments, runtime_principal,
                 source=None, checkpoint_hook=None):
        require(type(store) is ScopedSQLiteStore, "explicit scoped SQLite store required")
        require(type(trust) is kernel.FixedTrust, "independently configured fixed trust required")
        require(type(deployments) is tuple, "explicit deployments required")
        self.store, self.trust, self.deployments = store, trust, deployments
        self.runtime_principal, self.source = runtime_principal, source
        self.checkpoint_hook = checkpoint_hook
        self.materials = {d.runtime_principal: d for d in deployments}
        require(runtime_principal in self.materials, "missing local deployment")
        self.material, self.pin = self.materials[runtime_principal], decode(trust.pin_wire)
        self._verified_cache = None

    def _hook(self, stage):
        if self.checkpoint_hook is not None:
            self.checkpoint_hook(stage)

    @staticmethod
    def _window(evidence):
        from .control_plane._r1_validation_stream import WindowEvidence, from_history
        if type(evidence) is WindowEvidence:
            return evidence
        require(type(evidence) is kernel.HistoryEvidence, "explicit original history/window required")
        return from_history(evidence)

    @staticmethod
    def _slice(value):
        from .control_plane._r1_validation_stream import RegistrySlice
        if type(value) is RegistrySlice:
            return value
        require(type(value) is bytes, "registry source must supply original wires")
        reg = decode(value)
        return RegistrySlice(c2(reg["header"]), tuple(c2(e) for e in reg["events"]),
                             tuple((k, c2(v)) for k, v in reg["records"].items()))

    @staticmethod
    def _export(reg):
        from .control_plane._r1_validation_stream import RegistrySlice
        return RegistrySlice(c2(reg["header"]), tuple(c2(e) for e in reg["events"]),
                             tuple((k, c2(v)) for k, v in reg["records"].items()))

    def _boundary(self, metadata, first):
        scope = decode(metadata["scope_wire"])
        if first.restore_evidence:
            # The source boundary is independently verified by the original
            # source/backup verifier. The actual target seed must be the backup.
            matching = [p for p in first.restore_evidence
                        if decode(p.context_wire)["target_core_installation_id"] == self.material.core_installation_id]
            require(len(matching) == 1 and matching[0].expected_backup_checkpoint_wire ==
                    metadata["initial_checkpoint_wire"], "restore backup differs from independently initialized local target")
            return matching[0].source.chain_boundary
        boundary = first.chain_boundary
        expected_end = metadata["initial_checkpoint_wire"] if boundary is None else boundary.expected_end_checkpoint_wire
        result = kernel.ChainBoundary(c2(scope["identity"]), metadata["initial_checkpoint_wire"], expected_end,
            scope["owner_identity"], scope["owner_version"], scope["continuity_epoch"],
            scope["storage_generation_id"], scope["control_plane_generation_id"], scope["trust_domain_id"])
        if boundary is not None:
            require(boundary == result, "initial validation boundary differs from independently initialized store")
        return result

    @staticmethod
    def _mark(engine):
        registries = [engine.registry()] + [engine.registry(p) for p in sorted(engine.core_states)]
        return (len(engine.requests), len(engine.contexts),
                tuple((sem.rawhash(r["header"]), len(r["events"]), len(r["records"])) for r in registries))

    def _engine(self, db, item):
        from .control_plane._r1_validation_stream import BoundedHistory
        metadata = db.execute("SELECT * FROM metadata WHERE id=1").fetchone()
        rows = db.execute("SELECT sequence,evidence_wire FROM history_windows ORDER BY sequence").fetchall()
        require([r[0] for r in rows] == list(range(1, len(rows) + 1)), "missing original history window")
        wires = tuple(r[1] for r in rows)
        seed = (metadata["scope_wire"], metadata["initial_checkpoint_wire"], metadata["initial_business_state_wire"])
        cache = self._verified_cache
        if cache is not None and cache[0] == seed and wires[:len(cache[1])] == cache[1]:
            engine = cache[2].fork()
            start = len(cache[1])
        else:
            first = _unpack(wires[0]) if wires else item
            engine = BoundedHistory(self.trust, self.deployments, self._boundary(metadata, first),
                                    restore_evidence=first.restore_evidence)
            start = 0
        for wire in wires[start:]:
            original = _unpack(wire)
            self._append_terminal(engine, original)
        # Cache is strictly process-local, built only by verifying original
        # journal bytes, and matched against ALL of those bytes on every use.
        self._verified_cache = (seed, wires, engine.fork())
        if start == 0 and wires:
            self._hook("history_rebuilt")
        return engine

    def _append_terminal(self, engine, item):
        """Verify the full causal prefix, then the named operation's terminal.

        A normal concurrent request may have legitimate qualification records
        in this same Authority prefix while still unresolved. Those records
        must be checked and retained, but are not an assertion that the other
        request has terminated. The public whole-history verifier is unchanged.
        """
        from .control_plane._r1_validation_stream import RegistrySlice, WindowEvidence
        window = self._window(item.evidence)
        stats = engine.append(window, operation="REGISTRY_RELATIONS")
        selected = tuple(w for w in window.request_wires
                         if decode(w)["intent"]["operation_id"] == item.operation_id)
        require(len(selected) == 1, "named original operation must occur exactly once")
        proof = WindowEvidence(selected, RegistrySlice(window.authority.header_wire, (), ()), (),
            source_admission_wires=tuple(w for w in window.source_admission_wires
                                        if decode(w)["operation_id"] == item.operation_id))
        engine.append(proof, operation="TERMINAL_HISTORY")
        return stats

    def _validate(self, item):
        require(type(item) is FinishInput, "explicit finish input required")
        match(item.operation_id, "uuid")
        match(item.permit_digest, "hash")
        if type(item.evidence) is kernel.HistoryEvidence:
            # Preserve the existing public whole-history contract, including
            # its explicit expected tail and original per-call resource bound.
            kernel.validate_evidence("TERMINAL_HISTORY", item.evidence, self.trust,
                self.deployments, chain_boundary=item.chain_boundary, restore_evidence=item.restore_evidence)
        with self.store.transaction(write=False) as db:
            engine = self._engine(db, item)
            self._append_terminal(engine, item)
            if type(item.evidence) is not kernel.HistoryEvidence and item.chain_boundary is not None:
                self._window_boundary(item, engine)
            return self._parts(item, engine)

    def _window_boundary(self, item, engine):
        """Keep an explicit window's boundary assertion, including on old replay.

        This checks the selected original segment, not the current global head.
        Its facts have already been replayed from the independent local seed.
        The boundary never supplies missing historical evidence or permissions.
        """
        from .control_plane._r1_validation_chain import decode_boundary
        boundary = item.chain_boundary
        identity, cursor, expected_end = decode_boundary(boundary)
        selected = {decode(raw)["intent"]["operation_id"] for raw in item.evidence.request_wires}
        for op in selected:
            request = engine.requests[op]
            require(request["intent"]["identity"] == identity, "window boundary identity differs")
            sem.eq_fields(request["intent"]["scope"], {"actor_identity": boundary.owner_identity,
                **{k: getattr(boundary, k) for k in ("owner_version", "continuity_epoch",
                    "storage_generation_id", "control_plane_generation_id", "trust_domain_id")}},
                "window boundary governance scope differs")
        ordered = []
        for event in engine.authority["events"]:
            if event["event_kind"] != "TERMINAL":
                continue
            receipt = engine.authority["records"][event["output_digest"]]
            op = receipt["operation_id"]
            if op not in selected:
                continue
            request = engine.requests[op]
            require(sem.before_checkpoint(request) == cursor, "window boundary start or segment differs")
            audit = obj("audit_record", candidate=request[receipt["decision"].lower()]["audit_candidate"],
                        receipt_digest=h2(receipt))
            cursor = sem.after_checkpoint(receipt, audit)
            ordered.append(op)
        require(set(ordered) == selected and cursor == expected_end,
                "window does not reach explicit expected tail")

    def _parts(self, item, engine):
        requests, authority, contexts, state = (engine.requests, engine.registry(), engine.contexts, engine.authority_state)
        require(any(decode(w)["intent"]["operation_id"] == item.operation_id
                    for w in self._window(item.evidence).request_wires), "current input omits its named original operation")
        require(item.operation_id in requests, "operation missing from original evidence")
        request = requests[item.operation_id]
        require(item.permit_digest in state["permits"], "original issued finish permit missing")
        permit = state["permits"][item.permit_digest]
        target = sem._verified_permit_target(authority, state, permit, request, self.pin)
        receipt = state["terminals"][item.operation_id]
        selected = request[receipt["decision"].lower()]
        audit = obj("audit_record", candidate=selected["audit_candidate"], receipt_digest=h2(receipt))
        expected_scope = c2({"identity": request["intent"]["identity"],
            **{k: getattr(self.material, k) for k in ("core_installation_id", "storage_generation_id", "control_plane_generation_id")},
            "owner_identity": request["intent"]["scope"]["actor_identity"],
            "owner_version": request["intent"]["scope"]["owner_version"],
            "continuity_epoch": request["intent"]["scope"]["continuity_epoch"],
            "trust_domain_id": request["intent"]["scope"]["trust_domain_id"]})
        require(expected_scope == self.store.scope_wire, "actual local store scope differs")
        require(all(target[k] == getattr(self.material, k) for k in (
            "core_installation_id", "storage_generation_id", "control_plane_generation_id")), "permit target differs from local store")
        return {"requests": requests, "request": request, "authority": authority,
                "contexts": contexts, "authority_state": state, "permit": permit,
                "target": target, "receipt": receipt, "selected": selected,
                "audit": audit, "original": c2({"request": request, "terminal": receipt}), "engine": engine}

    def _capture(self, item, action, engine):
        require(self.source is not None and callable(getattr(self.source, "capture", None))
                and callable(getattr(self.source, "now_ms", None)), "authenticated registry/time source unavailable")
        # Contract: capture reads an already authenticated LOCAL snapshot; it
        # must not perform network I/O while the local transaction is held.
        context = self.source.capture(item.operation_id, action,
            local_history=self._export(engine.registry(self.runtime_principal)) if self.runtime_principal in engine.core_states else None,
            authority_history=self._export(engine.registry()) if engine.registry()["events"] else None)
        require(type(context) is TrustedLocalContext, "controlled source context required")
        require(type(context.checked_at) is int and context.checked_at >= 0, "trusted capture time invalid")
        return context

    def _context_input(self, item, context):
        from .control_plane._r1_validation_stream import WindowEvidence
        original = self._window(item.evidence)
        window = WindowEvidence(original.request_wires, self._slice(context.authority_history),
            ((self.runtime_principal, self._slice(context.core_history)),),
            source_admission_wires=original.source_admission_wires, context_wires=original.context_wires)
        return replace(item, evidence=window)

    def _verify_context(self, db, item, context, metadata, engine):
        observed = self._context_input(item, context)
        verification = self._append_terminal(engine, observed)
        parts = self._parts(item, engine)
        parts["verification"] = verification
        require(self.runtime_principal in engine.core_states, "target Core history missing")
        core, local = engine.registry(self.runtime_principal), engine.core_states[self.runtime_principal]
        saved = {r["operation_id"]: r["completion_wire"] for r in db.execute("SELECT operation_id,completion_wire FROM completions")}
        require(set(local["completions"]) == set(saved), "registry/local completion set differs")
        require(all(c2(value) == saved[op] for op, value in local["completions"].items()), "registry/local completion bytes differ")
        self._integrity(db, metadata, parts, local)
        return observed, parts, core, local

    def _journal(self, db, item, before, engine, kind, verification=None):
        if before == self._mark(engine):
            return
        sequence = db.execute("SELECT count(*) FROM history_windows").fetchone()[0] + 1
        window = self._window(item.evidence)
        operations = sorted({decode(raw)["intent"]["operation_id"] for raw in window.request_wires})
        # The engine independently enforces/counts new event operation IDs too.
        stats = {"kind": kind, "explicit_operation_ids": operations,
                 "explicit_operation_count": len(operations), "before": before, "after": self._mark(engine),
                 "journal_sequence": sequence}
        def public_stat(value):
            if type(value) is bytes:
                return {"original_wire_hex": value.hex()}
            if type(value) is dict:
                return {k: public_stat(v) for k, v in value.items()}
            if type(value) in (tuple, list):
                return [public_stat(v) for v in value]
            return value
        stats["actual_verification"] = public_stat(verification)
        db.execute("INSERT INTO history_windows VALUES(?,?,?)", (sequence, _pack(replace(item, evidence=window)),
            json.dumps(stats, sort_keys=True, separators=(",", ":")).encode("utf-8")))

    def _integrity(self, db, metadata, parts, local):
        """Recheck real local state under the same SQLite writer lock.

        The initial state is supplied at explicit creation. After APPLY, the
        validated original request and completion define the expected rows and
        current projection; a matching head alone cannot hide a changed value.
        """
        expected_rows = {}
        checkpoint = metadata["initial_checkpoint_wire"]
        business = metadata["initial_business_state_wire"]
        for op, completion in sorted(local["completions"].items(), key=lambda p: p[1]["position"]["event_sequence"]):
            request = parts["requests"][op]
            receipt = parts["authority_state"]["terminals"][op]
            selected = request[receipt["decision"].lower()]
            stored = db.execute("SELECT * FROM completions WHERE operation_id=?", (op,)).fetchone()
            operation = db.execute("SELECT * FROM operations WHERE operation_id=?", (op,)).fetchone()
            require(operation is not None and operation["status"] == "FINALIZED" and
                    operation["request_wire"] == c2(request) and
                    operation["original_wire"] == c2({"request": request, "terminal": receipt}), "durable completed original differs")
            audit = obj("audit_record", candidate=selected["audit_candidate"], receipt_digest=h2(receipt))
            expected = {"terminal_wire": c2(receipt), "audit_wire": c2(audit),
                "result_wire": c2(selected["result"]), "effect_wire": c2(selected["effect"]),
                "checkpoint_wire": c2(completion["after_checkpoint"]),
                "permit_wire": c2(parts["authority_state"]["permits"][completion["permit_digest"]])}
            require(stored is not None and all(stored[k] == v for k, v in expected.items()) and
                    sem.sha(stored["local_use_wire"]) == completion["local_use_digest"], "durable completion content differs")
            consumed = db.execute("SELECT * FROM permit_consumptions WHERE operation_id=?", (op,)).fetchone()
            require(consumed is not None and consumed["permit_digest"] == completion["permit_digest"] and
                    consumed["local_event_position"] == c2(completion["position"]), "durable completion consumption differs")
            require(c2(completion["before_checkpoint"]) == checkpoint, "durable completion predecessor differs")
            checkpoint = c2(completion["after_checkpoint"])
            if receipt["decision"] == "COMMIT":
                require(len(selected["effect"]["entries"]) == 1, "local effect entry count")
                entry = selected["effect"]["entries"][0]
                expected_rows[op] = (entry["mutation_id"], c2(entry["value"]))
                business = c2(entry["value"])
        actual_rows = {r["operation_id"]: (r["mutation_id"], r["value_wire"])
                       for r in db.execute("SELECT * FROM business_records")}
        require(actual_rows == expected_rows, "actual business rows differ from durable original effects")
        require(db.execute("SELECT count(*) FROM permit_consumptions").fetchone()[0] == len(local["completions"]), "unexpected permit consumption")
        require(metadata["checkpoint_wire"] == checkpoint, "actual local dual head differs from durable completion")
        require(metadata["business_state_wire"] == business, "actual local business projection differs from original effects")

    def _observe(self, item, action, supplied=None):
        # Save raw verified observations independently of APPLY permission.
        with self.store.transaction() as db:
            metadata = db.execute("SELECT * FROM metadata WHERE id=1").fetchone()
            engine = self._engine(db, item)
            before = self._mark(engine)
            self._append_terminal(engine, item)
            context = supplied or self._capture(item, action, engine)
            observed, parts, core, local = self._verify_context(db, item, context, metadata, engine)
            # Save the supplied original window before any source-only extension.
            original_engine = self._engine(db, item)
            original_before = self._mark(original_engine)
            original_stats = self._append_terminal(original_engine, item)
            self._journal(db, item, original_before, original_engine, "ORIGINAL_EVIDENCE", original_stats)
            self._journal(db, observed, self._mark(original_engine), engine, "OBSERVATION", parts["verification"])
        return context

    def _qualify(self, item, parts, core, local, context, actions):
        require(context.runtime_principal == self.runtime_principal, "authenticated caller differs from configured runtime")
        now = self.source.now_ms()
        require(type(now) is int and now >= context.checked_at and
                (not core["events"] or now >= core["events"][-1]["recorded_at"]), "trusted clock regressed")
        subject = sem.subject_from(local, context.policy_digest, context.inventory_digest, context.session_id)
        policy = subject["policy"]
        require(policy["runtime_principal"] == context.runtime_principal, "authenticated caller policy differs")
        sem.local_subject(local, subject, self.pin, self.material, now, actions,
                          parts["contexts"].get(policy["restoration_context_digest"]))
        sem.verify_finish_inventory(policy, subject["inventory"], {"request": parts["request"]})
        if "APPLY_VERIFIED_TERMINAL" in actions:
            permit = parts["permit"]
            require(local["permit_active"].get(item.permit_digest) is True and
                    local["permit_pointer"].get(item.operation_id) == item.permit_digest, "current observed permit missing/revoked/replaced")
            require(all(permit[k] == getattr(context, k) for k in
                ("runtime_principal", "session_id", "policy_digest", "inventory_digest")), "current permit subject differs")
            require(permit["issued_at"] <= now and now + 1000 < permit["expires_at"], "current conservative permit deadline")
        return now

    def _work(self, item, action, callback):
        self._observe(item, action)
        try:
            with self.store.transaction() as db:
                metadata = db.execute("SELECT * FROM metadata WHERE id=1").fetchone()
                engine = self._engine(db, item)
                before = self._mark(engine)
                context = self._capture(item, action, engine)
                observed, parts, core, local = self._verify_context(db, item, context, metadata, engine)
                if before != self._mark(engine):
                    raise _Advanced(context)
                return callback(db, metadata, context, item, parts, core, local)
        except _Advanced as exc:
            self._observe(item, action, exc.context)
            raise ContractError("observed source changed during local transaction; durable observation retained, retry required") from exc

    def _same(self, row, parts):
        require(row["request_wire"] == c2(parts["request"]) and row["original_wire"] == parts["original"],
                "same operation identity has different original content")

    def persist(self, item):
        self._validate(item)
        self._hook("validated")
        def save(db, metadata, context, merged, parts, core, local):
            row = db.execute("SELECT * FROM operations WHERE operation_id=?", (item.operation_id,)).fetchone()
            if row is not None:
                self._same(row, parts)
                if row["status"] == "FINALIZED":
                    return self._query_row(db, item, context, parts, core, local)
            self._qualify(item, parts, core, local, context, {"PERSIST_COORDINATION"})
            if row is None:
                intent = parts["request"]["intent"]
                conflict = db.execute("SELECT operation_id FROM operations WHERE mutation_id=? OR local_commit_id=?",
                    (intent["mutation_id"], intent["local_commit_id"])).fetchone()
                require(conflict is None, "original mutation/local commit identity already belongs to another operation")
                db.execute("INSERT INTO operations VALUES(?,?,?,?,?,?,?)", (item.operation_id,
                    intent["mutation_id"], intent["local_commit_id"], c2(parts["request"]), parts["original"], _pack(merged), "PENDING"))
            else:
                db.execute("UPDATE operations SET evidence_wire=? WHERE operation_id=?", (_pack(merged), item.operation_id))
        result = self._work(item, "PERSIST_COORDINATION", save)
        self._hook("evidence_saved")
        return result

    def finish(self, item):
        existing = self.persist(item)
        if existing is not None:
            return existing
        def apply(db, metadata, context, merged, parts, core, local):
            row = db.execute("SELECT * FROM operations WHERE operation_id=?", (item.operation_id,)).fetchone()
            require(row is not None, "durable original operation missing")
            self._same(row, parts)
            if row["status"] == "FINALIZED":
                return self._query_row(db, item, context, parts, core, local)
            actions = {"APPLY_VERIFIED_TERMINAL", "PERSIST_COORDINATION"}
            now = self._qualify(item, parts, core, local, context, actions)
            permit, request, receipt, target = (parts[k] for k in ("permit", "request", "receipt", "target"))
            require(metadata["checkpoint_wire"] == c2(target["before_checkpoint"]), "actual local predecessor/state differs")
            content = sem.completion_content(request, receipt)
            use = record("use_input", history_version=2, permit_digest=item.permit_digest,
                issuance_digest=permit["issuance_digest"], target_digest=sem.rawhash(target), terminal_digest=h2(receipt), **content)
            snapshot = record("local_snapshot", history_version=2, position=sem.position(core), checked_at=now,
                action="APPLY_VERIFIED_TERMINAL", runtime_principal=context.runtime_principal, session_id=context.session_id,
                policy_digest=context.policy_digest, inventory_digest=context.inventory_digest, operation_id=item.operation_id,
                request_digest=h2(request), source_decision_digest=h2(request["source_decision"]),
                target_digest=sem.rawhash(target), action_input_digest=sem.rawhash(use))
            completion = record("completion_record", history_version=2, position=snapshot["position"], completed_at=now,
                permit_digest=item.permit_digest, issuance_digest=permit["issuance_digest"], local_use_digest=sem.rawhash(snapshot),
                operation_id=item.operation_id, request_digest=h2(request), source_decision_digest=h2(request["source_decision"]),
                terminal_digest=h2(receipt), target_digest=sem.rawhash(target), before_checkpoint=permit["before_checkpoint"],
                after_checkpoint=permit["after_checkpoint"], **content)
            from .control_plane._r1_validation_stream import RegistrySlice, WindowEvidence
            apply_event = record("registry_event", history_version=2, position=snapshot["position"],
                recorded_at=now, event_kind="APPLY", input_digest=sem.rawhash(snapshot), output_digest=sem.rawhash(completion))
            original_window = self._window(item.evidence)
            apply_window = WindowEvidence((c2(request),),
                RegistrySlice(c2(parts["authority"]["header"]), (), ()),
                ((self.runtime_principal, RegistrySlice(c2(core["header"]), (c2(apply_event),),
                    tuple((sem.rawhash(v), c2(v)) for v in (target, use, snapshot, completion)))),),
                source_admission_wires=tuple(w for w in original_window.source_admission_wires
                    if decode(w)["operation_id"] == item.operation_id), context_wires=original_window.context_wires)
            completed_input = replace(item, evidence=apply_window)
            updated_engine = parts["engine"].fork()
            apply_stats = updated_engine.append(apply_window, operation="COMPLETION_HISTORY")
            effect = parts["selected"]["effect"]
            if receipt["decision"] == "COMMIT":
                require(len(effect["entries"]) == 1 and effect["entries"][0]["mutation_id"] == request["intent"]["mutation_id"], "local business effect must be the exact single mutation")
                entry = effect["entries"][0]
                require(db.execute("SELECT 1 FROM business_records WHERE mutation_id=?", (entry["mutation_id"],)).fetchone() is None,
                        "business mutation already exists")
                db.execute("INSERT INTO business_records VALUES(?,?,?)", (entry["mutation_id"], item.operation_id, c2(entry["value"])))
                db.execute("UPDATE metadata SET business_state_wire=? WHERE id=1", (c2(entry["value"]),))
            self._hook("after_effect")
            db.execute("INSERT INTO completions VALUES(?,?,?,?,?,?,?,?,?,?)", (item.operation_id, c2(receipt), c2(parts["audit"]),
                c2(parts["selected"]["result"]), c2(effect), c2(completion), c2(snapshot), c2(permit), c2(target["after_checkpoint"]), _pack(completed_input)))
            self._hook("after_audit")
            db.execute("UPDATE metadata SET checkpoint_wire=? WHERE id=1", (c2(target["after_checkpoint"]),))
            self._hook("after_head")
            db.execute("INSERT INTO permit_consumptions VALUES(?,?,?)", (item.operation_id, item.permit_digest, c2(snapshot["position"])))
            db.execute("UPDATE operations SET status='FINALIZED' WHERE operation_id=?", (item.operation_id,))
            self._hook("after_completion")
            self._hook("before_history_commit")
            self._journal(db, completed_input, self._mark(parts["engine"]), updated_engine, "ATOMIC_APPLY", apply_stats)
            self._hook("after_history_commit")
            self._hook("before_commit")
            # Read a local authenticated source snapshot against the pre-APPLY
            # facts. The staged effect/journal must not authorize itself.
            late = self._capture(item, "APPLY_VERIFIED_TERMINAL", parts["engine"])
            late_engine = parts["engine"].fork()
            self._append_terminal(late_engine, self._context_input(item, late))
            if self._mark(late_engine) != self._mark(parts["engine"]):
                raise _Advanced(late)
            self._qualify(item, parts, core, local, late, actions)
            require(all(getattr(late, k) == getattr(context, k) for k in
                ("runtime_principal", "session_id", "policy_digest", "inventory_digest")), "current subject changed before commit")
            return LocalFinishResult(True, item.operation_id, c2(parts["selected"]["result"]), c2(parts["audit"]),
                c2(receipt), c2(completion), c2(target["after_checkpoint"]))
        result = self._work(item, "APPLY_VERIFIED_TERMINAL", apply)
        self._hook("after_commit")
        return result

    def _query_row(self, db, item, context, parts, core, local):
        self._qualify(item, parts, core, local, context, {"QUERY_EXISTING"})
        row = db.execute("SELECT * FROM operations WHERE operation_id=?", (item.operation_id,)).fetchone()
        require(row is not None and row["status"] == "FINALIZED", "operation has no completed local result")
        self._same(row, parts)
        saved = db.execute("SELECT * FROM completions WHERE operation_id=?", (item.operation_id,)).fetchone()
        require(saved is not None, "original completion missing")
        proof = _unpack(saved["evidence_wire"])
        historical_engine = parts["engine"].fork()
        historical_engine.append(self._window(proof.evidence), operation="COMPLETION_HISTORY")
        historical = self._parts(proof, historical_engine)
        historical_core = historical_engine.registry(self.runtime_principal)
        historical_state = historical_engine.core_states[self.runtime_principal]
        completion = historical_state["completions"].get(item.operation_id)
        require(completion is not None and c2(completion) == saved["completion_wire"], "original completion proof differs")
        require(historical["original"] == parts["original"], "historical original content differs")
        expected = {"terminal_wire": c2(historical["receipt"]), "audit_wire": c2(historical["audit"]),
            "result_wire": c2(historical["selected"]["result"]), "effect_wire": c2(historical["selected"]["effect"]),
            "permit_wire": c2(historical["permit"]), "checkpoint_wire": c2(historical["target"]["after_checkpoint"]),
            "local_use_wire": c2(sem.record_by(historical_core, completion["local_use_digest"], "local_snapshot"))}
        require(all(saved[k] == v for k, v in expected.items()), "persisted result/Audit/receipt/use differs from original proof")
        consumed = db.execute("SELECT * FROM permit_consumptions WHERE operation_id=?", (item.operation_id,)).fetchone()
        require(consumed is not None and consumed["permit_digest"] == completion["permit_digest"] and
                consumed["local_event_position"] == c2(completion["position"]), "atomic permit consumption missing or different")
        business = db.execute("SELECT * FROM business_records WHERE operation_id=?", (item.operation_id,)).fetchone()
        if historical["receipt"]["decision"] == "COMMIT":
            entry = historical["selected"]["effect"]["entries"][0]
            require(business is not None and business["mutation_id"] == entry["mutation_id"] and business["value_wire"] == c2(entry["value"]),
                    "actual original business result differs")
        else:
            require(business is None, "ABORT acquired a business effect")
        return LocalFinishResult(False, item.operation_id, saved["result_wire"], saved["audit_wire"], saved["terminal_wire"],
                                 saved["completion_wire"], saved["checkpoint_wire"])

    def _load(self, operation_id):
        with self.store.transaction(write=False) as db:
            row = db.execute("SELECT evidence_wire FROM operations WHERE operation_id=?", (operation_id,)).fetchone()
            require(row is not None, "unknown local operation")
            return _unpack(row[0])

    def recover(self, operation_id):
        return self.finish(self._load(operation_id))

    def query(self, operation_id, request_wire):
        item = self._load(operation_id)
        parts = self._validate(item)
        require(request_wire == c2(parts["request"]), "query original request differs")
        return self._work(item, "QUERY_EXISTING", lambda db, metadata, context, merged, parts, core, local:
                          self._query_row(db, item, context, parts, core, local))
