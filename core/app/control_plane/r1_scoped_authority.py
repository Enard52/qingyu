"""Ordinary Scoped V2 Authority producer on the real restricted PostgreSQL store.

This explicit composition reuses the accepted product codec, real Ed25519
verification and original bounded-history kernel. It does not implement GENESIS,
restore admission, key rotation, policy issuance or operator override execution.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import fields

from . import _r1_validation_semantics as sem
from ._r1_validation_stream import BoundedHistory, RegistrySlice, WindowEvidence
from .r1_validation_codec import SCHEMA, ContractError, c2, decode, h2, obj, record, require, s2, sha, validate, validate_fields, RECORD
from .r1_validation_crypto import FixedTrust, verify_signed
from .r1_scoped_messages import AuthorityCaller, AuthorityReply
from .r1_scoped_postgres import ScopedPostgresStore


def _configuration(value):
    return {f.name: (getattr(value, f.name).hex() if isinstance(getattr(value, f.name), bytes)
                     else getattr(value, f.name)) for f in fields(value)}


def configuration_digest(trust, deployments, boundary):
    return sha(c2({"pin": trust.pin_wire.hex(), "root": trust.root_public_key.hex(),
        "deployments": [_configuration(v) for v in deployments], "boundary": _configuration(boundary)}))


def _empty(engine):
    return RegistrySlice(c2(engine.authority["header"]), (), ())


def _put(records, value, *, input_record=False):
    digest = h2(value) if value.get("type") in SCHEMA else sem.rawhash(value)
    records[digest] = deepcopy(value)
    if input_record:
        records[sem.rawhash(value)] = deepcopy(value)
    return digest


class ScopedAuthority:
    """No default configuration; independently fixed public trust is mandatory.

    The same immutable configuration digest is installed by the owner in the new
    scope. All new actions and qualification ingestion serialize on that scope.
    Current query qualification is checked separately from original action facts.
    """
    configuration_digest = staticmethod(configuration_digest)

    def __init__(self, *, store: ScopedPostgresStore, trust: FixedTrust, deployments: tuple,
                 boundary, receipt_signer, fault=None):
        require(type(store) is ScopedPostgresStore and type(trust) is FixedTrust,
                "explicit scoped PostgreSQL store and fixed trust required")
        require(configuration_digest(trust, deployments, boundary) == store.configuration_digest,
                "scope immutable configuration mismatch")
        require(getattr(receipt_signer, "key_id", None) == trust.receipt_key_id,
                "preprovisioned receipt signer differs from fixed pin")
        self.store, self.trust, self.deployments, self.boundary = store, trust, deployments, boundary
        self.signer, self.fault = receipt_signer, fault
        self._cached_wires, self._cached_engine = (), None
        BoundedHistory(trust, deployments, boundary)

    def _hook(self, name):
        if self.fault is not None:
            self.fault(name)

    def _engine(self, tx):
        # Database scope lock is already held. Compare EVERY original journal
        # byte, including old evidence, before using disposable replay state.
        # Only rows read at transaction entry can enter this cache: never the
        # subsequently staged/signature-bearing output of the current action.
        wires = tx.raw_windows
        cached = self._cached_engine
        prefix = self._cached_wires
        if cached is not None and len(wires) >= len(prefix) and wires[:len(prefix)] == prefix:
            if wires == prefix:
                return cached.fork()
            engine, start = cached.fork(), len(prefix)
        else:
            self._cached_engine, self._cached_wires = None, ()
            engine, start = BoundedHistory(self.trust, self.deployments, self.boundary), 0
        for window in tx.windows[start:]:
            terminal = any(decode(w)["event_kind"] == "TERMINAL" for w in window.authority.event_wires)
            engine.append(window, operation="TERMINAL_HISTORY" if terminal else "REGISTRY_RELATIONS")
        self._cached_engine, self._cached_wires = engine, wires
        return engine.fork()

    def _request(self, engine, request_wire):
        request = decode(request_wire)
        validate(request)
        require(request["type"] == "mutation_request", "only ordinary mutation is implemented")
        sem.verify_request(request, engine.pin, request["intent"]["scope"]["actor_identity"])
        operation_id = request["intent"]["operation_id"]
        require(operation_id not in engine.request_wires or engine.request_wires[operation_id] == request_wire,
                "operation original content conflict")
        return request

    def _subject(self, engine, caller, request, now, actions):
        require(type(caller) is AuthorityCaller, "server authenticated subject required")
        require(caller.runtime_principal in engine.materials, "authenticated runtime outside fixed deployment")
        subject = sem.subject_from(engine.authority_state, caller.policy_digest, caller.inventory_digest, caller.session_id)
        sem.check_subject(engine.authority_state, subject, engine.pin, engine.materials[caller.runtime_principal], now, actions)
        require(subject["policy"]["runtime_principal"] == subject["enrollment"]["runtime_principal"] == caller.runtime_principal,
                "authenticated principal differs from registry")
        require(subject["enrollment"]["context_kind"] == "INTACT_ADMITTED", "lifecycle/restore execution is not implemented")
        sem.verify_finish_inventory(subject["policy"], subject["inventory"], {"request": request})
        return subject

    def _current(self, engine, caller, request, now, action):
        subject = self._subject(engine, caller, request, now, sem.PRODUCING_ACTIONS)
        state, op = engine.authority_state, request["intent"]["operation_id"]
        gd = state["grant_pointer"].get(op)
        grant = state["grants"].get(gd)
        require(grant is not None and state["grant_active"].get(gd) is True, "current execution grant unavailable")
        sem.verify_grant_bindings(grant, request, subject["policy"], subject["inventory"], now=now,
            current_sequence=grant["grant_sequence"], authenticated_principal=caller.runtime_principal,
            authenticated_session=caller.session_id)
        lease = state["leases"].get(grant["lease_id"])
        require(lease is not None and state["lease_active"].get(grant["lease_id"]) is True,
                "current lease revoked or absent")
        require(lease["issued_at"] <= now < lease["expires_at"], "current lease expired")
        fences = state["fences"].get(op)
        require(fences is not None and fences["fences"] == sem.expected_fences(request)
            and fences["barrier_operation_id"] == op and fences["unresolved_operation_ids"] == [op],
            "current original fences/barrier differ")
        require(state["phase"].get(op) == ("ABSENT" if action == "PREPARE" else "PREPARED"), "current remote phase differs")
        require(sem.before_checkpoint(request) == engine.authority_checkpoint, "current predecessor differs")
        deadline = min(subject["policy"]["expires_at"], subject["session"]["expires_at"],
                       grant["expires_at"], lease["expires_at"])
        require(now < deadline, "current action deadline expired")
        return grant, fences, deadline

    def _reply(self, tx, engine, op, request_wire, authority_after):
        require(type(authority_after) is int and 0 <= authority_after <= len(engine.authority["events"]),
                "Authority cursor outside original history")
        records = {}
        # Each durable journal window contains original delta records. Repeated
        # content is harmless; old unrelated operations are not reintroduced.
        for window in tx.windows:
            positions = [decode(v)["position"]["event_sequence"] for v in window.authority.event_wires]
            if positions and max(positions) > authority_after:
                records.update(window.authority.record_wires)
        events = tuple(c2(e) for e in engine.authority["events"][authority_after:])
        require(len(events) <= 4096 and len(records) <= 4096, "response delta requires smaller original cursor interval")
        part = RegistrySlice(c2(engine.authority["header"]), events, tuple(records.items()))
        row = tx.operation(op)
        if row is None:
            return AuthorityReply("ABSENT", None, part)
        require(row.request_wire == request_wire, "operation original content conflict")
        expected_ack = engine.authority_state["acks"].get(op)
        expected_fix = engine.authority_state["fixes"].get((op, "NORMAL"))
        expected_terminal = engine.authority_state["terminals"].get(op)
        for wire, value in ((row.ack_wire, expected_ack), (row.acceptance_wire, expected_fix), (row.terminal_wire, expected_terminal)):
            require(wire == (None if value is None else c2(value)), "stored output differs from original journal")
        state = "TERMINAL" if row.terminal_wire else "FIX_ACCEPTED" if row.acceptance_wire else "PREPARED"
        return AuthorityReply(state, row.request_wire, part, row.ack_wire, row.acceptance_wire, row.terminal_wire)

    def register_qualification(self, window: WindowEvidence):
        """Explicit trusted issuer-adapter ingestion, never a public request API.

        It only accepts original governance/grant/permit history, verifies actual
        signatures and original issuance relations, and cannot manufacture Ack,
        FIX, terminal or Core completion. The adapter is an explicit composition
        dependency, not a request-supplied admin flag or production default.
        """
        require(type(window) is WindowEvidence and not window.cores and not window.context_wires,
                "qualification adapter only accepts ordinary Authority history")
        allowed = set(sem.A_KINDS) - {"PREPARE", "FIX_ACCEPTED", "TERMINAL"}
        require(all(decode(e)["event_kind"] in allowed for e in window.authority.event_wires),
                "qualification adapter cannot accept business facts")
        forbidden = {"prepare_ack", "terminal_receipt", "opening_receipt", "abort_override", "restoration_context"}
        require(all(decode(w).get("type") not in forbidden for _, w in window.authority.record_wires),
                "qualification adapter contains business or lifecycle evidence")
        def action(tx):
            engine = self._engine(tx)
            now = tx.now()
            require(all(decode(e)["recorded_at"] <= now for e in window.authority.event_wires), "future qualification event")
            engine.append(window, operation="REGISTRY_RELATIONS")
            tx.append(window)
            return len(engine.authority["events"])
        return self.store.transact(action)

    def query(self, operation_id, request_wire, caller, authority_after=0, *, request_digest=None):
        def action(tx):
            engine = self._engine(tx)
            original_wire = request_wire
            if original_wire is None:
                original_wire = engine.request_wires.get(operation_id)
                require(original_wire is not None, "query object has no admitted original request")
                require(type(request_digest) is str and h2(decode(original_wire)) == request_digest,
                        "query original request digest differs")
            request = self._request(engine, original_wire)
            require(request["intent"]["operation_id"] == operation_id, "query operation differs")
            self._subject(engine, caller, request, tx.now(), {"QUERY_EXISTING"})
            return self._reply(tx, engine, operation_id, original_wire, authority_after)
        return self.store.transact(action)

    def prepare(self, request_wire, source_admission_wire, caller, authority_after=0):
        def action(tx):
            engine = self._engine(tx)
            request = self._request(engine, request_wire)
            op = request["intent"]["operation_id"]
            row = tx.operation(op)
            if row is not None:
                require(row.request_wire == request_wire and row.source_wire == source_admission_wire, "operation original content conflict")
                self._subject(engine, caller, request, tx.now(), {"QUERY_EXISTING"})
                return self._reply(tx, engine, op, request_wire, authority_after)
            base = WindowEvidence((request_wire,), _empty(engine), (), (source_admission_wire,))
            engine.append(base, operation="REGISTRY_RELATIONS")
            result = self._produce(tx, engine, request, source_admission_wire, caller, "PREPARE", None, None, None, ())
            return self._reply(tx, result, op, request_wire, authority_after)
        result = self.store.transact(action)
        self._hook("after_prepare_commit")
        return result

    def decide(self, operation_id, request_wire, authorization_wire, proposal_wire,
               publication_wire, core_registry, caller, authority_after=0):
        def action(tx):
            engine = self._engine(tx)
            request = self._request(engine, request_wire)
            require(request["intent"]["operation_id"] == operation_id, "terminal operation differs")
            row = tx.operation(operation_id)
            require(row is not None and row.ack_wire is not None, "original PREPARE missing")
            require(row.request_wire == request_wire, "operation original content conflict")
            authorization, proposal = decode(authorization_wire), decode(proposal_wire)
            require(authorization.get("type") == "terminal_authorization" and proposal.get("kind") == "NORMAL",
                    "only original NORMAL authorization is implemented")
            sem.verify_override_proposal(proposal, request, decode(row.ack_wire), authorization, engine.pin)
            if row.acceptance_wire is not None:
                require(row.authorization_wire == authorization_wire and row.proposal_wire == proposal_wire,
                        "immutable NORMAL dispatch content conflict")
                if publication_wire is None or row.terminal_wire is not None:
                    if publication_wire is not None:
                        require(row.publication_wire == publication_wire, "immutable publication content conflict")
                    self._subject(engine, caller, request, tx.now(), {"QUERY_EXISTING"})
                    return self._reply(tx, engine, operation_id, request_wire, authority_after)
            phase = "FIX_ACCEPTED" if publication_wire is None else "TERMINAL"
            require(phase == "FIX_ACCEPTED" or row.acceptance_wire is not None, "terminal requires original accepted FIX")
            require(type(core_registry) is RegistrySlice, "original Core history required")
            principal = proposal["runtime_principal"]
            cores = ((principal, core_registry),)
            # Validate actual original proposal/publication before using signer.
            engine.append(WindowEvidence((request_wire,), _empty(engine), cores, (row.source_wire,)), operation="REGISTRY_RELATIONS")
            original = engine.core_states[principal]["proposals"].get((operation_id, "NORMAL"))
            require(original is not None and c2(original) == proposal_wire, "Core proposal evidence differs")
            publication = None if publication_wire is None else decode(publication_wire)
            if publication is not None:
                validate_fields(publication, RECORD["dispatch_publication"])
                original = engine.core_states[principal]["publications"].get((operation_id, "NORMAL"))
                require(original is not None and c2(original) == publication_wire, "Core publication evidence differs")
            engine = self._produce(tx, engine, request, row.source_wire, caller, phase, authorization, proposal, publication, cores)
            return self._reply(tx, engine, operation_id, request_wire, authority_after)
        result = self.store.transact(action)
        self._hook("after_fix_commit" if publication_wire is None else "after_terminal_commit")
        return result

    def _produce(self, tx, engine, request, source_wire, caller, phase, authorization, proposal, publication, cores):
        now = tx.now()
        grant, fences, deadline = self._current(engine, caller, request, now, phase)
        op, pin = request["intent"]["operation_id"], engine.pin
        ack = engine.authority_state["acks"].get(op)
        payload = record("action_input", history_version=2, operation_id=op, request_digest=h2(request),
            source_decision_digest=h2(request["source_decision"]), ack_digest=None if ack is None else h2(ack),
            authorization_digest=None if authorization is None else h2(authorization),
            proposal_digest=None if proposal is None else sem.rawhash(proposal),
            publication_digest=None if publication is None else sem.rawhash(publication))
        snapshot = record("execution_snapshot", history_version=2, position=sem.position(engine.authority),
            operation_id=op, request_digest=h2(request), source_decision_digest=h2(request["source_decision"]),
            action_input_digest=sem.rawhash(payload), checked_at=now,
            action={"PREPARE": "PREPARE_EXISTING", "FIX_ACCEPTED": "FIX_ORIGINAL_DISPATCH", "TERMINAL": "TERMINATE_ORIGINAL"}[phase],
            runtime_principal=caller.runtime_principal, session_id=caller.session_id, policy_digest=caller.policy_digest,
            inventory_digest=caller.inventory_digest, grant_digest=h2(grant), fences=fences["fences"],
            barrier_operation_id=op, unresolved_operation_ids=[op], remote_phase=engine.authority_state["phase"][op])
        if phase == "PREPARE":
            output = obj("prepare_ack", contract_revision=2, operation_id=op,
                identity_digest=h2(request["intent"]["identity"]), request_digest=h2(request),
                source_decision_digest=h2(request["source_decision"]), commit_candidate_digest=h2(request["commit"]),
                abort_candidate_digest=h2(request["abort"]), prepare_execution_grant_digest=h2(grant),
                authority_predecessor=request["intent"]["scope"]["expected_authority_ref"], prepared_at=now,
                prepare_execution_digest=sem.rawhash(snapshot), receipt_signature="0"*128,
                **{k: pin[k] for k in ("authority_domain_id", "authority_instance_id", "authority_generation", "receipt_key_id")})
        elif phase == "FIX_ACCEPTED":
            output = record("fix_acceptance", history_version=2, proposal_digest=sem.rawhash(proposal),
                execution_digest=sem.rawhash(snapshot), accepted_at=now, kind="NORMAL")
        else:
            decision = request["intent"]["requested_decision"]
            selected, scope = request[decision.lower()], request["intent"]["scope"]
            acceptance = engine.authority_state["fixes"][(op, "NORMAL")]
            output = obj("terminal_receipt", contract_revision=2, operation_id=op, operation_type="MUTATION",
                identity_digest=h2(request["intent"]["identity"]), request_digest=h2(request),
                source_decision_digest=h2(request["source_decision"]), ack_digest=h2(ack), authorization_kind="NORMAL",
                semantic_authorization_digest=h2(authorization), execution_grant_digest=h2(grant), decision=decision,
                result_state=selected["result"]["result_state"], candidate_digest=h2(selected), effect_digest=h2(selected["effect"]),
                result_digest=h2(selected["result"]), audit_candidate_digest=h2(selected["audit_candidate"]),
                state_before=scope["expected_state_version"], state_after=selected["result"]["state_version"],
                audit_sequence=selected["audit_candidate"]["audit_sequence"],
                authority_sequence=scope["expected_authority_ref"]["authority_sequence"]+1,
                previous_authority_ref=scope["expected_authority_ref"], decided_at=now,
                fix_execution_digest=acceptance["execution_digest"], terminal_execution_digest=sem.rawhash(snapshot),
                receipt_signature="0"*128,
                **{k: pin[k] for k in ("authority_domain_id", "authority_instance_id", "authority_generation", "receipt_key_id")})
        records = {}
        for value in (payload, snapshot, authorization, proposal, publication):
            if value is not None:
                _put(records, value, input_record=value is snapshot)
        def candidate(out):
            new_records = deepcopy(records)
            output_digest = _put(new_records, out)
            event = record("registry_event", history_version=2, position=snapshot["position"], recorded_at=now,
                event_kind=phase, input_digest=sem.rawhash(snapshot), output_digest=output_digest)
            return event, new_records
        event, prospective = candidate(output)
        registry = deepcopy(engine.authority)
        registry["records"].update(prospective)
        registry["events"].append(event)
        sem._authority_event(registry, event, deepcopy(engine.authority_state), pin, engine.materials, engine.requests, {})
        self._hook("before_sign")
        if phase != "FIX_ACCEPTED":
            signature = self.signer.sign(s2(output))
            require(type(signature) is bytes and len(signature) == 64, "receipt signer returned invalid signature")
            output["receipt_signature"] = signature.hex()
            verify_signed(output, self.trust)
        self._hook("after_sign")
        event, records = candidate(output)
        part = RegistrySlice(c2(registry["header"]), (c2(event),), tuple((d, c2(v)) for d, v in records.items()))
        window = WindowEvidence((c2(request),), part, cores, (source_wire,))
        # Core records were checked above; their exact overlap is harmless.
        engine.append(window, operation="TERMINAL_HISTORY" if phase == "TERMINAL" else "REGISTRY_RELATIONS")
        require(tx.now() < deadline, "action expired while signing")
        self._hook("before_database_append")
        arguments = {"operation_id": op, "request_wire": c2(request), "source_wire": source_wire,
                     "deadline": deadline}
        if phase == "PREPARE":
            arguments["ack_wire"] = c2(output)
        elif phase == "FIX_ACCEPTED":
            arguments.update(authorization_wire=c2(authorization), proposal_wire=c2(proposal), acceptance_wire=c2(output))
        else:
            arguments.update(publication_wire=c2(publication), terminal_wire=c2(output))
        tx.append(window, **arguments)
        self._hook("before_database_commit")
        return engine
