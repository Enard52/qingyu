"""Persistent ordinary grant/finish-permit provider for the scoped R1 path.

Operator policy is supplied once by initialization.  Normal request inventory,
lease, fences, grant and permit are then produced under the same PostgreSQL
scope lock and transaction as the Authority journal.  No request field selects
an issuer or upgrades the authenticated runtime subject.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
from uuid import UUID, NAMESPACE_URL, uuid5

from . import _r1_validation_semantics as sem
from ._r1_validation_stream import RegistrySlice, WindowEvidence
from .r1_scoped_messages import AuthorityCaller
from .r1_validation_codec import ACTIONS, SCHEMA, c2, decode, h2, obj, record, require, s2


def credential_digest(token: bytes) -> str:
    require(type(token) is bytes and len(token) >= 32, "credential entropy")
    return sha256(token).hexdigest()


def _id(scope_id, operation_id, name):
    return str(uuid5(NAMESPACE_URL, f"qingyu:r1d:{scope_id}:{operation_id}:{name}"))


def _digest(value):
    return h2(value) if value.get("type") in SCHEMA else sem.rawhash(value)


def _expected_source_wire(request, pin, material):
    intent, scope = request["intent"], request["intent"]["scope"]
    at = intent["created_at"]
    return c2(record("source_admission", operation_id=intent["operation_id"],
        intent_digest=h2(intent), source_decision_digest=h2(request["source_decision"]),
        identity_digest=h2(intent["identity"]), scope_digest=h2(scope),
        **{k: scope[k] for k in ("actor_identity", "caller_runtime_id", "session_id",
                                 "lease_id", "lease_generation")},
        admitted_at=at, session_issued_at=at - 1, session_expires_at=at + 60_000,
        lease_issued_at=at - 1, lease_expires_at=at + 60_000,
        normal_business_admission=True, core_installation_id=material.core_installation_id,
        deployment_admission_digest=sem.sha(material.deployment_bytes),
        component_artifact_digest=sem.sha(material.component_bytes),
        trust_config_digest=h2(pin)))


def _registry_delta(engine, entries):
    """Build exact contiguous Authority events from the locked replay head."""
    records, events = {}, []
    header = c2(engine.authority["header"])
    start = len(engine.authority["events"])
    registry_digest = sem.rawhash(engine.authority["header"])
    for offset, (kind, at, inp, out) in enumerate(entries, 1):
        records[sem.rawhash(inp)] = deepcopy(inp)
        records[_digest(inp)] = deepcopy(inp)
        if out is not None:
            records[_digest(out)] = deepcopy(out)
        event = record("registry_event", history_version=2,
            position={"history_version": 2, "registry_digest": registry_digest,
                      "event_sequence": start + offset},
            recorded_at=at, event_kind=kind, input_digest=sem.rawhash(inp),
            output_digest=None if out is None else _digest(out))
        events.append(c2(event))
    return RegistrySlice(header, tuple(events), tuple((d, c2(v)) for d, v in records.items()))


def _bind_original(part, value):
    """Include an issuance target as exact original bytes, without an event."""
    digest = sem.rawhash(value)
    records = dict(part.record_wires)
    old = records.get(digest)
    wire = c2(value)
    require(old is None or old == wire, "issuance target original conflict")
    records[digest] = wire
    return RegistrySlice(part.header_wire, part.event_wires, tuple(records.items()))


def _signed_issue(signer, engine, kind, at, body, target, event_sequence):
    typed = {"type": kind, "version": 2, "contract_revision": 2, **body}
    projection = {k: v for k, v in typed.items() if k not in ("issuance_digest", "receipt_signature")}
    snapshot = record("issuance_snapshot", history_version=2,
        position={"history_version": 2, "registry_digest": sem.rawhash(engine.authority["header"]),
                  "event_sequence": event_sequence},
        issued_at=at, issuance_kind="GRANT" if kind == "execution_grant" else "PERMIT",
        issuer_key_id=typed["receipt_key_id"],
        **{k: typed[k] for k in ("runtime_principal", "session_id", "policy_digest",
                                 "inventory_digest", "operation_id", "request_digest",
                                 "source_decision_digest")},
        restoration_context_digest=typed.get("restoration_context_digest"),
        issue_body_digest=sem.rawhash(projection), fences_or_target_digest=sem.rawhash(target))
    typed["issuance_digest"] = sem.rawhash(snapshot)
    typed["receipt_signature"] = signer.sign(s2({**typed, "receipt_signature": "0" * 128})).hex()
    return snapshot, typed


@dataclass(frozen=True)
class DurableAuthorization:
    caller: AuthorityCaller
    credential_digest: str
    object_wire: bytes
    authority_sequence: int


class DurableAuthorizationProvider:
    """Explicit composition with ``ScopedAuthority``; no production defaults.

    The provider deliberately uses the Authority's already-locked replay and
    signer.  This keeps current pointers, revocation state, issuance position,
    durable metadata and journal bytes within one PostgreSQL commit.
    """
    def __init__(self, authority, *, fault=None):
        require(hasattr(authority, "store") and hasattr(authority, "_engine"),
                "scoped Authority composition required")
        self.authority = authority
        self.fault = fault

    def _hook(self, name):
        if self.fault is not None:
            self.fault(name)

    @property
    def scope_id(self):
        return self.authority.store.scope_id

    def authenticate_principal(self, token: bytes) -> str:
        """Resolve an initialized base credential to its fixed principal.

        The caller supplies no policy, session, inventory or grant binding.
        Those bindings are always recovered from the locked registry later.
        """
        digest = credential_digest(token)
        def action(tx):
            row = tx.connection.execute(
                "SELECT * FROM control_plane.r1d_subject_by_credential(%s,%s)",
                (self.scope_id, digest)).fetchone()
            require(row is not None, "unknown durable credential")
            return row[0]
        return self.authority.store.transact(action)

    def install_subject(self, policy_wire: bytes, *, session_id: str,
                        session_expires_at: int, base_credential_digest: str):
        """Accept one offline Root-signed ordinary policy and create its session.

        This is initialization, not a Runtime endpoint. Exact replay returns the
        original session; changed content for the principal is rejected by SQL.
        """
        policy = decode(policy_wire)
        require(policy.get("type") == "recovery_policy" and policy["restoration_context_digest"] is None,
                "ordinary signed policy required")
        require(set(policy["capabilities"]) >= set(ACTIONS), "ordinary policy capabilities")
        principal = policy["runtime_principal"]

        def action(tx):
            old = tx.connection.execute("SELECT * FROM control_plane.r1d_subject(%s,%s)",
                                        (self.scope_id, principal)).fetchone()
            if old is not None:
                require(bytes(old[4]) == policy_wire and str(old[3]) == session_id
                        and old[6] == base_credential_digest and old[7] is True,
                        "durable subject exact replay conflict")
                engine = self.authority._engine(tx)
                require(engine.authority_state["policy_active"].get(h2(policy)) is True
                        and engine.authority_state["session_active"].get(session_id) is True,
                        "durable subject is revoked")
                return bytes(old[5])
            engine = self.authority._engine(tx)
            now = tx.now()
            require(policy["issued_at"] <= now < policy["expires_at"], "policy initialization interval")
            require(now < session_expires_at <= policy["expires_at"], "session initialization interval")
            enrollment = record("enrollment",
                **{k: policy[k] for k in ("runtime_principal", "core_installation_id",
                    "restoration_context_digest", "authority_domain_id", "authority_instance_id",
                    "authority_generation", "storage_generation_id", "control_plane_generation_id",
                    "deployment_admission_digest", "component_artifact_digest", "trust_config_digest")},
                policy_digest=h2(policy), context_kind="INTACT_ADMITTED", purpose="MUTATION_RECOVERY",
                identity_digest=h2(obj("identity", **{k: policy[k] for k in
                    ("qingyu_identity_id", "continuity_id", "genesis_operation_id")})))
            session = record("session_binding", history_version=2, session_id=session_id,
                             enrollment=enrollment, issued_at=now, expires_at=session_expires_at)
            part = _registry_delta(engine, (("POLICY_REGISTER", now, policy, None),
                                            ("SESSION_CREATE", now, session, None)))
            window = WindowEvidence((), part, ())
            engine.append(window, operation="REGISTRY_RELATIONS")
            tx.append(window)
            tx.connection.execute("SELECT control_plane.r1d_install_subject(%s,%s,%s,%s,%s,%s,%s)",
                (self.scope_id, principal, h2(policy), UUID(session_id), policy_wire, c2(session),
                 base_credential_digest))
            return c2(session)
        return self.authority.store.transact(action)

    def authenticate(self, token: bytes, operation_id: str, *, allow_terminal_query=False) -> AuthorityCaller:
        """Resolve only the principal from the token, then derive the caller
        binding from the locked canonical registry for the requested operation.
        """
        digest = credential_digest(token)
        def action(tx):
            row = tx.connection.execute(
                "SELECT * FROM control_plane.r1d_subject_by_credential(%s,%s)",
                (self.scope_id, digest)).fetchone()
            require(row is not None, "unknown durable credential")
            principal = row[0]
            engine = self.authority._engine(tx)
            gd = engine.authority_state["grant_pointer"].get(operation_id)
            require(gd is not None, "operation has no durable grant")
            grant = engine.authority_state["grants"][gd]
            require(grant["runtime_principal"] == principal, "credential principal differs from grant")
            subject = sem.subject_from(engine.authority_state, grant["policy_digest"],
                                       grant["inventory_digest"], grant["session_id"])
            sem.check_subject(engine.authority_state, subject, engine.pin, engine.materials[principal],
                              tx.now(), sem.PRODUCING_ACTIONS)
            if not (allow_terminal_query and
                    engine.authority_state["terminals"].get(operation_id) is not None):
                require(engine.authority_state["grant_active"].get(gd) is True,
                        "operation has no current durable grant")
            return AuthorityCaller(principal, grant["session_id"], grant["policy_digest"],
                                   grant["inventory_digest"])
        return self.authority.store.transact(action)

    def ensure_execution(self, request_wire: bytes, source_wire: bytes, *,
                         runtime_principal: str) -> DurableAuthorization:
        request = decode(request_wire)
        op = request["intent"]["operation_id"]

        def action(tx):
            engine = self.authority._engine(tx)
            request_value = self.authority._request(engine, request_wire)
            require(request_value["intent"]["operation_id"] == op, "operation identity")
            subject_row = tx.connection.execute("SELECT * FROM control_plane.r1d_subject(%s,%s)",
                (self.scope_id, runtime_principal)).fetchone()
            require(subject_row is not None and subject_row[7] is True, "durable subject unavailable")
            policy, session = decode(bytes(subject_row[4])), decode(bytes(subject_row[5]))
            state, now = engine.authority_state, tx.now()
            require(source_wire == _expected_source_wire(request_value, engine.pin,
                    engine.materials[runtime_principal]), "source admission original differs")
            current = state["grant_pointer"].get(op)
            if current is not None:
                grant = state["grants"][current]
                require(op in engine.admissions and c2(engine.admissions[op]) == source_wire,
                        "current grant source admission differs")
                current_subject = sem.subject_from(state, grant["policy_digest"],
                                                   grant["inventory_digest"], grant["session_id"])
                sem.check_subject(state, current_subject, engine.pin, engine.materials[runtime_principal],
                                  now, sem.PRODUCING_ACTIONS)
                # A committed terminal is immutable history. Recovery may need
                # to query it and obtain a finish permit after the execution
                # grant has expired or been revoked; this does not authorize a
                # new PREPARE/FIX/terminal action, whose route authentication
                # still requires a live current grant.
                if state["terminals"].get(op) is not None:
                    require(grant["request_digest"] == h2(request_value)
                            and grant["runtime_principal"] == runtime_principal,
                            "terminal query original binding differs")
                    caller = AuthorityCaller(runtime_principal, grant["session_id"],
                                             grant["policy_digest"], grant["inventory_digest"])
                    return DurableAuthorization(caller, subject_row[6], c2(grant),
                        next(e["position"]["event_sequence"] for e in engine.authority["events"]
                             if e["event_kind"] == "GRANT_ISSUED" and e["output_digest"] == current))
                require(state["grant_active"].get(current) is True,
                        "current grant unavailable")
                require(grant["request_digest"] == h2(request_value)
                        and grant["runtime_principal"] == runtime_principal,
                        "current grant original binding differs")
                caller = AuthorityCaller(runtime_principal, session["session_id"], h2(policy),
                                         grant["inventory_digest"])
                return DurableAuthorization(caller, subject_row[6], c2(grant),
                    next(e["position"]["event_sequence"] for e in engine.authority["events"]
                         if e["event_kind"] == "GRANT_ISSUED" and e["output_digest"] == current))
            intent, scope, identity = request_value["intent"], request_value["intent"]["scope"], request_value["intent"]["identity"]
            common = {"operation_id": op, "request_digest": h2(request_value),
                      "source_decision_digest": h2(request_value["source_decision"])}
            inventory = obj("recovery_inventory", inventory_id=_id(self.scope_id, op, "inventory"),
                policy_digest=h2(policy), core_installation_id=policy["core_installation_id"],
                runtime_principal=runtime_principal, session_id=session["session_id"],
                entries=[{**common, "local_commit_id": intent["local_commit_id"]}])
            af = {k: self.authority.trust.pin[k] for k in
                  ("authority_domain_id", "authority_instance_id", "authority_generation")}
            fences = record("fences", **af, identity=identity, owner_identity=scope["actor_identity"],
                owner_version=scope["owner_version"], continuity_epoch=scope["continuity_epoch"],
                state_version=scope["expected_state_version"], storage_generation_id=scope["storage_generation_id"],
                control_plane_generation_id=scope["control_plane_generation_id"],
                authority_ref=scope["expected_authority_ref"], audit_ref=scope["expected_audit_ref"])
            fence_state = record("fence_state", history_version=2, operation_id=op, fences=fences,
                                 barrier_operation_id=op, unresolved_operation_ids=[op])
            lease_deadline = min(policy["expires_at"], session["expires_at"])
            deadline = min(now + 29_000, lease_deadline)
            lease = record("operation_lease", history_version=2, lease_id=_id(self.scope_id, op, "lease"),
                lease_generation=1, operation_id=op, request_digest=h2(request_value),
                runtime_principal=runtime_principal, session_id=session["session_id"],
                issued_at=now, expires_at=lease_deadline)
            sequence = len(engine.authority["events"]) + 4
            snapshot, grant = _signed_issue(self.authority.signer, engine, "execution_grant", now,
                {"grant_id": _id(self.scope_id, op, "grant:1"), "grant_sequence": 1,
                 "policy_digest": h2(policy), "inventory_digest": h2(inventory), **common, **af,
                 **{k: identity[k] for k in ("continuity_id", "qingyu_identity_id", "genesis_operation_id")},
                 "owner_identity": scope["actor_identity"], "owner_version": scope["owner_version"],
                 "continuity_epoch": scope["continuity_epoch"], "expected_state_version": scope["expected_state_version"],
                 "storage_generation_id": scope["storage_generation_id"],
                 "control_plane_generation_id": scope["control_plane_generation_id"],
                 "runtime_principal": runtime_principal, "session_id": session["session_id"],
                 "lease_id": lease["lease_id"], "lease_generation": 1,
                 "issued_at": now, "expires_at": deadline, "receipt_key_id": self.authority.trust.receipt_key_id},
                fences, sequence)
            entries = (("INVENTORY_ACCEPT", now, inventory, None), ("FENCES_SET", now, fence_state, None),
                       ("LEASE_CREATE", now, lease, None), ("GRANT_ISSUED", now, snapshot, grant))
            part = _bind_original(_registry_delta(engine, entries), fences)
            window = WindowEvidence((request_wire,), part, (), (source_wire,))
            engine.append(window, operation="REGISTRY_RELATIONS")
            self._hook("before_grant_append")
            tx.append(window, deadline=deadline)
            tx.connection.execute("SELECT control_plane.r1d_record_issue(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (self.scope_id, UUID(grant["grant_id"]), "GRANT", UUID(op), 1, h2(request_value),
                 runtime_principal, UUID(session["session_id"]), h2(inventory), h2(grant), c2(grant),
                 sequence, now))
            return DurableAuthorization(AuthorityCaller(runtime_principal, session["session_id"], h2(policy), h2(inventory)),
                                        subject_row[6], c2(grant), sequence)
        result = self.authority.store.transact(action)
        self._hook("after_grant_commit")
        return result

    def ensure_permit(self, operation_id: str, *, runtime_principal: str,
                      request_digest: str) -> DurableAuthorization:
        def action(tx):
            engine = self.authority._engine(tx)
            request = engine.requests.get(operation_id)
            require(request is not None, "permit original request unavailable")
            require(h2(request) == request_digest, "permit original request digest differs")
            state, now = engine.authority_state, tx.now()
            terminal = state["terminals"].get(operation_id)
            require(terminal is not None, "permit requires committed terminal")
            gd = state["grant_pointer"].get(operation_id)
            require(gd is not None, "permit subject inventory unavailable")
            grant = state["grants"][gd]
            require(grant["runtime_principal"] == runtime_principal,
                    "permit principal differs from grant")
            subject = sem.subject_from(state, grant["policy_digest"], grant["inventory_digest"], grant["session_id"])
            sem.check_subject(state, subject, engine.pin, engine.materials[grant["runtime_principal"]], now,
                              set(sem.RESTORE_ACTIONS))
            current = state["permit_pointer"].get(operation_id)
            if current is not None:
                permit = state["permits"][current]
                require(state["permit_active"].get(current) is True,
                        "current permit unavailable")
                require(permit["request_digest"] == request_digest
                        and permit["runtime_principal"] == runtime_principal,
                        "current permit original binding differs")
                return DurableAuthorization(AuthorityCaller(grant["runtime_principal"], grant["session_id"],
                    grant["policy_digest"], grant["inventory_digest"]), "", c2(permit),
                    next(e["position"]["event_sequence"] for e in engine.authority["events"]
                         if e["event_kind"] == "PERMIT_ISSUED" and e["output_digest"] == current))
            policy = subject["policy"]
            selected = request[terminal["decision"].lower()]
            audit = obj("audit_record", candidate=selected["audit_candidate"], receipt_digest=h2(terminal))
            target = sem.finish_target(request, terminal, audit, policy, engine.pin)
            deadline = min(now + 29_000, policy["expires_at"], subject["session"]["expires_at"])
            seq = 1 if current is None else state["permits"][current]["permit_sequence"] + 1
            event_sequence = len(engine.authority["events"]) + 1
            snapshot, permit = _signed_issue(self.authority.signer, engine, "local_finish_permit", now,
                {"permit_id": _id(self.scope_id, operation_id, f"permit:{seq}"), "permit_sequence": seq,
                 "policy_digest": grant["policy_digest"], "inventory_digest": grant["inventory_digest"],
                 "restoration_context_digest": None, "core_installation_id": policy["core_installation_id"],
                 "runtime_principal": grant["runtime_principal"], "session_id": grant["session_id"],
                 "operation_id": operation_id, "request_digest": h2(request),
                 "source_decision_digest": h2(request["source_decision"]), "terminal_digest": h2(terminal),
                 "before_checkpoint": target["before_checkpoint"], "after_checkpoint": target["after_checkpoint"],
                 "issued_at": now, "expires_at": deadline, "receipt_key_id": self.authority.trust.receipt_key_id},
                target, event_sequence)
            part = _bind_original(_registry_delta(engine, (("PERMIT_ISSUED", now, snapshot, permit),)), target)
            window = WindowEvidence((), part, ())
            engine.append(window, operation="REGISTRY_RELATIONS")
            self._hook("before_permit_append")
            tx.append(window, deadline=deadline)
            tx.connection.execute("SELECT control_plane.r1d_record_issue(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (self.scope_id, UUID(permit["permit_id"]), "PERMIT", UUID(operation_id), seq, h2(request),
                 grant["runtime_principal"], UUID(grant["session_id"]), grant["inventory_digest"], h2(permit),
                 c2(permit), event_sequence, now))
            caller = AuthorityCaller(grant["runtime_principal"], grant["session_id"],
                                     grant["policy_digest"], grant["inventory_digest"])
            return DurableAuthorization(caller, "", c2(permit), event_sequence)
        result = self.authority.store.transact(action)
        self._hook("after_permit_commit")
        return result

    def query_issue(self, issue_id: str) -> bytes:
        """Return only the exact committed signed object; no reissuance."""
        def action(tx):
            row = tx.connection.execute("SELECT * FROM control_plane.r1d_issue(%s,%s)",
                                        (self.scope_id, UUID(issue_id))).fetchone()
            require(row is not None, "durable issue not found")
            return bytes(row[10])
        return self.authority.store.transact(action)

    def query_current_issue(self, kind: str, operation_id: str) -> bytes:
        require(kind in {"GRANT", "PERMIT"}, "durable issue kind")
        def action(tx):
            row = tx.connection.execute("SELECT * FROM control_plane.r1d_current_issue(%s,%s,%s)",
                                        (self.scope_id, kind, UUID(operation_id))).fetchone()
            require(row is not None, "durable operation issue not found")
            return bytes(row[10])
        return self.authority.store.transact(action)

    def revoke(self, kind: str, object_digest: str, authorization_wire: bytes, *, verify_operator):
        """Append a forward revocation through a separately authenticated Operator boundary.

        ``verify_operator`` is fixed by service composition, never selected by
        Runtime input.  The exact external authorization is retained in the
        durable side table because the accepted revocation record has no field
        for it; no new public protocol field is introduced.
        """
        allowed = {"POLICY_REVOKE", "SESSION_REVOKE", "LEASE_REVOKE", "GRANT_REVOKE", "PERMIT_REVOKE"}
        require(kind in allowed and callable(verify_operator), "operator revocation boundary")
        def action(tx):
            engine = self.authority._engine(tx)
            now = tx.now()
            require(verify_operator(authorization_wire, kind, object_digest, now) is True,
                    "operator revocation authorization rejected")
            # Exact replay is a no-op and cannot reactivate or move a pointer.
            old = tx.connection.execute(
                "SELECT * FROM control_plane.r1d_revocation(%s,%s,%s)",
                (self.scope_id, kind, object_digest)).fetchone()
            if old is not None:
                require(bytes(old[3]) == authorization_wire, "revocation exact replay conflict")
                return old[4]
            revocation = record("revocation", history_version=2, object_digest=object_digest)
            sequence = len(engine.authority["events"]) + 1
            part = _registry_delta(engine, ((kind, now, revocation, None),))
            window = WindowEvidence((), part, ())
            engine.append(window, operation="REGISTRY_RELATIONS")
            self._hook("before_revocation_append")
            tx.append(window)
            tx.connection.execute("SELECT control_plane.r1d_record_revocation(%s,%s,%s,%s,%s,%s)",
                (self.scope_id, kind, object_digest, authorization_wire, sequence, now))
            return sequence
        result = self.authority.store.transact(action)
        self._hook("after_revocation_commit")
        return result
