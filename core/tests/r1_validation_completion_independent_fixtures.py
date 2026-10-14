"""Reviewer-owned histories, built without product codec/semantic/author helpers.

All scalar formatting, H2/S2/RAW preimages, registry positions and joins below
are transcribed from the accepted contracts. Only final API adaptation imports
product dataclasses. Random Ed25519 private keys remain in memory.
"""
from copy import copy, deepcopy
import hashlib
import json
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def wire(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def raw(value):
    return sha(wire(value))


def h(value):
    return sha(b"QINGYU-R1-SCOPED-V2/" + value["type"].encode("ascii") + b"\0" + wire(value))


def typed(name, **values):
    return {"type": name, "version": 2, **values}


def sign(value, key):
    field = "root_signature" if "root_signature" in value else "receipt_signature"
    unsigned = {k: v for k, v in value.items() if k != field}
    preimage = b"QINGYU-R1-SCOPED-SIGN-V2/" + value["type"].encode("ascii") + b"\0" + wire(unsigned)
    return {**deepcopy(value), field: key.sign(preimage).hex()}


def register_header(pin, deployment=None):
    scope = {"registry_kind": "AUTHORITY_QUALIFICATION" if deployment is None else "CORE_LOCAL",
             **{k: pin[k] for k in ("authority_domain_id", "authority_instance_id", "authority_generation")},
             **{k: None if deployment is None else deployment[k] for k in
                ("core_installation_id", "storage_generation_id", "control_plane_generation_id")}}
    identifier = str(UUID(bytes=hashlib.sha256(b"QINGYU-R1-SCOPED-REGISTRY-V2\0" + wire(scope)).digest()[:16]))
    header = {"history_version": 2, "registry_id": identifier, **scope,
              "provenance_digest": h(pin) if deployment is None else sha(deployment["deployment_bytes"])}
    return {"header": header, "events": [], "records": {}}


def position(registry):
    return {"history_version": 2, "registry_digest": raw(registry["header"]), "event_sequence": len(registry["events"]) + 1}


def store_record(registry, value):
    result = h(value) if "type" in value else raw(value)
    registry["records"][result] = deepcopy(value)
    return result


def append_event(registry, kind, at, value, output=None):
    registry["records"][raw(value)] = deepcopy(value)
    store_record(registry, value)
    event = {"history_version": 2, "position": position(registry), "recorded_at": at, "event_kind": kind,
             "input_digest": raw(value), "output_digest": store_record(registry, output) if output is not None else None}
    registry["events"].append(event)
    return event


def observe(core, source_event, source_value, kind, at):
    record = {"history_version": 2, "authority_position": source_event["position"],
              "authority_event_digest": raw(source_event),
              "object_digest": h(source_value) if "type" in source_value else raw(source_value)}
    return append_event(core, kind, at, record)


ALL_ACTIONS = ["APPLY_VERIFIED_TERMINAL", "FIX_ORIGINAL_DISPATCH", "PERSIST_COORDINATION", "PREPARE_EXISTING", "QUERY_EXISTING", "TERMINATE_ORIGINAL"]


class IndependentHistory:
    """Variable identity/value/length generator with ordered COMMIT/ABORT state."""

    def __init__(self, seed=50000, initial_state=3):
        self.seed = seed
        self.owner_version, self.continuity_epoch = 2, 3
        self.root_key, self.receipt_key, tls_key = [Ed25519PrivateKey.generate() for _ in range(3)]
        self.root_public = self.root_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        receipt_public = self.receipt_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        spki = tls_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        self.pin = typed("authority_pin", authority_domain_id=self.uid(1), authority_instance_id=self.uid(2), authority_generation=1,
                         receipt_public_key=receipt_public.hex(), receipt_key_id=sha(receipt_public), api_version=2,
                         https_origin="https://independent.example.test", server_spki_sha256=sha(spki), operator_root_key_id=sha(self.root_public))
        self.deployment = {"runtime_principal": "independent-core-" + str(seed), "core_installation_id": self.uid(3),
                           "storage_generation_id": self.uid(4), "control_plane_generation_id": self.uid(5),
                           "deployment_bytes": ("independent-deployment-" + str(seed)).encode(),
                           "component_bytes": b"independent-read-only-validator-test-component", "tls_spki_der": spki}
        self.identity = typed("identity", qingyu_identity_id=self.uid(6), continuity_id=self.uid(7), genesis_operation_id=self.uid(8))
        self.owner = "independent-owner-" + str(seed)
        self.trust_domain_id = self.uid(9)
        self.start = typed("local_checkpoint", state_version=initial_state,
                           authority_ref=typed("authority_ref", wire_version=2, authority_generation=1, authority_sequence=7, receipt_hash=sha(b"external-start-receipt" + str(seed).encode())),
                           audit_ref=typed("audit_ref", wire_version=2, audit_sequence=12, audit_hash=sha(b"external-start-audit" + str(seed).encode())))
        self.cursor = deepcopy(self.start)
        self.authority = register_header(self.pin)
        self.core = register_header(self.pin, self.deployment)
        self.requests, self.admissions, self.operations = [], [], []

    def uid(self, offset):
        return str(UUID(int=self.seed + offset))

    def branch(self, intent, source, decision):
        scope = intent["scope"]
        value = {"payload": deepcopy(intent["payload"]), "capability": "core_governance", "requested_decision": intent["requested_decision"]}
        effect = typed("business_effect", entries=[{"mutation_id": intent["mutation_id"], "value": value}] if decision == "COMMIT" else [])
        result = typed("mutation_result", mutation_id=intent["mutation_id"], result_state="COMMITTED" if decision == "COMMIT" else "ABORTED",
                       state_version=scope["expected_state_version"] + (1 if decision == "COMMIT" else 0), effect_digest=h(effect), value=value if decision == "COMMIT" else None)
        audit = typed("audit_content", operation_id=intent["operation_id"], mutation_id=intent["mutation_id"], identity_digest=h(intent["identity"]),
                      scope_digest=h(scope), intent_digest=h(intent), source_decision_digest=h(source), payload_digest=h(typed("business_payload", value=intent["payload"])),
                      decision=decision, result_state=result["result_state"], state_version=result["state_version"], effect_digest=h(effect), result_digest=h(result),
                      audit_sequence=scope["expected_audit_ref"]["audit_sequence"] + 1, previous_audit_ref=scope["expected_audit_ref"], created_at=intent["created_at"])
        return typed("branch_bundle", decision=decision, effect=effect, result=result, audit_candidate=audit)

    def add_operation(self, decision="COMMIT", *, apply=True, request_checkpoint=None, faults=None):
        ordinal = len(self.operations)
        at = 10000 * (ordinal + 1)
        uid = lambda n: self.uid(100 + ordinal * 100 + n)
        faults = faults or {}
        row = {}
        def mutate(name, value):
            result = deepcopy(value)
            change = faults.get(name)
            if callable(change):
                change(result)
            elif change:
                result.update(deepcopy(change))
            row[name] = result
            return result
        before = deepcopy(request_checkpoint if request_checkpoint is not None else self.cursor)
        domain = {k: self.pin[k] for k in ("authority_domain_id", "authority_instance_id", "authority_generation")}
        scope = typed("requested_scope", **domain, trust_domain_id=self.trust_domain_id, actor_identity=self.owner,
                      owner_version=self.owner_version, continuity_epoch=self.continuity_epoch, expected_state_version=before["state_version"], storage_generation_id=self.deployment["storage_generation_id"],
                      control_plane_generation_id=self.deployment["control_plane_generation_id"], lease_id=uid(1), lease_generation=1, caller_runtime_id=uid(2),
                      session_id=uid(3), capability="core_governance", expected_authority_ref=before["authority_ref"], expected_audit_ref=before["audit_ref"])
        intent = typed("business_intent", operation_id=uid(4), mutation_id="review-mutation-" + str(ordinal), local_commit_id=uid(5), identity=self.identity,
                       scope=scope, payload={"value": 31 + ordinal, "unicode": "\u96ea\U0001f642", "ordinal": ordinal}, requested_decision=decision,
                       created_at=at, reason="Independent protocol construction")
        source = typed("source_decision", authorization_id=uid(6), authorization_kind="CALLER_INTENT", intent_digest=h(intent), identity_digest=h(self.identity),
                       scope_digest=h(scope), authorization_principal=self.owner, requested_decision=decision, created_at=at)
        request = typed("mutation_request", intent=intent, source_decision=source, commit=self.branch(intent, source, "COMMIT"), abort=self.branch(intent, source, "ABORT"))
        row.update(request=request, before=before)
        common = {"operation_id": intent["operation_id"], "request_digest": h(request), "source_decision_digest": h(source)}
        policy = typed("recovery_policy", policy_id=uid(7), deployment_admission_digest=sha(self.deployment["deployment_bytes"]), **domain,
                       **{k: self.identity[k] for k in ("continuity_id", "qingyu_identity_id", "genesis_operation_id")},
                       **{k: self.deployment[k] for k in ("runtime_principal", "core_installation_id", "storage_generation_id", "control_plane_generation_id")},
                       component_artifact_digest=sha(self.deployment["component_bytes"]), trust_config_digest=h(self.pin), restoration_context_digest=None,
                       capabilities=list(ALL_ACTIONS), allowed_operation_type="MUTATION", issued_at=at - 100, expires_at=at + 100000,
                       operator_root_key_id=self.pin["operator_root_key_id"], root_signature="0" * 128)
        policy = sign(mutate("policy", policy), self.root_key); row["policy"] = policy
        enrollment = {k: policy[k] for k in ("runtime_principal", "core_installation_id", "restoration_context_digest", "authority_domain_id", "authority_instance_id", "authority_generation",
                                           "storage_generation_id", "control_plane_generation_id", "deployment_admission_digest", "component_artifact_digest", "trust_config_digest")}
        enrollment.update(policy_digest=h(policy), purpose="MUTATION_RECOVERY", context_kind="INTACT_ADMITTED", identity_digest=h(self.identity))
        session = {"history_version": 2, "session_id": uid(8), "enrollment": enrollment, "issued_at": at + 100, "expires_at": at + 50000}
        inventory = typed("recovery_inventory", inventory_id=uid(9), policy_digest=h(policy), core_installation_id=self.deployment["core_installation_id"],
                          runtime_principal=self.deployment["runtime_principal"], session_id=session["session_id"], entries=[{**common, "local_commit_id": intent["local_commit_id"]}])
        binding = {"runtime_principal": self.deployment["runtime_principal"], "session_id": session["session_id"], "policy_digest": h(policy), "inventory_digest": h(inventory)}
        fences = {**domain, "identity": self.identity, "owner_identity": self.owner, "owner_version": self.owner_version, "continuity_epoch": self.continuity_epoch,
                  "state_version": before["state_version"], "storage_generation_id": scope["storage_generation_id"], "control_plane_generation_id": scope["control_plane_generation_id"],
                  "authority_ref": before["authority_ref"], "audit_ref": before["audit_ref"]}
        append_event(self.authority, "FENCES_SET", at, {"history_version": 2, "operation_id": intent["operation_id"], "fences": fences,
                     "barrier_operation_id": intent["operation_id"], "unresolved_operation_ids": [intent["operation_id"]]})
        observed = []
        for kind, obj in (("POLICY_REGISTER", policy), ("SESSION_CREATE", session), ("INVENTORY_ACCEPT", inventory)):
            observed.append((append_event(self.authority, kind, at + 100, obj), obj))
        lease = {"history_version": 2, "lease_id": uid(10), "lease_generation": 1, "operation_id": intent["operation_id"], "request_digest": h(request),
                 "runtime_principal": binding["runtime_principal"], "session_id": session["session_id"], "issued_at": at + 100, "expires_at": at + 20000}
        append_event(self.authority, "LEASE_CREATE", at + 100, lease)
        def issue(name, body, target):
            body = mutate(name + "_projection", body)
            issuance = {"history_version": 2, "position": position(self.authority), "issued_at": body["issued_at"],
                        "issuance_kind": "GRANT" if body["type"] == "execution_grant" else "PERMIT", "issuer_key_id": body["receipt_key_id"],
                        **{k: body[k] for k in (*binding.keys(), *common.keys())}, "restoration_context_digest": body.get("restoration_context_digest"),
                        "issue_body_digest": raw(body), "fences_or_target_digest": raw(target)}
            signed = sign({**body, "issuance_digest": raw(issuance), "receipt_signature": "0" * 128}, self.receipt_key)
            store_record(self.authority, target)
            event = append_event(self.authority, name.upper() + "_ISSUED", body["issued_at"], issuance, signed)
            row.update({name: signed, name + "_issuance": issuance})
            return signed, event
        grant, _ = issue("grant", typed("execution_grant", contract_revision=2, grant_id=uid(11), grant_sequence=1, **common, **binding, **domain,
                          **{k: self.identity[k] for k in ("qingyu_identity_id", "continuity_id", "genesis_operation_id")}, owner_identity=self.owner,
                          owner_version=self.owner_version, continuity_epoch=self.continuity_epoch, expected_state_version=before["state_version"], storage_generation_id=scope["storage_generation_id"],
                          control_plane_generation_id=scope["control_plane_generation_id"], lease_id=lease["lease_id"], lease_generation=1,
                          issued_at=at + 100, expires_at=at + 15000, receipt_key_id=self.pin["receipt_key_id"]), fences)
        def action_input(ack=None, auth=None, proposal=None, publication=None):
            return {"history_version": 2, **common, "ack_digest": h(ack) if ack else None, "authorization_digest": h(auth) if auth else None,
                    "proposal_digest": raw(proposal) if proposal else None, "publication_digest": raw(publication) if publication else None}
        def execution(action, when, payload):
            store_record(self.authority, payload)
            return {"history_version": 2, "position": position(self.authority), "checked_at": when, "action": action, **common, **binding,
                    "grant_digest": h(grant), "fences": fences, "barrier_operation_id": intent["operation_id"], "unresolved_operation_ids": [intent["operation_id"]],
                    "remote_phase": "ABSENT" if action == "PREPARE_EXISTING" else "PREPARED", "action_input_digest": raw(payload)}
        prepare = execution("PREPARE_EXISTING", at + 200, action_input())
        ack = sign(mutate("ack", typed("prepare_ack", contract_revision=2, **domain, **common, identity_digest=h(self.identity), commit_candidate_digest=h(request["commit"]),
                   abort_candidate_digest=h(request["abort"]), prepare_execution_grant_digest=h(grant), prepare_execution_digest=raw(prepare),
                   authority_predecessor=before["authority_ref"], prepared_at=at + 200, receipt_key_id=self.pin["receipt_key_id"], receipt_signature="0" * 128)), self.receipt_key)
        append_event(self.authority, "PREPARE", at + 200, prepare, ack)
        stage = typed("staged_evidence", operation_id=intent["operation_id"], local_commit_id=intent["local_commit_id"], request_digest=h(request), ack_digest=h(ack),
                      commit_candidate_digest=h(request["commit"]), abort_candidate_digest=h(request["abort"]))
        selected = request[decision.lower()]
        authorization = mutate("authorization", typed("terminal_authorization", authorization_id=uid(12), **common, local_commit_id=intent["local_commit_id"], ack_digest=h(ack),
                              decision=decision, candidate_digest=h(selected), staging_evidence_digest=h(stage), no_local_business_commit=decision == "ABORT", created_at=at + 300))
        for (event, value), kind in zip(observed, ("POLICY_OBSERVED", "SESSION_OBSERVED", "INVENTORY_OBSERVED")):
            observe(self.core, event, value, kind, at + 200)
        append_event(self.core, "LOCAL_PROTECTION", at + 200, {"history_version": 2, "policy_digest": h(policy), "component_valid": True,
                     "policy_active": True, "context_kind": "INTACT_ADMITTED"})
        def local(action, when, target, payload):
            self.core["records"][raw(target)] = deepcopy(target)
            store_record(self.core, target); store_record(self.core, payload)
            return {"history_version": 2, "position": position(self.core), "checked_at": when, "action": action, **common, **binding,
                    "target_digest": raw(target), "action_input_digest": raw(payload)}
        proposal = mutate("proposal", {"history_version": 2, "proposal_position": position(self.core), "kind": "NORMAL", **common,
                          "local_commit_id": intent["local_commit_id"], "ack_digest": h(ack), "staging_evidence_digest": h(stage), "semantic_authorization_digest": h(authorization),
                          "runtime_principal": binding["runtime_principal"], "session_id": binding["session_id"], "core_installation_id": self.deployment["core_installation_id"],
                          "created_at": at + 300, "no_local_business_commit": decision == "ABORT", "before_checkpoint": before})
        store_record(self.core, authorization)
        proposal_snapshot = local("PROPOSE_DISPATCH", at + 300, before, action_input(ack, authorization))
        append_event(self.core, "PROPOSAL", at + 300, proposal_snapshot, proposal)
        store_record(self.authority, proposal); store_record(self.authority, authorization)
        fix_snapshot = execution("FIX_ORIGINAL_DISPATCH", at + 350, action_input(ack, authorization, proposal))
        fix = {"history_version": 2, "proposal_digest": raw(proposal), "execution_digest": raw(fix_snapshot), "accepted_at": at + 350, "kind": "NORMAL"}
        append_event(self.authority, "FIX_ACCEPTED", at + 350, fix_snapshot, fix)
        store_record(self.core, fix)
        publication_input = mutate("publication_input", action_input(ack, authorization, proposal))
        publication_snapshot = local("PUBLISH_DISPATCH", at + 400, before, publication_input)
        publication = {"history_version": 2, "position": position(self.core), "published_at": at + 400, "proposal_digest": raw(proposal), "fix_acceptance_digest": raw(fix)}
        append_event(self.core, "PUBLICATION", at + 400, publication_snapshot, publication)
        store_record(self.authority, publication)
        terminal_snapshot = execution("TERMINATE_ORIGINAL", at + 500, action_input(ack, authorization, proposal, publication))
        receipt = sign(mutate("receipt", typed("terminal_receipt", contract_revision=2, **domain, **common, operation_type="MUTATION", identity_digest=h(self.identity),
                       ack_digest=h(ack), authorization_kind="NORMAL", semantic_authorization_digest=h(authorization), execution_grant_digest=h(grant),
                       decision=decision, result_state=selected["result"]["result_state"], candidate_digest=h(selected), effect_digest=h(selected["effect"]),
                       result_digest=h(selected["result"]), audit_candidate_digest=h(selected["audit_candidate"]), state_before=before["state_version"], state_after=selected["result"]["state_version"],
                       audit_sequence=before["audit_ref"]["audit_sequence"] + 1, authority_sequence=before["authority_ref"]["authority_sequence"] + 1,
                       previous_authority_ref=before["authority_ref"], decided_at=at + 500, receipt_key_id=self.pin["receipt_key_id"],
                       fix_execution_digest=raw(fix_snapshot), terminal_execution_digest=raw(terminal_snapshot), receipt_signature="0" * 128)), self.receipt_key)
        append_event(self.authority, "TERMINAL", at + 500, terminal_snapshot, receipt)
        audit = typed("audit_record", candidate=selected["audit_candidate"], receipt_digest=h(receipt))
        after = typed("local_checkpoint", state_version=selected["result"]["state_version"],
                      authority_ref=typed("authority_ref", wire_version=2, authority_generation=1, authority_sequence=receipt["authority_sequence"], receipt_hash=h(receipt)),
                      audit_ref=typed("audit_ref", wire_version=2, audit_sequence=receipt["audit_sequence"], audit_hash=h(audit)))
        if apply:
            target = {"history_version": 2, "identity_digest": h(self.identity), "authority_pin_digest": h(self.pin),
                      **{k: policy[k] for k in ("core_installation_id", "storage_generation_id", "control_plane_generation_id", "restoration_context_digest")},
                      **common, "terminal_digest": h(receipt), "before_checkpoint": before, "after_checkpoint": after}
            permit, permit_event = issue("permit", typed("local_finish_permit", contract_revision=2, permit_id=uid(13), permit_sequence=1, **common, **binding,
                                        restoration_context_digest=None, core_installation_id=self.deployment["core_installation_id"], terminal_digest=h(receipt),
                                        before_checkpoint=before, after_checkpoint=after, issued_at=at + 600, expires_at=at + 10000, receipt_key_id=self.pin["receipt_key_id"]), target)
            observe(self.core, permit_event, permit, "PERMIT_OBSERVED", at + 650)
            content = {"effect_digest": h(selected["effect"]), "result_digest": h(selected["result"]), "audit_record_digest": h(audit)}
            use = mutate("use_input", {"history_version": 2, "permit_digest": h(permit), "issuance_digest": permit["issuance_digest"], "target_digest": raw(target), "terminal_digest": h(receipt), **content})
            use_snapshot = local("APPLY_VERIFIED_TERMINAL", at + 700, target, use)
            completion = {"history_version": 2, "position": position(self.core), "completed_at": at + 700, "permit_digest": h(permit), "issuance_digest": permit["issuance_digest"],
                          "local_use_digest": raw(use_snapshot), **common, "terminal_digest": h(receipt), "target_digest": raw(target), "before_checkpoint": before, "after_checkpoint": after, **content}
            append_event(self.core, "APPLY", at + 700, use_snapshot, completion)
            row.update(target=target, completion=completion, use_snapshot=use_snapshot)
        admission = {"operation_id": intent["operation_id"], "intent_digest": h(intent), "source_decision_digest": h(source), "identity_digest": h(self.identity), "scope_digest": h(scope),
                     **{k: scope[k] for k in ("actor_identity", "caller_runtime_id", "session_id", "lease_id", "lease_generation")}, "admitted_at": at,
                     "session_issued_at": at - 10, "session_expires_at": at + 50, "lease_issued_at": at - 10, "lease_expires_at": at + 50,
                     "normal_business_admission": True, "core_installation_id": self.deployment["core_installation_id"], "deployment_admission_digest": sha(self.deployment["deployment_bytes"]),
                     "component_artifact_digest": sha(self.deployment["component_bytes"]), "trust_config_digest": h(self.pin)}
        row.update(ack=ack, stage=stage, authorization=authorization, proposal=proposal, fix=fix, publication=publication, receipt=receipt, audit=audit,
                   after=after, admission=admission, policy=policy, session=session, inventory=inventory)
        self.cursor = deepcopy(after)
        self.requests.append(request); self.admissions.append(admission); self.operations.append(row)
        return row

    def product_inputs(self):
        from app.control_plane.r1_validation import CoreHistory, DeploymentEvidence, HistoryEvidence
        from app.control_plane.r1_validation_crypto import FixedTrust
        deployment = DeploymentEvidence(**self.deployment)
        evidence = HistoryEvidence(tuple(wire(r) for r in self.requests), wire(self.authority),
                                   (CoreHistory(deployment.runtime_principal, wire(self.core)),),
                                   source_admission_wires=tuple(wire(a) for a in self.admissions))
        return evidence, FixedTrust(wire(self.pin), self.root_public), (deployment,)

    def boundary(self):
        from app.control_plane.r1_validation import ChainBoundary
        return ChainBoundary(identity_wire=wire(self.identity), start_checkpoint_wire=wire(self.start), expected_end_checkpoint_wire=wire(self.cursor),
                             owner_identity=self.owner, owner_version=self.owner_version, continuity_epoch=self.continuity_epoch, storage_generation_id=self.deployment["storage_generation_id"],
                             control_plane_generation_id=self.deployment["control_plane_generation_id"], trust_domain_id=self.trust_domain_id)


def establish_genesis(world):
    """Independently sign original JCS origin and a successful V2 first chain."""
    import rfc8785
    from app.control_plane.r1_provisioning import ObservedProvisionedTarget
    assert not world.operations
    pin, uid, material = world.pin, world.uid, world.deployment
    roles = dict(zip(("owner", "migrator", "service", "operator", "read_only"),
                     ("control_plane_owner", "control_plane_migrator", "control_plane_app", "control_plane_operator", "control_plane_reader")))
    # These independent synthetic observations are test inputs, never read from
    # a deployment or reconstructed from a completed signed package.
    observation = dict(isolated_cluster_deployment_id=uid(40), database_name="qingyu_control_r1_acceptance",
                       observed_tls_origin=pin["https_origin"], server_system_identifier=str(world.seed * 1000),
                       database_oid=201, owner_oid=301, role_oids=dict(zip(roles, range(301,306))), roles=roles,
                       receipt_key_slot_reference="dpapi-localmachine://independent/synthetic", receipt_key_id=pin["receipt_key_id"],
                       external_storage_identity=uid(41))
    observed = ObservedProvisionedTarget(**deepcopy(observation))
    shared = dict(provisioning_uuid=uid(42), authority_domain_id=pin["authority_domain_id"], authority_instance_id=pin["authority_instance_id"],
                  authority_generation=1, environment="acceptance", isolated_cluster_deployment_id=observation["isolated_cluster_deployment_id"],
                  database_name=observation["database_name"], canonical_initial_revision="0001_control_plane_r1_initial",
                  initial_migration_artifact_digest=sha(b"independent-declared-migration"), authored_ddl_snapshot_digest=sha(b"independent-declared-ddl"),
                  initial_migration_dependency_version=1, initial_migration_dependency_digest=sha(b"independent-declared-dependencies"),
                  schema_contract_version=1, schema_contract_digest=sha(b"independent-declared-schema"),
                  operator_approval=dict(approval_id=uid(43), decision="APPROVE_R1_INITIAL_PROVISIONING_AND_MIGRATION", approved_at="1970-01-01T00:00:00Z"),
                  expected_fingerprint_version=1, expected_schema_fingerprint=sha(b"independent-declared-fingerprint"), roles=roles,
                  receipt_key_slot_reference=observation["receipt_key_slot_reference"], test_only=True)
    intent = dict(shared, profile="R1_PERSONAL_PRODUCTION", planned_tls_origin=pin["https_origin"], role_policy="R1_RESTRICTED_V2",
                  receipt_key_creation_policy="CREATE_AFTER_SIGNED_INTENT_IN_SECRET_BOUNDARY", operator_root_key_id=pin["operator_root_key_id"])
    cluster = {k: observation[k] for k in ("isolated_cluster_deployment_id", "server_system_identifier", "database_name", "database_oid",
              "owner_oid", "role_oids", "receipt_key_id", "external_storage_identity", "observed_tls_origin")}
    completion = dict(shared, **{k:v for k,v in observation.items() if k not in shared},
                      creation_event_timestamp="1970-01-01T00:00:00Z", cluster_binding_fingerprint=sha(b"QINGYU-CP-R1-CLUSTER-BINDING-V1\0" + rfc8785.dumps(cluster)))
    def envelope(payload, prefix):
        unsigned = dict(version=2, key_id=pin["operator_root_key_id"], payload=payload)
        return dict(unsigned, signature=world.root_key.sign(prefix + rfc8785.dumps(unsigned)).hex())
    origin_raw = rfc8785.dumps(dict(intent=envelope(intent,b"QINGYU-CP-R1-PROVISIONING-INTENT\0"),
                                   completion=envelope(completion,b"QINGYU-CP-R1-PROVISIONING-COMPLETION\0")))
    origin_digest = sha(b"QINGYU-CP-R1-PROVISIONING-ORIGIN\0" + origin_raw)
    component = b"independent-initializer-component"
    auth = sign(typed("opening_authorization", opening_id=world.identity["genesis_operation_id"], opening_kind="NEW_GENESIS", identity=world.identity,
                      source_snapshot=None, target_authority_domain_id=pin["authority_domain_id"], target_authority_instance_id=pin["authority_instance_id"],
                      target_authority_generation=1, target_storage_generation_id=material["storage_generation_id"], target_control_plane_generation_id=material["control_plane_generation_id"],
                      core_installation_id=material["core_installation_id"], initializer_principal="independent-initializer", initializer_artifact_digest=sha(component),
                      initial_or_current_owner_identity=world.owner, owner_version=1, continuity_epoch=1, state_version=0,
                      signed_origin_digest=origin_digest, deployment_admission_digest=sha(material["deployment_bytes"]), trust_config_digest=h(pin), receipt_key_id=pin["receipt_key_id"],
                      tls_origin=pin["https_origin"], tls_spki_sha256=pin["server_spki_sha256"], operator_root_key_id=pin["operator_root_key_id"],
                      issued_at=100, expires_at=1000, reason="Independent supplied genesis", root_signature="0"*128),world.root_key)
    origins = dict(identity_digest=h(world.identity),opening_authorization_digest=h(auth),signed_origin_digest=origin_digest,trust_config_digest=h(pin))
    prior_a=typed("authority_ref",wire_version=2,authority_generation=1,authority_sequence=0,receipt_hash=h(typed("authority_origin",**origins)))
    prior_c=typed("audit_ref",wire_version=2,audit_sequence=0,audit_hash=h(typed("audit_origin",**origins)))
    common=dict(opening_id=auth["opening_id"],opening_kind="NEW_GENESIS",identity_digest=h(world.identity),opening_authorization_digest=h(auth),
                source_snapshot_digest=None,state_version=0,owner_identity=world.owner,owner_version=1,continuity_epoch=1)
    candidate=typed("opening_audit_content",**common,audit_sequence=1,previous_audit_ref=prior_c)
    attempt=typed("genesis_attempt",attempt_id=uid(44),opening_id=auth["opening_id"],opening_authorization_digest=h(auth),identity_digest=h(world.identity),
                  attempt_number=1,previous_attempt_digest=None,created_at=200)
    prepare=sign(typed("opening_prepare",opening_id=auth["opening_id"],opening_authorization_digest=h(auth),audit_candidate_digest=h(candidate),genesis_attempt_digest=h(attempt),
                       **{k:auth[k] for k in ("target_authority_domain_id","target_authority_instance_id","target_authority_generation")},prepared_at=300,
                       receipt_key_id=pin["receipt_key_id"],receipt_signature="0"*128),world.receipt_key)
    receipt=sign(typed("opening_receipt",**common,opening_prepare_digest=h(prepare),
                       **{k:pin[k] for k in ("authority_domain_id","authority_instance_id","authority_generation","receipt_key_id")},authority_sequence=1,
                       previous_authority_ref=prior_a,audit_candidate_digest=h(candidate),decided_at=400,receipt_signature="0"*128),world.receipt_key)
    audit=typed("audit_record",candidate=candidate,receipt_digest=h(receipt))
    prepared=typed("genesis_attempt_event",event_id=uid(45),attempt_id=attempt["attempt_id"],previous_event_digest=None,state="PREPARED",reason_code="PREPARED",evidence_digest=raw(prepare),created_at=300)
    succeeded=typed("genesis_attempt_event",event_id=uid(46),attempt_id=attempt["attempt_id"],previous_event_digest=h(prepared),state="SUCCEEDED",reason_code="SUCCEEDED",evidence_digest=raw(receipt),created_at=400)
    binding=dict(opening_id=auth["opening_id"],runtime_principal=auth["initializer_principal"],core_installation_id=material["core_installation_id"],initializer_artifact_digest=sha(component),
                 deployment_admission_digest=sha(material["deployment_bytes"]),trust_config_digest=h(pin),purpose="LIFECYCLE_OPENING",registration_state="ACTIVE",admitted_at=100,expires_at=1000)
    world.owner_version=world.continuity_epoch=1
    world.start=typed("local_checkpoint",state_version=0,authority_ref=typed("authority_ref",wire_version=2,authority_generation=1,authority_sequence=1,receipt_hash=h(receipt)),
                      audit_ref=typed("audit_ref",wire_version=2,audit_sequence=1,audit_hash=h(audit)))
    world.cursor=deepcopy(world.start)
    world.genesis=dict(authorization=auth,prepare=prepare,receipt=receipt,audit=audit,binding=binding,component=component,attempt=attempt,events=[prepared,succeeded],
                       origin_raw=origin_raw,origin_digest=origin_digest,observed_origin=observed)
    return world.genesis


def source_evidence(world, *, snapshot_fault=None, inventory_fault=None):
    """Full original member closure, with actual Core separated from derivation."""
    from app.control_plane._r1_validation_restore import ArchiveMember, OpeningEvidence, SourceEvidence, SourceDeploymentObservation, SourceFencingObservation
    g=world.genesis
    members=[]
    def add(role,value,*,original=False):
        content=value if original else wire(value)
        if any(r==role and b==content for r,_,b in members):return
        members.append((role,1+sum(r==role for r,_,_ in members),content))
    for role,key in (("OPENING_AUTHORIZATION","authorization"),("OPENING_PREPARE","prepare"),("AUTHORITY_RECEIPT","receipt"),("CORE_AUDIT","audit"),("INITIALIZER_ADMISSION","binding")):
        add(role,g[key])
    if g["attempt"] is not None:add("GENESIS_ATTEMPT",g["attempt"])
    add("INITIALIZER_COMPONENT",g["component"],original=True)
    for event in g["events"]:add("GENESIS_ATTEMPT_EVENT",event)
    inventory=[dict(operation_id=g["authorization"]["opening_id"],wire_version=2,request_raw_sha256=raw(g["authorization"]),authorization_raw_sha256=raw(g["authorization"]),
                    terminal_ref=world.start["authority_ref"],audit_ref=world.start["audit_ref"],state="COMMITTED")]
    actual=deepcopy(world.start);last=None
    for row in world.operations:
        for role,key in (("REQUEST","request"),("PREPARE_ACK","ack"),("STAGED_EVIDENCE","stage"),("TERMINAL_AUTHORIZATION","authorization"),("AUTHORITY_RECEIPT","receipt"),
                         ("SOURCE_ADMISSION","admission"),("EXECUTION_GRANT","grant"),("RECOVERY_POLICY","policy"),("RECOVERY_INVENTORY","inventory"),("SESSION_BINDING","session"),("DISPATCH_RECORD","proposal")):
            add(role,row[key])
        for decision in ("commit","abort"):add("AUDIT_CANDIDATE",row["request"][decision]["audit_candidate"])
        complete="completion" in row
        add("CORE_AUDIT" if complete else "DERIVED_AUDIT",row["audit"])
        if complete:
            actual=deepcopy(row["after"]);last=row["completion"]
            for role,key in (("FINISH_PERMIT","permit"),("ISSUANCE_SNAPSHOT","permit_issuance"),("FINISH_TARGET","target"),("LOCAL_USE","use_snapshot"),("COMPLETION_RECORD","completion")):
                add(role,row[key])
        inventory.append(dict(operation_id=row["request"]["intent"]["operation_id"],wire_version=2,request_raw_sha256=raw(row["request"]),authorization_raw_sha256=raw(row["authorization"]),
                              terminal_ref=row["after"]["authority_ref"],audit_ref=row["after"]["audit_ref"] if complete else None,state=row["receipt"]["result_state"]))
    inventory=typed("source_operation_inventory",authority_domain_id=world.pin["authority_domain_id"],authority_generation=world.pin["authority_generation"],entries=sorted(inventory,key=lambda v:v["operation_id"]))
    if inventory_fault:inventory_fault(inventory)
    add("OPERATION_INVENTORY",inventory)
    for registry,role in ((world.authority,"AUTHORITY_REGISTRY"),(world.core,"CORE_REGISTRY"),*((c,"CORE_REGISTRY") for c in getattr(world,"extra_cores",()))):
        add(role,registry);add("REGISTRY_HEADER",registry["header"])
        for event in registry["events"]:
            add("REGISTRY_EVENT",event);add("REGISTRY_INPUT",registry["records"][event["input_digest"]])
            if event["output_digest"]:add("REGISTRY_OUTPUT",registry["records"][event["output_digest"]])
            if event["event_kind"]=="PERMIT_ISSUED":
                issuance=registry["records"][event["input_digest"]]
                add("ISSUANCE_SNAPSHOT",issuance);add("FINISH_PERMIT",registry["records"][event["output_digest"]])
                add("FINISH_TARGET",registry["records"][issuance["fences_or_target_digest"]])
            if event["event_kind"]=="APPLY":add("LOCAL_USE",registry["records"][event["input_digest"]])
    origin=g["origin_raw"];deployment=b"opaque supplied independent source deployment: "+world.deployment["runtime_principal"].encode();fencing=b"opaque supplied independent fencing evidence: "+sha(deployment).encode()
    for role,value in (("SIGNED_ORIGIN",origin),("SOURCE_DEPLOYMENT",deployment),("SOURCE_FENCING",fencing),("ROOT_PUBLIC_KEY",world.root_public),
                       ("RECEIPT_PUBLIC_KEY",bytes.fromhex(world.pin["receipt_public_key"])),("TLS_SPKI_DER",world.deployment["tls_spki_der"]),
                       ("DEPLOYMENT_ADMISSION",world.deployment["deployment_bytes"]),("RECOVERY_COMPONENT",world.deployment["component_bytes"])):
        add(role,value,original=True)
    for role,value in getattr(world,"extra_archive_members",()):add(role,value,original=True)
    add("AUTHORITY_PIN",world.pin)
    profile="ALIGNED_OPENING" if all("completion" in r for r in world.operations) else "HISTORY_ONLY_TAIL"
    add("SOURCE_PROFILE",dict(history_version=2,profile=profile,authority_tip=world.cursor["authority_ref"],actual_core_audit_tip=actual["audit_ref"],actual_core_state_version=actual["state_version"],completion_digest=raw(last) if last else None))
    members=tuple(ArchiveMember(r,i,b) for r,i,b in sorted(members))
    manifest=typed("archive_manifest",entries=[dict(role=m.role,index=m.index,byte_length=len(m.raw),sha256=sha(m.raw)) for m in members])
    capture_time=getattr(world,"source_capture_time",10000*(len(world.operations)+1))
    snapshot=typed("source_snapshot",source_kind="V2_GENERATION_RESTORE",identity=world.identity,
                   **{"source_"+k:world.pin[k] for k in ("authority_domain_id","authority_instance_id","authority_generation")},
                   authority_tip=world.cursor["authority_ref"],audit_tip=actual["audit_ref"],state_version=actual["state_version"],owner_identity=world.owner,
                   owner_version=world.owner_version,continuity_epoch=world.continuity_epoch,storage_generation_id=world.deployment["storage_generation_id"],
                   control_plane_generation_id=world.deployment["control_plane_generation_id"],signed_origin_digest=g["origin_digest"],history_archive_digest=h(manifest),
                   operation_inventory_digest=h(inventory),source_deployment_digest=sha(deployment),source_fencing_evidence_digest=sha(fencing),captured_at=capture_time)
    if snapshot_fault:snapshot_fault(snapshot)
    opening=OpeningEvidence(wire(g["authorization"]),wire(g["prepare"]),wire(g["receipt"]),wire(g["audit"]),wire(g["binding"]),g["component"],
                            (wire(g["attempt"]),) if g["attempt"] is not None else (),tuple(wire(e) for e in g["events"]),
                            previous_source=getattr(world,"previous_source",None),previous_trust=getattr(world,"previous_trust",None))
    evidence,trust,deployments=world.product_inputs()
    observation=SourceDeploymentObservation(source_deployment_digest=sha(deployment),identity_wire=wire(world.identity),authority_pin_wire=wire(world.pin),
                core_installation_id=world.deployment["core_installation_id"],storage_generation_id=world.deployment["storage_generation_id"],
                control_plane_generation_id=world.deployment["control_plane_generation_id"],owner_identity=world.owner,owner_version=world.owner_version,
                continuity_epoch=world.continuity_epoch,state_version=actual["state_version"],authority_tip_wire=wire(world.cursor["authority_ref"]),audit_tip_wire=wire(actual["audit_ref"]),
                deployment_admission_digest=sha(world.deployment["deployment_bytes"]))
    fencing_observation=SourceFencingObservation(source_fencing_evidence_digest=sha(fencing),source_deployment_digest=sha(deployment),
                authority_tip_wire=wire(world.cursor["authority_ref"]),audit_tip_wire=wire(actual["audit_ref"]),observed_at=capture_time-1,
                observed_by="independent-supplied-inspector",authority_writer_state="ISOLATED",core_writer_state="ISOLATED")
    return SourceEvidence(wire(snapshot),wire(manifest),wire(inventory),members,evidence,world.boundary(),opening,observed_origin=g["observed_origin"],
                          source_deployment_observation=observation,source_fencing_observation=fencing_observation)


def restore_case(world, *, source=None, backup_count=0, context_fault=None, target_fault=None):
    """Restore original supplied tails into a distinct local registry only."""
    from app.control_plane.r1_validation import CoreHistory, DeploymentEvidence, HistoryEvidence
    from app.control_plane._r1_validation_restore import RestoreEvidence
    source=source or source_evidence(world)
    snapshot=json.loads(source.snapshot_wire)
    g=world.genesis
    backup_checkpoint=deepcopy(world.start if backup_count==0 else world.operations[backup_count-1]["after"])
    included=world.operations[:backup_count]
    backup=dict(identity=world.identity,checkpoint=backup_checkpoint,governed_results=[r["request"][r["receipt"]["decision"].lower()]["result"] for r in included],
                receipt_wires=[wire(g["receipt"]).hex()]+[wire(r["receipt"]).hex() for r in included],
                audit_wires=[wire(g["audit"]).hex()]+[wire(r["audit"]).hex() for r in included],captured_at=500 if backup_count==0 else 10000*backup_count+800)
    target=dict(runtime_principal="independent-restored-"+str(world.seed),core_installation_id=world.uid(8000),storage_generation_id=world.uid(8001),control_plane_generation_id=world.uid(8002),
                deployment_bytes=b"independent-restored-deployment-"+str(world.seed).encode(),component_bytes=b"independent-restored-component",tls_spki_der=world.deployment["tls_spki_der"])
    authority=deepcopy(world.authority);local=register_header(world.pin,target)
    at=snapshot["captured_at"]+1000
    context=typed("restoration_context",context_id=world.uid(8010),identity=world.identity,source_snapshot=snapshot,
                  target_core_installation_id=target["core_installation_id"],target_storage_generation_id=target["storage_generation_id"],target_control_plane_generation_id=target["control_plane_generation_id"],
                  target_authority_pin_digest=h(world.pin),restore_start_checkpoint=backup_checkpoint,restore_source_state_digest=raw(backup),allowed_actions=["APPLY_VERIFIED_TERMINAL","VERIFY_HISTORY"],
                  issued_at=at,expires_at=at+100000,reason="Independent original-history restore verification",operator_root_key_id=world.pin["operator_root_key_id"],root_signature="0"*128)
    if context_fault:context_fault(context)
    context=sign(context,world.root_key)
    restored=[]
    for ordinal,row in enumerate(world.operations[backup_count:]):
        time=at+1000*(ordinal+1);uid=lambda n:world.uid(8100+ordinal*100+n)
        request,receipt=row["request"],row["receipt"]
        policy=deepcopy(row["policy"])
        policy.update(policy_id=uid(1),restoration_context_digest=h(context),issued_at=at,expires_at=at+100000,
                      capabilities=["APPLY_VERIFIED_TERMINAL","PERSIST_COORDINATION","QUERY_EXISTING"],deployment_admission_digest=sha(target["deployment_bytes"]),
                      component_artifact_digest=sha(target["component_bytes"]),**{k:target[k] for k in ("runtime_principal","core_installation_id","storage_generation_id","control_plane_generation_id")})
        policy=sign(policy,world.root_key)
        enrollment={k:policy[k] for k in ("runtime_principal","core_installation_id","restoration_context_digest","authority_domain_id","authority_instance_id","authority_generation",
                                        "storage_generation_id","control_plane_generation_id","deployment_admission_digest","component_artifact_digest","trust_config_digest")}
        enrollment.update(policy_digest=h(policy),context_kind="MANUAL_RESTORE_ADMITTED",purpose="MUTATION_RECOVERY",identity_digest=h(world.identity))
        session=dict(history_version=2,session_id=uid(2),enrollment=enrollment,issued_at=time,expires_at=time+50000)
        common=dict(operation_id=request["intent"]["operation_id"],request_digest=h(request),source_decision_digest=h(request["source_decision"]))
        inventory=typed("recovery_inventory",inventory_id=uid(3),policy_digest=h(policy),core_installation_id=target["core_installation_id"],runtime_principal=target["runtime_principal"],
                        session_id=session["session_id"],entries=[dict(common,local_commit_id=request["intent"]["local_commit_id"])])
        observation=[]
        for kind,value in (("POLICY_REGISTER",policy),("SESSION_CREATE",session),("INVENTORY_ACCEPT",inventory)):
            observation.append((append_event(authority,kind,time,value),value))
        binding=dict(runtime_principal=target["runtime_principal"],session_id=session["session_id"],policy_digest=h(policy),inventory_digest=h(inventory))
        finish_target=dict(history_version=2,identity_digest=h(world.identity),authority_pin_digest=h(world.pin),
                           **{k:policy[k] for k in ("core_installation_id","storage_generation_id","control_plane_generation_id","restoration_context_digest")},
                           **common,terminal_digest=h(receipt),before_checkpoint=row["before"],after_checkpoint=row["after"])
        if target_fault:target_fault(finish_target)
        permit_body=typed("local_finish_permit",contract_revision=2,permit_id=uid(4),permit_sequence=2 if "permit" in row else 1,**common,**binding,restoration_context_digest=h(context),
                          core_installation_id=target["core_installation_id"],terminal_digest=h(receipt),before_checkpoint=row["before"],after_checkpoint=row["after"],
                          issued_at=time+100,expires_at=time+10000,receipt_key_id=world.pin["receipt_key_id"])
        issuance=dict(history_version=2,position=position(authority),issued_at=time+100,issuance_kind="PERMIT",issuer_key_id=world.pin["receipt_key_id"],**binding,**common,
                      restoration_context_digest=h(context),issue_body_digest=raw(permit_body),fences_or_target_digest=raw(finish_target))
        permit=sign(dict(permit_body,issuance_digest=raw(issuance),receipt_signature="0"*128),world.receipt_key)
        store_record(authority,finish_target)
        observation.append((append_event(authority,"PERMIT_ISSUED",time+100,issuance,permit),permit))
        for (event,value),kind in zip(observation,("POLICY_OBSERVED","SESSION_OBSERVED","INVENTORY_OBSERVED","PERMIT_OBSERVED")):
            observe(local,event,value,kind,time+150)
        append_event(local,"LOCAL_PROTECTION",time+150,dict(history_version=2,policy_digest=h(policy),component_valid=True,policy_active=True,context_kind="MANUAL_RESTORE_ADMITTED"))
        selected=request[receipt["decision"].lower()]
        content=dict(effect_digest=h(selected["effect"]),result_digest=h(selected["result"]),audit_record_digest=h(row["audit"]))
        use=dict(history_version=2,permit_digest=h(permit),issuance_digest=raw(issuance),target_digest=raw(finish_target),terminal_digest=h(receipt),**content)
        store_record(local,finish_target);store_record(local,use)
        execution=dict(history_version=2,position=position(local),checked_at=time+200,action="APPLY_VERIFIED_TERMINAL",**binding,**common,
                       target_digest=raw(finish_target),action_input_digest=raw(use))
        completion=dict(history_version=2,position=position(local),completed_at=time+200,permit_digest=h(permit),issuance_digest=raw(issuance),local_use_digest=raw(execution),
                        **common,terminal_digest=h(receipt),target_digest=raw(finish_target),before_checkpoint=row["before"],after_checkpoint=row["after"],**content)
        append_event(local,"APPLY",time+200,execution,completion)
        restored.append(dict(policy=policy,permit=permit,issuance=issuance,target=finish_target,completion=completion))
    original,trust,deployments=world.product_inputs()
    evidence=HistoryEvidence(original.request_wires,wire(authority),original.core_histories+(CoreHistory(target["runtime_principal"],wire(local)),),
                             context_wires=(wire(context),),source_admission_wires=original.source_admission_wires)
    return dict(evidence=evidence,trust=trust,deployments=deployments+(DeploymentEvidence(**target),),chain_boundary=world.boundary(),
                restore_evidence=(RestoreEvidence(wire(context),wire(backup),source,wire(backup_checkpoint)),),
                source=source,backup=backup,context=context,authority=authority,local=local,restored=restored,world=world)


def restored_final_source(case):
    """A newly captured, now aligned source on the restored physical target."""
    from dataclasses import asdict, replace
    original=case["world"]
    assert case["restore_evidence"][0].expected_backup_checkpoint_wire == wire(original.start)
    world=copy(original)
    world.deployment=asdict(case["deployments"][-1])
    world.authority=deepcopy(case["authority"]);world.core=deepcopy(case["local"])
    world.extra_cores=(deepcopy(original.core),)
    world.operations=deepcopy(original.operations)
    for row in world.operations:row.pop("completion",None)
    for row,restored in zip(world.operations,case["restored"]):
        row.update(completion=restored["completion"],permit=restored["permit"],permit_issuance=restored["issuance"],target=restored["target"])
        completion=row["completion"]
        row["use_snapshot"]=world.core["records"][completion["local_use_digest"]]
    world.product_inputs=lambda:(case["evidence"],case["trust"],case["deployments"])
    world.source_capture_time=max(e["recorded_at"] for e in world.core["events"])+1000
    proof=case["restore_evidence"][0]
    world.extra_archive_members=[("RESTORATION_CONTEXT",proof.context_wire),("RESTORE_SOURCE_STATE",proof.backup_wire),("ARCHIVE_MANIFEST",proof.source.manifest_wire),
        ("DEPLOYMENT_ADMISSION",original.deployment["deployment_bytes"]),("RECOVERY_COMPONENT",original.deployment["component_bytes"])]
    source=source_evidence(world)
    # The original business segment still has its original storage scope; the
    # final source's current physical scope comes from the verified context.
    return replace(source,chain_boundary=original.boundary(),restoration_evidence=case["restore_evidence"])


def partial_restore_case(case, completed_count):
    """Capture a real contiguous target prefix; no fabricated APPLY is retained."""
    from dataclasses import replace
    changed=dict(case);local=deepcopy(case["local"])
    allowed={r["completion"]["operation_id"] for r in case["restored"][:completed_count]}
    # Keep an actual event prefix, stopping immediately before the next APPLY.
    for index,event in enumerate(local["events"]):
        if event["event_kind"]=="APPLY" and local["records"][event["output_digest"]]["operation_id"] not in allowed:
            local["events"]=local["events"][:index];break
    pending=[event[key] for event in local["events"] for key in ("input_digest","output_digest") if event[key] is not None];seen=set()
    def visit(value):
        if type(value) is str and value in local["records"]:pending.append(value)
        elif type(value) is dict:
            for child in value.values():visit(child)
        elif type(value) is list:
            for child in value:visit(child)
    while pending:
        key=pending.pop()
        if key not in seen:seen.add(key);visit(local["records"][key])
    reachable={wire(local["records"][key]) for key in seen}
    local["records"]={key:value for key,value in local["records"].items() if wire(value) in reachable}
    changed["local"]=local;changed["restored"]=case["restored"][:completed_count]
    evidence=case["evidence"]
    changed["evidence"]=replace(evidence,core_histories=evidence.core_histories[:-1]+(replace(evidence.core_histories[-1],raw=wire(local)),))
    return changed


def generation_after_restore(case, final_source, *, generation_increment=1, wrong_audit_previous=False):
    """Root-authorized next generation anchored in a restored final source."""
    from dataclasses import asdict
    original=case["world"];world=copy(original);source_snapshot=json.loads(final_source.snapshot_wire)
    world.pin=deepcopy(original.pin)
    world.pin.update(authority_generation=original.pin["authority_generation"]+generation_increment,authority_instance_id=world.uid(9200))
    world.deployment=asdict(case["deployments"][-1])
    world.deployment.update(runtime_principal="independent-generation-"+str(world.seed),core_installation_id=world.uid(9201),storage_generation_id=world.uid(9202),
                            control_plane_generation_id=world.uid(9203),deployment_bytes=b"independent-next-generation-deployment-"+str(world.seed).encode())
    world.authority=register_header(world.pin);world.core=register_header(world.pin,world.deployment)
    world.requests=[];world.admissions=[];world.operations=[]
    world.previous_source=final_source;world.previous_trust=case["trust"]
    pin=world.pin;at=source_snapshot["captured_at"]+1000;component=b"independent-generation-initializer"
    auth=sign(typed("opening_authorization",opening_id=world.uid(9210),opening_kind="GENERATION_RESTORE",identity=world.identity,source_snapshot=source_snapshot,
               target_authority_domain_id=pin["authority_domain_id"],target_authority_instance_id=pin["authority_instance_id"],target_authority_generation=pin["authority_generation"],
               target_storage_generation_id=world.deployment["storage_generation_id"],target_control_plane_generation_id=world.deployment["control_plane_generation_id"],
               core_installation_id=world.deployment["core_installation_id"],initializer_principal="independent-generation-initializer",initializer_artifact_digest=sha(component),
               initial_or_current_owner_identity=world.owner,owner_version=world.owner_version,continuity_epoch=world.continuity_epoch,state_version=source_snapshot["state_version"],
               signed_origin_digest=original.genesis["origin_digest"],deployment_admission_digest=sha(world.deployment["deployment_bytes"]),trust_config_digest=h(pin),
               receipt_key_id=pin["receipt_key_id"],tls_origin=pin["https_origin"],tls_spki_sha256=pin["server_spki_sha256"],operator_root_key_id=pin["operator_root_key_id"],
               issued_at=at,expires_at=at+10000,reason="Independent opening after verified target completion",root_signature="0"*128),world.root_key)
    common=dict(opening_id=auth["opening_id"],opening_kind="GENERATION_RESTORE",identity_digest=h(world.identity),opening_authorization_digest=h(auth),
                source_snapshot_digest=h(source_snapshot),state_version=source_snapshot["state_version"],owner_identity=world.owner,owner_version=world.owner_version,continuity_epoch=world.continuity_epoch)
    previous=source_snapshot["audit_tip"] if not wrong_audit_previous else original.start["audit_ref"]
    candidate=typed("opening_audit_content",**common,audit_sequence=source_snapshot["audit_tip"]["audit_sequence"]+1,previous_audit_ref=previous)
    prepare=sign(typed("opening_prepare",opening_id=auth["opening_id"],opening_authorization_digest=h(auth),audit_candidate_digest=h(candidate),genesis_attempt_digest=None,
                **{k:auth[k] for k in ("target_authority_domain_id","target_authority_instance_id","target_authority_generation")},prepared_at=at+100,receipt_key_id=pin["receipt_key_id"],receipt_signature="0"*128),world.receipt_key)
    receipt=sign(typed("opening_receipt",**common,opening_prepare_digest=h(prepare),**{k:pin[k] for k in ("authority_domain_id","authority_instance_id","authority_generation","receipt_key_id")},
                authority_sequence=1,previous_authority_ref=source_snapshot["authority_tip"],audit_candidate_digest=h(candidate),decided_at=at+200,receipt_signature="0"*128),world.receipt_key)
    audit=typed("audit_record",candidate=candidate,receipt_digest=h(receipt))
    binding=dict(opening_id=auth["opening_id"],runtime_principal=auth["initializer_principal"],core_installation_id=world.deployment["core_installation_id"],
                 initializer_artifact_digest=sha(component),deployment_admission_digest=sha(world.deployment["deployment_bytes"]),trust_config_digest=h(pin),
                 purpose="LIFECYCLE_OPENING",registration_state="ACTIVE",admitted_at=at,expires_at=at+10000)
    world.genesis=dict(authorization=auth,prepare=prepare,receipt=receipt,audit=audit,binding=binding,component=component,attempt=None,events=[],
                       origin_raw=original.genesis["origin_raw"],origin_digest=original.genesis["origin_digest"],observed_origin=original.genesis["observed_origin"])
    world.start=typed("local_checkpoint",state_version=source_snapshot["state_version"],authority_ref=typed("authority_ref",wire_version=2,authority_generation=pin["authority_generation"],authority_sequence=1,receipt_hash=h(receipt)),
                      audit_ref=typed("audit_ref",wire_version=2,audit_sequence=candidate["audit_sequence"],audit_hash=h(audit)))
    world.cursor=deepcopy(world.start);world.source_capture_time=at+1000
    source=source_evidence(world);_,trust,deployments=world.product_inputs()
    return source,trust,case["deployments"]+deployments
