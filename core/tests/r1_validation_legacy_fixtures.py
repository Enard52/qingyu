"""Synthetic original-format origin evidence; private keys stay with callers."""
from dataclasses import asdict

import rfc8785

from app.control_plane.r1_provisioning import ObservedProvisionedTarget, cluster_binding_fingerprint


def make_origin(root_private, trust, *, initial_instance_id=None):
    pin = trust.pin
    roles = {"owner": "control_plane_owner", "migrator": "control_plane_migrator",
             "service": "control_plane_app", "operator": "control_plane_operator", "read_only": "control_plane_reader"}
    # Independent synthetic inspector input, authored before signed envelopes.
    observed = ObservedProvisionedTarget(
        isolated_cluster_deployment_id="10000000-0000-0000-0000-000000000001",
        database_name="qingyu_control_r1_acceptance", observed_tls_origin=pin["https_origin"],
        server_system_identifier="9876543210123456789", database_oid=16384, owner_oid=16385,
        role_oids={"owner": 16385, "migrator": 16386, "service": 16387, "operator": 16388, "read_only": 16389},
        roles=roles, receipt_key_slot_reference="dpapi-localmachine://synthetic/r1/test",
        receipt_key_id=pin["receipt_key_id"], external_storage_identity="10000000-0000-0000-0000-000000000002",
    )
    intent = {
        "provisioning_uuid": "10000000-0000-0000-0000-000000000003",
        "authority_domain_id": pin["authority_domain_id"],
        "authority_instance_id": initial_instance_id or pin["authority_instance_id"], "authority_generation": 1,
        "environment": "acceptance", "profile": "R1_PERSONAL_PRODUCTION",
        "isolated_cluster_deployment_id": observed.isolated_cluster_deployment_id,
        "database_name": observed.database_name, "planned_tls_origin": observed.observed_tls_origin,
        "canonical_initial_revision": "0001_control_plane_r1_initial",
        "initial_migration_artifact_digest": "a" * 64, "authored_ddl_snapshot_digest": "b" * 64,
        "initial_migration_dependency_version": 1, "initial_migration_dependency_digest": "c" * 64,
        "schema_contract_version": 1, "schema_contract_digest": "d" * 64,
        "operator_approval": {"approval_id": "10000000-0000-0000-0000-000000000004",
                              "decision": "APPROVE_R1_INITIAL_PROVISIONING_AND_MIGRATION",
                              "approved_at": "2026-09-12T00:00:00Z"},
        "expected_fingerprint_version": 1, "expected_schema_fingerprint": "e" * 64,
        "roles": roles, "role_policy": "R1_RESTRICTED_V2",
        "receipt_key_slot_reference": observed.receipt_key_slot_reference,
        "receipt_key_creation_policy": "CREATE_AFTER_SIGNED_INTENT_IN_SECRET_BOUNDARY",
        "operator_root_key_id": pin["operator_root_key_id"], "test_only": True,
    }
    excluded = {"profile", "planned_tls_origin", "role_policy", "receipt_key_creation_policy", "operator_root_key_id"}
    completion = {key: value for key, value in intent.items() if key not in excluded}
    completion.update(asdict(observed), creation_event_timestamp="2026-09-13T00:00:00Z")
    completion["cluster_binding_fingerprint"] = cluster_binding_fingerprint(**{
        key: getattr(observed, key) for key in ("isolated_cluster_deployment_id", "server_system_identifier",
            "database_name", "database_oid", "owner_oid", "role_oids", "receipt_key_id",
            "external_storage_identity", "observed_tls_origin")})

    def sign(payload, prefix):
        body = {"version": 2, "key_id": pin["operator_root_key_id"], "payload": payload}
        return {**body, "signature": root_private.sign(prefix + rfc8785.dumps(body)).hex()}
    return rfc8785.dumps({
        "intent": sign(intent, b"QINGYU-CP-R1-PROVISIONING-INTENT\0"),
        "completion": sign(completion, b"QINGYU-CP-R1-PROVISIONING-COMPLETION\0"),
    }), observed


def build_legacy_source(decisions=("COMMIT", "ABORT", "COMMIT"), *, offset=0, fault=None):
    """Actual F3 V1 wire formulas, signed in memory; no original DB helper runs.

    Fault callbacks run before dependent hashes/signatures so tests can exercise
    internally consistent bad relationships, not just stale digest failures.
    """
    from collections import defaultdict
    from copy import deepcopy
    from types import SimpleNamespace
    from uuid import UUID
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from app.canonical import canonical_json
    from app.control_plane.r1_validation import (ChainBoundary, DeploymentEvidence, SourceEvidence,
        SourceDeploymentObservation, ArchiveMember)
    from app.control_plane._r1_validation_restore import SourceFencingObservation
    from app.control_plane.r1_validation_crypto import FixedTrust
    from app.control_plane.r1_validation_codec import c2, obj, sha, h2
    from app.control_plane.r1_protocol import ExpectedIntent
    from app.control_plane._r1_validation_legacy import LegacyGenesisEvidence

    def uid(n): return str(UUID(int=n + offset))
    def raw_public(key): return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    def change(name, value):
        if fault: fault(name, value)
        return value
    root, receipt_key, tls = (Ed25519PrivateKey.generate() for _ in range(3))
    der = tls.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    pin = obj("authority_pin", authority_domain_id=uid(1), authority_instance_id=uid(2), authority_generation=1,
              receipt_public_key=raw_public(receipt_key).hex(), receipt_key_id=sha(raw_public(receipt_key)),
              api_version=1, https_origin="https://legacy.example.test", server_spki_sha256=sha(der),
              operator_root_key_id=sha(raw_public(root)))
    trust = FixedTrust(c2(pin), raw_public(root))
    material = DeploymentEvidence("legacy-test-core", uid(3), uid(4), uid(5),
                                  b"synthetic V1 deployment", b"synthetic V1 component", der)
    identity = obj("identity", qingyu_identity_id=uid(6), continuity_id=uid(7), genesis_operation_id=uid(8))
    owner, domain = "legacy-owner", uid(9)
    origin_raw, observed = make_origin(root, trust)
    import json
    origin = json.loads(origin_raw)
    ip, cp = origin["intent"]["payload"], origin["completion"]["payload"]
    origin_digest = sha(b"QINGYU-CP-R1-PROVISIONING-ORIGIN\0" + origin_raw)
    ap = {"provisioning_uuid": ip["provisioning_uuid"], "signed_provisioning_origin_digest": origin_digest,
          "canonical_initial_revision": ip["canonical_initial_revision"], "fingerprint_version": 1,
          "schema_fingerprint": ip["expected_schema_fingerprint"], "initial_migration_artifact_digest": ip["initial_migration_artifact_digest"],
          "database_name": ip["database_name"], "server_system_identifier": cp["server_system_identifier"],
          "cluster_binding_fingerprint": cp["cluster_binding_fingerprint"], "authority_domain_id": pin["authority_domain_id"],
          "authority_instance_id": pin["authority_instance_id"], "authority_generation": 1,
          "receipt_key_id": pin["receipt_key_id"], "observed_at": "2026-09-13T00:00:01Z", "test_only": True}
    body = {"version": 1, "key_id": pin["operator_root_key_id"], "payload": ap}
    attestation_raw = rfc8785.dumps({**body, "signature": root.sign(b"QINGYU-CP-R1-INITIAL-MIGRATION-ATTESTATION\0" + rfc8785.dumps(body)).hex()})
    roles = defaultdict(list)
    def add(role, raw): roles[role].append(raw)
    def sign(value, prefix, field):
        body = {**value, "receipt_key_id": pin["receipt_key_id"]}
        return {**body, field: receipt_key.sign(prefix + rfc8785.dumps(body)).hex()}
    def audit_value(seq, state, operation, mutation, decision, previous, payload_hash):
        return {"audit_seq": seq, "trust_domain_id": domain, "continuity_id": identity["continuity_id"],
                "continuity_epoch": 1, "state_version": state,
                "operation_type": "AUTHORITY_GENESIS_ACTIVATION" if seq == 1 else "GOVERNED_MUTATION",
                "actor_principal_id": owner, "capability": "core_governance", "request_id": operation,
                "mutation_id": mutation, "result_code": decision, "payload_hash": payload_hash,
                "previous_record_hash": previous, "created_at": "2026-09-13T00:01:00+00:00"}
    def request_value(op, kind, state, payload):
        return {"schema_version": 1, **{k: pin[k] for k in ("authority_domain_id", "authority_instance_id", "authority_generation")},
                "qingyu_identity_id": identity["qingyu_identity_id"], "continuity_id": identity["continuity_id"],
                "operation_id": op, "operation_type": kind, "expected_continuity_epoch": 0 if kind != "MUTATION" else 1,
                "expected_state_version": state, "expected_owner_version": 0 if kind != "MUTATION" else 1,
                "actor_or_owner_identity": owner, "caller_runtime_id": uid(10), "storage_generation_id": material.storage_generation_id,
                "payload": payload, "reason": "synthetic actual V1 wire"}
    def make_ack(req, expected):
        ack = {"ack_version": 1, **{k: req[k] for k in ("authority_domain_id", "authority_instance_id", "authority_generation",
               "qingyu_identity_id", "continuity_id", "operation_id", "operation_type", "caller_runtime_id", "storage_generation_id",
               "expected_continuity_epoch", "expected_owner_version", "expected_state_version")},
               **asdict(expected), "state": "PREPARED", "prepared_at": "2026-09-13T00:01:00Z"}
        return sign(change("ack", ack), b"QINGYU-CP-R1-PREPARE-ACK\0", "ack_signature")
    def make_receipt(req, expected, seq, previous, result, outcome):
        receipt = {"receipt_version": 1, "schema_version": 1,
            **{k: req[k] for k in ("authority_domain_id", "authority_instance_id", "authority_generation", "qingyu_identity_id",
               "continuity_id", "operation_id", "operation_type", "actor_or_owner_identity", "storage_generation_id")},
            **asdict(expected), "result_state": outcome, "result_code": "ACTIVATED" if seq == 1 else outcome,
            "continuity_epoch": 1, "control_plane_generation_id": material.control_plane_generation_id, "owner_version": 1,
            "lease_generation": None if seq == 1 else 1, "authority_sequence": seq, "previous_receipt_hash": previous,
            "result_payload_hash": sha(rfc8785.dumps(result)), "decided_at": "2026-09-13T00:01:01Z",
            "signed_provisioning_origin_digest": origin_digest if seq == 1 else None, "previous_generation": None,
            "previous_generation_sequence": None, "previous_generation_head_hash": None, "signed_dr_artifact_digest": None}
        return sign(change("receipt", receipt), b"QINGYU-CP-R1-AUTHORITY-RECEIPT\0", "receipt_signature")
    def checkpoint(receipt, audit, audit_raw):
        return obj("local_checkpoint", state_version=audit["state_version"],
            authority_ref=obj("authority_ref", wire_version=1, authority_generation=1, authority_sequence=receipt["authority_sequence"],
                             receipt_hash=sha(b"QINGYU-CP-R1-AUTHORITY-RECEIPT\0" + rfc8785.dumps(receipt))),
            audit_ref=obj("audit_ref", wire_version=1, audit_sequence=audit["audit_seq"], audit_hash=sha(audit_raw)))
    request = request_value(identity["genesis_operation_id"], "AUTHORITY_GENESIS_ACTIVATION", 0, {"synthetic_test_genesis": True})
    audit = change("genesis_audit", audit_value(1, 1, identity["genesis_operation_id"], None, "COMMITTED", None, "a" * 64))
    audit_raw = canonical_json(audit)
    result = {"synthetic_test_genesis": True}
    expected = ExpectedIntent(sha(rfc8785.dumps(request)), sha(audit_raw), "0"*64, sha(audit_raw))
    ack = make_ack(request, expected)
    seed = sha(b"QINGYU-CP-R1-GENESIS-HEAD\0" + rfc8785.dumps({"authority_domain_id": pin["authority_domain_id"],
        "authority_instance_id": pin["authority_instance_id"], "authority_generation": 1, "provisioning_uuid": ip["provisioning_uuid"],
        "signed_provisioning_origin_digest": origin_digest, "receipt_key_id": pin["receipt_key_id"], "operator_root_key_id": pin["operator_root_key_id"]}))
    receipt = make_receipt(request, expected, 1, seed, result, "COMMITTED")
    initial = checkpoint(receipt, audit, audit_raw)
    genesis = {"operation_id": identity["genesis_operation_id"], "request_envelope": request, "prepare_ack": ack,
        "receipt_payload": receipt, "receipt_hash": initial["authority_ref"]["receipt_hash"], **asdict(expected),
        **{k: identity[k] for k in ("genesis_operation_id", "qingyu_identity_id", "continuity_id")}}
    legacy = LegacyGenesisEvidence(rfc8785.dumps(genesis), expected, audit_raw, rfc8785.dumps(result), attestation_raw, "R1_ACCEPTANCE_TEST_ONLY")
    for role, raw in (("SOURCE_ADMISSION", legacy.evidence_wire), ("SOURCE_ADMISSION", attestation_raw),
                      ("REQUEST", rfc8785.dumps(request)), ("PREPARE_ACK", rfc8785.dumps(ack)),
                      ("AUTHORITY_RECEIPT", rfc8785.dumps(receipt)), ("CORE_AUDIT", audit_raw), ("REGISTRY_OUTPUT", legacy.result_wire)):
        add(role, raw)
    entries = [{"operation_id": identity["genesis_operation_id"], "wire_version": 1,
        "request_raw_sha256": sha(rfc8785.dumps(request)), "authorization_raw_sha256": None,
        "terminal_ref": initial["authority_ref"], "audit_ref": initial["audit_ref"], "state": "COMMITTED"}]
    prior = initial
    for i, decision in enumerate(decisions, 2):
        op, mutation = uid(100+i), "legacy-mutation-" + str(i+offset)
        value = {"payload": {"counter": i, "message": "晴雨", "fraction": 1e-7}, "capability": "core_governance", "requested_decision": decision}
        audits = [change("candidate_"+outcome, audit_value(i, prior["state_version"]+(outcome=="COMMITTED"), op, mutation, outcome,
                  prior["audit_ref"]["audit_hash"], sha(canonical_json({"mutation_id": mutation, "value": value["payload"], "decision": outcome}))))
                  for outcome in ("COMMITTED", "ABORTED")]
        audit_raws = tuple(canonical_json(a) for a in audits)
        staged = {"mutation_id": mutation, "state_version": prior["state_version"]+1, "value": value}
        aborted = {"mutation_id": mutation, "state_version": prior["state_version"], "result_state": "ABORTED", "core_audit_candidate_hash": sha(audit_raws[1])}
        payload = {"payload_version": 1, "mutation_id": mutation, "local_commit_id": uid(200+i), "lease_id": uid(11), "lease_generation": 1,
            "session_id": uid(12), "control_plane_generation_id": material.control_plane_generation_id,
            "genesis_operation_id": identity["genesis_operation_id"], "staged_result": staged, "staged_result_hash": sha(rfc8785.dumps(staged)),
            "core_audit_predecessor_hash": prior["audit_ref"]["audit_hash"], "core_audit_candidate_hash": sha(audit_raws[0]),
            "abort_result": aborted, "abort_result_hash": sha(rfc8785.dumps(aborted))}
        request = change("request", request_value(op, "MUTATION", prior["state_version"], payload))
        request_raw = rfc8785.dumps(request)
        expected = ExpectedIntent(sha(request_raw), payload["staged_result_hash"], payload["core_audit_predecessor_hash"], payload["core_audit_candidate_hash"])
        ack_raw = rfc8785.dumps(make_ack(request, expected))
        stage_raw = b"QINGYU-R1-CORE-STAGED-EVIDENCE-V1\0" + request_raw + ack_raw + b"".join(audit_raws)
        auth = {"authorization_version": 1, "decision": decision, "operation_id": op, "request_envelope_hash": sha(request_raw),
            **{k: payload[k] for k in ("local_commit_id", "staged_result_hash", "core_audit_predecessor_hash", "core_audit_candidate_hash")}}
        auth.update({"transaction_evidence_hash": sha(stage_raw)} if decision=="COMMIT" else {"abort_evidence_hash": sha(stage_raw), "no_local_business_commit": True})
        auth_raw = rfc8785.dumps(change("authorization", auth))
        outcome = "COMMITTED" if decision=="COMMIT" else "ABORTED"
        receipt = make_receipt(request, expected, i, prior["authority_ref"]["receipt_hash"], staged if decision=="COMMIT" else aborted, outcome)
        receipt_raw = rfc8785.dumps(receipt)
        selected = 0 if decision=="COMMIT" else 1
        after = checkpoint(receipt, audits[selected], audit_raws[selected])
        source = {"continuity_id": identity["continuity_id"], "continuity_epoch": 1, "lease_id": payload["lease_id"], "mutation_id": mutation,
                  "actor_principal_id": owner, "capability": "core_governance", "payload": value["payload"], "_r1_decision": decision}
        for role, raw in (("SOURCE_REQUEST", rfc8785.dumps(source)), ("REQUEST", request_raw), ("PREPARE_ACK", ack_raw),
                          ("STAGED_EVIDENCE", stage_raw), ("TERMINAL_AUTHORIZATION", auth_raw), ("AUTHORITY_RECEIPT", receipt_raw),
                          ("CORE_AUDIT", audit_raws[selected]), ("AUDIT_CANDIDATE", audit_raws[0]), ("AUDIT_CANDIDATE", audit_raws[1])):
            add(role, raw)
        entries.append({"operation_id": op, "wire_version": 1, "request_raw_sha256": sha(request_raw), "authorization_raw_sha256": sha(auth_raw),
                        "terminal_ref": after["authority_ref"], "audit_ref": after["audit_ref"], "state": outcome})
        prior = after
    inventory = obj("source_operation_inventory", authority_domain_id=pin["authority_domain_id"], authority_generation=1,
                    entries=sorted(entries, key=lambda e:e["operation_id"]))
    deployment_raw, fencing_raw = b"synthetic inspected V1 source deployment", b"synthetic V1 offline fence observation"
    profile = {"history_version": 2, "profile": "ALIGNED_OPENING", "authority_tip": prior["authority_ref"],
               "actual_core_audit_tip": prior["audit_ref"], "actual_core_state_version": prior["state_version"], "completion_digest": None}
    for role, raw in (("DEPLOYMENT_ADMISSION", material.deployment_bytes), ("RECOVERY_COMPONENT", material.component_bytes),
        ("TLS_SPKI_DER", der), ("AUTHORITY_PIN", trust.pin_wire), ("ROOT_PUBLIC_KEY", trust.root_public_key),
        ("RECEIPT_PUBLIC_KEY", raw_public(receipt_key)), ("SIGNED_ORIGIN", origin_raw), ("OPERATION_INVENTORY", c2(inventory)),
        ("SOURCE_DEPLOYMENT", deployment_raw), ("SOURCE_FENCING", fencing_raw), ("SOURCE_PROFILE", c2(profile))): add(role, raw)
    members = tuple(ArchiveMember(role, i, raw) for role in sorted(roles) for i, raw in enumerate(roles[role]))
    manifest = obj("archive_manifest", entries=[{"role": m.role, "index": m.index, "byte_length": len(m.raw), "sha256": sha(m.raw)} for m in members])
    snapshot = obj("source_snapshot", source_kind="V1_OFFLINE_UPGRADE", identity=identity,
        **{"source_"+k: pin[k] for k in ("authority_domain_id", "authority_instance_id", "authority_generation")},
        authority_tip=prior["authority_ref"], audit_tip=prior["audit_ref"], state_version=prior["state_version"],
        owner_identity=owner, owner_version=1, continuity_epoch=1, storage_generation_id=material.storage_generation_id,
        control_plane_generation_id=material.control_plane_generation_id, signed_origin_digest=origin_digest,
        history_archive_digest=h2(manifest), operation_inventory_digest=h2(inventory), source_deployment_digest=sha(deployment_raw),
        source_fencing_evidence_digest=sha(fencing_raw), captured_at=1_800_000_000_000)
    boundary = ChainBoundary(c2(identity), c2(initial), c2(prior), owner, 1, 1, material.storage_generation_id, material.control_plane_generation_id, domain)
    observation = SourceDeploymentObservation(sha(deployment_raw), c2(identity), trust.pin_wire, material.core_installation_id,
        material.storage_generation_id, material.control_plane_generation_id, owner, 1, 1, prior["state_version"],
        c2(prior["authority_ref"]), c2(prior["audit_ref"]), sha(material.deployment_bytes))
    source = SourceEvidence(c2(snapshot), c2(manifest), c2(inventory), members, None, boundary, None,
                            observed_origin=observed, legacy=legacy, source_deployment_observation=observation,
                            source_fencing_observation=SourceFencingObservation(sha(fencing_raw), sha(deployment_raw),
                                c2(prior["authority_ref"]), c2(prior["audit_ref"]), snapshot["captured_at"],
                                "synthetic independent inspector", "ISOLATED", "ISOLATED"))
    return SimpleNamespace(source=source, trust=trust, deployments=(material,), pin=pin, root=root,
                           receipt_key=receipt_key, before=initial, after=prior, identity=identity)
