"""Synthetic-only differential tests against the immutable pre-amendment blobs."""
import ast
import copy
from dataclasses import FrozenInstanceError, replace
from datetime import timedelta
import json
import os
from pathlib import Path
import subprocess
import sys
from types import ModuleType, SimpleNamespace

import pytest

from app.b2_genesis_authorization import (
    GenesisPreapprovalRequestCommitment, GenesisAuthorizationContext,
    GenesisAuthorizationVerifier, VerifiedGenesisAuthorization, NON_PRODUCTION,
    prepare_genesis_approval_request_commitment, genesis_authorization_context)
from app.b2_signer_trust import AuthorityEnvironmentMode
from app.b2_activation_lifecycle import activation_hash
from app.control_plane.r1_validation_codec import c2, decode, sha
from app.errors import CoreError
from app.r1_scoped_activation_core import ScopedV2PostgresCore, genesis_request_proof, encode_opening
from tests.test_b2_activation_lifecycle import (
    pg, scenario, authority, dependencies, table_bytes, resigned_proof)
from tests.test_b2_genesis_authorization import anchored, args

HEAD = "19f4943b68bc0f8559c1c9a91db03340431282bd"
LINEAGE = "NON_PRODUCTION:foundation-fixture"
ROOT = Path(__file__).resolve().parents[1]


def record(name, body):
    folder = os.environ.get("QINGYU_PREAPPROVAL_CASE_EVIDENCE")
    if folder:
        destination = Path(folder)
        destination.mkdir(exist_ok=True)
        (destination / (name + ".json")).write_text(json.dumps(body, indent=2, default=str) + "\n", encoding="utf-8")


def frozen(path, name):
    module = ModuleType("app." + name)
    module.__package__ = "app"
    sys.modules[module.__name__] = module
    source = subprocess.check_output(["git", "show", HEAD + ":" + path], cwd=ROOT)
    exec(compile(source, "frozen:" + HEAD + ":" + path, "exec"), module.__dict__)
    return module


def preview(s, **updates):
    kw = dict(authority_reference=s.target.authority_reference, intent_id=s.intent.intent_id,
              opening=s.proof, activation_approval=s.approval, synthetic_foundation_checkpoint=LINEAGE)
    kw.update(updates)
    return prepare_genesis_approval_request_commitment(s.core, **kw)


def approve(s, commitment):
    # In-memory SYNTHETIC_ONLY objects; no real decision or Git object is written.
    body = {**decode(commitment.wire), "schema_version": "qingyu-genesis-owner-authorization-v1",
            "decision": "APPROVE_SYNTHETIC_V2_NEW_GENESIS",
            "provenance": {"version": "thread-owner-checkpoint-v1",
                           "authorization_reference": "NON_PRODUCTION:preapproval-owner-fixture",
                           "authorization_sha256": "3" * 64}}
    evidence, verifier = anchored(body)
    s.core._genesis_authorization_verifier = verifier
    s.core.recovery_verifier = lambda: None
    context = genesis_authorization_context(s.core, **args(s))
    return evidence, context, verifier, verifier.verify(evidence, context)


@pytest.mark.parametrize("vector", range(6))
def test_frozen_golden_hash_and_identity_equivalence(scenario, vector):
    s = scenario
    s.control.create_authority(authority_reference=s.target.authority_reference, created_at=s.now,
                               provenance_record={"synthetic": True, "vector": vector})
    s.control.persist_smi(s.intent, authority_reference=s.target.authority_reference, now=s.now)
    before = table_bytes(s)
    old = frozen("app/b2_genesis_authorization.py", "_preapproval_frozen_authorization")
    # Placeholder verifier is historical synthetic fixture scaffolding ONLY.
    s.core._genesis_authorization_verifier = old.GenesisAuthorizationVerifier(
        NON_PRODUCTION, "0" * 40, "1" * 40, "2" * 64, LINEAGE)
    expected = old.genesis_authorization_context(s.core, **args(s))
    s.core._genesis_authorization_verifier = None
    commitment = preview(s)
    assert commitment.wire == expected.wire
    assert type(commitment) is GenesisPreapprovalRequestCommitment
    assert table_bytes(s) == before == (None, None, None)
    evidence, context, verifier, cap = approve(s, commitment)
    assert commitment.wire == context.wire
    assert commitment.genesis_request_hash == decode(expected.wire)["genesis_request_hash"]
    actual = s.core.execute_new_genesis(**args(s), now=s.now, authorization=cap)
    old_core = frozen("app/r1_scoped_activation_core.py", "_preapproval_frozen_core")
    original = old_core.ScopedV2PostgresCore(s.url(s.core_db), database=s.core_db, control=s.control,
        configuration=s.configuration, mode=AuthorityEnvironmentMode.SYNTHETIC_PRODUCTION_TEST,
        genesis_authorization_verifier=verifier)
    try:
        replay = original.execute_new_genesis(**args(s), now=s.now, authorization=cap)
        assert replay["outcome"] == "GENESIS_ALREADY_DURABLE"
        for field in ("identity", "identity_hash", "proof_wire", "genesis_hash", "checkpoint"):
            assert actual[field] == replay[field]
        assert actual["genesis_hash"] == commitment.genesis_request_hash
        assert s.core.execute_new_genesis(**args(s), now=s.now, authorization=cap)["outcome"] == "GENESIS_ALREADY_DURABLE"
    finally:
        original.engine.dispose()
    record("golden-" + str(vector), {"PASS": True, "old_context_hash": sha(expected.wire),
        "new_commitment_context_hash": sha(commitment.wire), "post_approval_context_hash": sha(context.wire),
        "genesis_request_hash": commitment.genesis_request_hash, "identity_hash": actual["identity_hash"],
        "proof_wire_hash": sha(bytes.fromhex(actual["proof_wire"])), "proof_wire": actual["proof_wire"],
        "frozen_replay": replay["outcome"]})


def test_commitment_readonly_without_pins_restart_and_new_process(scenario):
    s = scenario
    a, smi = dependencies(s)
    assert s.core.genesis_authorization_verifier is None
    start = len(s.statements)
    commitment = preview(s)
    assert all(statement.lstrip().upper().startswith("SELECT") for statement in s.statements[start:])
    assert table_bytes(s) == (None, None, None)
    for engine in (s.core.engine, s.control.engine):
        engine.dispose()
    assert preview(s).wire == commitment.wire
    assert preview(s, activation_approval=s.approval.model_copy(deep=True)).wire == commitment.wire
    data = dict(authority=a.wire.hex(), smi=smi.wire.hex(), opening=encode_opening(s.proof).hex(),
                approval=s.approval.model_dump(mode="json"))
    program = """import json,sys
from app.b2_activation_readiness import OwnerApproval
from app.r1_scoped_activation_core import genesis_request_proof,decode_opening
d=json.load(sys.stdin)
_,h=genesis_request_proof(authority_wire=bytes.fromhex(d['authority']),smi_wire=bytes.fromhex(d['smi']),opening=decode_opening(bytes.fromhex(d['opening'])),activation_approval=OwnerApproval.model_validate(d['approval']))
print(h)
"""
    cp = subprocess.run([sys.executable, "-B", "-c", program], cwd=ROOT,
                        input=json.dumps(data).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # Raw bytes/returncode retained before parsing; stdin contains public fixtures only.
    record("restart-raw-capture", {"stdout_hex": cp.stdout.hex(), "stderr_hex": cp.stderr.hex(),
                                   "returncode": cp.returncode, "RAW_CAPTURE_BEFORE_PARSE": True})
    assert cp.returncode == 0
    assert cp.stdout.decode().strip() == commitment.genesis_request_hash
    assert table_bytes(s) == (None, None, None)
    record("readonly-restart", {"PASS": True, "no_verifier": True, "new_process_hash": commitment.genesis_request_hash,
                                "new_read_connections": True, "derivation_statements": "SELECT_ONLY", "durable_core_rows": 0})


def test_valid_and_forged_commitments_never_cross_real_gate(scenario, monkeypatch):
    s = scenario
    dependencies(s)
    commitment = preview(s)
    with pytest.raises(FrozenInstanceError):
        commitment.wire = b"forged"
    forged = copy.deepcopy(commitment)
    object.__setattr__(forged, "wire", c2({"genesis_request_hash": "0" * 64}))
    fake = SimpleNamespace(mode=AuthorityEnvironmentMode.REAL_PRODUCTION, genesis_authorization_verifier=None)
    fake._verify_genesis_authorization = lambda value, **kw: ScopedV2PostgresCore._verify_genesis_authorization(fake, value, **kw)
    monkeypatch.setenv("ALLOW_GENESIS", "YES")
    attacks = [None, commitment, copy.copy(commitment), copy.deepcopy(commitment), forged,
               True, "APPROVE_REAL_V2_NEW_GENESIS", {"owner_approved": True}, s.approval]
    for attack in attacks:
        with pytest.raises(CoreError, match="GENESIS_FINAL_OWNER_CONFIRMATION_REQUIRED"):
            ScopedV2PostgresCore.execute_new_genesis(fake, **args(s), now=s.now, authorization=attack)
    assert table_bytes(s) == (None, None, None)
    assert not isinstance(commitment, VerifiedGenesisAuthorization)
    record("commitment-forgery", {"PASS": True, "attempts_rejected": len(attacks), "valid_preview_exists": True,
                                  "real_adapter_constructed": False, "real_GENESIS_attempt": False, "durable_core_rows": 0})


@pytest.mark.parametrize("changed", ["approval_id", "approved_at", "opening"])
def test_stale_owner_binding_recomputed_and_rejected(scenario, changed):
    s = scenario
    dependencies(s)
    commitment = preview(s)
    e, context, verifier, cap = approve(s, commitment)
    if changed == "opening":
        s.proof = resigned_proof(s, reason="NON_PRODUCTION:changed-opening")
    else:
        value = s.approval.approval_id + "-changed" if changed == "approval_id" else s.approval.approved_at + timedelta(seconds=1)
        s.approval = s.approval.model_copy(update={changed: value})
    changed_commitment = preview(s)
    assert changed_commitment.genesis_request_hash != commitment.genesis_request_hash
    current = genesis_authorization_context(s.core, **args(s))
    with pytest.raises(CoreError, match="GENESIS_REQUEST_MISMATCH"):
        verifier.verify(e, current)
    with pytest.raises(CoreError, match="GENESIS_REQUEST_MISMATCH"):
        s.core.execute_new_genesis(**args(s), now=s.now, authorization=cap)
    assert table_bytes(s) == (None, None, None)
    record("stale-" + changed, {"PASS": True, "old_hash": commitment.genesis_request_hash,
                               "new_hash": changed_commitment.genesis_request_hash, "durable_core_rows": 0})


@pytest.mark.parametrize("field", ["target_database", "adapter", "foundation_checkpoint"])
def test_context_only_constraints_not_falsely_injected_into_proof_hash(scenario, field):
    s = scenario
    dependencies(s)
    commitment = preview(s)
    e, context, verifier, _ = approve(s, commitment)
    if field == "foundation_checkpoint":
        changed = preview(s, synthetic_foundation_checkpoint="NON_PRODUCTION:other-foundation")
    else:
        cloned = copy.copy(s.core)
        setattr(cloned, "database" if field == "target_database" else "route", "NON_PRODUCTION:changed")
        changed = prepare_genesis_approval_request_commitment(cloned, authority_reference=s.target.authority_reference,
            intent_id=s.intent.intent_id, opening=s.proof, activation_approval=s.approval,
            synthetic_foundation_checkpoint=LINEAGE)
    assert changed.genesis_request_hash == commitment.genesis_request_hash
    assert changed.wire != commitment.wire
    with pytest.raises(CoreError):
        verifier.verify(e, GenesisAuthorizationContext(changed.wire))
    assert table_bytes(s) == (None, None, None)
    record("context-binding-" + field, {"PASS": True, "proof_hash_unchanged": True,
                                       "context_changed": True, "approval_mismatch_rejected": True})


@pytest.mark.parametrize("method", ["read_authority", "read_smi"])
def test_failed_read_does_not_produce_commitment_or_authority(scenario, monkeypatch, method):
    s = scenario
    dependencies(s)
    def unavailable(*args):
        raise CoreError("SYNTHETIC_READ_UNAVAILABLE")
    monkeypatch.setattr(s.control, method, unavailable)
    with pytest.raises(CoreError, match="SYNTHETIC_READ_UNAVAILABLE"):
        preview(s)
    assert table_bytes(s) == (None, None, None)


def test_missing_dependency_is_not_a_ready_commitment(scenario):
    s = scenario
    with pytest.raises(CoreError, match="AUTHORITY_MISMATCH"):
        preview(s)
    authority(s)
    with pytest.raises(CoreError, match="AUTHORITY_MISMATCH"):
        preview(s)
    assert table_bytes(s) == (None, None, None)


def test_every_original_proof_field_and_nested_wire_leaf_is_hash_sensitive(scenario):
    s = scenario
    a, smi = dependencies(s)
    kw = dict(authority_wire=a.wire, smi_wire=smi.wire, opening=s.proof, activation_approval=s.approval)
    _, baseline = genesis_request_proof(**kw)
    changed = []
    def paths(obj, prefix=()):
        if isinstance(obj, dict):
            for k, v in obj.items(): yield from paths(v, prefix + (k,))
        elif isinstance(obj, list):
            for i, v in enumerate(obj): yield from paths(v, prefix + (i,))
        else: yield prefix
    for name, wire in (("authority_wire", a.wire), ("smi_wire", smi.wire)):
        body = decode(wire)
        for path in paths(body):
            altered = copy.deepcopy(body)
            parent = altered
            for part in path[:-1]: parent = parent[part]
            parent[path[-1]] = {"NON_PRODUCTION_hash_sensitivity": True}
            _, result = genesis_request_proof(**{**kw, name: c2(altered)})
            assert result != baseline
            changed.append(name + "/" + "/".join(map(str, path)))
    for field in type(s.approval).model_fields:
        body = s.approval.model_dump(mode="json")
        body[field] = "NON_PRODUCTION:changed"
        altered = SimpleNamespace(model_dump=lambda **kw: body)
        # Unvalidated public projection deliberately tests pure hash sensitivity.
        _, result = genesis_request_proof(**{**kw, "activation_approval": altered})
        assert result != baseline
        changed.append("owner_approval/" + field)
    for field in ("authorization_wire", "prepare_wire", "receipt_wire", "audit_wire", "initializer_binding_wire",
                  "initializer_component_bytes", "attempt_wires", "attempt_event_wires", "attempt_evidence_wires"):
        old = getattr(s.proof, field)
        value = old + (b"NON_PRODUCTION_changed",) if isinstance(old, tuple) else old + b"NON_PRODUCTION_changed"
        _, result = genesis_request_proof(**{**kw, "opening": replace(s.proof, **{field: value})})
        assert result != baseline
        changed.append("opening_wire/" + field)
    assert genesis_request_proof(**kw, schema_version="NON_PRODUCTION:changed")[1] != baseline
    changed.append("schema_version")
    record("field-sensitivity", {"PASS": True, "baseline": baseline, "changed_one_at_a_time": changed,
        "count": len(changed), "scope": "Pure hash semantics only; deliberately invalid replacement leaves are not eligible execution requests.",
        "context_only_dimensions": ["classification", "foundation_checkpoint", "target_database", "adapter"]})


def test_production_foundation_metadata_fixed_without_production_access():
    fake = SimpleNamespace(mode=AuthorityEnvironmentMode.REAL_PRODUCTION)
    with pytest.raises(CoreError, match="FOUNDATION_CHECKPOINT_MISMATCH"):
        prepare_genesis_approval_request_commitment(fake, authority_reference="UNREAD", intent_id="UNREAD",
            opening=None, activation_approval=None, synthetic_foundation_checkpoint=LINEAGE)


@pytest.mark.parametrize("lineage", ["authority", "smi"])
def test_replaced_readback_lineage_invalidates_old_owner_checkpoint(scenario, lineage):
    s = scenario
    a, smi = dependencies(s)
    commitment = preview(s)
    evidence, _, verifier, cap = approve(s, commitment)
    authority_body, smi_body = a.payload, smi.payload
    if lineage == "authority":
        authority_body["provenance"] = {"synthetic": True, "replaced_readback": True}
        wire = c2(authority_body)
        a = replace(a, wire=wire, record_hash=activation_hash("authority", wire))
        smi_body["authority_hash"] = a.record_hash
    else:
        # Signature reference is not signed payload; signature and first approval
        # remain valid. Exact durable SMI wire/hash nevertheless changes.
        smi_body["intent"]["signature_metadata"]["signature_ref"] += "-replacement"
    wire = c2(smi_body)
    smi = replace(smi, wire=wire, record_hash=activation_hash("smi", wire))
    # Substitute a readback snapshot, not storage: no mutation API/DDL is used.
    s.core.control = SimpleNamespace(target=s.target, read_authority=lambda ref: a, read_smi=lambda ref: smi)
    replacement = preview(s)
    assert replacement.genesis_request_hash != commitment.genesis_request_hash
    current = genesis_authorization_context(s.core, **args(s))
    with pytest.raises(CoreError, match="(AUTHORITY|SMI)_MISMATCH"):
        verifier.verify(evidence, current)
    with pytest.raises(CoreError, match="(AUTHORITY|SMI)_MISMATCH"):
        s.core.execute_new_genesis(**args(s), now=s.now, authorization=cap)
    assert table_bytes(s) == (None, None, None)
    record("replaced-" + lineage, {"PASS": True, "old_hash": commitment.genesis_request_hash,
        "new_hash": replacement.genesis_request_hash, "readback_snapshot_replaced_only": True,
        "approval_reverification_rejected": True, "durable_core_rows": 0})


def test_production_shaped_pure_projection_needs_no_genesis_pins(scenario):
    s = scenario
    a, smi = dependencies(s)
    # Shape-only unit object backed by in-memory SYNTHETIC readbacks. It is not
    # a REAL adapter, has no engine, and cannot connect to a production target.
    view = SimpleNamespace(mode=AuthorityEnvironmentMode.REAL_PRODUCTION, database="qingyu_prod",
        route=s.core.route, configuration=s.configuration,
        control=SimpleNamespace(target=s.target, read_authority=lambda ref: a, read_smi=lambda ref: smi))
    commitment = prepare_genesis_approval_request_commitment(view,
        authority_reference=s.target.authority_reference, intent_id=s.intent.intent_id,
        opening=s.proof, activation_approval=s.approval)
    from app.b2_genesis_authorization import FOUNDATION_CHECKPOINT
    body = decode(commitment.wire)
    assert body["classification"] == "PRODUCTION" and body["foundation_checkpoint"] == FOUNDATION_CHECKPOINT
    assert commitment.genesis_request_hash == preview(s).genesis_request_hash
    assert not hasattr(view, "genesis_authorization_verifier")
    assert table_bytes(s) == (None, None, None)
    record("production-shaped-projection", {"PASS": True, "fixed_foundation": FOUNDATION_CHECKPOINT,
        "no_second_owner_verifier_or_pins": True, "pure_synthetic_readbacks_only": True,
        "production_adapter_constructed": False, "production_connections": 0})


def test_verifier_and_transaction_AST_preserved_except_pure_hash_extraction():
    old_auth = ast.parse(subprocess.check_output(["git", "show", HEAD + ":app/b2_genesis_authorization.py"], cwd=ROOT))
    new_auth = ast.parse((ROOT / "app/b2_genesis_authorization.py").read_text("utf-8-sig"))
    for name in ("GenesisAuthorizationEvidence", "GenesisAuthorizationContext", "VerifiedGenesisAuthorization", "GenesisAuthorizationVerifier"):
        before = next(n for n in old_auth.body if isinstance(n, ast.ClassDef) and n.name == name)
        after = next(n for n in new_auth.body if isinstance(n, ast.ClassDef) and n.name == name)
        assert ast.dump(before) == ast.dump(after)
    old = ast.parse(subprocess.check_output(["git", "show", HEAD + ":app/r1_scoped_activation_core.py"], cwd=ROOT))
    new = ast.parse((ROOT / "app/r1_scoped_activation_core.py").read_text("utf-8-sig"))
    def methods(tree):
        return {n.name: n for c in tree.body if isinstance(c, ast.ClassDef) for n in c.body if isinstance(n, ast.FunctionDef)}
    before, after = methods(old), methods(new)
    class RestoreReadbackHashCall(ast.NodeTransformer):
        def visit_Call(self, node):
            node = self.generic_visit(node)
            if isinstance(node.func, ast.Name) and node.func.id == "genesis_request_hash":
                return ast.Call(func=ast.Name(id="activation_hash", ctx=ast.Load()),
                                args=[ast.Constant(value="genesis"), *node.args], keywords=[])
            return node
    after["_state"] = RestoreReadbackHashCall().visit(after["_state"])
    for name in before:
        if name != "execute_new_genesis": assert ast.dump(before[name]) == ast.dump(after[name])
    original = before["execute_new_genesis"]
    extracted = after["execute_new_genesis"]
    nodes = []
    assignments = [n for n in original.body if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
                   and n.targets[0].id in ("proof_wire", "proof_hash")]
    assert len(assignments) == 2
    for n in extracted.body:
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name) and n.value.func.id == "genesis_request_proof":
            nodes.extend(assignments)
        else: nodes.append(n)
    extracted.body = nodes
    assert ast.dump(original) == ast.dump(extracted)
    occurrences = []
    for p in (ROOT / "app").rglob("*.py"):
        tree = ast.parse(p.read_text("utf-8-sig"))
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "activation_hash" and n.args and isinstance(n.args[0], ast.Constant) and n.args[0].value == "genesis":
                occurrences.append(str(p.relative_to(ROOT)))
    assert occurrences == ["app/r1_scoped_activation_core.py"] or occurrences == ["app\\r1_scoped_activation_core.py"]
    record("static-preservation", {"PASS": True, "verifier_models_AST_exact": True,
        "all_Core_methods_AST_exact_except_pure_hash_delegation": True,
        "transaction_gate_and_identity_AST_exact_after_extraction_normalization": True,
        "canonical_genesis_hash_calls": occurrences})
