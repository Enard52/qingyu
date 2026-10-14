"""Pure-host recovery-plan composition tests; no engines or production fixture."""
from copy import deepcopy
from dataclasses import asdict, replace
from types import SimpleNamespace

import pytest

from app.control_plane import r1_validation_codec as codec
from app.errors import CoreError
from ops import b2_activation_access as module
from ops.b2_activation_access import AccessPolicy, FixedAccess
from ops.b2_activation_operations import BACKUP_GENERATION, RecoveryBoundary


POLICY = AccessPolicy("REAL_PRODUCTION", "qingyu_control", "qingyu_prod")
BINDING = "c974c53dafbc72ace067d1e6e1075acea343024a8eca3e51793f56bc103b4f9d"
# Captured before amendment from the legal list representation and unchanged C2.
LIST_HASHES = {
    "roles": "279284a0c4c869a99a8d7664e3a2fafe548ed757007fba7953701eee757439e1",
    "acl": "6b4ce18cab87f41045f7c7e80cf141fb8bf25013f1c33411ae0d6340a23d4c5d",
}


def legal_payload(stage):
    return {"stage": stage, "policy": asdict(POLICY), "roles": module.ROLES,
            "owners": module.OWNERS,
            "tables": {k: list(v) for k, v in module.TABLES.items()},
            "inserts": {k: list(v) for k, v in module.INSERTS.items()},
            "default": "DENY"}


class NeverAdmin:
    def __getattr__(self, name):
        raise AssertionError("pure-host test must not access administrative engine")


@pytest.mark.parametrize("stage", ["roles", "acl"])
def test_known_tuple_and_existing_list_preserve_canonical_bytes_and_hash(monkeypatch, stage):
    expected_payload = deepcopy(legal_payload(stage))
    expected_wire = codec.c2(expected_payload)
    assert codec.sha(expected_wire) == LIST_HASHES[stage]
    encode = codec.c2
    captured = []

    def capture(payload):
        captured.append(deepcopy(payload))
        return encode(payload)

    monkeypatch.setattr(codec, "c2", capture)
    access = FixedAccess(POLICY)
    assert access.provisioning_plan_hash(stage) == LIST_HASHES[stage]
    tuple_payload = captured[-1]
    monkeypatch.setattr(module, "TABLES", {k: list(v) for k, v in module.TABLES.items()})
    monkeypatch.setattr(module, "INSERTS", {k: list(v) for k, v in module.INSERTS.items()})
    assert access.provisioning_plan_hash(stage) == LIST_HASHES[stage]
    assert tuple_payload == captured[-1] == expected_payload
    assert encode(tuple_payload) == encode(captured[-1]) == expected_wire


@pytest.mark.parametrize("stage", ["roles", "acl"])
def test_repeated_construction_and_mapping_insertion_order_are_deterministic(monkeypatch, stage):
    access = FixedAccess(POLICY)
    results = [access.provisioning_plan_hash(stage) for _ in range(20)]
    assert results == [LIST_HASHES[stage]] * 20
    # Object-key order is C2-defined; ordered field members must not be sorted.
    for name in ("TABLES", "INSERTS", "ROLES", "OWNERS"):
        monkeypatch.setattr(module, name, dict(reversed(list(getattr(module, name).items()))))
    assert access.provisioning_plan_hash(stage) == LIST_HASHES[stage]


@pytest.mark.parametrize("stage", ["roles", "acl"])
@pytest.mark.parametrize("field,key", [("TABLES", "control"), ("INSERTS", "genesis")])
def test_order_is_preserved_and_reversal_changes_hash(monkeypatch, stage, field, key):
    original = getattr(module, field)
    changed = {**original, key: tuple(reversed(original[key]))}
    monkeypatch.setattr(module, field, changed)
    expected = legal_payload(stage)
    assert expected["tables" if field == "TABLES" else "inserts"][key] == list(reversed(original[key]))
    assert FixedAccess(POLICY).provisioning_plan_hash(stage) == codec.sha(codec.c2(expected))
    assert FixedAccess(POLICY).provisioning_plan_hash(stage) != LIST_HASHES[stage]


@pytest.mark.parametrize("field,key", [("TABLES", "control"), ("INSERTS", "genesis")])
@pytest.mark.parametrize("bad", [{"a", "b"}, frozenset({"a", "b"}), "abc", {"a": "b"}, iter(["a"]), object()])
def test_non_ordered_field_representation_is_rejected(monkeypatch, field, key, bad):
    monkeypatch.setattr(module, field, {**getattr(module, field), key: bad})
    with pytest.raises(CoreError, match="B2_OPS_PROVISIONING_PLAN_ORDERED_VALUES_REQUIRED"):
        FixedAccess(POLICY).provisioning_plan_hash("roles")


@pytest.mark.parametrize("field,key", [("TABLES", "control"), ("INSERTS", "genesis")])
@pytest.mark.parametrize("bad", [{"a", "b"}, frozenset({"a", "b"}), ("nested",), object()])
def test_nested_unsupported_values_still_fail_c2_without_recursive_coercion(monkeypatch, field, key, bad):
    monkeypatch.setattr(module, field, {**getattr(module, field), key: ("valid", bad)})
    with pytest.raises(codec.ContractError, match="unsupported JSON type"):
        FixedAccess(POLICY).provisioning_plan_hash("acl")


@pytest.mark.parametrize("invalid", ["other", "", None, "roles-v2"])
def test_wrong_recovery_stage_remains_rejected(invalid):
    with pytest.raises(CoreError, match="B2_OPS_PROVISIONING_STAGE_MISMATCH"):
        FixedAccess(POLICY).provisioning_plan_hash(invalid)


def test_fixed_plan_has_no_arbitrary_payload_or_schema_input():
    with pytest.raises(TypeError):
        FixedAccess(POLICY).provisioning_plan_hash("roles", payload={"extra": True})
    with pytest.raises(TypeError):
        FixedAccess(POLICY).provisioning_plan_hash()
    with pytest.raises(CoreError, match="PROTECTED_COMPOSITION_REQUIRED"):
        FixedAccess({"schema": "wrong", "extra": True})
    with pytest.raises(CoreError, match="TARGET_MISMATCH"):
        replace(POLICY, core_database="wrong")


@pytest.mark.parametrize("stage", ["roles", "acl"])
def test_historical_empty_anchor_guard_now_reaches_original_recovery_rejection(stage):
    recovery = RecoveryBoundary("REAL_PRODUCTION", BINDING, BACKUP_GENERATION, ())
    access = FixedAccess(POLICY, recovery=recovery)
    assert access.provisioning_plan_hash(stage) == LIST_HASHES[stage]
    with pytest.raises(CoreError, match="B2_OPS_FRESH_RECOVERY_ANCHOR_REQUIRED"):
        access._recovery_guard(stage, NeverAdmin())


@pytest.mark.parametrize("stage", ["roles", "acl"])
def test_exact_anchor_guard_completes_with_host_only_admin_stub(stage):
    recovery = RecoveryBoundary("REAL_PRODUCTION", BINDING, BACKUP_GENERATION,
                                ((stage, LIST_HASHES[stage], "HOST_ONLY_UNIT_TEST_ANCHOR"),))
    queries = []

    class Connection:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def execute(self, query):
            queries.append(str(query))
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: [BINDING]))

    from sqlalchemy.engine import URL
    admin = SimpleNamespace(url=URL.create("postgresql+psycopg", username="postgres",
        host="/var/run/postgresql", port=5433, database="qingyu_control"), connect=lambda: Connection())
    FixedAccess(POLICY, recovery=recovery)._recovery_guard(stage, admin)
    assert len(queries) == 1 and queries[0].startswith("SELECT binding_hash FROM ")


@pytest.mark.parametrize("stage", ["roles", "acl"])
@pytest.mark.parametrize("violation", ["wrong_hash", "wrong_stage", "duplicate", "generation"])
def test_recovery_meaning_still_fails_closed_before_admin_access(stage, violation):
    anchor = (stage, LIST_HASHES[stage], "HOST_ONLY_UNIT_TEST_ANCHOR")
    anchors = ((stage, "0" * 64, anchor[2]),) if violation == "wrong_hash" else (("other", anchor[1], anchor[2]),) if violation == "wrong_stage" else (anchor, anchor) if violation == "duplicate" else (anchor,)
    recovery = RecoveryBoundary("REAL_PRODUCTION", BINDING,
        "wrong-generation" if violation == "generation" else BACKUP_GENERATION, anchors)
    with pytest.raises(CoreError, match="RECOVERY"):
        FixedAccess(POLICY, recovery=recovery)._recovery_guard(stage, NeverAdmin())


@pytest.mark.parametrize("bad", [("a", "b"), {"a", "b"}, frozenset({"a", "b"})])
def test_global_c2_still_rejects_tuple_and_unordered_values(bad):
    with pytest.raises(codec.ContractError, match="unsupported JSON type"):
        codec.c2(bad)
