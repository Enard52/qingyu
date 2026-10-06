import ast
from copy import copy, deepcopy
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import subprocess
import uuid

import pytest
from sqlalchemy import create_engine, event, text

from app.b2_migration_authorization import (
    BASE_CHECKPOINT, POLICY_ID, REAL_PRODUCTION, SYNTHETIC_TEST,
    PreparedMigrationPlan, ProductionMigrationAuthorizationEvidence,
    VerifiedProductionMigrationAuthorization, ProductionMigrationAuthorizationVerifier,
    ProtectedMigrationTarget, prepare_migration_plan,
)
from app.control_plane.b2_activation_schema import apply_activation_migration, CONTROL_REVISION, CORE_REVISION, SCHEMA_VERSION
from app.control_plane.r1_validation_codec import c2, decode, sha
from app.errors import CoreError
from app.b2_signer_trust import apply_postgres_production_signer_admission_trust_binding_store_migration
from tests.test_b2_activation_lifecycle import pg
from tests.test_b2_postgres_production_signer_admission_store import migrate_both


class NeverConnect:
    def __init__(self):
        self.begin_calls = 0

    def begin(self):
        self.begin_calls += 1
        raise AssertionError("authorization reached transaction")


def bound(engine, *, kind="core", database="qingyu_prod"):
    plan = prepare_migration_plan(database=database, kind=kind, classification=SYNTHETIC_TEST,
        environment="NON_PRODUCTION", base_checkpoint="NON_PRODUCTION:base",
        amendment_checkpoint="NON_PRODUCTION:amendment")
    evidence = ProductionMigrationAuthorizationEvidence(c2({"policy_id": POLICY_ID,
        "classification": SYNTHETIC_TEST, "base_checkpoint": "NON_PRODUCTION:base",
        "amendment_checkpoint": "NON_PRODUCTION:amendment", "plan_hash": plan.plan_hash}))
    verifier = ProductionMigrationAuthorizationVerifier(SYNTHETIC_TEST, "NON_PRODUCTION:base",
        "NON_PRODUCTION:amendment", plan.plan_hash, sha(evidence.wire))
    target = ProtectedMigrationTarget(engine, database, kind, "NON_PRODUCTION", verifier)
    return target, plan, evidence, verifier.verify(evidence, plan)


@pytest.mark.parametrize("kind,database", [("control", "qingyu_control"), ("core", "qingyu_prod")])
@pytest.mark.parametrize("invalid", [None, True, False, "YES", "ENABLE_PRODUCTION", {}, object()])
def test_uncomposed_production_target_without_capability_is_original_error(kind, database, invalid):
    engine = NeverConnect()
    with pytest.raises(CoreError, match="B2_REAL_MIGRATION_NOT_ENABLED"):
        apply_activation_migration(engine, database=database, kind=kind, authorization=invalid)
    assert engine.begin_calls == 0


@pytest.mark.parametrize("invalid", [None, True, "YES", {}, "evidence", "blank_object"])
def test_composed_target_still_requires_reverifiable_capability(invalid):
    engine = NeverConnect()
    target, _, evidence, _ = bound(engine)
    if invalid == "evidence": invalid = evidence
    if invalid == "blank_object": invalid = object.__new__(VerifiedProductionMigrationAuthorization)
    with pytest.raises(CoreError):
        apply_activation_migration(target, database="qingyu_prod", kind="core", authorization=invalid)
    assert engine.begin_calls == 0


@pytest.mark.parametrize("field,value", [
    ("database", "qingyu_control"), ("environment", "PRODUCTION"),
    ("ordered_migrations", [CONTROL_REVISION]), ("ordered_migrations", [CORE_REVISION, CONTROL_REVISION]),
    ("ordered_migrations", ["*"]), ("ordered_migrations", ["latest"]),
    ("dependencies", [{"migration_id": "other", "schema_version": "other"}]),
    ("ledger_precondition", "ABSENT_ONLY"), ("final_ledger", []),
    ("schema", "public"), ("ledger", "public.other"), ("family", "SQL"),
    ("base_checkpoint", "NON_PRODUCTION:other"), ("amendment_checkpoint", "NON_PRODUCTION:other"),
    ("classification", REAL_PRODUCTION), ("SQL", "arbitrary SQL"),
])
def test_each_plan_semantic_change_invalidates_even_self_consistent_request(field, value):
    engine = NeverConnect()
    target, plan, evidence, capability = bound(engine)
    changed = decode(plan.wire); changed[field] = value
    altered = PreparedMigrationPlan(c2(changed))
    assert altered.plan_hash != plan.plan_hash
    with pytest.raises(CoreError): target.verifier.verify(evidence, altered)
    # Even matching caller-controlled evidence/hash cannot make an unknown plan canonical.
    body = decode(evidence.wire); body["plan_hash"] = altered.plan_hash
    fake_evidence = ProductionMigrationAuthorizationEvidence(c2(body))
    fake_policy = replace(target.verifier, approved_plan_hash=altered.plan_hash, evidence_sha256=sha(fake_evidence.wire))
    with pytest.raises(CoreError): fake_policy.verify(fake_evidence, altered)
    assert engine.begin_calls == 0


@pytest.mark.parametrize("change", ["database", "kind", "environment", "amendment", "base", "policy", "classification"])
def test_current_target_revalidation_rejects_cross_context_before_transaction(change):
    engine = NeverConnect(); target, _, _, capability = bound(engine)
    database, kind = target.database, target.kind
    if change == "database": database = "qingyu_control"
    elif change == "kind": kind = "control"
    elif change == "environment": target = replace(target, environment="PRODUCTION")
    elif change == "amendment": target = replace(target, verifier=replace(target.verifier, amendment_checkpoint="NON_PRODUCTION:other"))
    elif change == "base": target = replace(target, verifier=replace(target.verifier, base_checkpoint="NON_PRODUCTION:other"))
    elif change == "policy": target = replace(target, verifier=replace(target.verifier, evidence_sha256="0" * 64))
    elif change == "classification":
        target = replace(target, environment="PRODUCTION", verifier=replace(target.verifier,
            classification=REAL_PRODUCTION, base_checkpoint=BASE_CHECKPOINT, amendment_checkpoint="1" * 40))
    with pytest.raises(CoreError):
        apply_activation_migration(target, database=database, kind=kind, authorization=capability)
    assert engine.begin_calls == 0


@pytest.mark.parametrize("attack", ["constructor", "replace", "blank", "field", "evidence", "relabel", "copy", "deepcopy", "deserialize"])
def test_fabricated_or_tampered_capability_cannot_continue(attack):
    engine = NeverConnect(); target, plan, evidence, capability = bound(engine)
    if attack in {"constructor", "replace"}:
        with pytest.raises(CoreError, match="VERIFIER_REQUIRED"):
            if attack == "constructor": VerifiedProductionMigrationAuthorization(evidence, plan.plan_hash)
            else: replace(capability, plan_hash="0" * 64)
        return
    fake = object.__new__(VerifiedProductionMigrationAuthorization)
    if attack != "blank":
        object.__setattr__(fake, "evidence", evidence)
        object.__setattr__(fake, "plan_hash", plan.plan_hash)
    if attack == "field": object.__setattr__(fake, "plan_hash", "0" * 64)
    if attack in {"evidence", "relabel"}:
        body = decode(evidence.wire); body["classification"] = REAL_PRODUCTION
        object.__setattr__(fake, "evidence", ProductionMigrationAuthorizationEvidence(c2(body)))
    if attack in {"copy", "deepcopy"}:
        object.__setattr__(fake, "plan_hash", "0" * 64)
        fake = copy(fake) if attack == "copy" else deepcopy(fake)
    if attack == "deserialize": fake = decode(c2({"evidence": evidence.wire.hex(), "plan_hash": plan.plan_hash}))
    with pytest.raises(CoreError):
        apply_activation_migration(target, database=target.database, kind=target.kind, authorization=fake)
    assert engine.begin_calls == 0


def test_valid_copies_are_revalidated_not_rejected_by_object_identity():
    target, plan, _, capability = bound(NeverConnect())
    for copied in (copy(capability), deepcopy(capability)):
        target.verifier.revalidate(copied, plan)
    with pytest.raises(FrozenInstanceError): capability.plan_hash = "0" * 64
    with pytest.raises(FrozenInstanceError): target.environment = "PRODUCTION"


@pytest.mark.parametrize("wire", [b"", b"[]", b"{}", b"\xff", "string", b"x" * 65537],
                         ids=["empty", "array", "object", "invalid-UTF8", "nonbytes", "oversize"])
def test_malformed_evidence_fails_closed(wire):
    target, plan, _, _ = bound(NeverConnect())
    with pytest.raises(CoreError): target.verifier.verify(ProductionMigrationAuthorizationEvidence(wire), plan)


@pytest.mark.parametrize("kind,database", [("control", "qingyu_prod"), ("core", "qingyu_control"), ("core", "arbitrary")])
def test_unknown_or_cross_database_plan_is_not_authorizable(kind, database):
    with pytest.raises(CoreError): bound(NeverConnect(), kind=kind, database=database)


def test_no_runtime_flags_or_cli_and_original_body_AST_identical():
    root = Path(__file__).resolve().parents[1]
    path = "app/control_plane/b2_activation_schema.py"
    old = ast.parse(subprocess.check_output(["git", "show", "HEAD:" + path], cwd=root).decode())
    new = ast.parse((root/path).read_text())
    before = next(n for n in old.body if isinstance(n, ast.FunctionDef))
    after = next(n for n in new.body if isinstance(n, ast.FunctionDef))
    assert ast.dump(ast.Module(body=before.body[2:], type_ignores=[])) == ast.dump(ast.Module(body=after.body[3:], type_ignores=[]))
    assert [n for n in new.body if isinstance(n, ast.FunctionDef)] == [after]
    module = (root/"app/b2_migration_authorization.py").read_text()
    assert all(word not in module for word in ("os.environ", "getenv(", "argparse", "create_engine(", "exec(", "eval("))
    assert [a.arg for a in after.args.kwonlyargs] == ["database", "kind", "authorization"]


def test_frozen_genesis_current_checkpoint_and_original_transaction_match():
    root = Path(__file__).resolve().parents[1]
    path = "app/r1_scoped_activation_core.py"
    current = ast.parse((root/path).read_text())
    frozen = ast.parse(subprocess.check_output(["git", "show", "HEAD:" + path], cwd=root).decode())
    assert ast.dump(current) == ast.dump(frozen)
    foundation = ast.parse(subprocess.check_output(["git", "show", "a5508234d7a4c605815d8dea8b52e9edfa5ac02a:" + path], cwd=root).decode())
    def execute(tree):
        return next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "execute_new_genesis")
    assert [ast.dump(n) for n in execute(foundation).body[1:]] == [ast.dump(n) for n in execute(current).body[2:]]


def test_valid_capability_without_protected_composition_cannot_unlock_target():
    engine = NeverConnect(); _, _, _, capability = bound(engine)
    with pytest.raises(CoreError, match="B2_REAL_MIGRATION_NOT_ENABLED"):
        apply_activation_migration(engine, database="qingyu_prod", kind="core", authorization=capability)
    assert engine.begin_calls == 0


@pytest.mark.parametrize("kind,database", [("control", "qingyu_control"), ("core", "qingyu_prod")])
def test_explicit_synthetic_production_shaped_context_reaches_same_body(kind, database):
    class Harness:
        def __init__(self): self.sql = []; self.begin_calls = 0
        def begin(self): self.begin_calls += 1; return self
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def execute(self, statement, params=None):
            self.sql.append(str(statement)); return self
        def scalar_one(self): return database
        def scalar_one_or_none(self):
            if "SELECT schema_version" in self.sql[-1]:
                from app.b2_signer_trust import POSTGRES_PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_STORE_SCHEMA_VERSION
                return POSTGRES_PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_STORE_SCHEMA_VERSION
            return None
    engine = Harness(); target, _, _, capability = bound(engine, kind=kind, database=database)
    assert target.verifier.classification == SYNTHETIC_TEST
    apply_activation_migration(target, database=database, kind=kind, authorization=capability)
    assert engine.begin_calls == 1
    assert any("CREATE TABLE" in sql for sql in engine.sql)
    assert [sql for sql in engine.sql if sql.startswith("INSERT")] == [engine.sql[-1]]
    assert ".activation_migrations VALUES" in engine.sql[-1]


def test_control_core_capabilities_cannot_be_exchanged():
    engine = NeverConnect()
    control, _, _, control_cap = bound(engine, kind="control", database="qingyu_control")
    core, _, _, core_cap = bound(engine)
    for target, wrong in [(control, core_cap), (core, control_cap)]:
        with pytest.raises(CoreError):
            apply_activation_migration(target, database=target.database, kind=target.kind, authorization=wrong)
    assert engine.begin_calls == 0


@pytest.mark.parametrize("kind", ["control", "core"])
def test_isolated_authorized_migration_replay_restart_nonactivation(pg, kind):
    database = "synthetic_migration_" + uuid.uuid4().hex[:10]
    pg.create_database(database)
    if kind == "control":
        migrate_both(pg.url(database), database)
        apply_postgres_production_signer_admission_trust_binding_store_migration(pg.url(database), expected_database_name=database)
    engine = create_engine(pg.url(database))
    target, plan, evidence, capability = bound(engine, kind=kind, database=database)
    schema = "governance" if kind == "control" else "r1_core_v2"
    tables = ("activation_authorities", "activation_smis") if kind == "control" else ("identity", "genesis", "lifecycle")
    # Verification alone produces no database object.
    with engine.connect() as c:
        assert c.execute(text("SELECT to_regclass(:table)"), {"table": schema + ".activation_migrations"}).scalar_one() is None
    try:
        apply_activation_migration(target, database=database, kind=kind, authorization=capability)
        with engine.connect() as c:
            first = c.execute(text(f"SELECT revision,version FROM {schema}.activation_migrations")).all()
            assert first == [(CONTROL_REVISION if kind == "control" else CORE_REVISION, SCHEMA_VERSION)]
            assert all(c.execute(text(f"SELECT count(*) FROM {schema}.{table}")).scalar_one() == 0 for table in tables)
        engine.dispose()
        fresh = create_engine(pg.url(database))
        fresh_target = replace(target, engine=fresh)
        fresh_cap = fresh_target.verifier.verify(evidence, plan)
        apply_activation_migration(fresh_target, database=database, kind=kind, authorization=fresh_cap)
        with fresh.connect() as c:
            assert c.execute(text(f"SELECT revision,version FROM {schema}.activation_migrations")).all() == first
            assert all(c.execute(text(f"SELECT count(*) FROM {schema}.{table}")).scalar_one() == 0 for table in tables)
        fresh.dispose()
    finally: engine.dispose()


def test_existing_version_conflict_is_not_reclassified_as_authorized_replay(pg):
    database = "synthetic_migration_" + uuid.uuid4().hex[:10]; pg.create_database(database)
    engine = create_engine(pg.url(database)); target, _, _, capability = bound(engine, database=database)
    try:
        apply_activation_migration(target, database=database, kind="core", authorization=capability)
        with engine.begin() as c:
            c.execute(text("UPDATE r1_core_v2.activation_migrations SET version='conflicting-test-version'"))
        with pytest.raises(CoreError, match="B2_ACTIVATION_SCHEMA_VERSION_CONFLICT"):
            apply_activation_migration(target, database=database, kind="core", authorization=capability)
        with engine.connect() as c:
            assert c.execute(text("SELECT count(*) FROM r1_core_v2.identity")).scalar_one() == 0
    finally: engine.dispose()


@pytest.mark.parametrize("kind", ["control", "core"])
def test_authorized_transaction_failure_rolls_back_original_body(pg, kind):
    database = "synthetic_migration_" + uuid.uuid4().hex[:10]; pg.create_database(database)
    if kind == "control":
        migrate_both(pg.url(database), database)
        apply_postgres_production_signer_admission_trust_binding_store_migration(pg.url(database), expected_database_name=database)
    engine = create_engine(pg.url(database)); target, _, _, capability = bound(engine, kind=kind, database=database)
    schema = "governance" if kind == "control" else "r1_core_v2"
    def inject(c, cursor, statement, params, context, many):
        if "INSERT INTO " + schema + ".activation_migrations VALUES" in statement: raise RuntimeError("injected before ledger insert")
    event.listen(engine, "before_cursor_execute", inject)
    try:
        with pytest.raises(RuntimeError, match="injected before ledger insert"):
            apply_activation_migration(target, database=database, kind=kind, authorization=capability)
        event.remove(engine, "before_cursor_execute", inject)
        with engine.connect() as c:
            assert c.execute(text("SELECT to_regclass(:table)"), {"table": schema + ".activation_migrations"}).scalar_one() is None
            table = ".activation_authorities" if kind == "control" else ".identity"
            assert c.execute(text("SELECT to_regclass(:table)"), {"table": schema + table}).scalar_one() is None
        apply_activation_migration(target, database=database, kind=kind, authorization=capability)
    finally: engine.dispose()
