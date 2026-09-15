"""Explicit F3 candidate source; never silently modifies the frozen migration.

The installer is for an independently isolated, labelled synthetic-test database.
Production deployment requires a later signed migration artifact and admission.
"""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import re
from typing import Any


F3_CONTRACT_VERSION = 1
_SQL_SOURCE = Path(__file__).with_name("r1_f3_candidate.sql").read_bytes()
F3_SCHEMA_DIGEST = sha256(b"QINGYU-R1-F3-CANDIDATE-SQL-V1\x00" + _SQL_SOURCE).hexdigest()
F3_CANDIDATE_SQL = _SQL_SOURCE.decode("utf-8").replace("__F3_DIGEST__", F3_SCHEMA_DIGEST)


def install_f3_test_schema(owner_connection: Any, *, test_database_name: str,
                           expected_test_label: str = "R1_F3_TEST_ONLY") -> None:
    """Install candidate on EMPTY six-table baseline; never create/adopt a target.

    The caller owns the enclosing setup transaction. This installer neither
    connects nor commits, and is never called by the runtime store/coordinator.
    An isolated test harness must separately prove cluster/container provenance.
    """
    if (expected_test_label != "R1_F3_TEST_ONLY"
            or not re.fullmatch(r"r1_f3_test_[a-z0-9_]{8,50}", test_database_name)):
        raise ValueError("explicit F3 synthetic-test database required")
    row = owner_connection.execute("""
        SELECT current_database(),current_user,
               pg_catalog.shobj_description(d.oid,'pg_database')
        FROM pg_catalog.pg_database d WHERE d.datname=current_database()
    """).fetchone()
    if tuple(row) != (test_database_name, "control_plane_owner",
                      f"R1_F3_TEST_ONLY:{test_database_name}"):
        raise ValueError("F3 test database/owner/label mismatch")
    names = {row[0] for row in owner_connection.execute("""
        SELECT c.relname FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='control_plane' AND c.relkind IN ('r','p','v','m','S','f')
    """).fetchall()}
    expected = {"cp_origin", "cp_receipt_keys", "cp_generations", "cp_runtime_sessions",
                "cp_continuities", "cp_operations"}
    if names != expected | {"cp_origin_singleton_id_seq"}:
        raise ValueError("F3 installer requires exact unextended baseline")
    sequence_binding = owner_connection.execute("""
        SELECT count(*) FROM pg_catalog.pg_depend d
        JOIN pg_catalog.pg_class s ON s.oid=d.objid
        JOIN pg_catalog.pg_namespace n ON n.oid=s.relnamespace
        JOIN pg_catalog.pg_class t ON t.oid=d.refobjid
        JOIN pg_catalog.pg_attribute a ON a.attrelid=t.oid AND a.attnum=d.refobjsubid
        WHERE d.classid='pg_catalog.pg_class'::regclass AND d.refclassid='pg_catalog.pg_class'::regclass
          AND n.nspname='control_plane' AND s.relname='cp_origin_singleton_id_seq' AND s.relkind='S'
          AND t.relnamespace=n.oid AND t.relname='cp_origin' AND a.attname='singleton_id'
          AND d.deptype='a'
    """).fetchone()[0]
    if sequence_binding != 1:
        raise ValueError("F3 origin sequence does not belong to exact baseline column")
    for name in sorted(expected):
        # Identifiers come solely from the fixed allowlist, never caller input.
        if owner_connection.execute(f"SELECT EXISTS(SELECT 1 FROM control_plane.{name})").fetchone()[0]:
            raise ValueError("F3 installer refuses existing Authority history")
    owner_connection.execute(F3_CANDIDATE_SQL, prepare=False)
