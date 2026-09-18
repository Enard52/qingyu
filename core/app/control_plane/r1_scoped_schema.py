"""Owner-only installer for a newly created, explicitly labelled test instance."""
from hashlib import sha256
from pathlib import Path
import re
from uuid import UUID

SCOPED_SQL = Path(__file__).with_name("r1_scoped_candidate.sql").read_bytes()
SCOPED_SCHEMA_DIGEST = sha256(SCOPED_SQL).hexdigest()


def install_scoped_test_schema(owner_connection, *, test_database_name: str,
                              scope_id: str, configuration_digest: str):
    """Caller proves new cluster ownership; this never connects, commits or adopts.

    This development candidate has no production migration/admission installer.
    Existing baseline/F3 migrations and digests remain unchanged.
    """
    if not re.fullmatch(r"r1_(?:f3|slice03|slice04)_test_[a-z0-9_]{8,50}", test_database_name):
        raise ValueError("explicit isolated scoped test database required")
    if not re.fullmatch(r"[0-9a-f]{64}", configuration_digest):
        raise ValueError("fixed configuration digest required")
    row = owner_connection.execute("""SELECT current_database(),current_user,
        pg_catalog.shobj_description(oid,'pg_database') FROM pg_catalog.pg_database
        WHERE datname=current_database()""").fetchone()
    labels = {f"R1_F3_TEST_ONLY:{test_database_name}", f"R1_SLICE03_TEST_ONLY:{test_database_name}",
              f"R1_SLICE04_TEST_ONLY:{test_database_name}"}
    if row is None or row[0] != test_database_name or row[1] != "control_plane_owner" or row[2] not in labels:
        raise ValueError("isolated database owner/label mismatch")
    if owner_connection.execute("SELECT to_regclass('control_plane.r1s_scopes')").fetchone()[0] is not None:
        raise ValueError("scoped installer refuses existing scoped resources")
    owner_connection.execute(SCOPED_SQL.decode("utf-8"), prepare=False)
    owner_connection.execute("INSERT INTO control_plane.r1s_scopes(scope_id,configuration_digest) VALUES(%s,%s)",
                             (UUID(scope_id), configuration_digest))
