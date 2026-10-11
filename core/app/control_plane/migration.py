"""CLI for the independent control-plane schema.

Usage: ``python -m app.control_plane.migration --dsn <redacted-dsn>``.
The DSN must point at a dedicated authority database; it is never read from
Core's ``CORE_DATABASE_URL`` automatically.
"""
from __future__ import annotations

import argparse

from .postgres import PostgresControlPlane


def main() -> None:
    parser = argparse.ArgumentParser(description="migrate Qingyu control-plane store")
    parser.add_argument("--dsn", required=True)
    parser.add_argument("--heads", action="store_true")
    parser.add_argument("--current", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    authority = PostgresControlPlane(args.dsn)
    if args.heads:
        print("0001_control_plane (head)")
        return
    if args.current or args.check:
        with authority._tx() as cursor:
            current = cursor.execute("SELECT current_database() AS name").fetchone()["name"]
            if current.lower() != authority.database_name:
                raise SystemExit("control-plane database identity mismatch")
            cursor.execute("SELECT version_num FROM alembic_version")
            versions = {row["version_num"] for row in cursor.fetchall()}
        if args.current:
            print(" ".join(sorted(versions)) or "(none)")
        if args.check and versions != {"0001_control_plane"}:
            raise SystemExit("control-plane migration head mismatch")
        return
    authority.migrate()


if __name__ == "__main__":
    main()
