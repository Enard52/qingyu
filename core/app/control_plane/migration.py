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
    args = parser.parse_args()
    PostgresControlPlane(args.dsn).migrate()


if __name__ == "__main__":
    main()
