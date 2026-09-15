"""Legacy Control Plane migration entry point is intentionally disabled.

The unproven ``0001_control_plane`` marker is forensic-only. Canonical R1
uses an independent Alembic lineage and a signed provisioning origin;
a DSN-only migration command is unsafe.
"""
from __future__ import annotations


def main() -> None:
    raise SystemExit(
        "legacy Control Plane migration is disabled; use the signed R1 "
        "provisioning workflow and control_plane_alembic.ini"
    )


if __name__ == "__main__":
    main()
