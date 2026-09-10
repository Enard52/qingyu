from __future__ import annotations

import argparse
import json

from .config import get_settings
from .control_plane import InMemoryControlPlane, UnavailableControlPlane
from .db import session_factory
from .services import CoreFoundationService


def main() -> None:
    parser = argparse.ArgumentParser(description="Qingyu Core foundation CLI")
    parser.add_argument("command", choices=["status"])
    args = parser.parse_args()
    settings = get_settings()
    authority = (
        InMemoryControlPlane()
        if settings.control_plane_backend == "memory"
        else UnavailableControlPlane()
    )
    service = CoreFoundationService(session_factory(settings), authority)
    if args.command == "status":
        print(json.dumps(service.identity_status().model_dump(mode="json"), sort_keys=True))


if __name__ == "__main__":
    main()

