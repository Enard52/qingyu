from __future__ import annotations

import argparse
import os
import subprocess
import sys

from tests.r1_private_config import ENV_NAME, resolve_slice03_private_config, sanitized_config_summary


SUITE = [
    "tests/test_r1_roundtrip_independent.py::IndependentRoundtripChecks",
    "tests/test_r1_scoped_authority.py::ScopedAuthorityAuthorTests",
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run owner-controlled Slice03 private-config suites without printing secrets.")
    parser.add_argument("--config", required=True, help="Path to owner-provided Slice03 private-config.json")
    parser.add_argument("--pytest-arg", action="append", default=[], help="Additional pytest argument")
    args = parser.parse_args()
    env = dict(os.environ)
    env[ENV_NAME] = args.config
    config = resolve_slice03_private_config(env)
    print({"slice03_private_suite": "starting", "config": sanitized_config_summary(config)})
    command = [sys.executable, "-m", "pytest", *SUITE, *args.pytest_arg]
    return subprocess.call(command, env=env)


if __name__ == "__main__":
    raise SystemExit(main())
