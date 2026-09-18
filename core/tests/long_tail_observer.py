from __future__ import annotations

import ast
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class SuiteObservation:
    name: str
    command: tuple[str, ...]
    status: str
    returncode: int | None
    elapsed_seconds: float
    stdout_tail: str
    stderr_tail: str


def classify_pytest_output(returncode: int | None, stdout: str, stderr: str, *, timed_out: bool = False) -> str:
    text = stdout + "\n" + stderr
    if timed_out:
        return "TIMEOUT"
    if "OWNER_PRIVATE_CONFIG_REQUIRED" in text:
        return "BLOCKED_BY_OWNER_CONFIG"
    if returncode == 0:
        return "PASS"
    if " short test summary info " in text and "FAILED" in text:
        return "FAIL"
    if "ERROR" in text or returncode not in (0, None):
        return "ERROR"
    if " skipped" in text and returncode == 0:
        return "SKIP"
    return "ERROR"


def run_observed_suite(name: str, command: Iterable[str], *, timeout_seconds: int = 300) -> SuiteObservation:
    start = time.monotonic()
    args = tuple(command)
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout_seconds, check=False)
        elapsed = time.monotonic() - start
        status = classify_pytest_output(completed.returncode, completed.stdout, completed.stderr)
        return SuiteObservation(name, args, status, completed.returncode, round(elapsed, 3), completed.stdout[-4000:], completed.stderr[-4000:])
    except subprocess.TimeoutExpired as exc:
        elapsed = time.monotonic() - start
        stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", errors="replace")
        stderr = (exc.stderr or "") if isinstance(exc.stderr, str) else (exc.stderr or b"").decode("utf-8", errors="replace")
        return SuiteObservation(name, args, "TIMEOUT", None, round(elapsed, 3), stdout[-4000:], stderr[-4000:])


def instrumented_tests_have_no_product_imports() -> bool:
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    forbidden = {"app.services", "app.models", "app.db"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in forbidden:
            return False
        if isinstance(node, ast.Import):
            if any(alias.name in forbidden for alias in node.names):
                return False
    return True
