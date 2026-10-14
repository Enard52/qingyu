from __future__ import annotations

import sys

from tests.long_tail_observer import classify_pytest_output, instrumented_tests_have_no_product_imports, run_observed_suite


def test_long_tail_observer_classifies_outputs():
    assert classify_pytest_output(0, "1 passed", "") == "PASS"
    assert classify_pytest_output(1, "FAILED tests/x.py", " short test summary info ") == "FAIL"
    assert classify_pytest_output(1, "ERROR tests/x.py", "") == "ERROR"
    assert classify_pytest_output(1, "OWNER_PRIVATE_CONFIG_REQUIRED", "") == "BLOCKED_BY_OWNER_CONFIG"
    assert classify_pytest_output(None, "", "", timed_out=True) == "TIMEOUT"


def test_long_tail_observer_timeout_and_no_product_imports():
    observation = run_observed_suite(
        "synthetic-timeout",
        [sys.executable, "-c", "import time; time.sleep(2)"],
        timeout_seconds=1,
    )

    assert observation.status == "TIMEOUT"
    assert observation.returncode is None
    assert instrumented_tests_have_no_product_imports() is True
