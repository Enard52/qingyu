from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from tests.long_tail_observer import run_observed_suite


LONG_ACCEPTANCE_SUITES = (
    ("window_finish_129_operations", (sys.executable, "-m", "pytest", "tests/test_r1_window_finish.py", "-s", "-vv", "--tb=short", "--durations=0")),
)


BASELINE = {
    "fixture_generate_sequence_129_seconds": 39.625,
    "simple_selected_case_seconds": 63.13,
    "batch04_full_suite_no_output_window_seconds": 300,
}


def recommended_timeout_seconds(multiplier: float = 3.0, floor: int = 900) -> int:
    # The full long acceptance contains the 129-operation scenario plus fixture and verification.
    # Use the observed no-output window as the baseline and apply a safety margin.
    return max(floor, int(BASELINE["batch04_full_suite_no_output_window_seconds"] * multiplier))


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Qingyu long acceptance suites with timing and classification.")
    parser.add_argument("--timeout-seconds", type=int, default=recommended_timeout_seconds())
    parser.add_argument("--output", default=None, help="Optional JSON output path")
    args = parser.parse_args()
    started = datetime.now(timezone.utc).isoformat()
    print("LONG_ACCEPTANCE START", flush=True)
    print(json.dumps({"baseline": BASELINE, "timeout_seconds": args.timeout_seconds}, indent=2), flush=True)
    observations = []
    exit_code = 0
    for name, command in LONG_ACCEPTANCE_SUITES:
        print(f"LONG_ACCEPTANCE SUITE START name={name}", flush=True)
        observation = run_observed_suite(name, command, timeout_seconds=args.timeout_seconds)
        item = {
            "name": observation.name,
            "command": list(observation.command),
            "status": observation.status,
            "returncode": observation.returncode,
            "elapsed_seconds": observation.elapsed_seconds,
            "stdout_tail": observation.stdout_tail,
            "stderr_tail": observation.stderr_tail,
        }
        observations.append(item)
        print(f"LONG_ACCEPTANCE SUITE FINISH name={name} status={observation.status} elapsed={observation.elapsed_seconds}", flush=True)
        if observation.status != "PASS":
            exit_code = 1
    result = {
        "schema_version": "qingyu-long-acceptance-run-v1",
        "started_at": started,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "baseline": BASELINE,
        "timeout_policy": {
            "timeout_seconds": args.timeout_seconds,
            "rationale": "max(900s floor, 3x observed 300s no-output full-suite window) for 129-operation long acceptance",
        },
        "suites": observations,
        "status": "PASS" if all(item["status"] == "PASS" for item in observations) else "LONG_RUNNING_NOT_COMPLETED",
    }
    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2), flush=True)
    print("LONG_ACCEPTANCE COMPLETE" if exit_code == 0 else "LONG_ACCEPTANCE INCOMPLETE", flush=True)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
