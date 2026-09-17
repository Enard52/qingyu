"""Run author tests and preserve their actual output separately from review."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import time
import unittest


def main():
    root = Path(__file__).resolve().parents[1]
    evidence = root / "docs/evidence/r1-acceptance-marathon/core-local-atomic-finish-slice-02-completion-20260916T193823Z"
    if not evidence.is_dir():
        raise RuntimeError("parent has not created this run's evidence directory")
    from tests import test_r1_atomic_finish as module
    names = sys.argv[1:]
    suite = unittest.defaultTestLoader.loadTestsFromNames(names) if names else unittest.defaultTestLoader.loadTestsFromModule(module)
    def hashes():
        paths = [root / "app/r1_atomic_finish.py", root / "app/_r1_scoped_sqlite.py", *sorted((root / "tests").glob("*r1_atomic_finish*.py"))]
        return [{"path": str(path.relative_to(root)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size}
                for path in paths if path.is_file()]
    before = hashes()
    stream = io.StringIO()
    started = time.time()
    with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    output = stream.getvalue()
    print(output, end="")
    record = {"kind": "author self-test; not independent review", "command": [sys.executable, "-B", "-m", "tests.r1_atomic_finish_run", *names],
        "started_unix": started, "elapsed_seconds": time.time()-started, "tests_run": result.testsRun,
        "failures": len(result.failures), "errors": len(result.errors), "skipped": len(result.skipped),
        "successful": result.wasSuccessful(), "output": output, "observations": module.OBSERVATIONS,
        "source_before": before, "source_after": hashes()}
    destination = evidence / "tests-results.json"
    prior = json.loads(destination.read_text(encoding="utf-8")) if destination.exists() else {"runs": []}
    prior["runs"].append(record)
    destination.write_text(json.dumps(prior, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
