"""Author cross-window execution log; preserves every actual failed run."""
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
        raise RuntimeError("missing current evidence directory")
    from tests import test_r1_window_finish as tests
    suite = unittest.defaultTestLoader.loadTestsFromNames(sys.argv[1:]) if len(sys.argv)>1 else unittest.defaultTestLoader.loadTestsFromModule(tests)
    paths = [root/"app/r1_atomic_finish.py", root/"app/_r1_scoped_sqlite.py",
        root/"app/control_plane/_r1_validation_stream.py", root/"app/control_plane/_r1_validation_semantics.py",
        *sorted((root/"tests").glob("r1_window_*.py")), *sorted((root/"tests").glob("test_r1_window*.py"))]
    def hashes():
        return [{"path": str(p.relative_to(root)), "bytes": p.stat().st_size,
                 "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in paths if p.exists()]
    output, before, started = io.StringIO(), hashes(), time.time()
    actual_stdout = sys.stdout
    class Tee:
        def write(self, value):
            output.write(value); actual_stdout.write(value); actual_stdout.flush()
        def flush(self):
            actual_stdout.flush()
    stream = Tee()
    with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    row = {"kind": "author cross-window tests, not independent review", "started_unix": started,
        "elapsed_seconds": time.time()-started, "command": [sys.executable,"-B","-m","tests.r1_window_run",*sys.argv[1:]],
        "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
        "skipped": len(result.skipped), "successful": result.wasSuccessful(), "output": output.getvalue(),
        "observations": tests.OBSERVATIONS, "source_before": before, "source_after": hashes()}
    target = evidence/"window-tests-results.json"
    document = json.loads(target.read_text(encoding="utf8")) if target.exists() else {"runs": []}
    document["runs"].append(row)
    def public_value(value):
        if type(value) is bytes:
            return {"raw_hex": value.hex()}
        raise TypeError("unexpected output type " + type(value).__name__)
    target.write_text(json.dumps(document, indent=2, ensure_ascii=False, default=public_value)+"\n", encoding="utf8")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
