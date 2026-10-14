"""Preserve independent raw output and actual observations for this task only."""
import hashlib
import io
import json
from pathlib import Path
import sys
import time
import unittest
from contextlib import redirect_stdout, redirect_stderr

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests import test_r1_window_independent as windows

N = ROOT / 'docs/evidence/r1-acceptance-marathon/core-local-atomic-finish-slice-02-completion-20260916T193823Z'
files = ['app/r1_atomic_finish.py', 'app/_r1_scoped_sqlite.py', 'app/control_plane/_r1_validation_stream.py',
         'app/control_plane/_r1_validation_semantics.py', 'tests/test_r1_window_independent.py',
         'tests/r1_window_independent_fixtures.py', 'tests/test_r1_atomic_finish_independent.py',
         'tests/r1_atomic_finish_independent_fixtures.py']
def hashes(): return {f: hashlib.sha256((ROOT / f).read_bytes()).hexdigest() for f in files}
suite = unittest.TestSuite()
for name in sys.argv[1:] or ['tests.test_r1_window_independent', 'tests.test_r1_atomic_finish_independent']:
    suite.addTests(unittest.defaultTestLoader.loadTestsFromName(name))
before = hashes(); started = time.time(); output = io.StringIO()
with redirect_stdout(output), redirect_stderr(output):
    result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
row = {'time': started, 'elapsed_seconds': time.time() - started, 'testsRun': result.testsRun,
       'failures': len(result.failures), 'errors': len(result.errors), 'skipped': len(result.skipped),
       'success': result.wasSuccessful(), 'before_sha256': before, 'after_sha256': hashes(),
       'raw_stdout': output.getvalue(), 'observations': windows.OBSERVATIONS}
path = N / 'independent-results.json'
document = json.loads(path.read_text('utf-8')) if path.exists() else {'runs': []}
document['runs'].append(row)
path.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding='utf-8')
print(output.getvalue()); print('RESULT', row['success'], 'SECONDS', row['elapsed_seconds'], flush=True)
sys.exit(0 if result.wasSuccessful() else 1)
