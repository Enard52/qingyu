from pathlib import Path
from datetime import datetime, timedelta, timezone
from app.importers.cleanup import cleanup_failed_staging
from app.importers.generic import ParserRegistry
from app.importers.report import empty_report

def test_cleanup_dry_run_and_protected_attempt(tmp_path):
    old = tmp_path/'staging'/'job'/'1'/'a'; old.mkdir(parents=True); old.touch()
    import os, time
    old_time = time.time() - 10*86400; os.utime(old, (old_time, old_time))
    assert cleanup_failed_staging(tmp_path, retention_days=7, dry_run=True, protected_paths=[old]) == []
    assert old.exists()
    assert cleanup_failed_staging(tmp_path, retention_days=7, dry_run=True) == [old.resolve()]
    assert cleanup_failed_staging(tmp_path, retention_days=7) == 1
    assert not old.exists()

def test_unsupported_real_export_is_explicit():
    code, parser = ParserRegistry().detect({'conversations': []})
    assert code == 'unsupported_real_chatgpt_export' and parser is None

def test_report_has_detailed_categories():
    report = empty_report('fixture', '0.1', 'matched')
    assert set(report['attachments']) == {'available','missing','referenced_only','failed'}
    assert set(report['conversations']) == {'new','existing','changed','skipped','failed'}
