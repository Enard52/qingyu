from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil

def cleanup_failed_staging(root: Path, retention_days: int = 7) -> int:
    base = root / "staging"; cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days); removed = 0
    if not base.exists(): return 0
    for job_dir in base.iterdir():
        if not job_dir.is_dir(): continue
        for attempt in job_dir.iterdir():
            if attempt.is_dir() and datetime.fromtimestamp(attempt.stat().st_mtime, timezone.utc) < cutoff:
                shutil.rmtree(attempt); removed += 1
    return removed
