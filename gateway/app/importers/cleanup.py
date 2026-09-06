from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil

def cleanup_failed_staging(root: Path, retention_days: int = 7, dry_run: bool = False, protected_paths=None):
    """Remove only expired attempt directories below staging root.
    protected_paths contains resolved paths belonging to active/current attempts.
    """
    base = (root / "staging").resolve(); cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    protected = {Path(p).resolve() for p in (protected_paths or [])}; candidates=[]
    if not base.exists(): return [] if dry_run else 0
    for job_dir in base.iterdir():
        if not job_dir.is_dir(): continue
        for attempt in job_dir.iterdir():
            path = attempt.resolve()
            if not attempt.is_dir() or base not in path.parents or path in protected: continue
            if datetime.fromtimestamp(attempt.stat().st_mtime, timezone.utc) < cutoff: candidates.append(path)
    if dry_run: return candidates
    for path in candidates: shutil.rmtree(path, ignore_errors=True)
    return len(candidates)

