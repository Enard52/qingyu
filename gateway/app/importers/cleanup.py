from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil

def cleanup_failed_staging(root: Path, retention_days: int = 7, dry_run: bool = False, protected_paths=None):
    base=(root/'staging').resolve(); cutoff=datetime.now(timezone.utc)-timedelta(days=retention_days); protected={Path(p).resolve() for p in (protected_paths or [])}; targets=[]
    if not base.exists(): return [] if dry_run else 0
    for job in base.iterdir():
        if not job.is_dir(): continue
        for attempt in job.iterdir():
            if not attempt.is_dir(): continue
            children=[p for p in attempt.iterdir() if p.is_dir()]
            candidates=children or [attempt]
            for candidate in candidates:
                path=candidate.resolve()
                if base not in path.parents or path in protected: continue
                if datetime.fromtimestamp(candidate.stat().st_mtime, timezone.utc)<cutoff: targets.append(path)
    if dry_run: return targets
    for path in targets: shutil.rmtree(path, ignore_errors=True)
    return len(targets)
