import logging
import os
import sys
import threading

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from ..config import get_settings
from ..database_config import DatabaseConfigurationError
from ..errors import safe_log_exception
try:
    from .processor import ImportProcessor
    from .worker import ClaimedJob, ImportWorker, LeaseLost
except DatabaseConfigurationError as exc:
    if __name__ == "__main__":
        sys.stderr.write(f"worker_startup_failed code={exc} exception=DatabaseConfigurationError\n")
        raise SystemExit(2) from None
    raise

logger = logging.getLogger(__name__)


class AttemptHealth:
    """Thread-safe heartbeat failure signal without retaining sensitive errors."""
    def __init__(self):
        self.failed = threading.Event()

    def mark_failed(self) -> None:
        self.failed.set()

    def raise_if_failed(self) -> None:
        if self.failed.is_set():
            raise LeaseLost("heartbeat_failed")


class WorkerRuntime:
    def __init__(self, archive_root, poll_interval=1.0, heartbeat_interval=10.0, lease_duration=30, error_backoff_max=5.0, session_factory=None):
        self.archive_root = archive_root
        self.poll_interval = poll_interval
        self.heartbeat_interval = heartbeat_interval
        self.lease_duration = lease_duration
        self.error_backoff_max = error_backoff_max
        if session_factory is None:
            from ..db import engine
            session_factory = lambda: Session(engine)
        self.session_factory = session_factory
        self.stop_event = threading.Event()
        self.last_iteration_failed = False

    def run_once(self) -> bool:
        self.last_iteration_failed = False
        db = self.session_factory()
        heartbeat_stop = None
        heartbeat = None
        operation = "recover_stale"
        try:
            worker = ImportWorker(db)
            worker.recover_stale()
            operation = "claim_next"
            claim = worker.claim_next(self.lease_duration)
            if claim is None:
                return False
            operation = "post_claim_setup"
            claim = self._prepare_claim(claim)
            heartbeat_stop = threading.Event()
            attempt_health = AttemptHealth()

            def heartbeat_loop():
                while not heartbeat_stop.wait(self.heartbeat_interval):
                    with self.session_factory() as heartbeat_db:
                        try:
                            alive = ImportWorker(heartbeat_db).heartbeat(claim.job_id, claim.lease_token, self.lease_duration)
                        except Exception as exc:
                            heartbeat_db.rollback()
                            attempt_health.mark_failed()
                            safe_log_exception(
                                logger,
                                logging.ERROR,
                                "import heartbeat failed",
                                error_code="heartbeat_failed",
                                operation="heartbeat",
                                exception=exc,
                                job_id=claim.job_id,
                            )
                            heartbeat_stop.set()
                            return
                        if not alive:
                            attempt_health.mark_failed()
                            heartbeat_stop.set()
                            return

            heartbeat = threading.Thread(target=heartbeat_loop, name=f"import-heartbeat-{claim.job_id}", daemon=True)
            operation = "heartbeat_setup"
            heartbeat.start()
            operation = "process_job"
            try:
                ImportProcessor(db, self.archive_root).process(claim, claim.lease_token, health_check=attempt_health.raise_if_failed)
            except LeaseLost:
                logger.info("import worker lost ownership", extra={"job_id": str(claim.job_id)})
            except SQLAlchemyError:
                raise
            except Exception as exc:
                safe_log_exception(
                    logger,
                    logging.ERROR,
                    "import job processing failed",
                    error_code="import_processing_failed",
                    operation="process_job",
                    exception=exc,
                    job_id=claim.job_id,
                )
            return True
        except SQLAlchemyError as exc:
            db.rollback()
            self.last_iteration_failed = True
            safe_log_exception(
                logger,
                logging.ERROR,
                "transient worker database failure",
                error_code="worker_database_unavailable",
                operation=operation,
                exception=exc,
            )
            return False
        finally:
            if heartbeat_stop is not None:
                heartbeat_stop.set()
            if heartbeat is not None:
                heartbeat.join(timeout=self.heartbeat_interval + 1)
            db.close()

    @staticmethod
    def _prepare_claim(claim: ClaimedJob) -> ClaimedJob:
        """Pure post-commit boundary hook; the claim contains no ORM state."""
        return claim

    def run_forever(self):
        consecutive_failures = 0
        try:
            while not self.stop_event.is_set():
                try:
                    worked = self.run_once()
                except SQLAlchemyError as exc:
                    # Final safety net: a database error must never reach Python's
                    # default unhandled-exception printer.
                    self.last_iteration_failed = True
                    safe_log_exception(
                        logger,
                        logging.ERROR,
                        "worker iteration database failure",
                        error_code="worker_database_unavailable",
                        operation="run_once",
                        exception=exc,
                    )
                    worked = False
                if self.last_iteration_failed:
                    consecutive_failures += 1
                    delay = min(self.poll_interval * (2 ** (consecutive_failures - 1)), self.error_backoff_max)
                    self.stop_event.wait(delay)
                else:
                    consecutive_failures = 0
                    if not worked:
                        self.stop_event.wait(self.poll_interval)
        except KeyboardInterrupt:
            self.stop_event.set()


def main() -> int:
    try:
        settings = get_settings()
        runtime = WorkerRuntime(
            archive_root=__import__('pathlib').Path(settings.archive_root),
            poll_interval=float(os.getenv("IMPORT_WORKER_POLL_SECONDS", "1")),
            heartbeat_interval=float(os.getenv("IMPORT_WORKER_HEARTBEAT_SECONDS", "10")),
            lease_duration=int(os.getenv("IMPORT_WORKER_LEASE_SECONDS", "30")),
        )
        runtime.run_forever()
        return 0
    except DatabaseConfigurationError as exc:
        sys.stderr.write(f"worker_startup_failed code={exc} exception=DatabaseConfigurationError\n")
        return 2
    except SQLAlchemyError as exc:
        sys.stderr.write(
            f"worker_startup_failed code=database_initialization_failed exception={exc.__class__.__name__}\n"
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
