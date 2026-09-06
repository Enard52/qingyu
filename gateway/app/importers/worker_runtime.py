import logging
import os
import threading

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import engine
from ..errors import safe_log_exception
from .processor import ImportProcessor
from .worker import ImportWorker, LeaseLost

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
    def __init__(self, archive_root, poll_interval=1.0, heartbeat_interval=10.0, lease_duration=30, error_backoff_max=5.0):
        self.archive_root = archive_root
        self.poll_interval = poll_interval
        self.heartbeat_interval = heartbeat_interval
        self.lease_duration = lease_duration
        self.error_backoff_max = error_backoff_max
        self.stop_event = threading.Event()
        self.last_iteration_failed = False

    def run_once(self) -> bool:
        self.last_iteration_failed = False
        with Session(engine) as db:
            worker = ImportWorker(db)
            operation = "recover_stale"
            try:
                worker.recover_stale()
                operation = "claim_next"
                job = worker.claim_next(self.lease_duration)
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
            if job is None:
                return False
            token = job.lease_token
            heartbeat_stop = threading.Event()
            attempt_health = AttemptHealth()

            def heartbeat_loop():
                while not heartbeat_stop.wait(self.heartbeat_interval):
                    with Session(engine) as heartbeat_db:
                        try:
                            alive = ImportWorker(heartbeat_db).heartbeat(job.id, token, self.lease_duration)
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
                                job_id=job.id,
                            )
                            heartbeat_stop.set()
                            return
                        if not alive:
                            attempt_health.mark_failed()
                            heartbeat_stop.set()
                            return

            heartbeat = threading.Thread(target=heartbeat_loop, name=f"import-heartbeat-{job.id}", daemon=True)
            heartbeat.start()
            try:
                ImportProcessor(db, self.archive_root).process(job, token, health_check=attempt_health.raise_if_failed)
            except LeaseLost:
                logger.info("import worker lost ownership", extra={"job_id": str(job.id)})
            except Exception as exc:
                safe_log_exception(
                    logger,
                    logging.ERROR,
                    "import job processing failed",
                    error_code="import_processing_failed",
                    operation="process_job",
                    exception=exc,
                    job_id=job.id,
                )
            finally:
                heartbeat_stop.set(); heartbeat.join(timeout=self.heartbeat_interval + 1)
            return True

    def run_forever(self):
        consecutive_failures = 0
        try:
            while not self.stop_event.is_set():
                worked = self.run_once()
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


def main():
    settings = get_settings()
    runtime = WorkerRuntime(
        archive_root=__import__('pathlib').Path(settings.archive_root),
        poll_interval=float(os.getenv("IMPORT_WORKER_POLL_SECONDS", "1")),
        heartbeat_interval=float(os.getenv("IMPORT_WORKER_HEARTBEAT_SECONDS", "10")),
        lease_duration=int(os.getenv("IMPORT_WORKER_LEASE_SECONDS", "30")),
    )
    runtime.run_forever()


if __name__ == "__main__": main()
