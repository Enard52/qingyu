import logging
import os
import threading
from time import sleep

from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import engine
from ..errors import safe_log_exception
from .processor import ImportProcessor
from .worker import ImportWorker, LeaseLost

logger = logging.getLogger(__name__)


class WorkerRuntime:
    def __init__(self, archive_root, poll_interval=1.0, heartbeat_interval=10.0, lease_duration=30):
        self.archive_root = archive_root
        self.poll_interval = poll_interval
        self.heartbeat_interval = heartbeat_interval
        self.lease_duration = lease_duration
        self.stop_event = threading.Event()

    def run_once(self) -> bool:
        with Session(engine) as db:
            worker = ImportWorker(db)
            worker.recover_stale()
            job = worker.claim_next(self.lease_duration)
            if job is None:
                return False
            token = job.lease_token
            heartbeat_stop = threading.Event()

            def heartbeat_loop():
                while not heartbeat_stop.wait(self.heartbeat_interval):
                    with Session(engine) as heartbeat_db:
                        if not ImportWorker(heartbeat_db).heartbeat(job.id, token, self.lease_duration):
                            heartbeat_stop.set()
                            return

            heartbeat = threading.Thread(target=heartbeat_loop, name=f"import-heartbeat-{job.id}", daemon=True)
            heartbeat.start()
            try:
                ImportProcessor(db, self.archive_root).process(job, token)
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
        try:
            while not self.stop_event.is_set():
                if not self.run_once(): self.stop_event.wait(self.poll_interval)
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
