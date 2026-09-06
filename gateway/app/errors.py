import logging
from typing import Any

from sqlalchemy.exc import SQLAlchemyError


def safe_database_error(exc: SQLAlchemyError) -> str:
    """Return the stable public/log representation; never stringify DB exceptions."""
    return "database_operation_failed"


def safe_log_exception(
    logger: logging.Logger,
    level: int,
    message: str,
    *,
    error_code: str,
    operation: str,
    exception: BaseException,
    job_id: Any | None = None,
    correlation_id: str | None = None,
) -> None:
    """Log exception metadata without retaining its message, args, or traceback."""
    extra = {
        "error_code": error_code,
        "operation": operation,
        "error_type": type(exception).__name__,
    }
    if job_id is not None:
        extra["job_id"] = str(job_id)
    if correlation_id is not None:
        extra["correlation_id"] = correlation_id
    logger.log(level, message, extra=extra)
