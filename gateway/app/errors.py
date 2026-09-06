from sqlalchemy.exc import SQLAlchemyError


def safe_database_error(exc: SQLAlchemyError) -> str:
    """Return the stable public/log representation; never stringify DB exceptions."""
    return "database_error"
