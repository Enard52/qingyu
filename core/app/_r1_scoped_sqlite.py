"""Explicit Core-local scoped storage; no implicit bootstrap or V1 migration.

This backend stores opaque original bytes. The local finish service, not this
module, validates the protocol and decides whether a write is authorized.
Every unit of work uses its own SQLite connection and an actual file. Writers
acquire BEGIN IMMEDIATE before reading mutable preconditions. SQLite errors,
including busy/commit errors, propagate: they are never converted to a terminal.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import os
from pathlib import Path
import sqlite3
from typing import Iterator


APPLICATION_ID = 0x51523241
SCHEMA_VERSION = 2


class ScopedStoreError(ValueError):
    """The explicitly supplied store is missing, incompatible, or wrong-scope."""


_DDL = (
    """CREATE TABLE history_windows (
        sequence INTEGER PRIMARY KEY NOT NULL,
        evidence_wire BLOB NOT NULL CHECK (typeof(evidence_wire) = 'blob'),
        verification_wire BLOB NOT NULL CHECK (typeof(verification_wire) = 'blob')
    )""",
    """CREATE TABLE metadata (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        scope_wire BLOB NOT NULL CHECK (typeof(scope_wire) = 'blob'),
        checkpoint_wire BLOB NOT NULL CHECK (typeof(checkpoint_wire) = 'blob'),
        business_state_wire BLOB NOT NULL CHECK (typeof(business_state_wire) = 'blob'),
        initial_checkpoint_wire BLOB NOT NULL CHECK (typeof(initial_checkpoint_wire) = 'blob'),
        initial_business_state_wire BLOB NOT NULL CHECK (typeof(initial_business_state_wire) = 'blob'),
        core_history_wire BLOB CHECK (core_history_wire IS NULL OR typeof(core_history_wire) = 'blob'),
        authority_history_wire BLOB CHECK (authority_history_wire IS NULL OR typeof(authority_history_wire) = 'blob')
    )""",
    """CREATE TABLE operations (
        operation_id TEXT PRIMARY KEY NOT NULL,
        mutation_id TEXT UNIQUE NOT NULL,
        local_commit_id TEXT UNIQUE NOT NULL,
        request_wire BLOB NOT NULL CHECK (typeof(request_wire) = 'blob'),
        original_wire BLOB NOT NULL CHECK (typeof(original_wire) = 'blob'),
        evidence_wire BLOB NOT NULL CHECK (typeof(evidence_wire) = 'blob'),
        status TEXT NOT NULL CHECK (status IN ('PENDING', 'FINALIZED'))
    )""",
    """CREATE TABLE completions (
        operation_id TEXT PRIMARY KEY NOT NULL REFERENCES operations(operation_id),
        terminal_wire BLOB NOT NULL CHECK (typeof(terminal_wire) = 'blob'),
        audit_wire BLOB NOT NULL CHECK (typeof(audit_wire) = 'blob'),
        result_wire BLOB NOT NULL CHECK (typeof(result_wire) = 'blob'),
        effect_wire BLOB NOT NULL CHECK (typeof(effect_wire) = 'blob'),
        completion_wire BLOB NOT NULL CHECK (typeof(completion_wire) = 'blob'),
        local_use_wire BLOB NOT NULL CHECK (typeof(local_use_wire) = 'blob'),
        permit_wire BLOB NOT NULL CHECK (typeof(permit_wire) = 'blob'),
        checkpoint_wire BLOB NOT NULL CHECK (typeof(checkpoint_wire) = 'blob'),
        evidence_wire BLOB NOT NULL CHECK (typeof(evidence_wire) = 'blob')
    )""",
    """CREATE TABLE business_records (
        mutation_id TEXT PRIMARY KEY NOT NULL,
        operation_id TEXT UNIQUE NOT NULL REFERENCES operations(operation_id),
        value_wire BLOB NOT NULL CHECK (typeof(value_wire) = 'blob')
    )""",
    """CREATE TABLE permit_consumptions (
        operation_id TEXT PRIMARY KEY NOT NULL REFERENCES completions(operation_id),
        permit_digest TEXT UNIQUE NOT NULL,
        local_event_position BLOB UNIQUE NOT NULL CHECK (typeof(local_event_position) = 'blob')
    )""",
)


def _normalize_sql(sql: str) -> str:
    return " ".join(sql.split())


_EXPECTED_SCHEMA = {
    statement.split()[2]: _normalize_sql(statement) for statement in _DDL
}


def _file_path(path: str | os.PathLike[str]) -> Path:
    supplied = Path(path)
    if not supplied.is_absolute() or supplied.name in ("", ":memory:"):
        raise ScopedStoreError("an explicit absolute file path is required")
    if supplied.is_symlink():
        raise ScopedStoreError("a symbolic-link database path is not supported")
    parent = supplied.parent.resolve(strict=True)
    if not parent.is_dir():
        raise ScopedStoreError("database parent must already be a directory")
    return parent / supplied.name


def _wire(value: bytes, name: str) -> bytes:
    if type(value) is not bytes or not value:
        raise ScopedStoreError(name + " must be nonempty immutable bytes")
    return value


def _timeout(value: int) -> int:
    if type(value) is not int or not 0 <= value <= 60_000:
        raise ScopedStoreError("busy timeout must be an integer from 0 to 60000 ms")
    return value


@dataclass(frozen=True, slots=True)
class ScopedSQLiteStore:
    """An explicit handle; constructing a handle never initializes a database.

    ``create`` is the sole initialization path and exclusively creates a new
    file. ``open`` validates an existing supported file without schema changes.
    Neither path loads the application's DSN or business configuration.
    """

    path: Path
    scope_wire: bytes
    busy_timeout_ms: int = 5000

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _file_path(self.path))
        _wire(self.scope_wire, "scope_wire")
        _timeout(self.busy_timeout_ms)

    @classmethod
    def create(cls, path: str | os.PathLike[str], *, scope_wire: bytes,
               checkpoint_wire: bytes, business_state_wire: bytes,
               busy_timeout_ms: int = 5000) -> ScopedSQLiteStore:
        handle = cls(_file_path(path), _wire(scope_wire, "scope_wire"), _timeout(busy_timeout_ms))
        _wire(checkpoint_wire, "checkpoint_wire")
        _wire(business_state_wire, "business_state_wire")
        if any(Path(str(handle.path) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")):
            raise ScopedStoreError("new database path has pre-existing SQLite sidecars")
        # Reserve the exact new resource before SQLite can open it. Never reuse,
        # truncate, migrate, or delete a file on failure, including sidecars.
        descriptor = os.open(handle.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        with handle._connection() as connection:
            if connection.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() != "wal":
                raise ScopedStoreError("WAL journal mode is required")
            connection.execute("BEGIN IMMEDIATE")
            try:
                for statement in _DDL:
                    connection.execute(statement)
                connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                connection.execute("INSERT INTO metadata VALUES (1, ?, ?, ?, ?, ?, NULL, NULL)",
                                   (scope_wire, checkpoint_wire, business_state_wire,
                                    checkpoint_wire, business_state_wire))
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        # The same reopened validation path is used after initialization and
        # after a process restart. No retained connection or in-memory state.
        return cls.open(handle.path, expected_scope_wire=scope_wire,
                        busy_timeout_ms=busy_timeout_ms)

    @classmethod
    def open(cls, path: str | os.PathLike[str], *, expected_scope_wire: bytes,
             busy_timeout_ms: int = 5000) -> ScopedSQLiteStore:
        handle = cls(_file_path(path), _wire(expected_scope_wire, "expected_scope_wire"),
                     _timeout(busy_timeout_ms))
        with handle.transaction(write=False):
            pass
        return handle

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True,
                                     isolation_level=None, timeout=self.busy_timeout_ms / 1000)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA synchronous=FULL")
            yield connection
        finally:
            connection.close()

    def _validate(self, connection: sqlite3.Connection) -> None:
        if (connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID
                or connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION
                or connection.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal"):
            raise ScopedStoreError("unsupported scoped SQLite schema or journal mode")
        rows = connection.execute("SELECT type, name, sql FROM sqlite_schema").fetchall()
        actual = {}
        for row in rows:
            if (row["type"] == "index" and row["name"].startswith("sqlite_autoindex_")
                    and row["sql"] is None):
                continue
            if row["type"] != "table" or row["name"] not in _EXPECTED_SCHEMA:
                raise ScopedStoreError("unsupported extra schema object")
            actual[row["name"]] = _normalize_sql(row["sql"])
        if actual != _EXPECTED_SCHEMA:
            raise ScopedStoreError("unsupported scoped SQLite schema definition")
        metadata = connection.execute("SELECT scope_wire FROM metadata").fetchall()
        if len(metadata) != 1 or metadata[0]["scope_wire"] != self.scope_wire:
            raise ScopedStoreError("local scope differs from independent expected scope")

    @contextmanager
    def transaction(self, *, write: bool = True) -> Iterator[sqlite3.Connection]:
        if type(write) is not bool:
            raise ScopedStoreError("transaction write mode must be a bool")
        with self._connection() as connection:
            # query_only is an enforcement boundary, not just a method name.
            connection.execute("PRAGMA query_only=" + ("OFF" if write else "ON"))
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            try:
                self._validate(connection)
                yield connection
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def inspect(self) -> dict:
        """Consistent opaque snapshot for diagnostics; not business admission."""
        with self.transaction(write=False) as connection:
            result = dict(connection.execute("SELECT * FROM metadata WHERE id=1").fetchone())
            result["counts"] = {
                table: connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                for table in ("operations", "completions", "permit_consumptions", "business_records")
            }
            result["business_records"] = [dict(row) for row in connection.execute(
                "SELECT mutation_id, operation_id, value_wire FROM business_records ORDER BY mutation_id")]
            result["sqlite_version"] = sqlite3.sqlite_version
            result["settings"] = {
                setting: connection.execute("PRAGMA " + setting).fetchone()[0]
                for setting in ("journal_mode", "synchronous", "foreign_keys", "busy_timeout",
                                "application_id", "user_version")
            }
            result["write_transaction"] = "BEGIN IMMEDIATE"
            result["read_transaction"] = "BEGIN"
            return result
