"""Restricted-routine PostgreSQL persistence for the canonical F3 coordinator."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Iterator
from uuid import UUID

import psycopg
from psycopg.pq import TransactionStatus
from psycopg.types.json import Jsonb

from .r1_commands import AbortAuthorization, AuthenticatedCaller, CommitAuthorization, MutationIntent
from .r1_protocol import ProtocolError, canonical_bytes


class StoreError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _translate(exc: psycopg.Error) -> StoreError:
    primary = getattr(getattr(exc, "diag", None), "message_primary", "") or ""
    if primary.startswith("R1_F3_") and primary[6:].replace("_", "").isalnum():
        return StoreError(primary[6:])
    if exc.sqlstate in {"40001", "40P01"}:
        return StoreError("TRANSACTION_CONFLICT")
    if exc.sqlstate == "23505":
        return StoreError("OPERATION_CONFLICT")
    return StoreError("DATABASE_UNAVAILABLE")


@dataclass(frozen=True, slots=True)
class StoreProposal:
    operation_id: str
    state: str
    wire: bytes
    historical: bool


@dataclass(frozen=True, slots=True)
class StoredOperation:
    state: str
    wire: bytes


class StoreTransaction:
    """One open connection/transaction; a proposal cannot escape to a later one."""

    def __init__(self, connection: psycopg.Connection, proposal: StoreProposal, *, phase: str):
        self.proposal = proposal
        self._connection = connection
        self._phase = phase
        self._finalized = proposal.historical
        self._active = True

    def finalize(self, operation_id: str, signature: bytes) -> bytes:
        if not self._active or self._finalized or operation_id != self.proposal.operation_id:
            raise StoreError("PROPOSAL_MISMATCH")
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise ProtocolError("signature must contain exactly 64 bytes")
        sql = ("SELECT control_plane.f3_finalize_prepare(%s,%s)" if self._phase == "prepare"
               else "SELECT control_plane.f3_finalize_terminal(%s,%s)")
        row = self._connection.execute(sql, (UUID(operation_id), signature)).fetchone()
        if row is None or row[0] is None:
            raise StoreError("FINALIZE_MISSING")
        self._finalized = True
        return bytes(row[0])

    def _close(self) -> None:
        self._active = False


class R1PostgresStore:
    """No DDL, fallback, signing key, environment DSN or base-table DML here.

    Production construction/admission is the coordinator factory's duty. The
    injected factory must return a fresh service-role psycopg connection.
    """

    def __init__(self, connection_factory: Callable[[], psycopg.Connection]):
        if not callable(connection_factory):
            raise TypeError("explicit PostgreSQL connection factory required")
        self._connection_factory = connection_factory

    @contextmanager
    def _connection(self):
        with self._connection_factory() as connection:
            if connection.autocommit:
                raise StoreError("AUTOCOMMIT_FORBIDDEN")
            identity = connection.execute("""SELECT session_user,current_user,r.rolsuper,r.rolinherit,
                r.rolcreatedb,r.rolcreaterole,r.rolreplication,r.rolbypassrls,
                pg_catalog.pg_has_role(current_user,'control_plane_owner','MEMBER'),
                pg_catalog.pg_has_role(current_user,'control_plane_migrator','MEMBER')
                FROM pg_catalog.pg_roles r WHERE r.rolname=current_user""").fetchone()
            if (identity is None or tuple(identity[:2]) != ("control_plane_app", "control_plane_app")
                    or any(identity[2:])):
                raise StoreError("RUNTIME_ROLE_FORBIDDEN")
            yield connection
            # psycopg's connection context silently skips COMMIT when already
            # closed. Returning a signature after that path would expose a
            # rolled-back proposal as a durable terminal result. Require an
            # explicit successful commit acknowledgement on the live session.
            if connection.closed:
                raise StoreError("TRANSACTION_NOT_COMMITTED")
            connection.commit()
            if connection.closed or connection.info.transaction_status != TransactionStatus.IDLE:
                raise StoreError("TRANSACTION_NOT_COMMITTED")

    @contextmanager
    def _operation(self, sql: str, parameters: tuple[Any, ...], *, phase: str) -> Iterator[StoreTransaction]:
        tx = None
        try:
            with self._connection() as connection:
                if connection.autocommit:
                    raise StoreError("AUTOCOMMIT_FORBIDDEN")
                with connection.transaction():
                    row = connection.execute(sql, parameters).fetchone()
                    if row is None or row[2] is None:
                        raise StoreError("PROPOSAL_MISSING")
                    tx = StoreTransaction(connection, StoreProposal(str(row[0]), row[1], bytes(row[2]), bool(row[3])), phase=phase)
                    yield tx
                    if not tx._finalized:
                        raise StoreError("UNFINALIZED_PROPOSAL")
                # Actual COMMIT (and deferred expiry guard) completes before return.
        except psycopg.Error as exc:
            raise _translate(exc) from None
        finally:
            if tx is not None:
                tx._close()

    def prepare(self, intent: MutationIntent, caller: AuthenticatedCaller):
        caller.validate_for(intent)
        return self._operation("SELECT * FROM control_plane.f3_propose_prepare(%s,%s,%s,%s)",
            (intent.request_wire, Jsonb(caller.as_mapping()), canonical_bytes(intent.result_payload("COMMITTED")),
             canonical_bytes(intent.result_payload("ABORTED"))), phase="prepare")

    def terminal(self, intent: MutationIntent, caller: AuthenticatedCaller,
                 authorization: CommitAuthorization | AbortAuthorization):
        caller.validate_for(intent)
        if not isinstance(authorization, (CommitAuthorization, AbortAuthorization)):
            raise ProtocolError("explicit commit or abort authorization required")
        authorization.validate_for(intent)
        return self._operation("SELECT * FROM control_plane.f3_propose_terminal(%s,%s,%s)",
            (intent.request_wire, Jsonb(caller.as_mapping()), authorization.wire), phase="terminal")

    def query(self, operation_id: str, caller: AuthenticatedCaller,
              request_envelope_hash: str | None = None) -> StoredOperation | None:
        try:
            with self._connection() as connection:
                row = connection.execute("SELECT * FROM control_plane.f3_query(%s,%s,%s)",
                    (UUID(operation_id), Jsonb(caller.as_mapping()), request_envelope_hash)).fetchone()
                return None if row is None else StoredOperation(row[0], bytes(row[1]))
        except psycopg.Error as exc:
            raise _translate(exc) from None

    def lookup_intent(self, operation_id: str, caller: AuthenticatedCaller) -> MutationIntent | None:
        try:
            with self._connection() as connection:
                row = connection.execute("SELECT control_plane.f3_lookup_intent(%s,%s)",
                    (UUID(operation_id), Jsonb(caller.as_mapping()))).fetchone()
                return None if row is None or row[0] is None else MutationIntent.from_wire(bytes(row[0]))
        except psycopg.Error as exc:
            raise _translate(exc) from None

    def describe(self) -> dict[str, Any]:
        try:
            with self._connection() as connection:
                cursor = connection.execute("SELECT * FROM control_plane.f3_runtime_description")
                rows = cursor.fetchall()
                if len(rows) != 1:
                    raise StoreError("AUTHORITY_NOT_ACTIVE")
                return dict(zip((column.name for column in cursor.description), rows[0], strict=True))
        except psycopg.Error as exc:
            raise _translate(exc) from None

    def genesis_evidence(self, caller: AuthenticatedCaller) -> dict[str, Any]:
        """Scoped immutable signed evidence; coordinator must verify it cryptographically."""
        try:
            with self._connection() as connection:
                row = connection.execute("SELECT control_plane.f3_genesis_evidence(%s)",
                                         (Jsonb(caller.as_mapping()),)).fetchone()
                if row is None or not isinstance(row[0], dict):
                    raise StoreError("GENESIS_FENCED")
                return row[0]
        except psycopg.Error as exc:
            raise _translate(exc) from None
