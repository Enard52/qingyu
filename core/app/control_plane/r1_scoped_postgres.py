"""Scoped V2 journal using the existing F3 restricted-runtime connection gate."""
from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID
import psycopg

from .r1_postgres_store import R1PostgresStore, StoreError, _translate
from ._r1_validation_stream import RegistrySlice, WindowEvidence
from .r1_validation_codec import c2, decode, require


def _part(part):
    return {"header": part.header_wire.hex(), "events": [v.hex() for v in part.event_wires],
            "records": [[d, v.hex()] for d, v in part.record_wires]}


def _read_part(value):
    require(type(value) is dict and set(value) == {"header", "events", "records"}, "journal registry shape")
    return RegistrySlice(bytes.fromhex(value["header"]), tuple(bytes.fromhex(v) for v in value["events"]),
                         tuple((d, bytes.fromhex(v)) for d, v in value["records"]))


def window_wire(window):
    require(type(window) is WindowEvidence, "original WindowEvidence required")
    return c2({"requests": [v.hex() for v in window.request_wires], "authority": _part(window.authority),
        "cores": [[p, _part(s)] for p, s in window.cores],
        "sources": [v.hex() for v in window.source_admission_wires],
        "contexts": [v.hex() for v in window.context_wires]})


def read_window(raw):
    # The storage envelope is unsigned and is not a protocol object. Individual
    # original wires are decoded and verified independently by BoundedHistory.
    value = decode(raw)
    require(set(value) == {"requests", "authority", "cores", "sources", "contexts"}, "journal exact fields")
    return WindowEvidence(tuple(bytes.fromhex(v) for v in value["requests"]), _read_part(value["authority"]),
        tuple((p, _read_part(s)) for p, s in value["cores"]),
        tuple(bytes.fromhex(v) for v in value["sources"]), tuple(bytes.fromhex(v) for v in value["contexts"]))


@dataclass(frozen=True)
class ScopedStoredOperation:
    request_wire: bytes
    source_wire: bytes
    ack_wire: bytes | None
    authorization_wire: bytes | None
    proposal_wire: bytes | None
    acceptance_wire: bytes | None
    publication_wire: bytes | None
    terminal_wire: bytes | None


class ScopedTransaction:
    def __init__(self, connection, scope_id, revision, cached_wires=(), cached_windows=()):
        self.connection, self.scope_id, self.revision = connection, scope_id, revision
        rows = connection.execute("SELECT * FROM control_plane.r1s_history(%s)", (scope_id,)).fetchall()
        if [r[0] for r in rows] != list(range(1, revision + 1)):
            raise StoreError("JOURNAL_GAP")
        self.raw_windows = tuple(bytes(r[1]) for r in rows)
        if (len(cached_wires) == len(cached_windows) and len(self.raw_windows) >= len(cached_wires)
                and self.raw_windows[:len(cached_wires)] == cached_wires):
            self.windows = list(cached_windows) + [read_window(raw) for raw in self.raw_windows[len(cached_wires):]]
        else:
            self.windows = [read_window(raw) for raw in self.raw_windows]

    def now(self):
        return self.connection.execute("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint").fetchone()[0]

    def operation(self, operation_id):
        row = self.connection.execute("SELECT * FROM control_plane.r1s_operation(%s,%s)",
                                      (self.scope_id, UUID(operation_id))).fetchone()
        return None if row is None else ScopedStoredOperation(*(None if v is None else bytes(v) for v in row[2:]))

    def append(self, window, *, deadline=None, operation_id=None, request_wire=None, source_wire=None,
               ack_wire=None, authorization_wire=None, proposal_wire=None, acceptance_wire=None,
               publication_wire=None, terminal_wire=None):
        parameters = (self.scope_id, self.revision, window_wire(window), deadline,
            None if operation_id is None else UUID(operation_id), request_wire, source_wire,
            ack_wire, authorization_wire, proposal_wire, acceptance_wire, publication_wire, terminal_wire)
        self.revision = self.connection.execute(
            "SELECT control_plane.r1s_append(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", parameters).fetchone()[0]
        self.windows.append(window)


class ScopedPostgresStore:
    """No DDL, environment DSN, signer or direct table privileges at runtime.

    All mutable qualification lives in this scope's journal. Its scope row is
    locked before reading any original history, through signer and final COMMIT.
    Semantic rejections are never classified as retryable transaction failures.
    """
    def __init__(self, connection_factory, *, scope_id: str, configuration_digest: str):
        self.connections = R1PostgresStore(connection_factory)
        self.scope_id, self.configuration_digest = UUID(scope_id), configuration_digest
        self._parsed_wires, self._parsed_windows = (), ()

    def transact(self, action):
        for attempt in range(3):
            try:
                with self.connections._connection() as connection:
                    revision = connection.execute("SELECT control_plane.r1s_lock(%s,%s)",
                        (self.scope_id, self.configuration_digest)).fetchone()[0]
                    tx = ScopedTransaction(connection, self.scope_id, revision, self._parsed_wires, self._parsed_windows)
                    # Immutable dataclasses containing only original bytes are
                    # parse caches, rooted in the exact freshly read prefix.
                    self._parsed_wires, self._parsed_windows = tx.raw_windows, tuple(tx.windows)
                    result = action(tx)
                # Existing connection gate explicitly verifies COMMIT completed.
                return result
            except psycopg.Error as exc:
                if exc.sqlstate in {"40001", "40P01"} and attempt < 2:
                    continue
                raise _translate(exc) from None
        raise StoreError("TRANSACTION_CONFLICT")
