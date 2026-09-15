from contextlib import contextmanager
from types import SimpleNamespace
from uuid import UUID

import pytest
from psycopg.pq import TransactionStatus

from app.control_plane.r1_commands import AuthenticatedCaller, CommitAuthorization, MutationIntent
from app.control_plane.r1_postgres_store import R1PostgresStore, StoreError
from r1_f3_helpers import authorization_value, mutation_envelope, uid


class ConnectionDouble:
    """Transaction-boundary test only; NOT PostgreSQL locking/SQL evidence."""
    autocommit = False

    def __init__(self, proposal, final=b"signed"):
        self.proposal = proposal
        self.final = final
        self.calls = []
        self.commits = 0
        self.rollbacks = 0
        self.closed = False
        self.info = SimpleNamespace(transaction_status=TransactionStatus.INTRANS)

    def __enter__(self):
        return self

    def __exit__(self, kind, *_):
        return False

    @contextmanager
    def transaction(self):
        try:
            yield
        except BaseException:
            self.rollbacks += 1
            raise

    def commit(self):
        self.commits += 1
        self.info.transaction_status = TransactionStatus.IDLE

    def execute(self, statement, parameters=()):
        if "SELECT session_user" in statement:
            self.row = ("control_plane_app", "control_plane_app") + (False,) * 8
            return self
        self.calls.append((statement, parameters))
        self.row = (self.final,) if "finalize" in statement else self.proposal
        return self

    def fetchone(self):
        return self.row


def scope():
    return AuthenticatedCaller(uid(1), uid(4), uid(5), uid(9), uid(6), "test-owner")


def test_unique_terminal_boundary_finalizes_only_signature_then_commits():
    intent = MutationIntent.from_envelope(mutation_envelope())
    connection = ConnectionDouble((intent.operation_id, "COMMITTED", b"unsigned", False))
    store = R1PostgresStore(lambda: connection)
    with store.terminal(intent, scope(), CommitAuthorization.from_mapping(authorization_value(intent))) as tx:
        assert connection.commits == 0
        assert tx.finalize(intent.operation_id, b"s" * 64) == b"signed"
    assert connection.commits == 1 and connection.rollbacks == 0
    assert connection.calls[-1] == ("SELECT control_plane.f3_finalize_terminal(%s,%s)",
                                    (UUID(intent.operation_id), b"s" * 64))
    with pytest.raises(StoreError, match="PROPOSAL_MISMATCH"):
        tx.finalize(intent.operation_id, b"s" * 64)


def test_failed_signer_or_unfinalized_proposal_rolls_back_prepare():
    intent = MutationIntent.from_envelope(mutation_envelope())
    for error in (False, True):
        connection = ConnectionDouble((intent.operation_id, "PREPARED", b"unsigned", False))
        with pytest.raises((StoreError, RuntimeError)):
            with R1PostgresStore(lambda: connection).prepare(intent, scope()):
                if error:
                    raise RuntimeError("signer failed")
        assert connection.rollbacks == 1 and connection.commits == 0


def test_historical_terminal_is_read_only_and_cannot_finalize():
    intent = MutationIntent.from_envelope(mutation_envelope())
    connection = ConnectionDouble((intent.operation_id, "ABORTED", b"old-wire", True))
    with R1PostgresStore(lambda: connection).prepare(intent, scope()) as tx:
        assert tx.proposal.wire == b"old-wire"
        with pytest.raises(StoreError):
            tx.finalize(intent.operation_id, b"s" * 64)
    assert len(connection.calls) == 1


def test_autocommit_connection_refuses_before_first_procedure():
    intent = MutationIntent.from_envelope(mutation_envelope())
    connection = ConnectionDouble(None)
    connection.autocommit = True
    with pytest.raises(StoreError, match="AUTOCOMMIT_FORBIDDEN"):
        with R1PostgresStore(lambda: connection).prepare(intent, scope()):
            pass
    assert connection.calls == []


def test_closed_connection_cannot_report_finalized_transaction_as_committed():
    intent = MutationIntent.from_envelope(mutation_envelope())
    connection = ConnectionDouble((intent.operation_id,"COMMITTED",b"unsigned",False))
    with pytest.raises(StoreError,match="TRANSACTION_NOT_COMMITTED"):
        with R1PostgresStore(lambda:connection).terminal(intent,scope(),
                CommitAuthorization.from_mapping(authorization_value(intent))) as tx:
            tx.finalize(intent.operation_id,b"s"*64)
            connection.closed = True
    assert connection.commits == 0
