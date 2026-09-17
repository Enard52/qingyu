"""File-only pre-terminal coordination journal, separate from local APPLY truth."""
from contextlib import contextmanager
from dataclasses import dataclass
import os
from pathlib import Path
import sqlite3

from .control_plane.r1_validation_codec import ContractError, require


_APP_ID = 0x51594333
_DDL = (
    "CREATE TABLE seed (id INTEGER PRIMARY KEY CHECK(id=1), scope_wire BLOB NOT NULL, checkpoint_wire BLOB NOT NULL)",
    """CREATE TABLE attempts (
        operation_id TEXT PRIMARY KEY NOT NULL, mutation_id TEXT UNIQUE NOT NULL,
        local_commit_id TEXT UNIQUE NOT NULL, request_wire BLOB NOT NULL,
        source_wire BLOB NOT NULL, ack_wire BLOB, authorization_wire BLOB,
        proposal_wire BLOB, acceptance_wire BLOB, publication_wire BLOB,
        terminal_wire BLOB, completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN(0,1)))""",
    "CREATE TABLE windows (sequence INTEGER PRIMARY KEY NOT NULL, evidence_wire BLOB NOT NULL)",
)


@dataclass(frozen=True)
class CoordinationJournal:
    path: Path
    scope_wire: bytes
    checkpoint_wire: bytes
    busy_timeout_ms: int = 5000

    def __post_init__(self):
        path = Path(self.path).resolve()
        require(path.is_absolute() and str(path) != ':memory:', "file journal required")
        require(type(self.scope_wire) is bytes and type(self.checkpoint_wire) is bytes, "independent seed bytes required")
        require(type(self.busy_timeout_ms) is int and 0 < self.busy_timeout_ms <= 60000, "journal timeout")
        object.__setattr__(self, 'path', path)

    @classmethod
    def create(cls, path, *, scope_wire, checkpoint_wire, busy_timeout_ms=5000):
        journal = cls(Path(path), scope_wire, checkpoint_wire, busy_timeout_ms)
        require(not any(Path(str(journal.path) + s).exists() for s in ('-wal', '-shm', '-journal')),
                "new journal has existing sidecars")
        descriptor = os.open(journal.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        with journal._connection() as db:
            require(db.execute('PRAGMA journal_mode=WAL').fetchone()[0].lower() == 'wal', 'journal WAL required')
            db.execute('BEGIN IMMEDIATE')
            try:
                for statement in _DDL:
                    db.execute(statement)
                db.execute(f'PRAGMA application_id={_APP_ID}')
                db.execute('PRAGMA user_version=1')
                db.execute('INSERT INTO seed VALUES(1,?,?)', (scope_wire, checkpoint_wire))
                db.execute('COMMIT')
            except BaseException:
                db.execute('ROLLBACK')
                raise
        return cls.open(path, scope_wire=scope_wire, checkpoint_wire=checkpoint_wire,
                        busy_timeout_ms=busy_timeout_ms)

    @classmethod
    def open(cls, path, *, scope_wire, checkpoint_wire, busy_timeout_ms=5000):
        journal = cls(Path(path), scope_wire, checkpoint_wire, busy_timeout_ms)
        with journal.transaction(write=False):
            pass
        return journal

    @contextmanager
    def _connection(self):
        db = sqlite3.connect(self.path.as_uri() + '?mode=rw', uri=True, isolation_level=None,
                             timeout=self.busy_timeout_ms / 1000)
        db.row_factory = sqlite3.Row
        try:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('PRAGMA foreign_keys=ON')
            db.execute(f'PRAGMA busy_timeout={self.busy_timeout_ms}')
            yield db
        finally:
            db.close()

    def _validate(self, db):
        require(db.execute('PRAGMA application_id').fetchone()[0] == _APP_ID and
                db.execute('PRAGMA user_version').fetchone()[0] == 1, 'unsupported coordination journal')
        require(db.execute('PRAGMA journal_mode').fetchone()[0].lower() == 'wal', 'journal WAL required')
        normalize = lambda s: ' '.join(s.split())
        objects = db.execute('SELECT type,name,tbl_name,sql FROM sqlite_master').fetchall()
        actual = {}
        for item in objects:
            if (item['type'] == 'index' and item['sql'] is None and
                    item['name'].startswith('sqlite_autoindex_') and item['tbl_name'] in {'seed', 'attempts', 'windows'}):
                continue
            require(item['type'] == 'table' and item['sql'] is not None, 'unexpected coordination schema object')
            actual[item['name']] = normalize(item['sql'])
        expected = {s.split()[2]: normalize(s) for s in _DDL}
        require(actual == expected, 'coordination journal schema differs')
        seed = db.execute('SELECT * FROM seed WHERE id=1').fetchone()
        require(seed is not None and seed['scope_wire'] == self.scope_wire and
                seed['checkpoint_wire'] == self.checkpoint_wire, 'independent coordination seed differs')

    @contextmanager
    def transaction(self, *, write=True):
        with self._connection() as db:
            db.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
            try:
                self._validate(db)
                yield db
                db.execute('COMMIT')
            except BaseException:
                if db.in_transaction:
                    db.execute('ROLLBACK')
                raise

    @staticmethod
    def freeze(db, operation_id, **fields):
        allowed = {'ack_wire', 'authorization_wire', 'proposal_wire', 'acceptance_wire', 'publication_wire', 'terminal_wire'}
        row = db.execute('SELECT * FROM attempts WHERE operation_id=?', (operation_id,)).fetchone()
        require(row is not None, 'original intent missing')
        for name, value in fields.items():
            require(name in allowed and type(value) is bytes, 'immutable journal field')
            require(row[name] is None or row[name] == value, 'original coordination bytes conflict')
            db.execute(f'UPDATE attempts SET {name}=? WHERE operation_id=?', (value, operation_id))

    def load(self, operation_id):
        with self.transaction(write=False) as db:
            row = db.execute('SELECT * FROM attempts WHERE operation_id=?', (operation_id,)).fetchone()
            require(row is not None, 'original intent missing')
            return dict(row)

    def pending(self):
        with self.transaction(write=False) as db:
            return tuple(r[0] for r in db.execute('SELECT operation_id FROM attempts WHERE completed=0 ORDER BY rowid'))

    def inspect(self):
        with self.transaction(write=False) as db:
            return {'attempts': [dict(r) for r in db.execute('SELECT * FROM attempts ORDER BY rowid')],
                    'windows': db.execute('SELECT count(*) FROM windows').fetchone()[0]}
