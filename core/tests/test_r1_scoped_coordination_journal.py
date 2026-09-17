"""Author checks of original-byte journal durability; not remote E2E evidence."""
from pathlib import Path
import multiprocessing
import os
import tempfile
import unittest

from app._r1_coordination_journal import CoordinationJournal
from app.control_plane.r1_validation_codec import ContractError


def _crash_writer(path, before_commit):
    journal = CoordinationJournal.open(path, scope_wire=b'original scope', checkpoint_wire=b'original checkpoint')
    with journal.transaction() as db:
        db.execute('INSERT INTO attempts(operation_id,mutation_id,local_commit_id,request_wire,source_wire) VALUES(?,?,?,?,?)',
            ('operation', 'mutation', 'local', b'original request', b'original admission'))
        if before_commit:
            os._exit(83)
    os._exit(84)


class CoordinationJournalTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix='r1-s03-author-journal-')
        self.path = Path(self.folder.name) / 'coordination.sqlite'
        self.journal = CoordinationJournal.create(self.path, scope_wire=b'original scope', checkpoint_wire=b'original checkpoint')

    def tearDown(self):
        self.folder.cleanup()

    def test_committed_intent_survives_owned_process_exit(self):
        process = multiprocessing.get_context('spawn').Process(target=_crash_writer, args=(str(self.path), False))
        process.start(); process.join(20)
        self.assertFalse(process.is_alive())
        self.assertEqual(process.exitcode, 84)
        reopened = CoordinationJournal.open(self.path, scope_wire=b'original scope', checkpoint_wire=b'original checkpoint')
        row = reopened.load('operation')
        self.assertEqual((row['request_wire'], row['source_wire']), (b'original request', b'original admission'))
        self.assertEqual(reopened.pending(), ('operation',))

    def test_uncommitted_intent_is_not_recovered_after_process_exit(self):
        process = multiprocessing.get_context('spawn').Process(target=_crash_writer, args=(str(self.path), True))
        process.start(); process.join(20)
        self.assertFalse(process.is_alive())
        self.assertEqual(process.exitcode, 83)
        self.assertEqual(self.journal.inspect()['attempts'], [])

    def test_same_dispatch_bytes_replay_but_conflict_rolls_back(self):
        with self.journal.transaction() as db:
            db.execute('INSERT INTO attempts(operation_id,mutation_id,local_commit_id,request_wire,source_wire) VALUES(?,?,?,?,?)',
                ('operation', 'mutation', 'local', b'original request', b'original admission'))
            self.journal.freeze(db, 'operation', authorization_wire=b'exact authorization', proposal_wire=b'exact proposal')
        with self.journal.transaction() as db:
            self.journal.freeze(db, 'operation', authorization_wire=b'exact authorization', proposal_wire=b'exact proposal')
        before = self.journal.inspect()
        with self.assertRaises(ContractError):
            with self.journal.transaction() as db:
                self.journal.freeze(db, 'operation', acceptance_wire=b'uncommitted acceptance', proposal_wire=b'changed proposal')
        self.assertEqual(self.journal.inspect(), before)

    def test_reopen_rejects_substituted_independent_seed_and_existing_create(self):
        with self.assertRaises(ContractError):
            CoordinationJournal.open(self.path, scope_wire=b'another scope', checkpoint_wire=b'original checkpoint')
        with self.assertRaises((ContractError, FileExistsError)):
            CoordinationJournal.create(self.path, scope_wire=b'original scope', checkpoint_wire=b'original checkpoint')
        self.assertEqual(self.journal.inspect()['attempts'], [])


if __name__ == '__main__':
    unittest.main()
