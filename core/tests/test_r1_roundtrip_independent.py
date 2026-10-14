"""Non-author Slice03 checks against owned PostgreSQL and real pinned HTTPS.

The shared controlled provider supplies only test initialization, source intake,
governance and permit issuance. These checks never synthesize or insert a business
Ack, FIX, terminal or local completion. Private test files are not evidence output.
"""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import unittest
from uuid import uuid4

import psycopg
from psycopg import sql

from app._r1_coordination_journal import CoordinationJournal
from app.control_plane.r1_scoped_authority import configuration_digest
from app.control_plane.r1_scoped_schema import install_scoped_test_schema
from app.control_plane.r1_scoped_transport import ScopedAuthorityClient, ScopedHTTPRejected
from app.control_plane.r1_validation_codec import ContractError, c2, decode, h2
from app.control_plane.r1_validation_crypto import FixedTrust, verify_signed
from tests.r1_roundtrip_provider import bootstrap, trust, material, boundary
from tests.r1_roundtrip_run import core, request_for, start_server
from tests.r1_private_config import resolve_slice03_private_config


ROOT = Path(__file__).resolve().parents[1]
OWNED = ROOT / '.tmp/r1-s03-harness-local'
OBSERVATIONS = []


class IndependentJournalChecks(unittest.TestCase):
    def test_unsupported_schema_names_cannot_hide_behind_sqlite_wildcard(self):
        folder = OWNED / ('review-journal-' + uuid4().hex)
        folder.mkdir(parents=True)
        for kind in ('table', 'trigger'):
            path = folder / (kind + '.sqlite')
            journal = CoordinationJournal.create(path, scope_wire=b'owned scope', checkpoint_wire=b'owned checkpoint')
            with sqlite3.connect(path) as db:
                if kind == 'table':
                    db.execute('CREATE TABLE sqlitex_extra (value BLOB)')
                else:
                    db.execute('CREATE TRIGGER sqlitex_extra AFTER INSERT ON attempts BEGIN SELECT 1; END')
            before = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaises(ContractError):
                CoordinationJournal.open(path, scope_wire=b'owned scope', checkpoint_wire=b'owned checkpoint')
            self.assertEqual(before, hashlib.sha256(path.read_bytes()).hexdigest())
        OBSERVATIONS.append({'case': 'strict_schema_hidden_table_and_trigger', 'rejected': 2, 'unchanged': True})


class IndependentRoundtripChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        resolved = resolve_slice03_private_config()
        cls.base = dict(resolved.data)
        c = cls.base
        labels = json.loads(subprocess.check_output(['docker', 'inspect', '--format', '{{json .Config.Labels}}', c['container']]))
        ports = json.loads(subprocess.check_output(['docker', 'inspect', '--format', '{{json .NetworkSettings.Ports}}', c['container']]))
        if labels.get('qingyu.slice03.owner') != c['owner'] or ports['5432/tcp'] != [{'HostIp': '127.0.0.1', 'HostPort': str(c['port'])}]:
            raise RuntimeError('owned Docker labels/loopback mapping mismatch')

    def connect(self, role='control_plane_app', *, autocommit=False):
        cfg = self.config
        password = cfg['app_password'] if role == 'control_plane_app' else cfg['migrator_password']
        return psycopg.connect(host=cfg['host'], port=cfg['port'], dbname=cfg['dbname'], user=role,
                               password=password, autocommit=autocommit)

    def setUp(self):
        suffix = uuid4().hex[:12]
        self.folder = OWNED / ('review-' + suffix)
        self.folder.mkdir()
        self.path = self.folder / 'private-config.json'
        self.database = 'r1_slice03_test_' + self.base['owner'].removeprefix('r1-s03-') + '_review_' + suffix
        c = self.base
        with psycopg.connect(host=c['host'], port=c['port'], dbname=c['dbname'], user='postgres',
                             password=c['admin_password'], autocommit=True) as db:
            if int(db.execute('SHOW server_version_num').fetchone()[0]) // 10000 != 16:
                raise RuntimeError('owned PostgreSQL16 required')
            db.execute(sql.SQL('CREATE DATABASE {} OWNER control_plane_owner').format(sql.Identifier(self.database)))
            db.execute(sql.SQL('COMMENT ON DATABASE {} IS {}').format(sql.Identifier(self.database),
                       sql.Literal('R1_SLICE03_TEST_ONLY:' + self.database)))
            db.execute(sql.SQL('REVOKE ALL ON DATABASE {} FROM PUBLIC').format(sql.Identifier(self.database)))
            db.execute(sql.SQL('GRANT CONNECT ON DATABASE {} TO control_plane_migrator,control_plane_app').format(sql.Identifier(self.database)))
        config = {key: c[key] for key in ('host', 'port', 'app_password', 'migrator_password', 'container')}
        config['dbname'] = self.database
        self.path.write_text(json.dumps(config), encoding='utf-8')
        self.config = bootstrap(self.path)
        digest = configuration_digest(trust(self.config), (material(self.config),), boundary(self.config))
        with self.connect('control_plane_migrator') as db:
            db.execute('SET ROLE control_plane_owner')
            db.execute('CREATE SCHEMA control_plane AUTHORIZATION control_plane_owner')
            db.execute('REVOKE ALL ON SCHEMA control_plane FROM PUBLIC')
            install_scoped_test_schema(db, test_database_name=self.database,
                scope_id=self.config['scope_id'], configuration_digest=digest)
        self.server, self.output = start_server(self.path)
        self.coordinator = core(self.path, create=True)

    def tearDown(self):
        if getattr(self, 'server', None) is not None:
            if self.server.poll() is None:
                self.server.terminate()
                self.server.wait(timeout=20)
            self.output.close()

    def physical(self):
        with self.connect('control_plane_migrator') as db:
            db.execute('SET ROLE control_plane_owner')
            remote = db.execute('SELECT operation_id,request_wire,ack_wire,authorization_wire,proposal_wire,acceptance_wire,publication_wire,terminal_wire FROM control_plane.r1s_operations ORDER BY operation_id').fetchall()
            journal_count = db.execute('SELECT count(*) FROM control_plane.r1s_journal').fetchone()[0]
        with self.coordinator.finisher.store.transaction(write=False) as db:
            local = [dict(row) for row in db.execute('SELECT * FROM completions ORDER BY operation_id')]
            counts = {table: db.execute('SELECT count(*) FROM ' + table).fetchone()[0]
                      for table in ('operations', 'business_records', 'completions', 'permit_consumptions')}
        return remote, journal_count, local, counts

    def test_runtime_privileges_and_procedure_ownership(self):
        with self.connect() as db:
            role = db.execute('SELECT session_user,current_user,rolsuper,rolinherit,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=current_user').fetchone()
            self.assertEqual(role[:2], ('control_plane_app', 'control_plane_app'))
            self.assertFalse(any(role[2:]))
            denied = db.execute("SELECT has_table_privilege(current_user,'control_plane.r1s_operations','INSERT,UPDATE,DELETE'), has_table_privilege(current_user,'control_plane.r1s_journal','INSERT,UPDATE,DELETE'), pg_has_role(current_user,'control_plane_owner','MEMBER')").fetchone()
            self.assertEqual(denied, (False, False, False))
            procedures = db.execute("SELECT p.proname,pg_get_userbyid(p.proowner),p.prosecdef,p.proconfig FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='control_plane' ORDER BY p.proname").fetchall()
            self.assertTrue(procedures)
            self.assertTrue(all(row[1] == 'control_plane_owner' for row in procedures))
            self.assertTrue(all('search_path=pg_catalog, control_plane, pg_temp' in (row[3] or []) for row in procedures))
        for statement in ('INSERT INTO control_plane.r1s_journal VALUES(NULL,1,NULL)',
                          'SET ROLE control_plane_owner'):
            with self.connect() as db:
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    db.execute(statement)
        OBSERVATIONS.append({'case': 'runtime_role_and_restricted_sql', 'database': self.database,
            'runtime_role': list(role), 'base_dml_and_owner_membership': list(denied), 'procedures': [r[0] for r in procedures]})

    def test_wrong_pin_never_acquires_credential(self):
        pin = dict(self.config['pin']); pin['server_spki_sha256'] = '0' * 64
        wrong = FixedTrust(c2(pin), bytes.fromhex(self.config['root_public']))
        calls = []
        client = ScopedAuthorityClient(trust=wrong, ca_file=str(self.folder / 'ca.pem'),
            credential_provider=lambda: calls.append('called') or 'synthetic-unused-token')
        with self.assertRaises(Exception):
            client.prepare(c2({}), c2({}))
        self.assertEqual(calls, [])
        self.assertEqual(self.physical()[0], [])
        OBSERVATIONS.append({'case': 'real_tls_wrong_spki', 'credential_calls': 0, 'business_rows': 0})

    def test_wrong_credential_rejected_before_business_fact(self):
        client = ScopedAuthorityClient(trust=trust(self.config), ca_file=str(self.folder / 'ca.pem'),
            credential_provider=lambda: 'independent-unregistered-test-token')
        with self.assertRaises(ScopedHTTPRejected):
            client.prepare(c2({}), c2({}))
        self.assertEqual(self.physical()[0], [])
        OBSERVATIONS.append({'case': 'real_tls_wrong_credential', 'business_rows': 0})

    def test_two_durable_originals_compete_through_real_worker_processes(self):
        originals = [request_for(self.coordinator) for _ in range(2)]
        operations = [self.coordinator.persist_intent(request, source) for request, source in originals]
        for request, source in originals:
            self.coordinator.source.ensure_execution(request, source)
        processes = [subprocess.Popen([sys.executable, '-B', '-m', 'tests.r1_roundtrip_run',
            'worker', str(self.path), op], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0) for op in operations]
        outputs = []
        for process in processes:
            raw, _ = process.communicate(timeout=120)
            outputs.append({'launcher_pid': process.pid, 'exit_code': process.returncode,
                            'output': raw.decode('utf-8', errors='replace')})
        self.assertEqual(sum(p['exit_code'] == 0 for p in outputs), 1, outputs)
        remote, _, local, counts = self.physical()
        self.assertEqual(sum(row[-1] is not None for row in remote), 1)
        self.assertEqual(counts, {'operations': 1, 'business_records': 1,
                                 'completions': 1, 'permit_consumptions': 1})
        self.assertEqual(len(local), 1)
        winner = local[0]['operation_id']
        original_by_id = {decode(request)['intent']['operation_id']: request for request, _ in originals}
        for row in remote:
            self.assertEqual(bytes(row[1]), original_by_id[str(row[0])])
            if str(row[0]) == winner:
                self.assertEqual(bytes(row[-1]), local[0]['terminal_wire'])
                verify_signed(bytes(row[-1]), trust(self.config))
        OBSERVATIONS.append({'case': 'independent_two_original_process_competition',
            'database': self.database, 'operations': operations, 'processes': outputs,
            'winner': winner, 'physical_counts': counts, 'authority_terminal_count': 1,
            'loser_completion_absent': True})

    def test_real_commit_abort_query_exact_replay_and_physical_bytes(self):
        records = []
        for decision in ('COMMIT', 'ABORT'):
            request, source = request_for(self.coordinator, decision)
            result = self.coordinator.governed_mutation(request, source)
            self.assertTrue(result.applied)
            verify_signed(result.terminal_wire, trust(self.config))
            query = self.coordinator.query(result.operation_id, request)
            repeat = self.coordinator.governed_mutation(request, source)
            self.assertEqual((query.result_wire, repeat.result_wire), (result.result_wire, result.result_wire))
            self.assertFalse(query.applied or repeat.applied)
            records.append((request, result))
        remote, journal_count, local, counts = self.physical()
        self.assertEqual(counts, {'operations': 2, 'business_records': 1, 'completions': 2, 'permit_consumptions': 2})
        by_id = {str(row[0]): row for row in remote}
        locals_by_id = {row['operation_id']: row for row in local}
        for request, result in records:
            row = by_id[result.operation_id]
            self.assertTrue(all(value is not None for value in row))
            self.assertEqual(bytes(row[1]), request)
            self.assertEqual(bytes(row[-1]), result.terminal_wire)
            self.assertEqual(locals_by_id[result.operation_id]['terminal_wire'], result.terminal_wire)
            self.assertEqual(locals_by_id[result.operation_id]['audit_wire'], result.audit_wire)
            self.assertEqual(locals_by_id[result.operation_id]['result_wire'], result.result_wire)
        before = self.physical()
        mutated = decode(records[0][0]); mutated['intent']['reason'] = 'changed original content'
        with self.assertRaises(ContractError):
            self.coordinator.query(records[0][1].operation_id, c2(mutated))
        self.assertEqual(before, self.physical())
        OBSERVATIONS.append({'case': 'independent_real_commit_abort', 'database': self.database,
            'authority_pid': self.server.pid, 'core_pid': os.getpid(), 'journal_windows': journal_count,
            'counts': counts, 'terminal_sha256': [hashlib.sha256(result.terminal_wire).hexdigest() for _, result in records],
            'wrong_original_query_rejected_unchanged': True})
        # A fresh coordinator has no verified cache. Its next public operation
        # must rebuild both journals, including each earlier physical APPLY.
        fresh = core(self.path)
        request, source = request_for(fresh, 'COMMIT')
        third = fresh.governed_mutation(request, source)
        self.assertTrue(third.applied)
        self.assertEqual(self.physical()[3], {'operations': 3, 'business_records': 2,
            'completions': 3, 'permit_consumptions': 3})
        for old_request, old_result in records:
            self.assertEqual(fresh.query(old_result.operation_id, old_request).result_wire,
                             old_result.result_wire)
        OBSERVATIONS.append({'case': 'cold_core_rebuild_then_third_public_operation',
            'counts': self.physical()[3], 'old_original_queries': 2,
            'same_sqlite_files': True, 'cache_inherited': False})


if __name__ == '__main__':
    unittest.main()
