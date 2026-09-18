"""Fresh PostgreSQL/TLS/process harness for Slice04 product composition."""
from pathlib import Path
import json
import os
import socket
import subprocess
import sys
import time

import psycopg
from cryptography.hazmat.primitives import serialization

from tests.r1_roundtrip_provider import material, trust, boundary, scope_wire, now_ms, uid, c2, decode, obj
from app.control_plane.r1_scoped_authority import ScopedAuthority, configuration_digest
from app.control_plane.r1_scoped_postgres import ScopedPostgresStore
from app.control_plane.r1_durable_authorization import DurableAuthorizationProvider
from app.control_plane.r1_durable_transport import (
    DurableAuthorityClient, DurableCredential, create_durable_authority_app,
)
from app.r1_durable_source import DurableAuthorizationSource
from app.r1_scoped_coordinator import ScopedCoreCoordinator, build_mutation_request
from app._r1_coordination_journal import CoordinationJournal
from app.r1_atomic_finish import ScopedCoreFinisher
from app._r1_scoped_sqlite import ScopedSQLiteStore

ROOT = Path(__file__).resolve().parents[1]


def config(path):
    return json.loads(Path(path).read_text())


def service(path, fault=None):
    cfg = config(path)
    def connection():
        return psycopg.connect(host=cfg['host'], port=cfg['port'], dbname=cfg['dbname'],
            user='control_plane_app', password=cfg['app_password'])
    class Signer:
        key_id = cfg['pin']['receipt_key_id']
        def __init__(self):
            # Online service loads only its receipt key.  Root key is never read.
            self.key = serialization.load_pem_private_key(
                (Path(path).parent / 'receipt.key').read_bytes(), None)
        def sign(self, raw):
            return self.key.sign(raw)
    digest = configuration_digest(trust(cfg), (material(cfg),), boundary(cfg))
    store = ScopedPostgresStore(connection, scope_id=cfg['scope_id'],
                                configuration_digest=digest)
    authority = ScopedAuthority(store=store, trust=trust(cfg), deployments=(material(cfg),),
        boundary=boundary(cfg), receipt_signer=Signer(), fault=fault)
    return authority, DurableAuthorizationProvider(authority, fault=fault)


def server(path, crash_stage=None):
    import hmac
    import uvicorn
    from app.control_plane.r1_api import authority_server_config
    folder, cfg = Path(path).parent, config(path)
    def fault(stage):
        if stage == crash_stage:
            (folder / 'server-crash.json').write_text(
                json.dumps({'pid': os.getpid(), 'stage': stage}), encoding='ascii')
            os._exit(83)
    authority, provider = service(path, fault)
    def operator(token, *details):
        return hmac.compare_digest(token, cfg['operator_credential'])
    app = create_durable_authority_app(authority, provider,
                                       operator_authenticator=operator)
    uvicorn.Server(authority_server_config(app, host='127.0.0.1',
        port=cfg['authority_port'], certificate_file=str(folder / 'tls.pem'),
        private_key_file=str(folder / 'tls.key'))).run()


def start_server(path, crash_stage=None):
    folder, cfg = Path(path).parent, config(path)
    output = (folder / ('durable-server-' + str(time.time_ns()) + '.log')).open('wb')
    args = [sys.executable, '-B', '-m', 'tests.r1_durable_run', 'server', str(path)]
    if crash_stage:
        args.append(crash_stage)
    child = subprocess.Popen(args, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
    for _ in range(150):
        if child.poll() is not None:
            raise RuntimeError('owned durable Authority failed startup; ' + output.name)
        try:
            with socket.create_connection(('127.0.0.1', cfg['authority_port']), timeout=.1):
                return child, output
        except OSError:
            time.sleep(.1)
    child.terminate(); child.wait()
    raise RuntimeError('owned durable Authority readiness timeout')


def core(path, *, create=False, hook=None, finish_hook=None):
    path = Path(path).resolve()
    cfg, folder = config(path), path.parent
    if create:
        store = ScopedSQLiteStore.create(folder / 'finish.sqlite', scope_wire=scope_wire(cfg),
            checkpoint_wire=c2(cfg['checkpoint']), business_state_wire=c2({}))
        journal = CoordinationJournal.create(folder / 'coordination.sqlite',
            scope_wire=scope_wire(cfg), checkpoint_wire=c2(cfg['checkpoint']))
    else:
        store = ScopedSQLiteStore.open(folder / 'finish.sqlite',
                                       expected_scope_wire=scope_wire(cfg))
        journal = CoordinationJournal.open(folder / 'coordination.sqlite',
            scope_wire=scope_wire(cfg), checkpoint_wire=c2(cfg['checkpoint']))
    client = DurableAuthorityClient(trust=trust(cfg), ca_file=str(folder / 'ca.pem'),
        credential_provider=DurableCredential(cfg['runtime_credential']), timeout_seconds=30)
    source = DurableAuthorizationSource(client=client, trust=trust(cfg),
        deployment=material(cfg), actor_identity=cfg['actor_identity'],
        storage_dir=folder / 'source-originals')
    finisher = ScopedCoreFinisher(store, trust=trust(cfg), deployments=(material(cfg),),
        runtime_principal=cfg['runtime_principal'], source=source,
        checkpoint_hook=finish_hook)
    return ScopedCoreCoordinator(journal=journal, finisher=finisher, client=client,
                                 source=source, checkpoint_hook=hook)


def request_for(path, coordinator, decision='COMMIT', value='durable'):
    cfg = config(path)
    with coordinator.finisher.store.transaction(write=False) as db:
        checkpoint = decode(db.execute('SELECT checkpoint_wire FROM metadata WHERE id=1').fetchone()[0])
    scope = obj('requested_scope',
        **{k: cfg['pin'][k] for k in ('authority_domain_id', 'authority_instance_id',
                                      'authority_generation')},
        actor_identity=cfg['actor_identity'], caller_runtime_id=uid(),
        session_id=uid(), lease_id=uid(), lease_generation=1,
        owner_version=1, continuity_epoch=1,
        expected_state_version=checkpoint['state_version'],
        storage_generation_id=cfg['storage_generation_id'],
        control_plane_generation_id=cfg['control_plane_generation_id'],
        trust_domain_id=cfg['trust_domain_id'],
        expected_authority_ref=checkpoint['authority_ref'],
        expected_audit_ref=checkpoint['audit_ref'], capability='core_governance')
    wire = build_mutation_request(identity=cfg['identity'], scope=scope,
        payload={'key': 'slice04', 'value': value}, mutation_id=uid(), decision=decision,
        created_at=now_ms())
    return wire, coordinator.source.intake(wire)


if __name__ == '__main__':
    if len(sys.argv) >= 3 and sys.argv[1] == 'server':
        server(sys.argv[2], sys.argv[3] if len(sys.argv) == 4 else None)
    else:
        raise SystemExit('usage: python -m tests.r1_durable_run server CONFIG [CRASH_STAGE]')
