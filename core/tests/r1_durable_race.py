"""Deterministic multi-process action/revocation ordering probes."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import time

from app.control_plane.r1_validation_codec import ContractError, decode, h2
from tests.r1_durable_run import config, core, request_for, service


def wait_file(path, process, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        if process.poll() is not None:
            raise RuntimeError('worker exited before barrier: ' + str(process.returncode))
        time.sleep(.02)
    raise RuntimeError('barrier timeout: ' + str(path))


def worker_prepare(config_path, request_path, source_path, folder):
    folder = Path(folder)
    def fault(stage):
        if stage == 'before_database_append':
            (folder / 'prepare-ready').write_text('ready')
            while not (folder / 'release').exists():
                time.sleep(.01)
    authority, provider = service(config_path, fault)
    request_wire, source_wire = Path(request_path).read_bytes(), Path(source_path).read_bytes()
    op = decode(request_wire)['intent']['operation_id']
    (folder / 'prepare-started').write_text('started')
    try:
        caller = provider.authenticate(config(config_path)['runtime_credential'].encode('ascii'), op)
        reply = authority.prepare(request_wire, source_wire, caller)
        (folder / 'prepare-result').write_text(json.dumps({'state': reply.state}))
    except Exception as exc:
        (folder / 'prepare-result').write_text(json.dumps({'error': type(exc).__name__}))


def worker_revoke(config_path, digest, folder, barrier):
    folder = Path(folder)
    def fault(stage):
        if barrier and stage == 'before_revocation_append':
            (folder / 'revoke-ready').write_text('ready')
            while not (folder / 'release').exists():
                time.sleep(.01)
    _, provider = service(config_path, fault)
    (folder / 'revoke-started').write_text('started')
    try:
        sequence = provider.revoke('GRANT_REVOKE', digest,
            b'fixed-operator-race-authorization',
            verify_operator=lambda wire, kind, object_digest, now: True)
        (folder / 'revoke-result').write_text(json.dumps({'sequence': sequence}))
    except Exception as exc:
        (folder / 'revoke-result').write_text(json.dumps({'error': type(exc).__name__}))


def worker_issue(config_path, request_path, source_path, folder, name):
    folder = Path(folder)
    request_wire, source_wire = Path(request_path).read_bytes(), Path(source_path).read_bytes()
    (folder / ('issue-ready-' + name)).write_text('ready')
    while not (folder / 'release').exists():
        time.sleep(.01)
    _, provider = service(config_path)
    try:
        issued = provider.ensure_execution(request_wire, source_wire,
            runtime_principal=config(config_path)['runtime_principal'])
        (folder / ('issue-result-' + name)).write_text(json.dumps({
            'sha256': hashlib.sha256(issued.object_wire).hexdigest(),
            'sequence': issued.authority_sequence}))
    except Exception as exc:
        (folder / ('issue-result-' + name)).write_text(json.dumps({'error': type(exc).__name__}))


def history(config_path, operation_id):
    authority, _ = service(config_path)
    def read(tx):
        engine = authority._engine(tx)
        rows = []
        for event in engine.authority['events']:
            value = engine.authority['records'][event['input_digest']]
            if value.get('operation_id') == operation_id or event['event_kind'] == 'GRANT_REVOKE':
                rows.append((event['event_kind'], event['position']['event_sequence']))
        return rows
    return authority.store.transact(read)


def run(config_path, order):
    path = Path(config_path).resolve()
    folder = path.parent / ('race-' + order)
    folder.mkdir(exist_ok=False)
    coordinator = core(path, create=True)
    request_wire, source_wire = request_for(path, coordinator, 'COMMIT', order)
    operation_id = decode(request_wire)['intent']['operation_id']
    request_path, source_path = folder / 'request.wire', folder / 'source.wire'
    request_path.write_bytes(request_wire); source_path.write_bytes(source_wire)
    _, provider = service(path)
    if order == 'concurrent-issue':
        python = sys.executable
        processes = []
        for name in ('a', 'b'):
            processes.append(subprocess.Popen([python, '-B', '-m', 'tests.r1_durable_race',
                'issue', str(path), str(request_path), str(source_path), str(folder), name]))
        for name, process in zip(('a', 'b'), processes):
            wait_file(folder / ('issue-ready-' + name), process)
        (folder / 'release').write_text('release')
        for process in processes:
            process.wait(timeout=30)
            if process.returncode:
                raise RuntimeError('issue worker failed')
        values = [json.loads((folder / ('issue-result-' + name)).read_text())
                  for name in ('a', 'b')]
        assert values[0] == values[1] and 'sha256' in values[0]
        rows = history(path, operation_id)
        assert sum(kind == 'GRANT_ISSUED' for kind, _ in rows) == 1
        print(json.dumps({'order': order, 'operation_id': operation_id,
            'results': values, 'relevant_history': rows,
            'deterministic_start_barrier': True, 'single_issuance': True},
            indent=2, sort_keys=True))
        return
    issued = provider.ensure_execution(request_wire, source_wire,
        runtime_principal=config(path)['runtime_principal'])
    digest = h2(decode(issued.object_wire))
    python = sys.executable
    prepare_args = [python, '-B', '-m', 'tests.r1_durable_race', 'prepare', str(path),
                    str(request_path), str(source_path), str(folder)]
    revoke_args = [python, '-B', '-m', 'tests.r1_durable_race', 'revoke', str(path),
                   digest, str(folder)]
    if order == 'action-first':
        prepare = subprocess.Popen(prepare_args)
        wait_file(folder / 'prepare-ready', prepare)
        revoke = subprocess.Popen(revoke_args + ['no-barrier'])
        wait_file(folder / 'revoke-started', revoke)
    else:
        revoke = subprocess.Popen(revoke_args + ['barrier'])
        wait_file(folder / 'revoke-ready', revoke)
        prepare = subprocess.Popen(prepare_args)
        wait_file(folder / 'prepare-started', prepare)
    (folder / 'release').write_text('release')
    for process in (prepare, revoke):
        process.wait(timeout=30)
        if process.returncode:
            raise RuntimeError('worker failed: ' + str(process.returncode))
    prepare_result = json.loads((folder / 'prepare-result').read_text())
    revoke_result = json.loads((folder / 'revoke-result').read_text())
    rows = history(path, operation_id)
    if order == 'action-first':
        assert prepare_result == {'state': 'PREPARED'}
        assert revoke_result['sequence'] > next(n for k, n in rows if k == 'PREPARE')
    else:
        assert prepare_result == {'error': 'ContractError'}
        assert revoke_result['sequence'] == max(n for _, n in rows)
        assert not any(kind == 'PREPARE' for kind, _ in rows)
    result = {'order': order, 'operation_id': operation_id,
              'grant_sha256': hashlib.sha256(issued.object_wire).hexdigest(),
              'prepare': prepare_result, 'revoke': revoke_result,
              'relevant_history': rows, 'deterministic_barrier': True}
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    if sys.argv[1] == 'prepare':
        worker_prepare(*sys.argv[2:])
    elif sys.argv[1] == 'revoke':
        worker_revoke(*sys.argv[2:5], sys.argv[5] == 'barrier')
    elif sys.argv[1] == 'issue':
        worker_issue(*sys.argv[2:])
    elif sys.argv[1] == 'run':
        run(sys.argv[2], sys.argv[3])
    else:
        raise SystemExit('unknown mode')
