"""Create isolated Slice04 resources without discovering existing services."""
from pathlib import Path
import datetime
import hashlib
import importlib.metadata
import json
import secrets
import socket
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'docs/evidence/r1-acceptance-marathon/durable-authorization-provider-slice-04-20260917T041000Z'
IMAGE = 'postgres@sha256:f1c3376c26f2609ab9f29f71f824103fe2fcd8ee0346485cb6122a4f93df6f94'


def create():
    owner = 'r1-s04-' + secrets.token_hex(6)
    folder = ROOT / '.tmp' / owner
    folder.mkdir(parents=True, exist_ok=False)
    label = 'qingyu.slice04.owner=' + owner

    def docker(*args):
        return subprocess.check_output(['docker', *args], stderr=subprocess.STDOUT).decode().strip()

    image = json.loads(docker('image', 'inspect', IMAGE))[0]
    network, volume, container = owner + '-net', owner + '-data', owner + '-pg'
    docker('network', 'create', '--label', label, network)
    docker('volume', 'create', '--label', label, volume)
    password = secrets.token_urlsafe(32)
    environment = folder / 'postgres.env'
    environment.write_text('POSTGRES_PASSWORD=' + password + '\nPOSTGRES_DB=r1_slice04\n', encoding='ascii')
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    docker('run', '--detach', '--name', container, '--label', label, '--network', network,
           '--mount', 'type=volume,source=' + volume + ',target=/var/lib/postgresql/data',
           '--publish', '127.0.0.1:' + str(port) + ':5432', '--env-file', str(environment), IMAGE)
    owned = json.loads(docker('inspect', container))[0]
    assert owned['Config']['Labels']['qingyu.slice04.owner'] == owner
    binding = owned['NetworkSettings']['Ports']['5432/tcp']
    assert binding == [{'HostIp': '127.0.0.1', 'HostPort': str(port)}]
    config = {'owner': owner, 'folder': str(folder), 'host': '127.0.0.1', 'port': port,
        'dbname': 'r1_slice04', 'admin_password': password,
        'app_password': secrets.token_urlsafe(32), 'migrator_password': secrets.token_urlsafe(32),
        'runtime_credential': secrets.token_urlsafe(48), 'operator_credential': secrets.token_urlsafe(48),
        'container': container, 'network': network, 'volume': volume}
    private = folder / 'private-config.json'
    private.write_text(json.dumps(config), encoding='utf8')
    import psycopg
    for _ in range(60):
        try:
            with psycopg.connect(host='127.0.0.1', port=port, dbname=config['dbname'],
                                 user='postgres', password=password, connect_timeout=2) as connection:
                version = connection.execute('SELECT version()').fetchone()[0]
            break
        except psycopg.OperationalError:
            time.sleep(.5)
    else:
        raise RuntimeError('owned PostgreSQL unavailable')
    dependencies = {}
    for name in ('cryptography', 'rfc8785', 'pytest', 'psycopg', 'psycopg-binary',
                 'fastapi', 'uvicorn', 'pydantic', 'starlette'):
        distribution = importlib.metadata.distribution(name)
        record = (distribution.read_text('RECORD') or '').encode()
        dependencies[name] = {'version': distribution.version,
                              'installed_record_sha256': hashlib.sha256(record).hexdigest()}
    public = {'owner': owner, 'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'container': container, 'container_id': owned['Id'], 'network': network, 'volume': volume,
        'loopback_port': port, 'image_digest': IMAGE, 'image_id': image['Id'],
        'postgres_version': version, 'dependencies': dependencies,
        'private_config_path': str(private), 'secret_values_omitted': True,
        'purpose': 'Slice04 fresh isolated durable authorization provider integration'}
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / 'environment.json').write_text(json.dumps(public, indent=2) + '\n', encoding='utf8')
    print(json.dumps(public, indent=2))


def initialize(config_path):
    """Install the product schema and one offline authorized subject."""
    from uuid import uuid4
    import psycopg
    from psycopg import sql
    from cryptography.hazmat.primitives import serialization
    from tests.r1_roundtrip_provider import bootstrap, trust, material, boundary, now_ms, c2, obj, s2, sha, public
    from tests.r1_durable_run import service
    from app.control_plane.r1_scoped_authority import configuration_digest
    from app.control_plane.r1_scoped_schema import install_scoped_test_schema
    from app.control_plane.r1_durable_schema import SQL
    from app.control_plane.r1_durable_authorization import credential_digest
    from app.control_plane.r1_validation_codec import ACTIONS

    path = Path(config_path).resolve()
    cfg = json.loads(path.read_text())
    assert path.parent == Path(cfg['folder']).resolve()
    assert path.parent.parent == (ROOT / '.tmp').resolve()
    assert cfg['host'] == '127.0.0.1' and cfg['container'] == cfg['owner'] + '-pg'
    owned = json.loads(subprocess.check_output(['docker', 'inspect', cfg['container']]))[0]
    assert owned['Config']['Labels']['qingyu.slice04.owner'] == cfg['owner']
    assert owned['NetworkSettings']['Ports']['5432/tcp'] == [
        {'HostIp': '127.0.0.1', 'HostPort': str(cfg['port'])}]
    cfg = bootstrap(path)
    # Name the material for this product slice before its immutable configuration
    # digest is installed.  Secrets remain solely in the private temp folder.
    cfg['runtime_principal'] = 'slice04-durable-core'
    name = 'r1_slice04_test_' + cfg['owner'].removeprefix('r1-s04-')
    cfg['dbname'] = name
    path.write_text(json.dumps(cfg), encoding='utf8')
    with psycopg.connect(host=cfg['host'], port=cfg['port'], dbname='r1_slice04',
                         user='postgres', password=cfg['admin_password'], autocommit=True) as db:
        assert int(db.execute('SHOW server_version_num').fetchone()[0]) // 10000 == 16
        assert not db.execute("SELECT rolname FROM pg_roles WHERE rolname LIKE 'control_plane_%'").fetchall()
        for role in ('owner', 'reader'):
            db.execute(sql.SQL('CREATE ROLE {} NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS').format(sql.Identifier('control_plane_' + role)))
        for role in ('migrator', 'app'):
            db.execute(sql.SQL('CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD {}').format(
                sql.Identifier('control_plane_' + role), sql.Literal(cfg[role + '_password'])))
        db.execute('GRANT control_plane_owner TO control_plane_migrator')
        db.execute(sql.SQL('CREATE DATABASE {} OWNER control_plane_owner').format(sql.Identifier(name)))
        db.execute(sql.SQL('COMMENT ON DATABASE {} IS {}').format(sql.Identifier(name),
            sql.Literal('R1_SLICE04_TEST_ONLY:' + name)))
        db.execute(sql.SQL('REVOKE ALL ON DATABASE {} FROM PUBLIC').format(sql.Identifier(name)))
        db.execute(sql.SQL('GRANT CONNECT ON DATABASE {} TO control_plane_migrator,control_plane_app').format(sql.Identifier(name)))
    with psycopg.connect(host=cfg['host'], port=cfg['port'], dbname=name,
                         user='control_plane_migrator', password=cfg['migrator_password']) as db:
        db.execute('SET ROLE control_plane_owner')
        db.execute('CREATE SCHEMA control_plane AUTHORIZATION control_plane_owner')
        db.execute('REVOKE ALL ON SCHEMA control_plane FROM PUBLIC')
        db.execute('ALTER DEFAULT PRIVILEGES FOR ROLE control_plane_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC')
        install_scoped_test_schema(db, test_database_name=name, scope_id=cfg['scope_id'],
            configuration_digest=configuration_digest(trust(cfg), (material(cfg),), boundary(cfg)))
        db.execute(SQL)

    # Offline initialization process alone reads Root and signs the policy.
    root = serialization.load_pem_private_key((path.parent / 'root.key').read_bytes(), None)
    at = now_ms()
    pin, identity, d = cfg['pin'], cfg['identity'], material(cfg)
    policy = obj('recovery_policy', policy_id=str(uuid4()),
        deployment_admission_digest=sha(d.deployment_bytes),
        **{k: pin[k] for k in ('authority_domain_id', 'authority_instance_id', 'authority_generation')},
        **{k: identity[k] for k in ('continuity_id', 'qingyu_identity_id', 'genesis_operation_id')},
        **{k: getattr(d, k) for k in ('core_installation_id', 'storage_generation_id',
                                      'control_plane_generation_id', 'runtime_principal')},
        component_artifact_digest=sha(d.component_bytes), trust_config_digest=__import__('app.control_plane.r1_validation_codec', fromlist=['h2']).h2(pin),
        restoration_context_digest=None, capabilities=list(ACTIONS),
        allowed_operation_type='MUTATION', issued_at=at - 1000, expires_at=at + 3_600_000,
        operator_root_key_id=pin['operator_root_key_id'], root_signature='0' * 128)
    policy['root_signature'] = root.sign(s2(policy)).hex()
    policy_wire = c2(policy)
    session_id = str(uuid4())
    authority, provider = service(path)
    provider.install_subject(policy_wire, session_id=session_id,
        session_expires_at=at + 3_500_000,
        base_credential_digest=credential_digest(cfg['runtime_credential'].encode('ascii')))
    (path.parent / 'operator-policy.wire').write_bytes(policy_wire)
    public_result = {'owner': cfg['owner'], 'database': name, 'scope_id': cfg['scope_id'],
        'runtime_principal': cfg['runtime_principal'], 'session_id': session_id,
        'policy_digest': __import__('app.control_plane.r1_validation_codec', fromlist=['h2']).h2(policy),
        'root_used_only_by_initializer': True, 'business_facts_inserted': False}
    (EVIDENCE / 'initialization.json').write_text(json.dumps(public_result, indent=2) + '\n')
    print(json.dumps(public_result, indent=2))


if __name__ == '__main__':
    import sys
    if len(sys.argv) == 1:
        create()
    elif len(sys.argv) == 3 and sys.argv[1] == 'initialize':
        initialize(sys.argv[2])
    else:
        raise SystemExit('usage: python -m tests.r1_durable_resources [initialize PRIVATE_CONFIG_PATH]')
