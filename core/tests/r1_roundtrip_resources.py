"""Explicit isolated Slice03 resources; never discovers or modifies old services."""
from pathlib import Path
import datetime, hashlib, importlib.metadata, json, secrets, socket, subprocess, time

ROOT=Path(__file__).resolve().parents[1]
EVIDENCE=ROOT/'docs/evidence/r1-acceptance-marathon/normal-mutation-durable-roundtrip-slice-03-20260916T220000Z'

def create():
    token='r1-s03-'+secrets.token_hex(6)
    folder=ROOT/'.tmp'/token
    folder.mkdir(parents=True,exist_ok=False)
    label='qingyu.slice03.owner='+token
    def docker(*args):
        return subprocess.check_output(['docker',*args],stderr=subprocess.STDOUT).decode().strip()
    digest='postgres@sha256:f1c3376c26f2609ab9f29f71f824103fe2fcd8ee0346485cb6122a4f93df6f94'
    info=json.loads(docker('image','inspect',digest))[0]
    net=token+'-net';volume=token+'-data';container=token+'-pg'
    docker('network','create','--label',label,net)
    docker('volume','create','--label',label,volume)
    password=secrets.token_urlsafe(32)
    env=folder/'postgres.env'
    env.write_text('POSTGRES_PASSWORD='+password+'\nPOSTGRES_DB=r1_slice03\n',encoding='ascii')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));host_port=sock.getsockname()[1]
    docker('run','--detach','--name',container,'--label',label,'--network',net,
           '--mount','type=volume,source='+volume+',target=/var/lib/postgresql/data',
           '--publish','127.0.0.1:'+str(host_port)+':5432','--env-file',str(env),digest)
    own=json.loads(docker('inspect',container))[0]
    assert own['Config']['Labels']['qingyu.slice03.owner']==token
    port=own['NetworkSettings']['Ports']['5432/tcp'][0]
    assert port['HostIp']=='127.0.0.1'
    config={'owner':token,'folder':str(folder),'host':'127.0.0.1','port':int(port['HostPort']),
            'dbname':'r1_slice03','admin_password':password,'app_password':secrets.token_urlsafe(32),
            'migrator_password':secrets.token_urlsafe(32),'container':container,'network':net,'volume':volume}
    cf=folder/'private-config.json';cf.write_text(json.dumps(config),encoding='utf8')
    import psycopg
    for attempt in range(60):
        try:
            with psycopg.connect(host=config['host'],port=config['port'],dbname=config['dbname'],user='postgres',password=password,connect_timeout=2) as conn:
                version=conn.execute('select version()').fetchone()[0]
            break
        except psycopg.OperationalError:time.sleep(.5)
    else:raise RuntimeError('owned PostgreSQL unavailable')
    deps={}
    for name in ('cryptography','rfc8785','pytest','psycopg','psycopg-binary','fastapi','uvicorn','pydantic','starlette'):
        dist=importlib.metadata.distribution(name)
        deps[name]={'version':dist.version,'installed_record_sha256':hashlib.sha256((dist.read_text('RECORD') or '').encode()).hexdigest()}
    public={'owner':token,'created_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'container':container,'container_id':own['Id'],'network':net,'volume':volume,'loopback_port':config['port'],
            'image_digest':digest,'image_id':info['Id'],'postgres_version':version,'dependencies':deps,
            'dependency_source':'https://pypi.org/simple; uv existing compatible isolated venv; no whole-environment upgrade',
            'private_config_path':str(cf),'secret_values_omitted':True}
    EVIDENCE.mkdir(parents=True,exist_ok=True)
    destination=EVIDENCE/('environment.json' if not (EVIDENCE/'environment.json').exists() else 'environment-'+token+'.json')
    destination.write_text(json.dumps(public,indent=2)+'\n',encoding='utf8')
    print(json.dumps(public,indent=2))
    return cf

def initialize(config_path):
    """Initialize ONLY the freshly created resource identified by its label."""
    from tests.r1_roundtrip_provider import bootstrap,trust,material,boundary
    from app.control_plane.r1_scoped_authority import configuration_digest
    from app.control_plane.r1_scoped_schema import install_scoped_test_schema
    import psycopg
    from psycopg import sql
    path=Path(config_path).resolve();cfg=json.loads(path.read_text())
    assert path.parent==Path(cfg['folder']).resolve() and path.parent.parent==(ROOT/'.tmp').resolve()
    assert cfg['host']=='127.0.0.1' and cfg['container']==cfg['owner']+'-pg'
    own=json.loads(subprocess.check_output(['docker','inspect',cfg['container']]))[0]
    assert own['Config']['Labels']['qingyu.slice03.owner']==cfg['owner']
    assert own['NetworkSettings']['Ports']['5432/tcp']==[{'HostIp':'127.0.0.1','HostPort':str(cfg['port'])}]
    cfg=bootstrap(path)
    name='r1_slice03_test_'+cfg['owner'].removeprefix('r1-s03-')
    with psycopg.connect(host=cfg['host'],port=cfg['port'],dbname=cfg['dbname'],user='postgres',password=cfg['admin_password'],autocommit=True) as db:
        assert int(db.execute('SHOW server_version_num').fetchone()[0])//10000==16
        assert not db.execute("SELECT rolname FROM pg_roles WHERE rolname LIKE 'control_plane_%'").fetchall(),'fresh owned instance required'
        for role in ('owner','reader'):
            db.execute(sql.SQL('CREATE ROLE {} NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS').format(sql.Identifier('control_plane_'+role)))
        for role in ('migrator','app'):
            db.execute(sql.SQL('CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD {}').format(sql.Identifier('control_plane_'+role),sql.Literal(cfg[role+'_password'])))
        db.execute('GRANT control_plane_owner TO control_plane_migrator')
        db.execute(sql.SQL('CREATE DATABASE {} OWNER control_plane_owner').format(sql.Identifier(name)))
        db.execute(sql.SQL('COMMENT ON DATABASE {} IS {}').format(sql.Identifier(name),sql.Literal('R1_SLICE03_TEST_ONLY:'+name)))
        db.execute(sql.SQL('REVOKE ALL ON DATABASE {} FROM PUBLIC').format(sql.Identifier(name)))
        db.execute(sql.SQL('GRANT CONNECT ON DATABASE {} TO control_plane_migrator,control_plane_app').format(sql.Identifier(name)))
    cfg['dbname']=name;path.write_text(json.dumps(cfg),encoding='utf8')
    with psycopg.connect(host=cfg['host'],port=cfg['port'],dbname=name,user='control_plane_migrator',password=cfg['migrator_password']) as db:
        db.execute('SET ROLE control_plane_owner');db.execute('CREATE SCHEMA control_plane AUTHORIZATION control_plane_owner')
        db.execute('REVOKE ALL ON SCHEMA control_plane FROM PUBLIC')
        db.execute('ALTER DEFAULT PRIVILEGES FOR ROLE control_plane_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC')
        install_scoped_test_schema(db,test_database_name=name,scope_id=cfg['scope_id'],configuration_digest=configuration_digest(trust(cfg),(material(cfg),),boundary(cfg)))
    print('Fresh owned roles/schema initialized; no business Ack/FIX/terminal/completion inserted.')

if __name__=='__main__':
    import sys
    if len(sys.argv)==1:create()
    elif len(sys.argv)==3 and sys.argv[1]=='initialize':initialize(sys.argv[2])
    else:raise SystemExit('usage: python -m tests.r1_roundtrip_resources [initialize PRIVATE_CONFIG_PATH]')
