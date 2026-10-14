"""Opt-in synthetic activation harness; never used by production composition.

Load with pytest -p tests.activation_foundation_guard. The harness registers
fixture-owned Docker ports before any connection; it rejects production file,
guest, and connection access, and records outcomes without credentials.
"""
import ast
import json
import os
from pathlib import Path
import sys
import subprocess

PORTS = set()
RESOURCES = []
LEDGER = {"production_file_attempts_blocked":0, "production_private_file_opens":0,
          "production_secret_reads":0, "production_signing_operations":0,
          "production_connection_attempts_blocked":0, "production_connections":0,
          "synthetic_connections":0, "production_guest_attempts_blocked":0}
RESULTS = []
DESELECTED = []
WARNINGS = []


def production_path(value):
    if not isinstance(value,(str,bytes,os.PathLike)):
        return False
    name = os.fsdecode(value).replace("\\", "/").lower()
    return "wsl.localhost/qingyu-prod-local-01" in name or "wsl$/qingyu-prod-local-01" in name or name.startswith("<repo>/production/")


def file_guard(value):
    if production_path(value):
        LEDGER["production_file_attempts_blocked"] += 1
        raise RuntimeError("Foundation harness denied production filesystem access")


def audit(event,args):
    if event in {"open", "os.listdir", "os.scandir", "os.mkdir", "os.remove", "os.rmdir", "os.chmod", "os.truncate"}:
        file_guard(args[0])
    if event in {"os.rename", "os.link", "os.symlink"}:
        file_guard(args[0]);file_guard(args[1])
    if event == "subprocess.Popen":
        command = args[1]
        words = command if isinstance(command,(list,tuple)) else [command]
        joined = " ".join(map(str,words)).lower()
        if "wsl" in joined or "qingyu-prod-local-01" in joined:
            LEDGER["production_guest_attempts_blocked"] += 1
            raise RuntimeError("Foundation harness denied production guest command")


def install_boundary():
    import psycopg
    from psycopg.conninfo import conninfo_to_dict
    from tests.test_foundation_closure_rehearsal import FoundationPostgresEnvironment
    sys.addaudithook(audit)
    original_stat = os.stat
    def stat(path,*a,**kw):
        file_guard(path)
        return original_stat(path,*a,**kw)
    os.stat = stat
    original_create = FoundationPostgresEnvironment.create
    def create(env):
        PORTS.add(str(env.port))
        RESOURCES.append({"owner":env.owner,"container":env.container,"network":env.network,
                          "volume":env.volume,"port":env.port,"folder":str(env.folder)})
        return original_create(env)
    FoundationPostgresEnvironment.create = create
    original_connect = psycopg.connect
    def connect(conninfo="",**kw):
        info = conninfo_to_dict(conninfo,**kw)
        if (info.get("host") != "127.0.0.1" or str(info.get("port")) not in PORTS
                or info.get("dbname") in {"qingyu_control", "qingyu_prod"}
                or info.get("service") or info.get("hostaddr")):
            LEDGER["production_connection_attempts_blocked"] += 1
            raise RuntimeError("Foundation harness denied unregistered database connection")
        LEDGER["synthetic_connections"] += 1
        return original_connect(conninfo,**kw)
    psycopg.connect = connect
    from app.b2_signer_trust import EncryptedFileBackedEd25519SignerProvider
    original_sign = EncryptedFileBackedEd25519SignerProvider.sign
    def sign(provider,*a,**kw):
        file_guard(provider.encrypted_private_key_path)
        return original_sign(provider,*a,**kw)
    EncryptedFileBackedEd25519SignerProvider.sign = sign
    original_popen = subprocess.Popen
    def popen(args,*a,**kw):
        if isinstance(args,(list,tuple)) and "python" in Path(str(args[0])).name.lower():
            if "-c" not in args:
                raise RuntimeError("Foundation harness requires an instrumented Python child")
            args=list(args);index=args.index("-c")+1
            args[index]="from tests.activation_foundation_guard import install_child_guard; install_child_guard();\n"+args[index]
            env=dict(kw.get("env") or os.environ)
            env["QINGYU_FOUNDATION_ALLOWED_PORTS"]=json.dumps(sorted(PORTS))
            parent=os.environ.get("QINGYU_ACTIVATION_TEST_RESULTS")
            if parent:
                folder=Path(parent).parent/"child-access"
                folder.mkdir(exist_ok=True)
                env["QINGYU_FOUNDATION_CHILD_RESULTS"]=str(folder)
            kw["env"]=env
        return original_popen(args,*a,**kw)
    subprocess.Popen=popen


def install_child_guard():
    import atexit
    import uuid
    PORTS.update(json.loads(os.environ["QINGYU_FOUNDATION_ALLOWED_PORTS"]))
    install_boundary()
    folder=Path(os.environ["QINGYU_FOUNDATION_CHILD_RESULTS"])
    @atexit.register
    def report():
        (folder/("child-"+uuid.uuid4().hex+".json")).write_text(json.dumps({"ledger":LEDGER,"allowed_ports":sorted(PORTS)}),encoding="utf-8")


def pytest_configure(config):
    install_boundary()


def pytest_collection_modifyitems(config,items):
    # Preserve unsafe historical tests unchanged, explicitly isolate their entire
    # transitive fixture paths. Do not silently mark a production test as PASS.
    hazardous = {"tests/test_b2_activation_readiness.py":{"real_file_backed_signer_fixture"},
                 "tests/test_b2_signer_trust.py":{"_real_wsl_production_provider_record_admission","_d_backed_test_dir","_trusted_wsl_observation","test_d_backed_wsl_rootfs_attestation_accepts_posix_and_unc_paths"},
                 "tests/test_b2_postgres_production_trust_store.py":{"test_correct_canonical_qingyu_control_rehearsal_migrates_and_store_works"},
                 "tests/test_b2_postgres_production_signer_admission_store.py":{"trusted_storage_observation","test_correct_canonical_qingyu_control_rehearsal_migrates_admission_store"}}
    excluded = {}
    for filename, roots in hazardous.items():
        tree = ast.parse(Path(filename).read_text(encoding="utf-8-sig"))
        functions = {n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
        graph = {name:({x.func.id for x in ast.walk(n) if isinstance(x,ast.Call) and isinstance(x.func,ast.Name)}
                      | {arg.arg for arg in n.args.args}) for name,n in functions.items()}
        unsafe = set(roots)
        while True:
            updated = unsafe | {n for n,calls in graph.items() if calls & unsafe}
            if updated == unsafe: break
            unsafe = updated
        excluded[filename] = unsafe
    kept, removed = [], []
    for item in items:
        path = item.nodeid.split("::")[0]
        name = getattr(item,"originalname",None) or item.name.split("[")[0]
        if name in excluded.get(path,set()):
            removed.append(item); DESELECTED.append({"nodeid":item.nodeid,"reason":"historical real-signer/production-directory fixture isolated"})
        else: kept.append(item)
    items[:] = kept
    config.hook.pytest_deselected(items=removed)


def pytest_runtest_logreport(report):
    if report.when == "call" or report.failed:
        RESULTS.append({"nodeid":report.nodeid,"phase":report.when,"outcome":report.outcome,
                        "error":str(report.longrepr) if report.failed else None})


def pytest_warning_recorded(warning_message,when,nodeid,location):
    WARNINGS.append({"category":warning_message.category.__name__,"message":str(warning_message.message),"nodeid":nodeid})


def pytest_sessionfinish(session,exitstatus):
    output = os.environ.get("QINGYU_ACTIVATION_TEST_RESULTS")
    if output:
        Path(output).write_text(json.dumps({"exit_code":int(exitstatus),"tests":RESULTS,
            "deselected":DESELECTED,"warnings":WARNINGS,"access_ledger":LEDGER,
            "owned_resources":RESOURCES,"selected_nodeids":[item.nodeid for item in session.items]},indent=2)+"\n",encoding="utf-8")
