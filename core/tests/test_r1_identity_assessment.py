"""Report-only acceptance evaluator tests; no Windows resource access required."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location("identity_assess", Path(__file__).parents[1] / "tools/r1_windows_identity/assess.py")
assessor = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(assessor)


def outcome(error):
    return {"granted": error == 0, "winerror": error, "access_denied": error == 5}


@pytest.fixture
def capture(tmp_path):
    a = assessor
    module_files = dict(zip(sorted(a.MODULES), [
        "app/__init__.py", "app/control_plane/r1_protocol.py", "app/control_plane/r1_root_pin.py",
        "vendor/cryptography/__init__.py", "vendor/cryptography/hazmat/bindings/_rust.pyd",
        "vendor/cryptography/hazmat/primitives/asymmetric/ed25519.py"]))
    manifest = {p: "a" * 64 for p in [*module_files.values(), "probe.py", "ServiceHost.exe", "runtime/python.exe"]}
    manifest_raw = json.dumps({"files": manifest}).encode()
    (tmp_path / "manifest.json").write_bytes(manifest_raw)
    digest = hashlib.sha256(manifest_raw).hexdigest()
    documents = {"capture.json": {"manifest_sha256": digest, "private_metadata_only": True,
                                  "completed_utc": "2026-09-14T00:00:00Z"}, "observed-processes.json": []}
    for number, name in enumerate((*a.SERVICES, "operator")):
        service = name in a.SERVICES
        files = {a.BASE / p for p in manifest} | {a.BASE / "manifest.json", a.PUBLIC, a.PRIVATE}
        dirs = {parent for f in files for parent in f.parents}
        rows = []
        for kind, paths, rights in (("file", files, a.FILE_RIGHTS), ("directory", dirs, a.DIR_RIGHTS)):
            for path in sorted(paths):
                custody = path in {a.PRIVATE, a.PRIVATE.parent, a.PRIVATE.parent.parent}
                values = {right: outcome(0 if not service or (right in {"read_data", "list_directory"} and not custody) else 5) for right in rights}
                rows.append({"kind": kind, "path": str(path), "rights": values})
        registry = []
        for view in ("32", "64"):
            for path in a.REG_PATHS:
                values = {right: outcome(2 if view == "32" and path != "HKLM\\SOFTWARE" else
                                         5 if service and right != "read" else 0) for right in a.REG_RIGHTS}
                registry.append({"path": path, "view": view, "rights": values})
        report = {"schema_version": 1, "completed": True, "requested_identity": name,
                  "root_pin": {"loaded": True, "matches_expected": True, "key_id": a.PIN,
                               "profile": "R1_ACCEPTANCE_TEST_ONLY", "test_only": True, "duplicate_equivalent": False},
                  "ed25519_vector": {"verified": True, "tamper_rejected": True},
                  "manifest": {"verified": True, "file_count": len(manifest), "sha256": digest},
                  "runtime": {"isolated": True, "executable": str(a.BASE / "runtime/python.exe"),
                              "probe_path": str(a.BASE / "probe.py"), "initial_sys_path": [str(a.BASE / "runtime")],
                              "module_paths": {k: str(a.BASE / v) for k, v in module_files.items()}},
                  "identity": {"user_sid": a.SERVICES.get(name, "operator-synthetic"), "elevated": not service,
                               "token_type": 1, "groups": [{"sid": "S-1-5-11", "attributes": 7}],
                               "privileges": [{"name": "SeChangeNotifyPrivilege", "dangerous": False}],
                               "dangerous_privileges_present": []},
                  "process": {"pid": 100 + number, "parent_pid": 200 + number}, "file_access": rows,
                  "registry_access": registry,
                  "service_access": [{"service": s, "rights": {r: outcome(5 if service else 0) for r in a.SERVICE_RIGHTS}} for s in a.SERVICES]}
        documents[name + ".json"] = report
        if service:
            for pid, parent, executable, command in ((100 + number, 200 + number, "runtime/python.exe", 'python.exe -I probe.py ' + name),
                                                      (200 + number, 1, "ServiceHost.exe", "ServiceHost.exe runtime")):
                documents["observed-processes.json"].append({"service": name, "pid": pid, "parent_pid": parent,
                    "executable": str(a.BASE / executable), "command_line": command, "owner_sid": a.SERVICES[name]})

    def save():
        for filename, document in documents.items():
            (tmp_path / filename).write_text(json.dumps(document), encoding="utf-8")
        return tmp_path
    return documents, save


def test_complete_synthetic_capture_passes(capture):
    _, save = capture
    result = assessor.assess(save())
    assert result["passed"], result["failures"]
    assert len(result["matrix"]) == 3 and result["checks"] > 100


def test_operator_os_software_mutation_is_outside_positive_control(capture):
    documents, save = capture
    for row in documents["operator.json"]["registry_access"]:
        if row["path"] == "HKLM\\SOFTWARE":
            for right in assessor.REG_RIGHTS - {"read"}:
                row["rights"][right] = outcome(5)
    assert assessor.assess(save())["passed"]


@pytest.mark.parametrize("malformed", [None, {}, {"completed": True}])
def test_malformed_service_report_fails(capture, malformed):
    documents, save = capture
    documents[next(iter(assessor.SERVICES)) + ".json"] = malformed
    result = assessor.assess(save())
    assert not result["passed"]
    assert any("malformed_report" in f for f in result["failures"])


@pytest.mark.parametrize("fault", ["unsafe_write", "missing_not_denied", "wrong_sid", "disabled_dangerous_privilege",
                                  "admin_group", "dev_import", "missing_file", "missing_module", "wrong_pin",
                                  "pid_mismatch", "duplicate_row", "registry32_write", "service_config_write",
                                  "operator_custody_denied", "manifest_mismatch", "unfinished"])
def test_security_faults_fail_despite_completed(capture, fault):
    documents, save = capture
    name = next(iter(assessor.SERVICES))
    report = documents[name + ".json"]
    if fault in {"unsafe_write", "missing_not_denied"}:
        report["file_access"][0]["rights"]["write_data"] = outcome(0 if fault == "unsafe_write" else 2)
    elif fault == "wrong_sid":
        report["identity"]["user_sid"] = "S-1-5-18"
    elif fault == "disabled_dangerous_privilege":
        report["identity"]["privileges"].append({"name": "SeDebugPrivilege", "enabled": False, "dangerous": False})
    elif fault == "admin_group":
        report["identity"]["groups"].append({"sid": "S-1-5-32-544", "attributes": 16})
    elif fault == "dev_import":
        report["runtime"]["initial_sys_path"].append("D:/development")
    elif fault == "missing_file":
        report["file_access"].pop(0)
    elif fault == "missing_module":
        report["runtime"]["module_paths"].pop("app.control_plane.r1_root_pin")
    elif fault == "wrong_pin":
        report["root_pin"]["key_id"] = "0" * 64
    elif fault == "pid_mismatch":
        report["process"]["pid"] = 999
    elif fault == "duplicate_row":
        report["file_access"].append(copy.deepcopy(report["file_access"][0]))
    elif fault == "registry32_write":
        report["registry_access"][0]["rights"]["set_value"] = outcome(0)
    elif fault == "service_config_write":
        report["service_access"][0]["rights"]["write_dac"] = outcome(0)
    elif fault == "operator_custody_denied":
        row = next(r for r in documents["operator.json"]["file_access"] if r["path"] == str(assessor.PRIVATE))
        row["rights"]["read_data"] = outcome(5)
    elif fault == "manifest_mismatch":
        documents["capture.json"]["manifest_sha256"] = "0" * 64
    elif fault == "unfinished":
        report["completed"] = False
    result = assessor.assess(save())
    assert not result["passed"] and result["failure_count"] > 0


def test_missing_capture_fails(tmp_path):
    assert assessor.assess(tmp_path)["passed"] is False


@pytest.mark.parametrize("malformed", ["{", '{"files":{},"files":{}}', '{"files":{"../escape":"bad"}}'])
def test_invalid_manifest_fails_without_following_paths(tmp_path, malformed):
    (tmp_path / "manifest.json").write_text(malformed)
    result = assessor.assess(tmp_path)
    assert not result["passed"] and result["failures"]
