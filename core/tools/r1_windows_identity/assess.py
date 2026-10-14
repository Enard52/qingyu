"""Evaluate captured JSON evidence only; never opens any probed resource."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath as P
import re
import sys

BASE = P(r"C:\Program Files\Qingyu\ControlPlane\R1\Acceptance")
PUBLIC = P(r"C:\ProgramData\Qingyu\ControlPlane\R1\operator-root-acceptance-test-only.pub")
PRIVATE = P(r"C:\ProgramData\QingyuR1Operator\AcceptanceTestOnly\operator-root-encrypted.pem")
PIN = "e50485fc68a6a2b26a2b369e6e34789125fb9573c279075b090a1365b7cb74f1"
SERVICES = {
    "QingyuControlPlaneR1Acceptance": "S-1-5-80-521220990-1857042447-2197016169-2159567703-611382270",
    "QingyuControlPlaneR1AcceptanceMigrator": "S-1-5-80-3253374542-705302118-4188924831-1122857046-3825746319",
}
FILE_RIGHTS = {"read_data", "write_data", "append_data", "delete", "write_dac", "write_owner"}
DIR_RIGHTS = {"list_directory", "create_file", "create_directory", "delete_child", "delete", "write_dac", "write_owner"}
REG_RIGHTS = {"read", "set_value", "create_subkey", "delete", "write_dac", "write_owner"}
SERVICE_RIGHTS = {"change_config", "write_dac", "write_owner"}
REG_PATHS = ["HKLM\\" + "\\".join(["SOFTWARE", "Qingyu", "ControlPlane", "R1", "OperatorRoot", "AcceptanceTestOnly"][:n]) for n in range(1, 7)]
MODULES = {"app", "app.control_plane.r1_root_pin", "app.control_plane.r1_protocol", "cryptography",
           "cryptography.hazmat.primitives.asymmetric.ed25519", "cryptography.hazmat.bindings._rust"}
BROAD = {P("C:/"), P("C:/Program Files"), P("C:/ProgramData")}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def load_json(path):
    # Fixed report names only. No paths inside JSON are followed.
    raw = path.read_bytes()
    if len(raw) > 20_000_000:
        raise ValueError("report too large")
    return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique_object), raw


def protected(value):
    return (isinstance(value, str) and bool(value) and ".." not in P(value).parts
            and P(value).is_absolute() and P(value).is_relative_to(BASE)
            and ":" not in value[2:])


class Assessment:
    def __init__(self):
        self.failures = []
        self.checks = 0
        self.matrix = {}

    def check(self, condition, where):
        self.checks += 1
        if not condition:
            self.failures.append(where)
        return bool(condition)

    def access(self, outcome, error, where):
        self.check(isinstance(outcome, dict) and outcome.get("granted") is (error == 0)
                   and type(outcome.get("winerror")) is int and outcome["winerror"] == error
                   and outcome.get("access_denied") is (error == 5), where)

    def index(self, rows, keys, where):
        self.check(isinstance(rows, list), where + ".list")
        result = {}
        for row in rows if isinstance(rows, list) else []:
            if not self.check(isinstance(row, dict), where + ".row"):
                continue
            key = tuple(row.get(k) for k in keys)
            if not self.check(all(isinstance(k, str) for k in key), where + ".key"):
                continue
            self.check(key not in result, where + ".duplicate")
            result[key] = row
        return result

    def report(self, name, report, manifest, digest, observed):
        start = len(self.failures)
        is_service = name in SERVICES
        self.check(report.get("schema_version") == 1 and report.get("completed") is True, name + ".completed")
        self.check(report.get("requested_identity") == name, name + ".requested_identity")
        pin = report["root_pin"]
        self.check(pin.get("loaded") is True and pin.get("matches_expected") is True and pin.get("key_id") == PIN
                   and pin.get("profile") == "R1_ACCEPTANCE_TEST_ONLY" and pin.get("test_only") is True
                   and pin.get("duplicate_equivalent") is False, name + ".formal_pin")
        vector = report["ed25519_vector"]
        self.check(vector.get("verified") is True and vector.get("tamper_rejected") is True, name + ".ed25519")
        sealed = report["manifest"]
        self.check(sealed.get("verified") is True and sealed.get("sha256") == digest
                   and sealed.get("file_count") == len(manifest), name + ".manifest")
        runtime = report["runtime"]
        self.check(runtime.get("isolated") is True, name + ".isolated")
        self.check(protected(runtime.get("executable")) and P(runtime["executable"]) == BASE / "runtime/python.exe", name + ".executable")
        self.check(protected(runtime.get("probe_path")) and P(runtime["probe_path"]) == BASE / "probe.py", name + ".probe_path")
        paths = runtime.get("initial_sys_path")
        self.check(isinstance(paths, list) and bool(paths) and all(protected(p) for p in paths), name + ".initial_sys_path")
        modules = runtime.get("module_paths")
        self.check(isinstance(modules, dict) and MODULES <= set(modules)
                   and all(protected(p) for p in modules.values()), name + ".module_paths")
        for module in MODULES:
            if isinstance(modules, dict) and protected(modules.get(module)):
                self.check(P(modules[module]).relative_to(BASE).as_posix() in manifest, name + ".module_in_manifest." + module)
        token = report["identity"]
        if is_service:
            self.check(token.get("user_sid") == SERVICES[name], name + ".sid")
            self.check(token.get("elevated") is False and token.get("token_type") == 1, name + ".token")
            groups = token.get("groups")
            self.check(isinstance(groups, list) and bool(groups)
                       and all(isinstance(g, dict) and g.get("sid") != "S-1-5-32-544" for g in groups), name + ".no_administrators_group")
            privileges = token.get("privileges")
            self.check(isinstance(privileges, list) and len(privileges) == 1
                       and privileges[0].get("name") == "SeChangeNotifyPrivilege"
                       and privileges[0].get("dangerous") is False
                       and token.get("dangerous_privileges_present") == [], name + ".privileges")
            process = report["process"]
            pid, parent = process.get("pid"), process.get("parent_pid")
            self.check(type(pid) is int and pid > 0 and type(parent) is int and parent > 0 and pid != parent, name + ".pids")
            rows = [r for r in observed if r.get("service") == name]
            self.check(bool(rows), name + ".observation_present")
            self.check(all(r.get("owner_sid") == SERVICES[name] and protected(r.get("executable")) for r in rows), name + ".observed_identity")
            self.check(any(r.get("pid") == pid and r.get("parent_pid") == parent
                           and P(r.get("executable", "")) == BASE / "runtime/python.exe"
                           and re.search(r"(?:^|\s)-I(?:\s|$)", r.get("command_line", "")) for r in rows), name + ".observed_probe")
            self.check(any(r.get("pid") == parent and P(r.get("executable", "")) == BASE / "ServiceHost.exe" for r in rows), name + ".observed_host")

        expected_files = {BASE / p for p in manifest} | {BASE / "manifest.json", PUBLIC, PRIVATE}
        expected_dirs = {parent for f in expected_files for parent in f.parents}
        entries = self.index(report.get("file_access"), ("kind", "path"), name + ".filesystem")
        wanted = {("file", p) for p in expected_files} | {("directory", p) for p in expected_dirs}
        actual = {(kind, P(path)) for kind, path in entries}
        self.check(actual == wanted and len(actual) == len(entries), name + ".filesystem_exact_set")
        for (kind, path_text), row in entries.items():
            path = P(path_text)
            rights = row.get("rights", {})
            expected_rights = FILE_RIGHTS if kind == "file" else DIR_RIGHTS
            self.check(set(rights) == expected_rights, name + ".filesystem_rights_schema")
            if (kind, path) not in wanted:
                continue
            if is_service:
                for right in expected_rights:
                    if kind == "directory" and path in BROAD and right in {"create_file", "create_directory"}:
                        # Creation of unrelated children does not replace protected children.
                        continue
                    read = right in {"read_data", "list_directory"}
                    custody = path == PRIVATE or path == PRIVATE.parent or path == PRIVATE.parent.parent
                    error = 0 if read and not custody else 5
                    self.access(rights.get(right), error, name + ".filesystem." + str(path) + "." + right)
            elif kind == "file" and path in {PRIVATE, PUBLIC, BASE / "app/control_plane/r1_root_pin.py"}:
                for right in FILE_RIGHTS:
                    self.access(rights.get(right), 0, name + ".operator_file." + str(path) + "." + right)

        registry = self.index(report.get("registry_access"), ("view", "path"), name + ".registry")
        self.check(set(registry) == {(view, path) for view in ("32", "64") for path in REG_PATHS}, name + ".registry_exact_set")
        for (view, path), row in registry.items():
            rights = row.get("rights", {})
            self.check(set(rights) == REG_RIGHTS, name + ".registry_rights_schema")
            for right in REG_RIGHTS:
                if not is_service and path == "HKLM\\SOFTWARE" and right != "read":
                    # Positive operator mutation control is the Qingyu subtree;
                    # OS-wide SOFTWARE ownership is outside this acceptance scope.
                    continue
                error = 2 if view == "32" and path != "HKLM\\SOFTWARE" else (5 if is_service and right != "read" else 0)
                self.access(rights.get(right), error, name + ".registry." + view + "." + path + "." + right)
        service_rows = self.index(report.get("service_access"), ("service",), name + ".service_config")
        self.check(set(service_rows) == {(s,) for s in SERVICES}, name + ".service_config_exact_set")
        for row in service_rows.values():
            rights = row.get("rights", {})
            self.check(set(rights) == SERVICE_RIGHTS, name + ".service_rights_schema")
            if is_service:
                for right in SERVICE_RIGHTS:
                    self.access(rights.get(right), 5, name + ".service_config." + row["service"] + "." + right)
        self.matrix[name] = {"passed": len(self.failures) == start, "files": len(expected_files),
                             "directories": len(expected_dirs), "registry_keys": len(registry),
                             "service_config_targets": len(service_rows), "failures": len(self.failures) - start}


def assess(directory):
    a = Assessment()
    root = Path(directory)
    try:
        record, raw = load_json(root / "manifest.json")
        manifest = record["files"]
        valid = (isinstance(manifest, dict) and bool(manifest) and set(record) == {"files"})
        if valid:
            for rel, digest in manifest.items():
                path = PurePosixPath(rel)
                valid = valid and bool(rel) and "\\" not in rel and ":" not in rel and not path.is_absolute()
                valid = valid and ".." not in path.parts and str(path) == rel and rel != "manifest.json"
                valid = valid and isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
        required = {"probe.py", "ServiceHost.exe", "runtime/python.exe", "app/control_plane/r1_root_pin.py"}
        valid = valid and required <= set(manifest)
        if not a.check(valid, "manifest.schema_and_required_files"):
            raise ValueError("manifest rejected")
        digest = hashlib.sha256(raw).hexdigest()
        capture, _ = load_json(root / "capture.json")
        a.check(capture.get("manifest_sha256") == digest and capture.get("private_metadata_only") is True
                and isinstance(capture.get("completed_utc"), str) and bool(capture["completed_utc"]), "capture.manifest_and_metadata")
        observed, _ = load_json(root / "observed-processes.json")
        if not a.check(isinstance(observed, list) and bool(observed) and all(isinstance(r, dict) for r in observed), "observations.schema"):
            raise ValueError("observations rejected")
        a.check(all(r.get("service") in SERVICES for r in observed), "observations.service_set")
        for name in (*SERVICES, "operator"):
            try:
                report, _ = load_json(root / (name + ".json"))
                a.report(name, report, manifest, digest, observed)
            except (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError):
                a.check(False, name + ".missing_or_malformed_report")
                a.matrix.setdefault(name, {"passed": False})
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        a.check(False, "capture.missing_or_malformed_evidence")
    return {"schema_version": 1, "passed": not a.failures, "checks": a.checks,
            "failure_count": len(a.failures), "failures": a.failures, "matrix": a.matrix,
            "limitations": ["Evaluates supplied report evidence; this is not a code signature or independent attestation of every report field.",
                            "Permission opens demonstrate granted or denied rights, not actual mutation or deletion.",
                            "Registry32 error 2 is absence, not access denial.",
                            "Reads only fixed JSON report filenames and the copied manifest; no private-key or database bytes are accessed."]}


def main():
    if len(sys.argv) != 2:
        print(json.dumps({"passed": False, "failures": ["usage: assess.py SEALED_REPORT_DIRECTORY"]}))
        return 2
    result = assess(sys.argv[1])
    print(json.dumps(result, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
