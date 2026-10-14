"""Nonmutating Windows acceptance identity probe; emits one JSON document.

Run using the protected deployment's Python with -I. No database or private
key bytes are read. A successful open proves a granted access right only.
"""
from __future__ import annotations

import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import time

BASE = Path(r"C:\Program Files\Qingyu\ControlPlane\R1\Acceptance")
PUBLIC = Path(r"C:\ProgramData\Qingyu\ControlPlane\R1\operator-root-acceptance-test-only.pub")
PRIVATE = Path(r"C:\ProgramData\QingyuR1Operator\AcceptanceTestOnly\operator-root-encrypted.pem")
REGISTRY = r"SOFTWARE\Qingyu\ControlPlane\R1\OperatorRoot\AcceptanceTestOnly"
SERVICES = ("QingyuControlPlaneR1Acceptance", "QingyuControlPlaneR1AcceptanceMigrator")
EXPECTED_PIN = "e50485fc68a6a2b26a2b369e6e34789125fb9573c279075b090a1365b7cb74f1"
DANGEROUS = {"SeAssignPrimaryTokenPrivilege", "SeBackupPrivilege", "SeRestorePrivilege",
             "SeDebugPrivilege", "SeImpersonatePrivilege", "SeTcbPrivilege",
             "SeTakeOwnershipPrivilege", "SeLoadDriverPrivilege", "SeCreateTokenPrivilege",
             "SeSecurityPrivilege", "SeRelabelPrivilege", "SeEnableDelegationPrivilege",
             "SeManageVolumePrivilege", "SeCreatePermanentPrivilege",
             "SeTrustedCredManAccessPrivilege", "SeDelegateSessionUserImpersonatePrivilege"}
RIGHTS = {"read_data": 1, "write_data": 2, "append_data": 4,
          "delete": 0x10000, "write_dac": 0x40000, "write_owner": 0x80000}


def bind(dll, name, args, result):
    fn = getattr(dll, name)
    fn.argtypes, fn.restype = args, result
    return fn


def initialize():
    global k, a, close
    k = C.WinDLL("kernel32", use_last_error=True)
    a = C.WinDLL("advapi32", use_last_error=True)
    close = bind(k, "CloseHandle", [W.HANDLE], W.BOOL)


class SID_ATTR(C.Structure):
    _fields_ = [("Sid", C.c_void_p), ("Attributes", W.DWORD)]


class LUID(C.Structure):
    _fields_ = [("LowPart", W.DWORD), ("HighPart", W.LONG)]


class LUID_ATTR(C.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", W.DWORD)]


def sid_string(sid):
    out = W.LPWSTR()
    fn = bind(a, "ConvertSidToStringSidW", [C.c_void_p, C.POINTER(W.LPWSTR)], W.BOOL)
    if not fn(sid, C.byref(out)):
        raise C.WinError(C.get_last_error())
    try:
        return out.value
    finally:
        bind(k, "LocalFree", [C.c_void_p], C.c_void_p)(C.cast(out, C.c_void_p))


def identity():
    token = W.HANDLE()
    process = bind(k, "GetCurrentProcess", [], W.HANDLE)()
    if not bind(a, "OpenProcessToken", [W.HANDLE, W.DWORD, C.POINTER(W.HANDLE)], W.BOOL)(process, 8, C.byref(token)):
        raise C.WinError(C.get_last_error())
    info = bind(a, "GetTokenInformation", [W.HANDLE, C.c_int, C.c_void_p, W.DWORD, C.POINTER(W.DWORD)], W.BOOL)

    def get(kind):
        size = W.DWORD()
        info(token, kind, None, 0, C.byref(size))
        if not size.value:
            raise C.WinError(C.get_last_error())
        buf = C.create_string_buffer(size.value)
        if not info(token, kind, buf, size, C.byref(size)):
            raise C.WinError(C.get_last_error())
        return buf

    try:
        user_buf, group_buf, privilege_buf, integrity_buf = get(1), get(2), get(3), get(25)
        user = C.cast(user_buf, C.POINTER(SID_ATTR)).contents
        count = C.cast(group_buf, C.POINTER(W.DWORD)).contents.value
        class GROUPS(C.Structure):
            _fields_ = [("Count", W.DWORD), ("Entries", SID_ATTR * count)]
        groups = [{"sid": sid_string(g.Sid), "attributes": g.Attributes}
                  for g in C.cast(group_buf, C.POINTER(GROUPS)).contents.Entries]
        count = C.cast(privilege_buf, C.POINTER(W.DWORD)).contents.value
        class PRIVILEGES(C.Structure):
            _fields_ = [("Count", W.DWORD), ("Entries", LUID_ATTR * count)]
        lookup = bind(a, "LookupPrivilegeNameW", [W.LPCWSTR, C.POINTER(LUID), W.LPWSTR, C.POINTER(W.DWORD)], W.BOOL)
        privileges = []
        for entry in C.cast(privilege_buf, C.POINTER(PRIVILEGES)).contents.Entries:
            length = W.DWORD(256)
            name = C.create_unicode_buffer(256)
            if not lookup(None, C.byref(entry.Luid), name, C.byref(length)):
                raise C.WinError(C.get_last_error())
            privileges.append({"name": name.value, "attributes": entry.Attributes,
                               "enabled": bool(entry.Attributes & 2), "dangerous": name.value in DANGEROUS})
        integrity = sid_string(C.cast(integrity_buf, C.POINTER(SID_ATTR)).contents.Sid)
        result = {"user_sid": sid_string(user.Sid), "groups": groups, "privileges": privileges,
                  "dangerous_privileges_present": [p["name"] for p in privileges if p["dangerous"]],
                  "integrity_sid": integrity,
                  "elevated": bool(C.cast(get(20), C.POINTER(W.DWORD)).contents.value),
                  "elevation_type": C.cast(get(18), C.POINTER(W.DWORD)).contents.value,
                  "token_type": C.cast(get(8), C.POINTER(W.DWORD)).contents.value}
    finally:
        close(token)
    system = C.create_unicode_buffer(32768)
    n = bind(k, "GetSystemDirectoryW", [W.LPWSTR, W.UINT], W.UINT)(system, len(system))
    if not 0 < n < len(system):
        raise RuntimeError("system_directory_unavailable")
    exe = str(Path(system.value) / "whoami.exe")
    completed = subprocess.run([exe, "/all", "/fo", "csv"], capture_output=True,
                               text=True, errors="replace", timeout=20,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    result["whoami"] = {"executable": exe, "exit_code": completed.returncode, "stdout": completed.stdout}
    return result


def file_open(path, right, directory=False):
    fn = bind(k, "CreateFileW", [W.LPCWSTR, W.DWORD, W.DWORD, C.c_void_p, W.DWORD, W.DWORD, W.HANDLE], W.HANDLE)
    handle = fn(str(path), right, 7, None, 3, 0x02000000 if directory else 0, None)
    granted = handle != C.c_void_p(-1).value
    error = 0 if granted else C.get_last_error()
    if granted:
        close(handle)
    return {"granted": granted, "winerror": error, "access_denied": error == 5}


def manifest():
    if not sys.flags.isolated or not Path(__file__).resolve().is_relative_to(BASE) or not Path(sys.executable).resolve().is_relative_to(BASE):
        raise RuntimeError("protected_isolated_runtime_required")
    if any(not Path(p).resolve().is_relative_to(BASE) for p in sys.path if p):
        raise RuntimeError("unprotected_import_path")
    for path in (BASE, *BASE.parents):
        if path.is_symlink() or path.is_junction():
            raise RuntimeError("reparse_deployment_parent")
    raw = (BASE / "manifest.json").read_bytes()
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_manifest_key")
            result[key] = value
        return result
    record = json.loads(raw, object_pairs_hook=unique_pairs)
    if not isinstance(record, dict) or set(record) != {"files"} or not isinstance(record["files"], dict) or not record["files"]:
        raise ValueError("manifest_schema")
    expected = record["files"]
    for rel, digest in expected.items():
        parts = PurePosixPath(rel)
        if (not rel or "\\" in rel or ":" in rel or parts.is_absolute() or ".." in parts.parts
                or str(parts) != rel or rel == "manifest.json" or not isinstance(digest, str)
                or not re.fullmatch("[0-9a-f]{64}", digest)):
            raise ValueError("manifest_entry")
    files = []
    for path in BASE.rglob("*"):
        if path.is_symlink() or path.is_junction():
            raise RuntimeError("reparse_deployment_entry")
        if path.is_file() and path != BASE / "manifest.json":
            files.append(path)
    if {p.relative_to(BASE).as_posix() for p in files} != set(expected):
        raise RuntimeError("manifest_file_set_mismatch")
    actual = {p.relative_to(BASE).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    if actual != expected:
        raise RuntimeError("manifest_set_or_digest_mismatch")
    return {"verified": True, "file_count": len(files), "sha256": hashlib.sha256(raw).hexdigest()}, files


def registry_access():
    fn = bind(a, "RegOpenKeyExW", [W.HKEY, W.LPCWSTR, W.DWORD, W.DWORD, C.POINTER(W.HKEY)], W.LONG)
    end = bind(a, "RegCloseKey", [W.HKEY], W.LONG)
    rights = {"read": 0x20019, "set_value": 2, "create_subkey": 4, "delete": 0x10000,
              "write_dac": 0x40000, "write_owner": 0x80000}
    rows = []
    parts = REGISTRY.split("\\")
    for view, mask in (("64", 0x100), ("32", 0x200)):
        for depth in range(1, len(parts) + 1):
            path = "\\".join(parts[:depth])
            results = {}
            for name, right in rights.items():
                handle = W.HKEY()
                error = fn(W.HKEY(0xFFFFFFFF80000002), path, 0, right | mask, C.byref(handle))
                if not error:
                    end(handle)
                results[name] = {"granted": error == 0, "winerror": error, "access_denied": error == 5}
            rows.append({"path": "HKLM\\" + path, "view": view, "rights": results})
    return rows


def service_access():
    scm = bind(a, "OpenSCManagerW", [W.LPCWSTR, W.LPCWSTR, W.DWORD], W.HANDLE)(None, None, 1)
    if not scm:
        raise C.WinError(C.get_last_error())
    end = bind(a, "CloseServiceHandle", [W.HANDLE], W.BOOL)
    op = bind(a, "OpenServiceW", [W.HANDLE, W.LPCWSTR, W.DWORD], W.HANDLE)
    rows = []
    try:
        for service in SERVICES:
            results = {}
            for name, right in {"change_config": 2, "write_dac": 0x40000, "write_owner": 0x80000}.items():
                handle = op(scm, service, right)
                error = 0 if handle else C.get_last_error()
                if handle:
                    end(handle)
                results[name] = {"granted": bool(handle), "winerror": error, "access_denied": error == 5}
            rows.append({"service": service, "rights": results})
    finally:
        end(scm)
    return rows


def root_failure(exc):
    # RootPinError uses fixed, public validation messages in the formal loader.
    allowed = {
        "operator-root storage ACL not verified", "operator-root storage ACL verification timed out",
        "operator-root storage ACL verification unavailable", "operator-root trust source unavailable",
        "operator-root pin conflict in 32-bit HKLM view", "conflicting operator-root public key and key ID",
        "canonical 64-bit operator-root pin missing", "missing or unexpected operator-root registry value",
        "operator-root registry value type mismatch", "invalid operator-root test-only flag",
        "Windows PowerShell system directory unavailable", "Windows machine trust source unavailable",
        "unsupported operator-root profile", "operator root must be a raw 32-byte Ed25519 public key",
        "operator-root profile mismatch", "malformed operator-root key ID",
        "unsupported operator-root pin version", "test-only operator root cannot enter production",
    }
    result = {"loaded": False, "error_type": type(exc).__name__,
              "reason": str(exc) if type(exc).__name__ == "RootPinError" and str(exc) in allowed else "unclassified_public_loader_error"}
    cause = exc.__cause__
    if cause is not None:
        result["cause_type"] = type(cause).__name__
        result["cause_winerror"] = getattr(cause, "winerror", None)
    return result


def main():
    sys.dont_write_bytecode = True
    result = {"schema_version": 1, "completed": False,
              "limitations": ["Access probes only open existing objects with requested rights and immediately close handles; no write, deletion, ownership, ACL or registry mutation is performed.",
                              "Manifest SHA-256 confirms deployed contents against the protected manifest, not an independent code signature.",
                              "A disabled dangerous privilege is still reported as present; no privilege is enabled.",
                              "Private-key bytes and database configuration are never read."]}
    try:
        if os.name != "nt" or len(sys.argv) != 2 or sys.argv[1] not in (*SERVICES, "operator"):
            raise RuntimeError("expected_windows_and_exact_identity_argument")
        result["requested_identity"] = sys.argv[1]
        result["process"] = {"pid": os.getpid(), "parent_pid": os.getppid()}
        # Bounded window for the independent operator collector to observe this
        # SCM-launched process and its owner before it completes the probe.
        if sys.argv[1] in SERVICES:
            time.sleep(3)
        result["runtime"] = {"executable": sys.executable, "isolated": bool(sys.flags.isolated),
                             "initial_sys_path": list(sys.path), "probe_path": str(Path(__file__).resolve())}
        initialize()
        result["identity"] = identity()
        result["manifest"], files = manifest()
        sys.path.insert(0, str(BASE / "vendor"))
        sys.path.insert(0, str(BASE))
        try:
            from app.control_plane.r1_root_pin import load_operator_root_pin, ACCEPTANCE_TEST_ONLY
            pin = load_operator_root_pin(ACCEPTANCE_TEST_ONLY)
            result["root_pin"] = {"loaded": True, "key_id": pin.key_id, "matches_expected": pin.key_id == EXPECTED_PIN,
                                  "profile": pin.profile, "test_only": pin.test_only,
                                  "duplicate_equivalent": pin.duplicate_equivalent}
        except Exception as exc:
            result["root_pin"] = root_failure(exc)
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            key = Ed25519PublicKey.from_public_bytes(bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))
            signature = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
            key.verify(signature, b"")
            from cryptography.exceptions import InvalidSignature
            try:
                key.verify(signature, b"invalid")
            except InvalidSignature:
                result["ed25519_vector"] = {"verified": True, "tamper_rejected": True, "source": "RFC8032 test 1 public verification only"}
            else:
                raise RuntimeError("tamper_accepted")
        except Exception as exc:
            result["ed25519_vector"] = {"verified": False, "error_type": type(exc).__name__}
        result["runtime"]["module_paths"] = {
            name: str(getattr(sys.modules[name], "__file__", "")) for name in
            ("app", "app.control_plane.r1_root_pin", "app.control_plane.r1_protocol", "cryptography",
             "cryptography.hazmat.primitives.asymmetric.ed25519", "cryptography.hazmat.bindings._rust")
            if name in sys.modules}
        targets = set(files + [BASE / "manifest.json", PUBLIC, PRIVATE])
        dirs = set()
        for path in targets:
            dirs.update(path.parents)
        result["file_access"] = [{"path": str(path), "kind": "file", "rights":
                                  {name: file_open(path, right) for name, right in RIGHTS.items()}}
                                 for path in sorted(targets, key=str)]
        directory_rights = {"list_directory": 1, "create_file": 2, "create_directory": 4,
                            "delete_child": 0x40, "delete": 0x10000, "write_dac": 0x40000, "write_owner": 0x80000}
        result["file_access"].extend({"path": str(path), "kind": "directory", "rights":
                                      {name: file_open(path, right, True) for name, right in directory_rights.items()}}
                                     for path in sorted(dirs, key=str))
        result["registry_access"] = registry_access()
        result["service_access"] = service_access()
        result["completed"] = True
    except Exception as exc:
        result["error_type"] = type(exc).__name__
        # Exception text and tracebacks are deliberately omitted from output.
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0 if result["completed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
