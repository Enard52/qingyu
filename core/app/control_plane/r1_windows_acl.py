"""Read-only native Windows ACL gate for the independently provisioned R1 pin.

Only owner and DACL information is requested; no SACL, token privilege changes,
shell, or security-policy changes are involved. Unsupported ACE forms reject.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import os
from pathlib import Path
import struct


class WindowsAclError(ValueError):
    """The public trust-anchor storage is unsafe or cannot be verified."""


_GENERIC_WRITE_OR_ALL = 0x40000000 | 0x10000000
_WRITE_FILE = 0x116 | 0x40 | 0x10000 | 0x40000 | 0x80000 | _GENERIC_WRITE_OR_ALL
_REPLACE_PARENT = 0x40 | 0x10000 | 0x40000 | 0x80000 | _GENERIC_WRITE_OR_ALL
_WRITE_REGISTRY = 0x2 | 0x4 | 0x20 | 0x10000 | 0x40000 | 0x80000 | _GENERIC_WRITE_OR_ALL
_DACL_PRESENT = 0x0004
_INHERIT_ONLY_ACE = 0x08
_READ_CONTROL = 0x20000
_REGISTRY64 = 0x100
_REGISTRY32 = 0x200
_REPARSE_POINT = 0x400
_FILE_PARENTS = (
    r"C:\ProgramData",
    r"C:\ProgramData\Qingyu",
    r"C:\ProgramData\Qingyu\ControlPlane",
    r"C:\ProgramData\Qingyu\ControlPlane\R1",
)
_REGISTRY_PARENTS = (
    r"SOFTWARE\Qingyu",
    r"SOFTWARE\Qingyu\ControlPlane",
    r"SOFTWARE\Qingyu\ControlPlane\R1",
    r"SOFTWARE\Qingyu\ControlPlane\R1\OperatorRoot",
)
# Binary SIDs are independent of account-name localization.
_ALLOWED_SIDS = frozenset((
    bytes.fromhex("010100000000000512000000"),  # S-1-5-18 (SYSTEM)
    bytes.fromhex("01020000000000052000000020020000"),  # S-1-5-32-544
))


@dataclass(frozen=True, slots=True)
class _Descriptor:
    control: int
    owner: bytes | None
    dacl: bytes | None


def _valid_sid(sid: bytes) -> bool:
    return (len(sid) >= 8 and sid[0] == 1 and sid[1] <= 15
            and len(sid) == 8 + 4 * sid[1])


def _verify_descriptor(descriptor: _Descriptor, write_mask: int) -> None:
    """Apply the conservative gate to copied descriptor components, without I/O.

An empty DACL denies all access. Missing and present-but-null DACLs do not.
Deny ACEs never excuse an unsafe allow ACE, regardless of ordering. Ordinary
inherit-only ACEs do not grant access to the object currently being checked.
"""
    dacl = descriptor.dacl
    if not descriptor.control & _DACL_PRESENT or dacl is None:
        raise WindowsAclError("null or missing DACL")
    if descriptor.owner is None or not _valid_sid(descriptor.owner):
        raise WindowsAclError("missing or malformed owner SID")
    if descriptor.owner not in _ALLOWED_SIDS:
        raise WindowsAclError("unsafe owner")
    if len(dacl) < 8:
        raise WindowsAclError("malformed DACL header")
    revision, _reserved, acl_size, ace_count, _reserved2 = struct.unpack_from("<BBHHH", dacl)
    if revision not in (2, 4) or acl_size != len(dacl) or acl_size % 4:
        raise WindowsAclError("malformed DACL size or revision")
    offset = 8
    for _ in range(ace_count):
        if offset + 4 > acl_size:
            raise WindowsAclError("truncated ACE header")
        ace_type, flags, ace_size = struct.unpack_from("<BBH", dacl, offset)
        if ace_size < 4 or ace_size % 4 or offset + ace_size > acl_size:
            raise WindowsAclError("malformed ACE size")
        # Object, compound and callback ACEs have different SID layouts and/or
        # conditional semantics. Do not silently treat them as ordinary ACEs.
        if ace_type not in (0, 1):  # ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE
            raise WindowsAclError("unsupported DACL ACE type")
        if ace_size < 16:
            raise WindowsAclError("truncated access ACE")
        rights = struct.unpack_from("<I", dacl, offset + 4)[0]
        sid = dacl[offset + 8:offset + ace_size]
        if not _valid_sid(sid):
            raise WindowsAclError("malformed ACE SID")
        if (ace_type == 0 and not flags & _INHERIT_ONLY_ACE
                and sid not in _ALLOWED_SIDS and rights & write_mask):
            raise WindowsAclError("unsafe write grant")
        offset += ace_size
    # ACL allocations may have unused space after AceCount entries. Windows
    # ignores it, so it must not be interpreted as additional effective ACEs.


class _WindowsAclApi:
    def __init__(self) -> None:
        # Restrict DLL loading to System32; all imports and API access are lazy
        # so the pure policy tests can also run on non-Windows hosts.
        advapi = ctypes.WinDLL("advapi32.dll", use_last_error=True, winmode=0x800)
        kernel = ctypes.WinDLL("kernel32.dll", use_last_error=True, winmode=0x800)
        pointer = ctypes.c_void_p
        pointer_out = ctypes.POINTER(pointer)
        dword = wintypes.DWORD
        boolean = wintypes.BOOL

        def bind(dll, name, arguments, result):
            function = getattr(dll, name)
            function.argtypes = arguments
            function.restype = result
            return function

        security_arguments = [ctypes.c_int, dword] + [pointer_out] * 5
        self.get_named = bind(advapi, "GetNamedSecurityInfoW",
                              [wintypes.LPCWSTR] + security_arguments, dword)
        self.get_security = bind(advapi, "GetSecurityInfo",
                                 [pointer] + security_arguments, dword)
        self.get_control = bind(advapi, "GetSecurityDescriptorControl",
                                [pointer, ctypes.POINTER(wintypes.WORD),
                                 ctypes.POINTER(dword)], boolean)
        self.get_owner = bind(advapi, "GetSecurityDescriptorOwner",
                              [pointer, pointer_out, ctypes.POINTER(boolean)], boolean)
        self.get_dacl = bind(advapi, "GetSecurityDescriptorDacl",
                             [pointer, ctypes.POINTER(boolean), pointer_out,
                              ctypes.POINTER(boolean)], boolean)
        self.valid_descriptor = bind(advapi, "IsValidSecurityDescriptor", [pointer], boolean)
        self.valid_sid = bind(advapi, "IsValidSid", [pointer], boolean)
        self.sid_length = bind(advapi, "GetLengthSid", [pointer], dword)
        self.valid_acl = bind(advapi, "IsValidAcl", [pointer], boolean)
        self.get_ace = bind(advapi, "GetAce", [pointer, dword, pointer_out], boolean)
        self.get_attributes = bind(kernel, "GetFileAttributesW", [wintypes.LPCWSTR], dword)
        self.local_free = bind(kernel, "LocalFree", [pointer], pointer)

    @staticmethod
    def _require(success, operation: str) -> None:
        if not success:
            raise WindowsAclError(f"{operation} unavailable (Windows error {ctypes.get_last_error()})")

    def _read_descriptor(self, pointer: ctypes.c_void_p) -> _Descriptor:
        if not pointer or not self.valid_descriptor(pointer):
            raise WindowsAclError("invalid security descriptor")
        control, revision = wintypes.WORD(), wintypes.DWORD()
        self._require(self.get_control(pointer, ctypes.byref(control), ctypes.byref(revision)),
                      "security descriptor control")
        if revision.value != 1:
            raise WindowsAclError("unsupported security descriptor revision")
        owner, dacl = ctypes.c_void_p(), ctypes.c_void_p()
        defaulted, present = wintypes.BOOL(), wintypes.BOOL()
        self._require(self.get_owner(pointer, ctypes.byref(owner), ctypes.byref(defaulted)),
                      "security descriptor owner")
        self._require(self.get_dacl(pointer, ctypes.byref(present), ctypes.byref(dacl),
                                    ctypes.byref(defaulted)), "security descriptor DACL")
        if bool(present.value) != bool(control.value & _DACL_PRESENT):
            raise WindowsAclError("inconsistent DACL presence")
        owner_bytes = None
        if owner:
            if not self.valid_sid(owner):
                raise WindowsAclError("malformed owner SID")
            length = self.sid_length(owner)
            if not 8 <= length <= 68:
                raise WindowsAclError("malformed owner SID length")
            owner_bytes = ctypes.string_at(owner, length)
        dacl_bytes = None
        if present.value and dacl:
            if not self.valid_acl(dacl):
                raise WindowsAclError("invalid DACL")
            header = ctypes.string_at(dacl, 8)
            _revision, _reserved, length, count, _reserved2 = struct.unpack("<BBHHH", header)
            if length < 8:
                raise WindowsAclError("malformed DACL length")
            dacl_bytes = ctypes.string_at(dacl, length)
            offset = 8
            for index in range(count):
                ace = ctypes.c_void_p()
                self._require(self.get_ace(dacl, index, ctypes.byref(ace)), "DACL ACE")
                if ace.value != dacl.value + offset or offset + 4 > length:
                    raise WindowsAclError("invalid DACL ACE location")
                ace_size = struct.unpack_from("<H", dacl_bytes, offset + 2)[0]
                if ace_size < 4 or offset + ace_size > length:
                    raise WindowsAclError("malformed DACL ACE length")
                offset += ace_size
        return _Descriptor(control.value, owner_bytes, dacl_bytes)

    def _check_result(self, result: int, descriptor: ctypes.c_void_p, mask: int) -> None:
        try:
            if result:
                raise WindowsAclError(f"security descriptor unavailable (Windows error {result})")
            _verify_descriptor(self._read_descriptor(descriptor), mask)
        finally:
            if descriptor and self.local_free(descriptor):
                raise WindowsAclError("security descriptor release failed")

    def check_file(self, path: str, mask: int, *, allow_missing: bool = False,
                   require_directory: bool = False) -> None:
        attributes = self.get_attributes(path)
        if attributes == 0xFFFFFFFF:
            error = ctypes.get_last_error()
            if allow_missing and error in (2, 3):  # FILE_NOT_FOUND, PATH_NOT_FOUND
                return
            raise WindowsAclError(f"public trust path attributes unavailable (Windows error {error})")
        if attributes & _REPARSE_POINT:
            raise WindowsAclError("reparse point in public trust path")
        if require_directory and not attributes & 0x10:  # FILE_ATTRIBUTE_DIRECTORY
            raise WindowsAclError("public-key directory must be admin-staged")
        descriptor = ctypes.c_void_p()
        result = self.get_named(path, 1, 0x1 | 0x4, None, None, None, None,
                                ctypes.byref(descriptor))  # SE_FILE_OBJECT; OWNER | DACL
        self._check_result(result, descriptor, mask)

    def check_registry(self, path: str, view: int, mask: int) -> None:
        import winreg

        # Open every parent independently with the explicit view, and request
        # only READ_CONTROL. GetSecurityInfo uses this already-resolved handle.
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, _READ_CONTROL | view) as key:
            descriptor = ctypes.c_void_p()
            result = self.get_security(ctypes.c_void_p(int(key)), 4, 0x1 | 0x4,
                                       None, None, None, None,
                                       ctypes.byref(descriptor))  # SE_REGISTRY_KEY
            self._check_result(result, descriptor, mask)


def verify_windows_acl(registry_slot: str, public_file: Path,
                       duplicate_equivalent: bool) -> None:
    """Verify each fixed trust-path ancestor and requested registry view, or reject."""
    if os.name != "nt":
        raise WindowsAclError("Windows machine trust source unavailable")
    try:
        api = _WindowsAclApi()
        for index, path in enumerate((*_FILE_PARENTS, str(public_file))):
            api.check_file(path, _REPLACE_PARENT if index == 0 else _WRITE_FILE)
        for view in ((_REGISTRY64, _REGISTRY32) if duplicate_equivalent else (_REGISTRY64,)):
            for path in (*_REGISTRY_PARENTS, registry_slot):
                api.check_registry(path, view, _WRITE_REGISTRY)
    except WindowsAclError:
        raise
    except (OSError, ValueError, AttributeError, ImportError) as exc:
        raise WindowsAclError("operator-root storage ACL verification unavailable") from exc


def verify_windows_parent_acl(public_file: Path, duplicate_equivalent: bool) -> None:
    """Verify existing ceremony parents and any public leaf, before slot creation.

All parent directories and registry keys must already exist. Only the public
file may be absent; access denial or another ambiguous error still rejects.
No registry slot, trust value, public content, or private key is read or written.
"""
    if os.name != "nt":
        raise WindowsAclError("Windows machine trust source unavailable")
    try:
        api = _WindowsAclApi()
        for index, path in enumerate(_FILE_PARENTS):
            api.check_file(path, _REPLACE_PARENT if index == 0 else _WRITE_FILE,
                           require_directory=True)
        api.check_file(str(public_file), _WRITE_FILE, allow_missing=True)
        for view in ((_REGISTRY64, _REGISTRY32) if duplicate_equivalent else (_REGISTRY64,)):
            for path in _REGISTRY_PARENTS:
                api.check_registry(path, view, _WRITE_REGISTRY)
    except WindowsAclError:
        raise
    except (OSError, ValueError, AttributeError, ImportError) as exc:
        raise WindowsAclError("operator-root parent ACL verification unavailable") from exc
