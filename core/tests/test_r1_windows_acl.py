"""ACL policy uses synthetic public descriptors; no machine ACLs are changed."""

import ctypes
from pathlib import Path
import struct
import sys
from types import SimpleNamespace

import pytest

from app.control_plane import r1_windows_acl as acl


SYSTEM = bytes.fromhex("010100000000000512000000")
ADMINS = bytes.fromhex("01020000000000052000000020020000")
USERS = bytes.fromhex("01020000000000052000000021020000")


def ace(rights, sid=USERS, *, kind=0, flags=0):
    return struct.pack("<BBHI", kind, flags, 8 + len(sid), rights) + sid


def descriptor(*aces, owner=SYSTEM, control=acl._DACL_PRESENT):
    entries = b"".join(aces)
    dacl = struct.pack("<BBHHH", 2, 0, 8 + len(entries), len(aces), 0) + entries
    return acl._Descriptor(control, owner, dacl)


@pytest.mark.parametrize("owner", [SYSTEM, ADMINS])
def test_safe_owner_empty_dacl_and_read_only_grants_are_accepted(owner):
    acl._verify_descriptor(descriptor(owner=owner), acl._WRITE_FILE)
    acl._verify_descriptor(descriptor(ace(0x80020089), owner=owner), acl._WRITE_FILE)
    acl._verify_descriptor(descriptor(ace(0x10000000, sid=owner)), acl._WRITE_FILE)


@pytest.mark.parametrize("control,dacl", [(0, None), (0, b""), (4, None)])
def test_missing_and_null_dacl_reject(control, dacl):
    with pytest.raises(acl.WindowsAclError, match="null or missing DACL"):
        acl._verify_descriptor(acl._Descriptor(control, SYSTEM, dacl), acl._WRITE_FILE)


@pytest.mark.parametrize("owner", [None, b"", SYSTEM[:-1], SYSTEM + b"\0", USERS])
def test_missing_malformed_or_untrusted_owner_reject(owner):
    with pytest.raises(acl.WindowsAclError, match="owner"):
        acl._verify_descriptor(descriptor(owner=owner), acl._WRITE_FILE)


@pytest.mark.parametrize("right", [0x2, 0x4, 0x10, 0x100, 0x40, 0x10000,
                                   0x40000, 0x80000, 0x40000000, 0x10000000])
def test_file_effective_write_grants_reject(right):
    with pytest.raises(acl.WindowsAclError, match="unsafe write grant"):
        acl._verify_descriptor(descriptor(ace(right)), acl._WRITE_FILE)


@pytest.mark.parametrize("right", [0x2, 0x4, 0x20, 0x10000, 0x40000, 0x80000,
                                   0x40000000, 0x10000000])
def test_registry_effective_write_grants_reject(right):
    with pytest.raises(acl.WindowsAclError, match="unsafe write grant"):
        acl._verify_descriptor(descriptor(ace(right)), acl._WRITE_REGISTRY)


@pytest.mark.parametrize("right", [0x40, 0x10000, 0x40000, 0x80000, 0x40000000, 0x10000000])
def test_programdata_replacement_rights_reject(right):
    with pytest.raises(acl.WindowsAclError, match="unsafe write grant"):
        acl._verify_descriptor(descriptor(ace(right)), acl._REPLACE_PARENT)


def test_programdata_creation_rights_are_distinct_from_replacement_rights():
    acl._verify_descriptor(descriptor(ace(0x2 | 0x4)), acl._REPLACE_PARENT)
    with pytest.raises(acl.WindowsAclError, match="unsafe write grant"):
        acl._verify_descriptor(descriptor(ace(0x2 | 0x4)), acl._WRITE_FILE)


def test_inherit_only_grants_do_not_apply_but_inherited_grants_do():
    acl._verify_descriptor(descriptor(ace(0x10000000, flags=0x0B)), acl._WRITE_FILE)
    with pytest.raises(acl.WindowsAclError, match="unsafe write grant"):
        acl._verify_descriptor(descriptor(ace(0x10000000, flags=0x10)), acl._WRITE_FILE)


def test_denial_does_not_hide_an_unsafe_grant():
    acl._verify_descriptor(descriptor(ace(0x10000000, kind=1)), acl._WRITE_FILE)
    with pytest.raises(acl.WindowsAclError, match="unsafe write grant"):
        acl._verify_descriptor(descriptor(ace(0x10000000, kind=1), ace(0x2)), acl._WRITE_FILE)


@pytest.mark.parametrize("kind", [4, 5, 6, 9, 10, 11, 12, 0xFF])
@pytest.mark.parametrize("flags", [0, 8])
def test_unsupported_object_callback_compound_or_unknown_aces_fail_closed(kind, flags):
    with pytest.raises(acl.WindowsAclError, match="unsupported DACL ACE type"):
        acl._verify_descriptor(descriptor(ace(0x2, kind=kind, flags=flags)), acl._WRITE_FILE)


@pytest.mark.parametrize("dacl", [
    b"",  # Missing ACL header.
    struct.pack("<BBHHH", 1, 0, 8, 0, 0),  # Unknown revision.
    struct.pack("<BBHHH", 2, 0, 12, 0, 0),  # Claimed size exceeds allocation.
    struct.pack("<BBHHH", 2, 0, 8, 1, 0),  # Claimed ACE is absent.
    struct.pack("<BBHHHBBH", 2, 0, 12, 1, 0, 0, 0, 0),  # Zero ACE size.
    struct.pack("<BBHHHBBH", 2, 0, 12, 1, 0, 0, 0, 4),  # Missing SID and mask.
    struct.pack("<BBHHHBBH", 2, 0, 12, 1, 0, 0, 0, 20),  # Out-of-bounds ACE.
])
def test_malformed_acl_and_ace_bounds_fail_closed(dacl):
    with pytest.raises(acl.WindowsAclError):
        acl._verify_descriptor(acl._Descriptor(4, SYSTEM, dacl), acl._WRITE_FILE)


@pytest.mark.parametrize("sid", [b"\x02" + USERS[1:], b"\x01\x10" + USERS[2:],
                                USERS[:-4], USERS + b"\0\0\0\0"])
def test_malformed_sid_inside_ace_rejects_even_for_inherit_only(sid):
    with pytest.raises(acl.WindowsAclError, match="malformed ACE SID"):
        acl._verify_descriptor(descriptor(ace(0x2, sid=sid, flags=8)), acl._WRITE_FILE)


@pytest.mark.parametrize("duplicate", [False, True])
def test_all_fixed_ancestors_masks_and_explicit_registry_views_are_checked(monkeypatch, duplicate):
    calls = []
    api = SimpleNamespace(check_file=lambda path, mask: calls.append(("file", path, mask)),
                          check_registry=lambda path, view, mask: calls.append((view, path, mask)))
    monkeypatch.setattr(acl, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(acl, "_WindowsAclApi", lambda: api)
    public = Path(r"C:\ProgramData\Qingyu\ControlPlane\R1\operator-root.pub")
    slot = r"SOFTWARE\Qingyu\ControlPlane\R1\OperatorRoot\AcceptanceTestOnly"
    acl.verify_windows_acl(slot, public, duplicate)
    assert calls[:5] == [("file", path, acl._REPLACE_PARENT if index == 0 else acl._WRITE_FILE)
                         for index, path in enumerate((*acl._FILE_PARENTS, str(public)))]
    views = (0x100, 0x200) if duplicate else (0x100,)
    assert calls[5:] == [(view, path, acl._WRITE_REGISTRY) for view in views
                         for path in (*acl._REGISTRY_PARENTS, slot)]


def test_native_failure_rejects_without_fallback(monkeypatch):
    def denied(*_):
        raise PermissionError("READ_CONTROL denied")

    monkeypatch.setattr(acl, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(acl, "_WindowsAclApi", lambda: SimpleNamespace(check_file=denied))
    with pytest.raises(acl.WindowsAclError, match="verification unavailable"):
        acl.verify_windows_acl("slot", Path("public"), False)


@pytest.mark.parametrize("attributes", [0x400, 0xFFFFFFFF])
def test_reparse_or_unavailable_file_attributes_reject_before_acl_read(attributes, monkeypatch):
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 5, raising=False)
    api = object.__new__(acl._WindowsAclApi)
    api.get_attributes = lambda _: attributes
    api.get_named = lambda *_: pytest.fail("unsafe file must reject before descriptor read")
    with pytest.raises(acl.WindowsAclError):
        api.check_file("public", acl._WRITE_FILE)


@pytest.mark.parametrize("view", [0x100, 0x200])
def test_registry_handle_uses_only_read_control_and_requested_view(monkeypatch, view):
    opened, inspected = [], []

    class Key:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            opened.append("closed")

        def __int__(self):
            return 123

    def open_key(hive, path, reserved, rights):
        opened.append((hive, path, reserved, rights))
        return Key()

    registry = SimpleNamespace(HKEY_LOCAL_MACHINE="HKLM", OpenKey=open_key)
    monkeypatch.setitem(sys.modules, "winreg", registry)
    api = object.__new__(acl._WindowsAclApi)
    api.get_security = lambda handle, kind, information, *_: inspected.append(
        (handle.value, kind, information)) or 0
    api._check_result = lambda result, descriptor, mask: None
    api.check_registry("slot", view, acl._WRITE_REGISTRY)
    assert opened == [("HKLM", "slot", 0, 0x20000 | view), "closed"]
    assert inspected == [(123, 4, 5)]


def test_allocated_descriptor_is_released_when_validation_fails():
    api = object.__new__(acl._WindowsAclApi)
    released = []
    api.local_free = lambda pointer: released.append(pointer.value) or None
    api._read_descriptor = lambda _: acl._Descriptor(4, SYSTEM, None)
    with pytest.raises(acl.WindowsAclError, match="null or missing DACL"):
        api._check_result(0, ctypes.c_void_p(123), acl._WRITE_FILE)
    assert released == [123]


@pytest.mark.parametrize("duplicate", [False, True])
def test_parent_preflight_checks_both_requested_views_without_a_registry_slot(monkeypatch, duplicate):
    calls = []
    api = SimpleNamespace(
        check_file=lambda path, mask, **options: calls.append(("file", path, mask, options)),
        check_registry=lambda path, view, mask: calls.append((view, path, mask)))
    monkeypatch.setattr(acl, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(acl, "_WindowsAclApi", lambda: api)
    public = Path(r"C:\ProgramData\Qingyu\ControlPlane\R1\operator-root.pub")
    acl.verify_windows_parent_acl(public, duplicate)
    assert calls[:4] == [("file", path, acl._REPLACE_PARENT if index == 0 else acl._WRITE_FILE,
                          {"require_directory": True})
                         for index, path in enumerate(acl._FILE_PARENTS)]
    assert calls[4] == ("file", str(public), acl._WRITE_FILE, {"allow_missing": True})
    views = (0x100, 0x200) if duplicate else (0x100,)
    assert calls[5:] == [(view, path, acl._WRITE_REGISTRY)
                         for view in views for path in acl._REGISTRY_PARENTS]


@pytest.mark.parametrize("error", [2, 3, 5, 32, 87])
@pytest.mark.parametrize("allow_missing", [False, True])
def test_only_missing_public_leaf_can_be_skipped(monkeypatch, error, allow_missing):
    monkeypatch.setattr(ctypes, "get_last_error", lambda: error, raising=False)
    api = object.__new__(acl._WindowsAclApi)
    api.get_attributes = lambda _: 0xFFFFFFFF
    api.get_named = lambda *_: pytest.fail("missing or inaccessible leaf has no readable descriptor")
    if allow_missing and error in (2, 3):
        api.check_file("public", acl._WRITE_FILE, allow_missing=True)
    else:
        with pytest.raises(acl.WindowsAclError, match="attributes unavailable"):
            api.check_file("public", acl._WRITE_FILE, allow_missing=allow_missing)


def test_optional_existing_leaf_still_checks_its_descriptor():
    api = object.__new__(acl._WindowsAclApi)
    calls = []
    api.get_attributes = lambda _: 0x20
    api.get_named = lambda path, kind, info, *_: calls.append((path, kind, info)) or 0
    api._check_result = lambda result, descriptor, mask: calls.append((result, mask))
    api.check_file("public", acl._WRITE_FILE, allow_missing=True)
    assert calls == [("public", 1, 5), (0, acl._WRITE_FILE)]


def test_optional_leaf_cannot_be_a_reparse_point():
    api = object.__new__(acl._WindowsAclApi)
    api.get_attributes = lambda _: 0x400
    api.get_named = lambda *_: pytest.fail("reparse point must reject first")
    with pytest.raises(acl.WindowsAclError, match="reparse point"):
        api.check_file("public", acl._WRITE_FILE, allow_missing=True)


@pytest.mark.parametrize("error", [2, 3, 5])
def test_leaf_disappearance_or_denial_after_attributes_still_rejects(error):
    api = object.__new__(acl._WindowsAclApi)
    api.get_attributes = lambda _: 0x20
    api.get_named = lambda *_: error
    with pytest.raises(acl.WindowsAclError, match="security descriptor unavailable"):
        api.check_file("public", acl._WRITE_FILE, allow_missing=True)


def test_ceremony_parent_must_be_a_directory():
    api = object.__new__(acl._WindowsAclApi)
    api.get_attributes = lambda _: 0x20
    api.get_named = lambda *_: pytest.fail("a regular-file ancestor must reject first")
    with pytest.raises(acl.WindowsAclError, match="directory must be admin-staged"):
        api.check_file("parent", acl._WRITE_FILE, require_directory=True)


def test_parent_preflight_cannot_skip_an_inaccessible_public_leaf(monkeypatch):
    api = object.__new__(acl._WindowsAclApi)
    api.get_attributes = lambda path: 0xFFFFFFFF if path == "public" else 0x10
    api.get_named = lambda *_: 0
    api._check_result = lambda *_: None
    api.check_registry = lambda *_: pytest.fail("leaf denial must stop preflight")
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 5, raising=False)
    monkeypatch.setattr(acl, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(acl, "_WindowsAclApi", lambda: api)
    with pytest.raises(acl.WindowsAclError, match="attributes unavailable"):
        acl.verify_windows_parent_acl(Path("public"), True)


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows descriptor APIs")
@pytest.mark.parametrize("sddl,accepted", [
    ("O:SYG:SY", False),
    ("O:SYG:SYD:NO_ACCESS_CONTROL", False),
    ("O:SYG:SYD:", True),
    ("O:BAG:SYD:(A;;GA;;;BA)(A;;GR;;;BU)", True),
    ("O:SYG:SYD:(A;;GW;;;BU)", False),
    ("O:SYG:SYD:(A;;GA;;;BU)", False),
    ("O:SYG:SYD:(A;OIIO;GA;;;BU)", True),
    ("O:SYG:SYD:(A;ID;GA;;;BU)", False),
    ("O:BUG:SYD:", False),
])
def test_real_native_descriptor_extraction_in_memory(sddl, accepted):
    api = acl._WindowsAclApi()
    dll = ctypes.WinDLL("advapi32.dll", use_last_error=True, winmode=0x800)
    convert = dll.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32,
                        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint32)]
    convert.restype = ctypes.c_int32
    pointer = ctypes.c_void_p()
    assert convert(sddl, 1, ctypes.byref(pointer), None)
    try:
        actual = api._read_descriptor(pointer)
        if accepted:
            acl._verify_descriptor(actual, acl._WRITE_FILE)
        else:
            with pytest.raises(acl.WindowsAclError):
                acl._verify_descriptor(actual, acl._WRITE_FILE)
    finally:
        api.local_free(pointer)
