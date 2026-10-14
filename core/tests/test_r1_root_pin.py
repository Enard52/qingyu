"""The R1 root-pin tests inject public trust records; no machine state is written."""

from dataclasses import replace
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from app.control_plane.r1_protocol import key_id
from app.control_plane.r1_root_pin import (
    ACCEPTANCE_TEST_ONLY, PRODUCTION, RootPinError, RootTrustRecord,
    WindowsMachineRootTrustSource, load_operator_root_pin,
)
from app.control_plane import r1_root_pin


class Source:
    def __init__(self, record):
        self.record = record
        self.requested_profile = None

    def read(self, profile):
        self.requested_profile = profile
        if self.record is None:
            raise FileNotFoundError("missing root")
        return self.record


@pytest.fixture
def public_record():
    # Ephemeral test-only key. The private half is never exported or installed.
    public = Ed25519PrivateKey.generate().public_key()
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return RootTrustRecord(1, ACCEPTANCE_TEST_ONLY, True, key_id(public), raw, True)


def test_explicit_acceptance_profile_loads_matching_pinned_public_key(public_record):
    source = Source(public_record)
    pin = load_operator_root_pin("acceptance", source=source)
    assert source.requested_profile == ACCEPTANCE_TEST_ONLY
    assert pin.key_id == public_record.key_id
    assert pin.public_key.public_bytes(serialization.Encoding.Raw,
                                       serialization.PublicFormat.Raw) == public_record.public_key_bytes
    assert pin.test_only is True


def test_production_requires_explicit_non_test_record(public_record):
    with pytest.raises(RootPinError, match="profile mismatch"):
        load_operator_root_pin("production", source=Source(public_record))
    production = replace(public_record, profile=PRODUCTION, test_only=False)
    source = Source(production)
    pin = load_operator_root_pin("production", source=source)
    assert source.requested_profile == PRODUCTION
    assert pin.test_only is False


@pytest.mark.parametrize("change", [
    {"version": 0}, {"version": True}, {"profile": "OTHER"},
    {"test_only": False}, {"test_only": 1},
    {"key_id": "A" * 64}, {"key_id": "0" * 64},
    {"public_key_bytes": b"short"}, {"public_key_bytes": b"\x00" * 32},
    {"public_key_bytes": "not bytes"},
    {"acl_verified": False},
])
def test_conflict_malformed_or_unverified_acl_rejects(public_record, change):
    with pytest.raises(RootPinError):
        load_operator_root_pin(ACCEPTANCE_TEST_ONLY,
                               source=Source(replace(public_record, **change)))


def test_missing_source_and_unsafe_caller_profile_reject(public_record):
    with pytest.raises(RootPinError):
        load_operator_root_pin(ACCEPTANCE_TEST_ONLY, source=Source(None))
    with pytest.raises(RootPinError):
        load_operator_root_pin("development", source=Source(public_record))


def test_env_cannot_select_or_replace_pinned_root(public_record, monkeypatch):
    monkeypatch.setenv("QINGYU_OPERATOR_ROOT_PUBLIC_KEY", "00" * 32)
    monkeypatch.setenv("QINGYU_OPERATOR_ROOT_PROFILE", PRODUCTION)
    pin = load_operator_root_pin(ACCEPTANCE_TEST_ONLY, source=Source(public_record))
    assert pin.key_id == public_record.key_id


class RegistryKey:
    def __init__(self, values):
        self.values = values

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


class RegistryStub:
    HKEY_LOCAL_MACHINE = object()
    KEY_READ = 0x20019
    KEY_WOW64_64KEY = 0x100
    KEY_WOW64_32KEY = 0x200
    REG_DWORD = 4
    REG_SZ = 1

    def __init__(self, canonical, duplicate):
        self.views = {self.KEY_WOW64_64KEY: canonical,
                      self.KEY_WOW64_32KEY: duplicate}
        self.opened = []

    def OpenKey(self, hive, path, reserved, access):
        assert hive is self.HKEY_LOCAL_MACHINE
        assert reserved == 0
        assert path == r1_root_pin._SLOTS[ACCEPTANCE_TEST_ONLY][0]
        view = access & (self.KEY_WOW64_64KEY | self.KEY_WOW64_32KEY)
        assert access == self.KEY_READ | view
        self.opened.append(view)
        values = self.views[view]
        if values is None:
            raise FileNotFoundError(path)
        return RegistryKey(values)

    @staticmethod
    def QueryInfoKey(key):
        return 0, len(key.values), 0

    @staticmethod
    def EnumValue(key, index):
        name = list(key.values)[index]
        value, kind = key.values[name]
        return name, value, kind

    @staticmethod
    def QueryValueEx(key, name):
        return key.values[name]


def registry_values(record):
    return {"PinVersion": (record.version, RegistryStub.REG_DWORD),
            "Profile": (record.profile, RegistryStub.REG_SZ),
            "TestOnly": (int(record.test_only), RegistryStub.REG_DWORD),
            "PublicKeyId": (record.key_id, RegistryStub.REG_SZ)}


@pytest.mark.parametrize("duplicate_case,expected_duplicate", [
    ("missing", False), ("same", True),
])
def test_explicit_registry_views_accept_only_missing_or_equivalent(
        public_record, tmp_path, monkeypatch, duplicate_case, expected_duplicate):
    raw = tmp_path / "operator-root.pub"
    raw.write_bytes(public_record.public_key_bytes)
    canonical = registry_values(public_record)
    duplicate = {"missing": None, "same": canonical}[duplicate_case]
    registry = RegistryStub(canonical, duplicate)
    acl_checks = []
    monkeypatch.setattr(r1_root_pin.os, "name", "nt")
    monkeypatch.setitem(sys.modules, "winreg", registry)
    monkeypatch.setitem(r1_root_pin._SLOTS, ACCEPTANCE_TEST_ONLY,
                        (r1_root_pin._SLOTS[ACCEPTANCE_TEST_ONLY][0], raw))
    monkeypatch.setattr(r1_root_pin, "_verify_windows_acl",
                        lambda slot, file, duplicate: acl_checks.append((slot, file, duplicate)))
    pin = load_operator_root_pin("acceptance", source=WindowsMachineRootTrustSource())
    assert pin.duplicate_equivalent is expected_duplicate
    assert registry.opened == [registry.KEY_WOW64_64KEY, registry.KEY_WOW64_32KEY]
    assert acl_checks == [(r1_root_pin._SLOTS[ACCEPTANCE_TEST_ONLY][0],
                           raw, expected_duplicate)]


@pytest.mark.parametrize("duplicate_change", [
    "empty",
    {"PublicKeyId": ("0" * 64, RegistryStub.REG_SZ)},
    {"PublicKeyId": ("bad-type", RegistryStub.REG_DWORD)},
    {"PublicKeyId": None},
    {"TestOnly": (2, RegistryStub.REG_DWORD)},
])
def test_conflicting_or_malformed_32_bit_view_fails_closed(
        public_record, tmp_path, monkeypatch, duplicate_change):
    raw = tmp_path / "operator-root.pub"
    raw.write_bytes(public_record.public_key_bytes)
    canonical = registry_values(public_record)
    duplicate = {} if duplicate_change == "empty" else dict(canonical)
    if duplicate_change != "empty":
        for name, value in duplicate_change.items():
            if value is None:
                del duplicate[name]
            else:
                duplicate[name] = value
    registry = RegistryStub(canonical, duplicate)
    monkeypatch.setattr(r1_root_pin.os, "name", "nt")
    monkeypatch.setitem(sys.modules, "winreg", registry)
    monkeypatch.setitem(r1_root_pin._SLOTS, ACCEPTANCE_TEST_ONLY,
                        (r1_root_pin._SLOTS[ACCEPTANCE_TEST_ONLY][0], raw))
    monkeypatch.setattr(r1_root_pin, "_verify_windows_acl",
                        lambda *_: pytest.fail("ACL must not run for a conflicting pin"))
    with pytest.raises(RootPinError, match="pin conflict in 32-bit HKLM view"):
        load_operator_root_pin("acceptance", source=WindowsMachineRootTrustSource())
    assert registry.opened == [registry.KEY_WOW64_64KEY, registry.KEY_WOW64_32KEY]


def test_missing_canonical_64_bit_pin_never_uses_32_bit_fallback(monkeypatch):
    registry = RegistryStub(None, {})
    monkeypatch.setattr(r1_root_pin.os, "name", "nt")
    monkeypatch.setitem(sys.modules, "winreg", registry)
    with pytest.raises(RootPinError, match="canonical 64-bit operator-root pin missing"):
        WindowsMachineRootTrustSource().read(ACCEPTANCE_TEST_ONLY)
    assert registry.opened == [registry.KEY_WOW64_64KEY]


def test_native_acl_failure_remains_root_pin_error(monkeypatch):
    from app.control_plane import r1_windows_acl
    def reject(*args):
        raise r1_windows_acl.WindowsAclError("unsafe write grant")
    monkeypatch.setattr(r1_windows_acl, "verify_windows_acl", reject)
    with pytest.raises(RootPinError, match="operator-root storage ACL not verified"):
        r1_root_pin._verify_windows_acl("SOFTWARE\\Qingyu", r1_root_pin._FILE_BASE, False)


@pytest.mark.parametrize("duplicate", [False, True])
def test_native_acl_receives_exact_slot_path_and_duplicate_policy(monkeypatch, duplicate):
    from app.control_plane import r1_windows_acl
    calls = []
    monkeypatch.setattr(r1_windows_acl, "verify_windows_acl", lambda *args: calls.append(args))
    slot, public_file = r1_root_pin._SLOTS[ACCEPTANCE_TEST_ONLY]
    r1_root_pin._verify_windows_acl(slot, public_file, duplicate)
    assert calls == [(slot, public_file, duplicate)]
