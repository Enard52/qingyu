"""External ceremony tests never install a pin or persist private material."""

from pathlib import Path
import ctypes
import importlib.util
import sys
from types import SimpleNamespace
from contextlib import contextmanager

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
import pytest

from app.control_plane.r1_protocol import key_id
from app.control_plane.r1_root_pin import ACCEPTANCE_TEST_ONLY
from app.control_plane import r1_root_pin

_TOOL = Path(__file__).resolve().parents[1] / "tools" / "provision_r1_acceptance_root.py"
_SPEC = importlib.util.spec_from_file_location("provision_r1_acceptance_root", _TOOL)
assert _SPEC is not None and _SPEC.loader is not None
ceremony = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ceremony)


def test_offline_public_recovery_rejects_private_reparse_before_read(tmp_path, monkeypatch):
    private = tmp_path / "offline-private.pem"
    public = tmp_path / "public-transfer.pub"
    private.write_bytes(b"not a real key")
    monkeypatch.setattr(ceremony, "_verify_private_parent", lambda _: None)
    original_is_symlink = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink",
                        lambda path: path == private or original_is_symlink(path))
    monkeypatch.setattr(Path, "read_bytes", lambda _: pytest.fail("read before reparse check"))
    with pytest.raises(ceremony.ProvisioningError, match="not a regular file"):
        ceremony.export_public_offline(private, public, b"independent-long-passphrase")


def _public_key():
    public = Ed25519PrivateKey.generate().public_key()
    return public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw), key_id(public)


def test_create_is_external_one_time_encrypted_and_private_first(tmp_path, monkeypatch):
    private = tmp_path / "offline-private.pem"
    public = tmp_path / "transfer.pub"
    checks = []
    writes = []
    monkeypatch.setattr(ceremony, "_verify_private_parent", lambda path: checks.append(path))
    monkeypatch.setattr(ceremony, "_verify_private_file", lambda path: checks.append(path))
    monkeypatch.setattr(ceremony, "_write_exclusive",
                        lambda path, payload: writes.append((path, payload)))
    original_read = Path.read_bytes
    monkeypatch.setattr(Path, "read_bytes", lambda path: writes[0][1]
                        if path == private else original_read(path))
    metadata = ceremony.create_offline(private, public, b"independent-long-passphrase")
    assert checks == [private, private]
    assert [entry[0] for entry in writes] == [private, public]
    assert b"ENCRYPTED PRIVATE KEY" in writes[0][1]
    assert b"PRIVATE KEY-----" not in writes[1][1]
    assert len(writes[1][1]) == 32
    loaded = serialization.load_pem_private_key(
        writes[0][1], b"independent-long-passphrase")
    assert isinstance(loaded, Ed25519PrivateKey)
    assert _public_raw(loaded) == writes[1][1]
    assert metadata == {"profile": ACCEPTANCE_TEST_ONLY,
                        "public_key_id": key_id(Ed25519PublicKey.from_public_bytes(writes[1][1])),
                        "public_key_format": "ed25519-raw-32"}


def _public_raw(private):
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def test_existing_root_or_weak_password_rejects_before_generation(tmp_path, monkeypatch):
    private = tmp_path / "offline-private.pem"
    public = tmp_path / "transfer.pub"
    monkeypatch.setattr(ceremony, "_verify_private_parent", lambda *_: None)
    monkeypatch.setattr(ceremony, "_verify_private_file", lambda *_: None)
    monkeypatch.setattr(ceremony.Ed25519PrivateKey, "generate",
                        lambda: pytest.fail("must not generate"))
    with pytest.raises(ceremony.ProvisioningError, match="strong encryption"):
        ceremony.create_offline(private, public, b"short")
    private.touch()
    with pytest.raises(ceremony.ProvisioningError, match="already exists"):
        ceremony.create_offline(private, public, b"independent-long-passphrase")


def test_failed_public_export_cannot_create_second_root(tmp_path, monkeypatch):
    private = tmp_path / "offline-private.pem"
    public = tmp_path / "transfer.pub"
    monkeypatch.setattr(ceremony, "_verify_private_parent", lambda *_: None)
    monkeypatch.setattr(ceremony, "_verify_private_file", lambda *_: None)
    writes = []
    encrypted = []

    def fail_public(path, payload):
        writes.append(path)
        if path == public:
            raise OSError("simulated interruption")
        encrypted.append(payload)
        private.touch()

    monkeypatch.setattr(ceremony, "_write_exclusive", fail_public)
    original_read = Path.read_bytes
    monkeypatch.setattr(Path, "read_bytes", lambda path: encrypted[0]
                        if path == private else original_read(path))
    with pytest.raises(OSError, match="simulated interruption"):
        ceremony.create_offline(private, public, b"independent-long-passphrase")
    assert writes == [private, public]
    with pytest.raises(ceremony.ProvisioningError, match="already exists"):
        ceremony.create_offline(private, public, b"independent-long-passphrase")


def test_post_write_private_acl_failure_blocks_public_export(tmp_path, monkeypatch):
    private = tmp_path / "offline-private.pem"
    public = tmp_path / "transfer.pub"
    monkeypatch.setattr(ceremony, "_verify_private_parent", lambda *_: None)
    monkeypatch.setattr(ceremony, "_verify_private_file",
                        lambda *_: (_ for _ in ()).throw(
                            ceremony.ProvisioningError("unsafe private-file ACL")))
    writes = []
    monkeypatch.setattr(ceremony, "_write_exclusive",
                        lambda path, _payload: writes.append(path))
    with pytest.raises(ceremony.ProvisioningError, match="unsafe private-file ACL"):
        ceremony.create_offline(private, public, b"independent-long-passphrase")
    assert writes == [private]


def test_unreadable_persisted_root_blocks_public_export(tmp_path, monkeypatch):
    private = tmp_path / "operator-root-encrypted.pem"
    public = tmp_path / "transfer.pub"
    monkeypatch.setattr(ceremony, "_verify_private_parent", lambda *_: None)
    monkeypatch.setattr(ceremony, "_verify_private_file", lambda *_: None)
    writes = []
    monkeypatch.setattr(ceremony, "_write_exclusive",
                        lambda path, _payload: writes.append(path))
    original_read = Path.read_bytes
    monkeypatch.setattr(Path, "read_bytes", lambda path: b"corrupt-private"
                        if path == private else original_read(path))
    with pytest.raises(ceremony.ProvisioningError, match="persisted encrypted root"):
        ceremony.create_offline(private, public, b"independent-long-passphrase")
    assert writes == [private]


def test_private_path_inside_git_is_rejected(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    monkeypatch.setattr(ceremony, "_powershell_acl",
                        lambda *_: pytest.fail("Git check must happen before ACL command"))
    with pytest.raises(ceremony.ProvisioningError, match="Git worktree"):
        ceremony._verify_private_parent(repo / "root.pem")


def test_private_directory_acl_preflight_covers_read_and_replacement(tmp_path, monkeypatch):
    scripts = []
    monkeypatch.setattr(ceremony, "_powershell_acl", scripts.append)
    ceremony._verify_private_parent(tmp_path / "root.pem")
    assert len(scripts) == 1
    assert "$privateDirectoryAnyAccess = 0x001fffff -bor $genericWrite" in scripts[0]
    assert "$replace = 0x00000040" in scripts[0]
    assert "DiscretionaryAclPresent" in scripts[0]
    assert "ReparsePoint" in scripts[0]
    assert "PropagationFlags]::InheritOnly" in scripts[0]


def test_pin_requires_independent_fingerprint_before_any_host_write(tmp_path, monkeypatch):
    raw, fingerprint = _public_key()
    export = tmp_path / "transfer.pub"
    export.write_bytes(raw)
    monkeypatch.setattr(ceremony.os, "name", "nt")
    monkeypatch.setattr(ceremony, "_pin_parent_preflight",
                        lambda *_: pytest.fail("must reject before ACL or writes"))
    with pytest.raises(ceremony.ProvisioningError, match="independently approved"):
        ceremony.install_public_pin(export, "0" * 64)
    assert fingerprint != "0" * 64


def test_existing_or_conflicting_pin_never_replaced(tmp_path, monkeypatch):
    raw, fingerprint = _public_key()
    export = tmp_path / "transfer.pub"
    export.write_bytes(raw)
    monkeypatch.setattr(ceremony.os, "name", "nt")
    source = SimpleNamespace(_read_view=lambda _winreg, _slot, view, **_:
                             (1, ACCEPTANCE_TEST_ONLY, 1, fingerprint)
                             if view == 0x100 else None)
    monkeypatch.setattr(r1_root_pin, "WindowsMachineRootTrustSource", lambda: source)
    monkeypatch.setitem(sys.modules, "winreg", SimpleNamespace(
        KEY_WOW64_64KEY=0x100, KEY_WOW64_32KEY=0x200))
    monkeypatch.setattr(ceremony, "_pin_parent_preflight",
                        lambda *_: pytest.fail("must not mutate"))
    with pytest.raises(ceremony.ProvisioningError, match="already exists"):
        ceremony.install_public_pin(export, fingerprint)
    source._read_view = lambda _winreg, _slot, view, **_: (
        None if view == 0x100 else (1, ACCEPTANCE_TEST_ONLY, 1, "f" * 64))
    with pytest.raises(ceremony.ProvisioningError, match="conflicting 32-bit"):
        ceremony.install_public_pin(export, fingerprint)


def test_empty_existing_64_bit_key_fails_closed(tmp_path, monkeypatch):
    raw, fingerprint = _public_key()
    export = tmp_path / "transfer.pub"
    export.write_bytes(raw)
    monkeypatch.setattr(ceremony.os, "name", "nt")
    monkeypatch.setattr(r1_root_pin, "WindowsMachineRootTrustSource",
                        lambda: SimpleNamespace(_read_view=lambda *_args, **_kwargs:
                                                (_ for _ in ()).throw(
                                                    r1_root_pin.RootPinError("missing values"))))
    monkeypatch.setitem(sys.modules, "winreg", SimpleNamespace(KEY_WOW64_64KEY=0x100))
    monkeypatch.setattr(ceremony, "_new_64bit_pin_key",
                        lambda *_: pytest.fail("existing empty key must not be adopted"))
    with pytest.raises(r1_root_pin.RootPinError, match="missing values"):
        ceremony.install_public_pin(export, fingerprint)


def test_registry_creation_race_rejects_existing_key_disposition(monkeypatch):
    closed = []

    class Create:
        def __call__(self, *_args):
            ctypes.cast(_args[7], ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.c_void_p(42)
            ctypes.cast(_args[8], ctypes.POINTER(ctypes.c_uint32))[0] = ctypes.c_uint32(2)
            return 0

    monkeypatch.setattr(ceremony.os, "name", "nt")
    monkeypatch.setattr(ceremony.ctypes, "WinDLL",
                        lambda *_args, **_kwargs: SimpleNamespace(RegCreateKeyExW=Create()))
    registry = SimpleNamespace(HKEY_LOCAL_MACHINE=0x80000002,
                               KEY_SET_VALUE=0x2, KEY_WOW64_64KEY=0x100,
                               CloseKey=closed.append)
    with pytest.raises(ceremony.ProvisioningError, match="appeared during installation"):
        with ceremony._new_64bit_pin_key(registry, "SOFTWARE\\Qingyu"):
            pytest.fail("existing key may not be adopted")
    assert closed == [42]


def test_install_public_pin_only_writes_fixed_64_bit_slot_after_preflight(tmp_path, monkeypatch):
    raw, fingerprint = _public_key()
    export = tmp_path / "transfer.pub"
    export.write_bytes(raw)
    fixed = tmp_path / "fixed.pub"
    slot = r1_root_pin._SLOTS[ACCEPTANCE_TEST_ONLY][0]
    monkeypatch.setitem(r1_root_pin._SLOTS, ACCEPTANCE_TEST_ONLY, (slot, fixed))
    monkeypatch.setattr(ceremony.os, "name", "nt")
    source = SimpleNamespace(_read_view=lambda *_args, **_kwargs: None)
    monkeypatch.setattr(r1_root_pin, "WindowsMachineRootTrustSource", lambda: source)
    checks = []
    monkeypatch.setattr(ceremony, "_pin_parent_preflight",
                        lambda *args: checks.append(args))
    monkeypatch.setattr(r1_root_pin, "_verify_windows_acl",
                        lambda *args: checks.append(("new-key-acl", args)))
    monkeypatch.setattr(r1_root_pin, "load_operator_root_pin",
                        lambda _profile: SimpleNamespace(key_id=fingerprint,
                                                         duplicate_equivalent=False))
    writes = []

    registry = SimpleNamespace(
        HKEY_LOCAL_MACHINE=object(), KEY_WOW64_64KEY=0x100,
        KEY_WOW64_32KEY=0x200, KEY_SET_VALUE=0x2, REG_DWORD=4, REG_SZ=1,
        SetValueEx=lambda *_args: writes.append(("value", _args)),
    )
    monkeypatch.setitem(sys.modules, "winreg", registry)

    @contextmanager
    def new_key(_winreg, _slot):
        writes.append(("create", (_winreg, _slot)))
        yield 99

    monkeypatch.setattr(ceremony, "_new_64bit_pin_key", new_key)
    metadata = ceremony.install_public_pin(export, fingerprint)
    assert fixed.read_bytes() == raw
    assert checks == [(slot, fixed, False), ("new-key-acl", (slot, fixed, False))]
    assert writes[0] == ("create", (registry, slot))
    assert [write[1][1] for write in writes[1:]] == [
        "PinVersion", "Profile", "TestOnly", "PublicKeyId"]
    assert metadata["public_key_id"] == fingerprint
    assert metadata["registry_view"] == "HKLM-64"


def test_new_pin_acl_failure_prevents_value_install(tmp_path, monkeypatch):
    raw, fingerprint = _public_key()
    export = tmp_path / "transfer.pub"
    export.write_bytes(raw)
    fixed = tmp_path / "fixed.pub"
    slot = r1_root_pin._SLOTS[ACCEPTANCE_TEST_ONLY][0]
    monkeypatch.setitem(r1_root_pin._SLOTS, ACCEPTANCE_TEST_ONLY, (slot, fixed))
    monkeypatch.setattr(ceremony.os, "name", "nt")
    monkeypatch.setattr(r1_root_pin, "WindowsMachineRootTrustSource",
                        lambda: SimpleNamespace(_read_view=lambda *_a, **_k: None))
    monkeypatch.setattr(ceremony, "_pin_parent_preflight", lambda *_: None)
    monkeypatch.setattr(r1_root_pin, "_verify_windows_acl",
                        lambda *_: (_ for _ in ()).throw(r1_root_pin.RootPinError("unsafe ACL")))

    @contextmanager
    def new_key(*_):
        yield 99

    monkeypatch.setattr(ceremony, "_new_64bit_pin_key", new_key)
    monkeypatch.setitem(sys.modules, "winreg", SimpleNamespace(
        KEY_WOW64_64KEY=0x100, KEY_WOW64_32KEY=0x200,
        SetValueEx=lambda *_: pytest.fail("must not write values before ACL pass")))
    with pytest.raises(ceremony.ProvisioningError, match="ACL failed before values"):
        ceremony.install_public_pin(export, fingerprint)


def test_pin_parent_acl_uses_native_gate_and_fails_closed(monkeypatch):
    from app.control_plane import r1_windows_acl
    calls = []
    monkeypatch.setattr(r1_windows_acl, "verify_windows_parent_acl",
                        lambda *args: calls.append(args))
    slot, public_file = r1_root_pin._SLOTS[ACCEPTANCE_TEST_ONLY]
    ceremony._pin_parent_preflight(slot, public_file, True)
    assert calls == [(public_file, True)]
    def refuse(*args):
        raise r1_windows_acl.WindowsAclError("unsafe write grant")
    monkeypatch.setattr(r1_windows_acl, "verify_windows_parent_acl", refuse)
    with pytest.raises(ceremony.ProvisioningError, match="public trust parent ACL not verified"):
        ceremony._pin_parent_preflight(slot, public_file, False)
