"""Operator-only, test-only R1 acceptance root ceremony.

``create-local-acceptance`` is manually invoked on the acceptance Windows
host. Its encrypted private key stays in operator custody outside Git and
outside application/API/migration credentials. Public-pin installation is a
separate, independently approved ceremony; no trust on first use. No runtime
or migration imports or invokes this tool. Existing keys/pins are never
overwritten, repaired, or rotated by this tool.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
import getpass
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

ACCEPTANCE_TEST_ONLY = "R1_ACCEPTANCE_TEST_ONLY"


def key_id(public_key: Ed25519PublicKey) -> str:
    """The protocol fingerprint: SHA-256 of the raw Ed25519 public key."""
    return hashlib.sha256(public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()


class ProvisioningError(RuntimeError):
    """Unsafe or incomplete external operator ceremony."""


_PRIVATE_PARENT_ACL = r"""
$ErrorActionPreference = 'Stop'
$operator = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$allowed = @($operator, 'S-1-5-18', 'S-1-5-32-544')
$genericWrite = 0x10000000 -bor 0x40000000
$privateDirectoryAnyAccess = 0x001fffff -bor $genericWrite
$replace = 0x00000040 -bor 0x00010000 -bor 0x00040000 -bor 0x00080000 -bor $genericWrite
$target = [IO.Path]::GetFullPath('__PARENT__')
$item = Get-Item -LiteralPath $target -Force
if (-not $item.PSIsContainer) { throw 'private parent is not a directory' }
$current = $item
while ($null -ne $current) {
  if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'private path contains a reparse point'
  }
  $acl = Get-Acl -LiteralPath $current.FullName
  $raw = [Security.AccessControl.RawSecurityDescriptor]::new(
    $acl.GetSecurityDescriptorBinaryForm(), 0)
  if ((($raw.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -eq 0) -or
      ($null -eq $raw.DiscretionaryAcl)) { throw 'null or missing DACL' }
  if ($current.FullName -eq $target) {
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($allowed -notcontains $owner) { throw 'unsafe private directory owner' }
  }
  $mask = if ($current.FullName -eq $target) { $privateDirectoryAnyAccess } else { $replace }
  foreach ($rule in $acl.GetAccessRules($true, $true,
             [Security.Principal.SecurityIdentifier])) {
    if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
    # An INHERIT_ONLY ACE does not grant rights on this ancestor. Every
    # descendant is checked separately with its own effective DACL.
    if (($rule.PropagationFlags -band
         [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
    if (($allowed -notcontains $rule.IdentityReference.Value) -and
        (([int]$rule.FileSystemRights -band $mask) -ne 0)) {
      throw 'unsafe private path write grant'
    }
  }
  $current = $current.Parent
}
'ACL_OK'
"""

_PRIVATE_FILE_ACL = r"""
$ErrorActionPreference = 'Stop'
$operator = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$allowed = @($operator, 'S-1-5-18', 'S-1-5-32-544')
$genericWrite = 0x10000000 -bor 0x40000000
$item = Get-Item -LiteralPath '__PRIVATE_FILE__' -Force
if ($item.PSIsContainer -or
    (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
  throw 'private key is not a regular file'
}
$acl = Get-Acl -LiteralPath $item.FullName
$raw = [Security.AccessControl.RawSecurityDescriptor]::new(
  $acl.GetSecurityDescriptorBinaryForm(), 0)
if ((($raw.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -eq 0) -or
    ($null -eq $raw.DiscretionaryAcl)) { throw 'null or missing private-file DACL' }
$owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
if ($allowed -notcontains $owner) { throw 'unsafe private-file owner' }
foreach ($rule in $acl.GetAccessRules($true, $true,
           [Security.Principal.SecurityIdentifier])) {
  if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
  if (($allowed -notcontains $rule.IdentityReference.Value) -and
      (([int]$rule.FileSystemRights -band (0x001fffff -bor $genericWrite)) -ne 0)) {
    throw 'unsafe private-file access grant'
  }
}
'ACL_OK'
"""


def _powershell_acl(script: str) -> None:
    if os.name != "nt":
        raise ProvisioningError("operator provisioning requires Windows")
    # A parent PowerShell 7 session can prepend its incompatible modules to
    # PSModulePath. Resolve Windows PowerShell and its built-in modules from
    # the OS system directory, not from PATH or inherited user/module search.
    system_directory = ctypes.create_unicode_buffer(32768)
    size = ctypes.windll.kernel32.GetSystemDirectoryW(
        system_directory, len(system_directory))
    if size == 0 or size >= len(system_directory):
        raise ProvisioningError("Windows PowerShell system directory unavailable")
    windows_ps = Path(system_directory.value) / "WindowsPowerShell" / "v1.0"
    environment = os.environ.copy()
    environment["PSModulePath"] = str(windows_ps / "Modules")
    try:
        result = subprocess.run(
            [str(windows_ps / "powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=15, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProvisioningError("operator ACL preflight unavailable") from exc
    if result.returncode != 0 or result.stdout.strip() != "ACL_OK":
        raise ProvisioningError("operator ACL preflight failed")


def _verify_private_parent(path: Path) -> None:
    # The directory must exist *before* the key is generated; the tool does
    # not create it with an inherited, potentially writable DACL.
    if not path.is_absolute() or not path.parent.is_dir():
        raise ProvisioningError("private key requires a pre-existing absolute directory")
    resolved = path.resolve(strict=False)
    if any((parent / ".git").exists() for parent in resolved.parents):
        raise ProvisioningError("private key cannot be stored inside a Git worktree")
    quoted = str(path.parent).replace("'", "''")
    _powershell_acl(_PRIVATE_PARENT_ACL.replace("__PARENT__", quoted))


def _verify_private_file(path: Path) -> None:
    _verify_private_parent(path)
    if not path.is_file() or path.is_symlink():
        raise ProvisioningError("operator private key is not a regular file")
    quoted = str(path).replace("'", "''")
    _powershell_acl(_PRIVATE_FILE_ACL.replace("__PRIVATE_FILE__", quoted))


def _raw_public(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _verify_public_destination(private_path: Path, public_path: Path) -> None:
    if (not public_path.is_absolute() or not public_path.parent.is_dir() or
            private_path.resolve(strict=False) == public_path.resolve(strict=False)):
        raise ProvisioningError("public export needs a distinct pre-existing absolute directory")


def _write_exclusive(path: Path, payload: bytes) -> None:
    if not path.is_absolute() or not path.parent.is_dir():
        raise ProvisioningError("output requires a pre-existing absolute directory")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    except FileExistsError as exc:
        raise ProvisioningError("existing root material may not be replaced") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        # Leave the partial exclusive file in place. Operator recovery must
        # inspect it in operator custody; automatic deletion is forbidden.
        raise


def create_offline(private_path: Path, public_path: Path, password: bytes) -> dict[str, str]:
    """Generate one encrypted PKCS#8 acceptance root under operator control.

    The caller must supply a distinct absolute private path in a pre-staged,
    ACL-restricted directory. No key data is emitted or logged.
    """
    if len(password) < 16:
        raise ProvisioningError("a strong encryption password is required")
    _verify_private_parent(private_path)
    _verify_public_destination(private_path, public_path)
    if private_path.exists() or public_path.exists():
        raise ProvisioningError("root already exists; no implicit replacement or rotation")
    private = Ed25519PrivateKey.generate()
    encrypted = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password),
    )
    public = _raw_public(private)
    _write_exclusive(private_path, encrypted)
    # The exclusive file may inherit a weaker DACL than its safe parent.
    # Refuse public export/success until the actual custody file is checked.
    _verify_private_file(private_path)
    # Persisted custody, not only the in-memory key, must support later
    # authorized signatures. A failed readback leaves the same key in place.
    try:
        persisted = serialization.load_pem_private_key(
            private_path.read_bytes(), password)
    except (OSError, ValueError, TypeError) as exc:
        raise ProvisioningError("persisted encrypted root is unreadable or invalid") from exc
    if (not isinstance(persisted, Ed25519PrivateKey)
            or _raw_public(persisted) != public):
        raise ProvisioningError("persisted root identity differs from generated root")
    # A crash here leaves one private root, not a second. The operator can
    # recover the public export with export_public_offline().
    _write_exclusive(public_path, public)
    return {"profile": ACCEPTANCE_TEST_ONLY,
            "public_key_id": key_id(private.public_key()),
            "public_key_format": "ed25519-raw-32"}


def export_public_offline(private_path: Path, public_path: Path,
                          password: bytes) -> dict[str, str]:
    """Recover only a missing public export from the same encrypted root."""
    _verify_private_file(private_path)
    _verify_public_destination(private_path, public_path)
    if public_path.exists():
        raise ProvisioningError("public export already exists; no replacement")
    try:
        loaded = serialization.load_pem_private_key(private_path.read_bytes(), password)
    except (OSError, ValueError, TypeError) as exc:
        raise ProvisioningError("encrypted operator root unavailable or invalid") from exc
    if not isinstance(loaded, Ed25519PrivateKey):
        raise ProvisioningError("operator root is not Ed25519")
    _write_exclusive(public_path, _raw_public(loaded))
    return {"profile": ACCEPTANCE_TEST_ONLY,
            "public_key_id": key_id(loaded.public_key()),
            "public_key_format": "ed25519-raw-32"}


def _pin_parent_preflight(registry_slot: str, public_file: Path,
                          duplicate_equivalent: bool) -> None:
    """Use the same native fail-closed policy before exclusive pin creation."""
    from app.control_plane.r1_windows_acl import WindowsAclError, verify_windows_parent_acl

    try:
        verify_windows_parent_acl(public_file, duplicate_equivalent)
    except (WindowsAclError, OSError, ValueError) as exc:
        raise ProvisioningError("public trust parent ACL not verified") from exc


@contextmanager
def _new_64bit_pin_key(winreg, slot: str):
    """Create the HKLM slot only if RegCreateKeyExW says it was *new*.

    ``winreg.CreateKeyEx`` hides the creation disposition and can silently
    adopt a key created between preflight and write. That is forbidden here.
    """
    if os.name != "nt":
        raise ProvisioningError("pin installation requires Windows")
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    create = advapi.RegCreateKeyExW
    create.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32,
                       ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                       ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
                       ctypes.POINTER(ctypes.c_uint32)]
    create.restype = ctypes.c_long
    handle = ctypes.c_void_p()
    disposition = ctypes.c_uint32()
    status = create(ctypes.c_void_p(int(winreg.HKEY_LOCAL_MACHINE)), slot, 0,
                    None, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY,
                    None, ctypes.byref(handle), ctypes.byref(disposition))
    if status != 0 or not handle.value:
        if handle.value:
            winreg.CloseKey(handle.value)
        raise ProvisioningError("cannot exclusively create canonical 64-bit pin")
    if disposition.value != 1:  # REG_CREATED_NEW_KEY
        winreg.CloseKey(handle.value)
        raise ProvisioningError("canonical root pin appeared during installation")
    try:
        yield handle.value
    finally:
        winreg.CloseKey(handle.value)


def install_public_pin(public_path: Path, expected_key_id: str) -> dict[str, str]:
    """Install only the immutable acceptance public pin on a staged host.

    An existing partial or different 64-bit key is deliberately not repaired.
    A public file left by a crash is reusable only if byte-identical.
    """
    if os.name != "nt":
        raise ProvisioningError("pin installation requires Windows")
    from app.control_plane.r1_root_pin import (
        RootPinError, WindowsMachineRootTrustSource, _SLOTS,
        _verify_windows_acl, load_operator_root_pin,
    )
    import winreg

    raw = public_path.read_bytes()
    if len(raw) != 32:
        raise ProvisioningError("operator public export must be raw Ed25519-32")
    public = Ed25519PublicKey.from_public_bytes(raw)
    fingerprint = key_id(public)
    if expected_key_id != fingerprint:
        raise ProvisioningError("public export does not match independently approved fingerprint")
    slot, fixed_file = _SLOTS[ACCEPTANCE_TEST_ONLY]
    source = WindowsMachineRootTrustSource()
    canonical = source._read_view(winreg, slot, winreg.KEY_WOW64_64KEY,
                                  allow_missing=True)
    duplicate = source._read_view(winreg, slot, winreg.KEY_WOW64_32KEY,
                                  allow_missing=True)
    expected = (1, ACCEPTANCE_TEST_ONLY, 1, fingerprint)
    if canonical is not None:
        raise ProvisioningError("canonical root pin already exists; no replacement")
    if duplicate is not None and duplicate != expected:
        raise ProvisioningError("conflicting 32-bit root pin")
    _pin_parent_preflight(slot, fixed_file, duplicate is not None)
    if fixed_file.exists():
        if fixed_file.read_bytes() != raw:
            raise ProvisioningError("existing public-key file conflicts with root")
    else:
        _write_exclusive(fixed_file, raw)
    # Key creation happens only after file/parent checks; incomplete registry
    # writes remain invalid and require explicit operator recovery.
    with _new_64bit_pin_key(winreg, slot) as key:
        try:
            _verify_windows_acl(slot, fixed_file, duplicate is not None)
        except RootPinError as exc:
            raise ProvisioningError("new pin ACL failed before values were written") from exc
        winreg.SetValueEx(key, "PinVersion", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "Profile", 0, winreg.REG_SZ, ACCEPTANCE_TEST_ONLY)
        winreg.SetValueEx(key, "TestOnly", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "PublicKeyId", 0, winreg.REG_SZ, fingerprint)
    try:
        pin = load_operator_root_pin(ACCEPTANCE_TEST_ONLY)
    except RootPinError as exc:
        raise ProvisioningError("installed pin failed runtime verification") from exc
    if pin.key_id != fingerprint:
        raise ProvisioningError("installed pin fingerprint mismatch")
    return {"profile": ACCEPTANCE_TEST_ONLY, "public_key_id": fingerprint,
            "registry_view": "HKLM-64", "registry_slot": slot,
            "public_key_file": str(fixed_file),
            "duplicate_equivalent": str(pin.duplicate_equivalent).lower()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("create-local-acceptance", "export-public-local-acceptance"):
        command = commands.add_parser(name)
        command.add_argument("--private-path", type=Path, required=True)
        command.add_argument("--public-path", type=Path, required=True)
    install = commands.add_parser("install-public-pin")
    install.add_argument("--public-path", type=Path, required=True)
    install.add_argument("--expected-key-id", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "install-public-pin":
            metadata = install_public_pin(args.public_path, args.expected_key_id)
        else:
            password = getpass.getpass("Acceptance root encryption passphrase: ").encode("utf-8")
            if args.command == "create-local-acceptance":
                confirm = getpass.getpass("Confirm encryption password: ").encode("utf-8")
                if password != confirm:
                    raise ProvisioningError("password confirmation mismatch")
                metadata = create_offline(args.private_path, args.public_path, password)
            else:
                metadata = export_public_offline(args.private_path, args.public_path, password)
    except ProvisioningError as exc:
        print(f"operator ceremony refused: {exc}", file=sys.stderr)
        return 2
    except Exception:
        # OS and trust-source errors can include custody paths. Never echo
        # exception text, private material, or passphrases into a transcript.
        print("operator ceremony refused: filesystem, key, or trust operation failed", file=sys.stderr)
        return 2
    print(json.dumps(metadata, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
