"""Load the independently operator-provisioned, immutable R1 root public pin.

Signed manifests and environment variables are deliberately not trust sources.
This module reads public material only; it never creates or replaces a key.
The acceptance test private root may remain in ACL-protected operator custody
on the acceptance host; this module neither reads nor handles it. Production
root custody still requires a separate offline ceremony.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .r1_protocol import key_id


PRODUCTION = "R1_PERSONAL_PRODUCTION"
ACCEPTANCE_TEST_ONLY = "R1_ACCEPTANCE_TEST_ONLY"
_REGISTRY_BASE = r"SOFTWARE\Qingyu\ControlPlane\R1\OperatorRoot"
_FILE_BASE = Path(r"C:\ProgramData\Qingyu\ControlPlane\R1")
_SLOTS = {
    PRODUCTION: (_REGISTRY_BASE + r"\Production", _FILE_BASE / "operator-root-production.pub"),
    ACCEPTANCE_TEST_ONLY: (_REGISTRY_BASE + r"\AcceptanceTestOnly",
                           _FILE_BASE / "operator-root-acceptance-test-only.pub"),
}
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class RootPinError(ValueError):
    """The operator-root public trust anchor cannot safely be used."""


@dataclass(frozen=True, slots=True)
class RootTrustRecord:
    version: int
    profile: str
    test_only: bool
    key_id: str
    public_key_bytes: bytes
    acl_verified: bool
    duplicate_equivalent: bool = False


class RootTrustSource(Protocol):
    def read(self, profile: str) -> RootTrustRecord: ...


@dataclass(frozen=True, slots=True)
class OperatorRootPin:
    profile: str
    test_only: bool
    key_id: str
    public_key: Ed25519PublicKey
    duplicate_equivalent: bool = False


def load_operator_root_pin(profile: str, *, source: RootTrustSource | None = None) -> OperatorRootPin:
    """Return a pinned verification key, or fail closed.

    ``source`` is an explicit injection seam for isolated tests. Production
    callers omit it. ``profile`` must be an explicit caller policy, never
    inferred from a signed manifest's ``test_only`` claim.
    """
    if type(profile) is not str:
        raise RootPinError("unsupported operator-root profile")
    requested_profile = {"production": PRODUCTION, "acceptance": ACCEPTANCE_TEST_ONLY,
                         PRODUCTION: PRODUCTION, ACCEPTANCE_TEST_ONLY: ACCEPTANCE_TEST_ONLY}.get(profile)
    if requested_profile is None:
        raise RootPinError("unsupported operator-root profile")
    try:
        record = (source if source is not None else WindowsMachineRootTrustSource()).read(
            requested_profile)
    except RootPinError:
        raise
    except (OSError, ValueError, RuntimeError) as exc:
        raise RootPinError("operator-root trust source unavailable") from exc
    if not isinstance(record, RootTrustRecord):
        raise RootPinError("invalid operator-root trust record")
    if type(record.version) is not int or record.version != 1:
        raise RootPinError("unsupported operator-root pin version")
    if record.profile != requested_profile or type(record.test_only) is not bool:
        raise RootPinError("operator-root profile mismatch")
    if record.test_only != (requested_profile == ACCEPTANCE_TEST_ONLY):
        raise RootPinError("test-only operator root cannot enter production")
    if record.acl_verified is not True:
        raise RootPinError("operator-root storage ACL not verified")
    if type(record.duplicate_equivalent) is not bool:
        raise RootPinError("invalid operator-root duplicate status")
    if type(record.key_id) is not str or _HEX64.fullmatch(record.key_id) is None:
        raise RootPinError("malformed operator-root key ID")
    if type(record.public_key_bytes) is not bytes or len(record.public_key_bytes) != 32:
        raise RootPinError("operator root must be a raw 32-byte Ed25519 public key")
    try:
        root = Ed25519PublicKey.from_public_bytes(record.public_key_bytes)
    except ValueError as exc:
        raise RootPinError("malformed operator-root public key") from exc
    if key_id(root) != record.key_id:
        raise RootPinError("conflicting operator-root public key and key ID")
    return OperatorRootPin(profile=requested_profile, test_only=record.test_only,
                           key_id=record.key_id, public_key=root,
                           duplicate_equivalent=record.duplicate_equivalent)


def _verify_windows_acl(registry_slot: str, public_file: Path,
                        duplicate_equivalent: bool) -> None:
    """Native read-only security check; unavailable or ambiguous state rejects."""
    from .r1_windows_acl import WindowsAclError, verify_windows_acl

    try:
        verify_windows_acl(registry_slot, public_file, duplicate_equivalent)
    except (WindowsAclError, OSError, ValueError) as exc:
        raise RootPinError("operator-root storage ACL not verified") from exc


class WindowsMachineRootTrustSource:
    """Fixed HKLM metadata plus fixed protected raw-public-key file.

    Registry values: PinVersion (DWORD=1), Profile (REG_SZ), TestOnly
    (DWORD 0/1), PublicKeyId (REG_SZ, lowercase SHA-256 of raw key).
    """

    def read(self, profile: str) -> RootTrustRecord:
        if os.name != "nt":
            raise RootPinError("Windows machine trust source unavailable")
        import winreg

        try:
            registry_slot, public_file = _SLOTS[profile]
        except KeyError as exc:
            raise RootPinError("unsupported operator-root profile") from exc
        canonical = self._read_view(winreg, registry_slot, winreg.KEY_WOW64_64KEY)
        try:
            duplicate = self._read_view(winreg, registry_slot, winreg.KEY_WOW64_32KEY,
                                        allow_missing=True)
        except (OSError, RootPinError) as exc:
            raise RootPinError("operator-root pin conflict in 32-bit HKLM view") from exc
        if duplicate is not None and duplicate != canonical:
            raise RootPinError("operator-root pin conflict in 32-bit HKLM view")
        duplicate_equivalent = duplicate is not None
        _verify_windows_acl(registry_slot, public_file, duplicate_equivalent)
        raw = public_file.read_bytes()
        return RootTrustRecord(version=canonical[0], profile=canonical[1],
                               test_only=bool(canonical[2]), key_id=canonical[3],
                               public_key_bytes=raw, acl_verified=True,
                               duplicate_equivalent=duplicate_equivalent)

    @staticmethod
    def _read_view(winreg, registry_slot: str, view: int,
                   *, allow_missing: bool = False) -> tuple[int, str, int, str] | None:
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_slot, 0,
                                 winreg.KEY_READ | view)
        except FileNotFoundError:
            if allow_missing:
                return None
            raise RootPinError("canonical 64-bit operator-root pin missing")
        with key:
            count = winreg.QueryInfoKey(key)[1]
            names = {winreg.EnumValue(key, index)[0] for index in range(count)}
            if names != {"PinVersion", "Profile", "TestOnly", "PublicKeyId"}:
                raise RootPinError("missing or unexpected operator-root registry value")
            def value(name: str, kind: int):
                data, actual_kind = winreg.QueryValueEx(key, name)
                if actual_kind != kind:
                    raise RootPinError("operator-root registry value type mismatch")
                return data

            version = value("PinVersion", winreg.REG_DWORD)
            profile = value("Profile", winreg.REG_SZ)
            test_only = value("TestOnly", winreg.REG_DWORD)
            root_key_id = value("PublicKeyId", winreg.REG_SZ)
            if test_only not in (0, 1):
                raise RootPinError("invalid operator-root test-only flag")
            return version, profile, test_only, root_key_id
