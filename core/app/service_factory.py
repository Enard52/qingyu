"""Shared Web/CLI composition; production R1 has no implicit dependency source."""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Callable

from .config import Settings
from .control_plane.authority import InMemoryControlPlane, UnavailableControlPlane
from .control_plane.r1_admission import AdmissionError, VerifiedCoreAdmission, verify_canonical_root
from .control_plane.r1_root_pin import RootTrustSource, PRODUCTION
from .control_plane.r1_client import AuthorityClient
from .db import session_factory
from .r1_local_store import CoreRuntimeScope, R1LocalStore
from .r1_service import R1CoreConsumer
from .services import CoreFoundationService


@dataclass(frozen=True, slots=True)
class CoreRuntimeDependencies:
    public_admission: VerifiedCoreAdmission
    scope: CoreRuntimeScope
    genesis_evidence_wire: bytes
    credential_reference: str
    credential_provider: Callable[[], str]
    root_profile: str = PRODUCTION
    root_trust_source: RootTrustSource | None = None


@lru_cache
def _legacy_authority(backend: str, environment: str):
    return InMemoryControlPlane() if backend == "memory" and environment in {"test", "development"} else UnavailableControlPlane()


def build_core_service(settings: Settings, *, runtime: CoreRuntimeDependencies | None = None):
    if settings.control_plane_backend != "r1_https":
        return CoreFoundationService(session_factory(settings), _legacy_authority(settings.control_plane_backend, settings.app_env))
    if not isinstance(runtime, CoreRuntimeDependencies) or not isinstance(runtime.public_admission, VerifiedCoreAdmission):
        raise AdmissionError("R1 requires explicitly admitted public deployment and local runtime evidence")
    pin = runtime.public_admission.pin
    expected = {
        "control_plane_api_base_url": pin.https_origin,
        "control_plane_domain_id": pin.authority_domain_id,
        "control_plane_instance_id": pin.authority_instance_id,
        "control_plane_generation": pin.authority_generation,
        "control_plane_spki_sha256": pin.server_spki_sha256,
        "control_plane_receipt_key_id": pin.receipt_key_id,
        "control_plane_root_key_id": pin.operator_root_key_id,
    }
    if any(getattr(settings, name) != value for name, value in expected.items()):
        raise AdmissionError("configured Core trust differs from verified public admission")
    if runtime.credential_reference != settings.control_plane_credential_reference:
        raise AdmissionError("outbound credential reference differs from admitted runtime binding")
    if settings.app_env == "production" and runtime.public_admission.root.test_only:
        raise AdmissionError("test Root cannot enter production")
    if settings.app_env == "production" and runtime.root_profile != PRODUCTION:
        raise AdmissionError("production requires independent production Root profile")
    verify_canonical_root(runtime.public_admission, profile=runtime.root_profile, source=runtime.root_trust_source)
    local = R1LocalStore(session_factory(settings), admission=runtime.public_admission, scope=runtime.scope,
                        genesis_evidence_wire=runtime.genesis_evidence_wire)
    # Constructing the client does not resolve its outbound credential.
    client = AuthorityClient(pin=pin, ca_file=settings.control_plane_ca_file,
                             credential_provider=runtime.credential_provider)
    return R1CoreConsumer(local_store=local, client=client)


def build_activation_core_service(*, route, adapter, environment_mode):
    """Explicit V2 activation composition, with no fallback to the legacy factory.

    No secrets are resolved and no database is connected during composition.
    The closed real GENESIS final-confirmation gate remains in the adapter.
    """
    from .errors import CoreError
    from .b2_signer_trust import AuthorityEnvironmentMode
    from .r1_scoped_activation_core import ScopedV2PostgresCore, SCOPED_V2_POSTGRES
    from .r1_service import ScopedV2CoreConsumer
    if route != SCOPED_V2_POSTGRES:
        raise CoreError("B2_PRODUCTION_NEW_GENESIS_V2_ROUTE_REQUIRED")
    if (not isinstance(environment_mode, AuthorityEnvironmentMode)
            or type(adapter) is not ScopedV2PostgresCore or adapter.mode != environment_mode):
        raise CoreError("B2_ACTIVATION_ROUTE_ENVIRONMENT_MISMATCH")
    return ScopedV2CoreConsumer(adapter=adapter)
