"""Explicit Authority process composition; no auto-provisioning or Root signer.

A deployment host supplies real independent inspectors and preprovisioned
secret capabilities. Their absence blocks startup, including this module's CLI.
No environment flag can manufacture admission from configuration shape.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .r1_admission import AdmissionError, AuthorityAdmission, verify_canonical_root
from .r1_root_pin import RootTrustSource, PRODUCTION
from .r1_api import authority_server_config, create_authority_app
from .r1_commands import AuthenticatedCaller
from .r1_coordinator import R1Coordinator, ReceiptSigner
from .r1_postgres_store import R1PostgresStore


@dataclass(frozen=True, slots=True)
class AuthorityRuntimeDependencies:
    admission: AuthorityAdmission
    service_connection_factory: Callable
    receipt_signer: ReceiptSigner
    authenticator: Callable[[str], AuthenticatedCaller]
    root_profile: str = PRODUCTION
    root_trust_source: RootTrustSource | None = None


def create_authority_runtime(*, runtime: AuthorityRuntimeDependencies | None = None):
    if not isinstance(runtime, AuthorityRuntimeDependencies):
        raise AdmissionError("independent observations and preprovisioned service credentials are required")
    verify_canonical_root(runtime.admission.public, profile=runtime.root_profile, source=runtime.root_trust_source)
    runtime.admission.verify()
    coordinator = R1Coordinator(store=R1PostgresStore(runtime.service_connection_factory),
        admission=runtime.admission, receipt_signer=runtime.receipt_signer)
    return create_authority_app(coordinator=coordinator, authenticator=runtime.authenticator)


def main(*, runtime: AuthorityRuntimeDependencies | None = None):
    import argparse
    import uvicorn
    parser = argparse.ArgumentParser(description="Admitted Qingyu R1 Authority service")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--tls-key", required=True)
    args = parser.parse_args()
    app = create_authority_runtime(runtime=runtime)
    uvicorn.Server(authority_server_config(app, host=args.host, port=args.port,
                   certificate_file=args.certificate, private_key_file=args.tls_key)).run()


if __name__ == "__main__":
    main()
