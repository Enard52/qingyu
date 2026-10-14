from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.control_plane.authority import InMemoryControlPlane
from app.db import Base
from app.models import CoreMetadata
from app.services import CoreFoundationService


@pytest.fixture
def foundation():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    with factory.begin() as session:
        session.add(CoreMetadata(id=1, status="UNINITIALIZED"))
    authority = InMemoryControlPlane()
    return CoreFoundationService(factory, authority), factory, authority


@pytest.fixture
def genesis_request():
    from app.schemas import GenesisRequest

    return GenesisRequest(
        trust_domain_id=uuid.uuid4(),
        qingyu_identity_id=uuid.uuid4(),
        continuity_id=uuid.uuid4(),
        continuity_alias="qingyu-main",
        genesis_request_id="genesis-1",
        genesis_nonce="0123456789abcdef",
        initial_owner_fingerprint="owner-fingerprint-1",
        actor_principal_id="owner-1",
        governance_provenance={"source": "test"},
    )
