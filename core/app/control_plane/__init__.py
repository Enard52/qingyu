"""Core-facing authority adapters; direct PostgreSQL access is excluded."""

from .authority import (
    InMemoryControlPlane,
    UnavailableControlPlane,
)
__all__ = ["InMemoryControlPlane", "UnavailableControlPlane"]
