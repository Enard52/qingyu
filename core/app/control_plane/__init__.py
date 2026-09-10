"""Non-cloned control-plane authority adapters."""

from .authority import (
    InMemoryControlPlane,
    UnavailableControlPlane,
)

__all__ = ["InMemoryControlPlane", "UnavailableControlPlane"]

