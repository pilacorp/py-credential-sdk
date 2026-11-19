from __future__ import annotations


class ErrNotFound(LookupError):
    """No Type Metadata for the type."""


class ErrInvalid(ValueError):
    """Type Metadata document is invalid."""


class ErrClaims(ValueError):
    """Claim metadata is invalid."""


class ErrCycle(ValueError):
    """extends cycle."""


class ErrViolated(ValueError):
    """Payload violates claim metadata."""
