"""Error sentinels shared by jose subpackages."""


class JoseError(Exception):
    """Base for jose errors."""


class ErrMalformed(JoseError):
    """Input does not have the shape a standard requires."""


class ErrInvalidArgument(JoseError):
    """Caller mistake rather than bad input data."""


class ErrUnsupportedAlg(JoseError):
    """Algorithm the SDK does not implement."""


class ErrUnsupportedKey(JoseError):
    """Key type or curve the SDK does not implement."""
