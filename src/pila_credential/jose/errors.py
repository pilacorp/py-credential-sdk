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


_WRAPPED: dict[tuple[type, type], type] = {}


def wrap(sentinel: type[Exception], cause: BaseException, msg: str | None = None) -> Exception:
    """Return `sentinel(msg)` that is also an instance of type(cause) and has it as __cause__.

    Go wraps the cause with %w so errors.Is matches both; this gives `except sentinel`
    and `except type(cause)` the same property. Falls back to the plain sentinel when
    the two classes cannot be combined.
    """
    text = msg if msg is not None else str(cause)
    ct = type(cause)
    if ct is sentinel or issubclass(sentinel, ct):
        err: Exception = sentinel(text)
    elif issubclass(ct, sentinel):
        err = ct(text)
    else:
        key = (sentinel, ct)
        cls = _WRAPPED.get(key)
        if cls is None:
            try:
                cls = type(sentinel.__name__, (sentinel, ct), {"__module__": sentinel.__module__})
            except TypeError:
                cls = sentinel
            _WRAPPED[key] = cls
        try:
            err = cls(text)
        except TypeError:
            err = sentinel(text)
    err.__cause__ = cause
    return err
