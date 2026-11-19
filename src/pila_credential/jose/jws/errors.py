"""Error sentinels for jose/jws."""


class JwsError(Exception):
    pass


class ErrAlgNotAllowed(JwsError):
    pass


class ErrAlgKeyMismatch(JwsError):
    pass


class ErrBadSignature(JwsError):
    pass


class ErrBadKey(JwsError):
    pass


class ErrUnsupportedHeader(JwsError):
    pass


class ErrSignerFailed(JwsError):
    pass


class ErrSelfCheck(JwsError):
    pass
