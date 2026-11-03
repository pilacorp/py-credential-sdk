from hashlib import sha256

from digitalcredential.errors import DigitalCredentialError, MALFORMED
from digitalcredential.split import split_sd_jwt


class Credential:
    def __init__(self, compact: str) -> None:
        self.compact = compact

    def serialize(self) -> str:
        return self.compact

    def hash(self) -> str:
        if not self.compact:
            raise ValueError("Hash of a nil or zero Credential")
        jwt = self.compact.split("~")[0]
        return sha256(jwt.encode("utf-8")).hexdigest()


def parse(compact: str) -> Credential:
    try:
        split_sd_jwt(compact)
    except DigitalCredentialError:
        raise
    except Exception as exc:
        raise DigitalCredentialError(MALFORMED, str(exc)) from exc
    return Credential(compact)
