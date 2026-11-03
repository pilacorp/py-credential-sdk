import hashlib
import json

from digitalcredential.typemeta import Integrity, Load, Multi, Ref, Static, new_http_resolver
from digitalcredential.typemeta.errors import ErrNotFound
from digitalcredential.typemeta.http import HTTPResolverConfig
from digitalcredential.typemeta.multi import CancelledError


def _doc(vct: str, extra: str = "") -> bytes:
    return json.dumps({"vct": vct, **({} if not extra else json.loads("{" + extra.strip(",") + "}"))}).encode()


def test_http_resolver_with_injectable_fetch() -> None:
    good = _doc("https://publisher.example/t")
    served = {"n": 0}

    def fetch(url: str) -> tuple[bytes, dict[str, str]]:
        served["n"] += 1
        if url.endswith("/missing"):
            return b"", {"content-type": "application/json", "status": "404"}
        if url.endswith("/503"):
            return b"", {"content-type": "application/json", "status": "503"}
        if served["n"] == 1:
            return good[:-1], {"content-type": "application/json", "cache-control": "max-age=60"}
        return good, {"content-type": "application/json", "cache-control": "max-age=60"}

    r = new_http_resolver(
        HTTPResolverConfig(
            trusted_publisher_origins=["https://publisher.example/"],
            fetch=fetch,
        )
    )
    for vct in (
        "urn:example:t",
        "http://publisher.example/t",
        "https://other.example/t",
        "https://publisher.example/t#f",
    ):
        try:
            r.metadata(Ref(vct=vct))
            raise AssertionError("expected ErrNotFound")
        except ErrNotFound:
            pass
    ref = Ref(vct="https://publisher.example/t", integrity=Integrity(good))
    try:
        Load(r, ref)
        raise AssertionError("expected integrity failure")
    except Exception:
        pass
    m = Load(r, ref)
    assert m.vct == "https://publisher.example/t"
    Load(r, ref)
    assert served["n"] == 2


def test_typemeta_multi() -> None:
    a = "https://a.example/t"
    b = "https://b.example/t"
    ra = Static(_doc(a))
    rb = Static(_doc(b))

    class Counted:
        def __init__(self, inner) -> None:
            self.inner = inner
            self.calls = 0

        def metadata(self, ref: Ref) -> bytes:
            self.calls += 1
            return self.inner.metadata(ref)

    cb = Counted(rb)
    m = Multi(ra, cb)
    assert m.metadata(Ref(vct=a)) == _doc(a)
    assert m.metadata(Ref(vct=b)) == _doc(b)
    cb.calls = 0
    m.metadata(Ref(vct=a))
    assert cb.calls == 0
    try:
        m.metadata(Ref(vct="https://c.example/t"))
        raise AssertionError("expected ErrNotFound")
    except ErrNotFound:
        pass


def test_typemeta_multi_cancelled_context() -> None:
    class Ctx:
        def __init__(self) -> None:
            self._cancelled = False

        def cancel(self) -> None:
            self._cancelled = True

        def cancelled(self) -> bool:
            return self._cancelled

    rb = Static(_doc("https://b.example/t"))
    m = Multi(rb)
    ctx = Ctx()
    ctx.cancel()
    try:
        m.metadata_ctx(ctx, Ref(vct="https://b.example/t"))
        raise AssertionError("expected cancel")
    except CancelledError:
        pass
