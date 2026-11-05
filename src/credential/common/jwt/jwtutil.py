"""JWT helpers shared by credential/vc, credential/vp and credential/common/jwt
(Go: credential/internal/jwtutil)."""
from __future__ import annotations

import json
import math
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


def b64url_decode(s: str) -> bytes:
    """Strict unpadded base64url (Go base64.RawURLEncoding): no '=', no foreign characters."""
    import base64
    import binascii

    if not isinstance(s, str) or not _B64URL_RE.match(s) or len(s) % 4 == 1:
        raise ValueError("illegal base64 data")
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ValueError("illegal base64 data") from exc


def b64url_encode(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _reject_constant(name: str) -> Any:
    raise ValueError(f"invalid JSON constant {name}")


def json_loads(data: bytes | str) -> Any:
    """json.loads that refuses NaN/Infinity, which Go's decoder rejects."""
    return json.loads(data, parse_constant=_reject_constant)


def json_dumps(obj: Any) -> bytes:
    """Compact JSON the way Go's json.Marshal writes a map: sorted keys, HTML-escaped."""
    s = json.dumps(obj, separators=(",", ":"), ensure_ascii=False, sort_keys=True, allow_nan=False)
    s = s.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    s = s.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return s.encode("utf-8")


def set_issued_at(payload: dict[str, Any], built_at: float | datetime | None = None) -> None:
    """Record when the signing input was fixed (iat). exp and nbf are deliberately not derived."""
    if built_at is None:
        built_at = time.time()
    if isinstance(built_at, datetime):
        built_at = built_at.timestamp()
    payload["iat"] = int(math.floor(built_at))


def numeric_claim(payload: dict[str, Any], name: str) -> int | None:
    """Read a NumericDate claim; None when absent/null. Raises on a bad type or value <= 0."""
    raw = payload.get(name)
    if raw is None:
        return None
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise ValueError(f"invalid {name} type: {type(raw).__name__}")
    try:
        sec = int(raw)  # float64 -> int64 truncates toward zero
    except (ValueError, OverflowError) as exc:
        raise ValueError(f"invalid {name} value: {raw}") from exc
    if sec <= 0:
        raise ValueError(f"invalid {name} value: {raw}")
    return sec


def _rfc3339(sec: int) -> str:
    return datetime.fromtimestamp(sec, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def check_time_claims(payload: dict[str, Any], leeway: timedelta | float = 0) -> None:
    """RFC 7519 4.1.4-4.1.5: refuse the token on/after exp or before nbf (leeway widens both)."""
    lw = leeway.total_seconds() if isinstance(leeway, timedelta) else float(leeway)
    now = time.time()
    nbf = numeric_claim(payload, "nbf")
    if nbf is not None and now + lw < nbf:
        raise ValueError(f"signature is not valid before {_rfc3339(nbf)} (nbf)")
    exp = numeric_claim(payload, "exp")
    if exp is not None and not (now - lw < exp):
        raise ValueError(f"signature expired at {_rfc3339(exp)} (exp)")


def trim_recovery_byte(signature: bytes) -> bytes:
    """Drop a trailing recovery id: 65-byte r||s||v -> 64-byte r||s."""
    return signature[:64] if len(signature) == 65 else signature
