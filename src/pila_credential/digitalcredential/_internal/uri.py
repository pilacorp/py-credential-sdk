from __future__ import annotations

import ipaddress


def check(s: str) -> None:
    if not valid(s):
        raise ValueError("is not a URI (RFC 3986)")
    scheme, _, rest = s.partition(":")
    if scheme.lower() in ("http", "https") and not _has_host(rest):
        raise ValueError("is an http or https URI without a host (RFC 9110 §4.2.1, §4.2.2)")


def _has_host(rest: str) -> bool:
    if not rest.startswith("//"):
        return False
    rest = rest[2:]
    authority = rest.split("/")[0].split("?")[0].split("#")[0]
    if "@" in authority:
        authority = authority.split("@", 1)[1]
    host = authority.split(":")[0]
    return host != "" or authority.startswith("[")


def valid(s: str) -> bool:
    if not _ascii_or_pct(s):
        return False
    s, _, fragment = s.partition("#")
    if fragment and not _uri_chars(fragment, ":@/?"):
        return False
    s, _, query = s.partition("?")
    if query and not _uri_chars(query, ":@/?"):
        return False
    if ":" not in s:
        return False
    scheme, path = s.split(":", 1)
    if not _is_scheme(scheme):
        return False
    if path.startswith("//"):
        rest = path[2:]
        slash = rest.find("/")
        authority = rest if slash < 0 else rest[:slash]
        abempty = "" if slash < 0 else rest[slash + 1 :]
        if not _is_authority(authority):
            return False
        path = abempty
    return _uri_chars(path, ":@/")


def _is_scheme(s: str) -> bool:
    if not s or not _alpha(s[0]):
        return False
    for c in s[1:]:
        if not (_alpha(c) or _digit(c) or c in "+-."):
            return False
    return True


def _is_authority(s: str) -> bool:
    if "@" in s:
        userinfo, s = s.split("@", 1)
        if not _uri_chars(userinfo, ":"):
            return False
    host, port = s, ""
    if s.startswith("["):
        end = s.find("]")
        if end < 0 or not _is_ip_literal(s[1:end]):
            return False
        if "%" in s[1:end]:
            return False
        host = ""
        after = s[end + 1 :]
        if after:
            if not after.startswith(":"):
                return False
            port = after[1:]
    else:
        host, _, port = s.partition(":")
    if not all(_digit(c) for c in port):
        return False
    if host and any(ord(c) >= 0x80 for c in host):
        return False
    return _uri_chars(host, "")


def _is_ip_literal(s: str) -> bool:
    if s and s[0] in "vV":
        rest = s[1:]
        if "." not in rest:
            return False
        hex_part, tail = rest.split(".", 1)
        if not hex_part or not tail or "%" in tail or not _uri_chars(tail, ":"):
            return False
        return all(c in "0123456789abcdefABCDEF" for c in hex_part)
    try:
        addr = ipaddress.ip_address(s)
        return isinstance(addr, ipaddress.IPv6Address)
    except ValueError:
        return False


def _uri_chars(s: str, extra: str) -> bool:
    i = 0
    while i < len(s):
        c = s[i]
        if c == "%":
            if i + 2 >= len(s) or not _is_hex(s[i + 1]) or not _is_hex(s[i + 2]):
                return False
            i += 3
            continue
        if _alpha(c) or _digit(c) or c in "-._~!$&'()*+,;=" or c in extra:
            i += 1
            continue
        return False
    return True


def _alpha(c: str) -> bool:
    return "a" <= c <= "z" or "A" <= c <= "Z"


def _digit(c: str) -> bool:
    return "0" <= c <= "9"


def _is_hex(c: str) -> bool:
    return _digit(c) or "a" <= c <= "f" or "A" <= c <= "F"


def _ascii_or_pct(s: str) -> bool:
    i = 0
    while i < len(s):
        if s[i] == "%":
            if i + 2 >= len(s) or not _is_hex(s[i + 1]) or not _is_hex(s[i + 2]):
                return False
            i += 3
            continue
        if ord(s[i]) >= 0x80:
            return False
        i += 1
    return True
