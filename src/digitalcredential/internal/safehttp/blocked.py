from __future__ import annotations

import ipaddress

_BLOCKED = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.88.99.2/32"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("64:ff9b:1::/48"),
    ipaddress.ip_network("100::/64"),
    ipaddress.ip_network("100:0:0:1::/64"),
    ipaddress.ip_network("2001:db8::/32"),
    ipaddress.ip_network("3fff::/20"),
    ipaddress.ip_network("5f00::/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("2001::/23"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("fec0::/10"),
]

_IPV4_COMPAT = ipaddress.ip_network("::/96")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_SIX_TO_FOUR = ipaddress.ip_network("2002::/16")


def parse_addr(raw: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if "%" in raw:
        raw = raw.split("%", 1)[0]
    return ipaddress.ip_address(raw)


def embedded_ipv4(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if isinstance(ip, ipaddress.IPv4Address):
        return ip
    if ip.ipv4_mapped:
        return ip.ipv4_mapped
    if ip in _IPV4_COMPAT or ip in _NAT64:
        return ipaddress.IPv4Address(ip.packed[12:16])
    if ip in _SIX_TO_FOUR:
        return ipaddress.IPv4Address(ip.packed[2:6])
    return ip


def blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    ip = embedded_ipv4(ip)
    for p in _BLOCKED:
        if ip in p:
            return True
    return False


def blocked_host(host: str) -> bool:
    try:
        return blocked(parse_addr(host))
    except ValueError:
        return True
