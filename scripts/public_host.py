"""Validate public IPv4 deployment targets shared by order and deploy tools."""

from __future__ import annotations

import ipaddress
import re
import socket


HOST_LABEL = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)\Z", re.IGNORECASE)
NUMERIC_DOTTED = re.compile(r"[0-9.]+\Z")


def is_public_unicast(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        address.is_global
        and not address.is_multicast
        and not address.is_unspecified
        and not address.is_reserved
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_private
    )


def is_public_ipv4(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return address.version == 4 and is_public_unicast(address)


def normalize_public_host(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("需要商家显示的公网主机名或 IPv4")
    try:
        host = value.strip().encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as error:
        raise ValueError("公网主机名无效") from error
    if (not host or host == "localhost" or host.endswith(".localhost")
            or host.endswith(".local")):
        raise ValueError("主机必须是公网 IPv4 或可公开解析的主机名")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if NUMERIC_DOTTED.fullmatch(host):
            raise ValueError("数字形式的主机必须是完整有效的公网 IPv4")
        labels = host.split(".")
        # Numeric TLDs and inet_aton-style hexadecimal IPv4 components are not DNS names.
        if (len(labels) < 2 or len(host) > 253 or labels[-1].isdigit()
                or all(re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)", part) for part in labels)
                or not all(HOST_LABEL.fullmatch(label) for label in labels)):
            raise ValueError("公网主机名无效")
        return host
    if not is_public_ipv4(address):
        raise ValueError("主机地址必须是可公开路由的 IPv4")
    return str(address)


def require_public_resolution(host: str) -> set[str]:
    normalized = normalize_public_host(host)
    try:
        literal = ipaddress.ip_address(normalized)
    except ValueError:
        try:
            answers = socket.getaddrinfo(normalized, None, type=socket.SOCK_STREAM)
        except socket.gaierror as error:
            raise ValueError(f"公网主机名无法解析：{normalized}") from error
        addresses = {answer[4][0].split("%", 1)[0] for answer in answers}
        if not addresses:
            raise ValueError(f"公网主机名没有地址记录：{normalized}")
        parsed = {ipaddress.ip_address(address) for address in addresses}
        if any(not is_public_unicast(address) for address in parsed):
            raise ValueError("公网主机名解析到了非公网地址")
        ipv4 = {str(address) for address in parsed if is_public_ipv4(address)}
        if not ipv4:
            raise ValueError("部署目标需要至少一个可公开路由的 IPv4")
        return ipv4
    return {str(literal)}
