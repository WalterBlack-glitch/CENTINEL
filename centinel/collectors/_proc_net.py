"""Lectura de /proc/net/tcp(6): parsing de direcciones y conexiones salientes.

Compartido por netwatch (proceso ↔ IP) y beacon (periodicidad de callbacks).
Solo lectura, sin subprocess, sin shell, sin dependencias externas.
"""
from __future__ import annotations

import ipaddress

_ESTABLISHED = "01"
_MAX_CONNS = 4096


def parse_hex_addr(hexaddr: str) -> tuple[str, int] | None:
    """Convierte 'HEXIP:HEXPORT' de /proc/net/tcp(6) en (ip, puerto)."""
    try:
        ip_hex, port_hex = hexaddr.split(":")
        port = int(port_hex, 16)
        if len(ip_hex) == 8:            # IPv4, little-endian por bytes
            b = bytes.fromhex(ip_hex)
            ip = ".".join(str(x) for x in reversed(b))
        elif len(ip_hex) == 32:         # IPv6: 4 palabras de 32 bits, le por palabra
            words = [ip_hex[i:i + 8] for i in range(0, 32, 8)]
            raw = b"".join(bytes.fromhex(w)[::-1] for w in words)
            ip = str(ipaddress.IPv6Address(raw))
        else:
            return None
        return ip, port
    except (ValueError, ipaddress.AddressValueError):
        return None


def is_external_ip(ip: str) -> bool:
    """True solo si la IP es enrutable por internet (ni LAN/loopback/reservada)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local
                or a.is_multicast or a.is_reserved or a.is_unspecified)


def established_remote_ips(max_conns: int = _MAX_CONNS) -> set[str]:
    """Conjunto de IPs remotas externas con conexión TCP ESTABLISHED ahora."""
    out: set[str] = set()
    count = 0
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path) as f:
                next(f, None)   # cabecera
                for line in f:
                    if count >= max_conns:
                        return out
                    parts = line.split()
                    if len(parts) < 4 or parts[3] != _ESTABLISHED:
                        continue
                    rem = parse_hex_addr(parts[2])
                    if not rem:
                        continue
                    count += 1
                    if is_external_ip(rem[0]):
                        out.add(rem[0])
        except OSError:
            continue
    return out
