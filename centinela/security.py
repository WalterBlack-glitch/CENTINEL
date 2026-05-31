"""Utilidades de endurecimiento: drop de privilegios y validación de rutas.

Centinela necesita root SOLO para abrir el socket de captura (scapy) y leer
auth.log. Tras abrir esos recursos, suelta privilegios para que el resto del
pipeline (parser de input hostil, correlación, DNS, render) no corra como root.
"""
from __future__ import annotations

import os
from pathlib import Path


def drop_privileges(user: str = "nobody", group: str = "nogroup") -> bool:
    """Baja a un usuario sin privilegios. Devuelve True si bajó.

    Llamar DESPUÉS de abrir el sniffer y el fd de auth.log. No-op fuera de
    Linux/si no se es root o si el usuario no existe.
    """
    if os.name != "posix" or os.getuid() != 0:
        return False
    try:
        import grp
        import pwd
    except ImportError:
        return False
    try:
        pw = pwd.getpwnam(user)
        gr = grp.getgrnam(group)
    except KeyError:
        return False
    os.setgroups([])
    os.setgid(gr.gr_gid)
    os.setuid(pw.pw_uid)
    os.umask(0o077)
    # Verifica que no se pueda re-escalar.
    if os.getuid() == 0:
        raise SystemExit("[centinela] fallo crítico al soltar privilegios")
    return True


def safe_path(p: str, *, must_exist: bool = False,
              base: str | None = None) -> str:
    """Normaliza y valida una ruta (M-4: path traversal / lectura arbitraria)."""
    rp = Path(p).resolve()
    if base:
        broot = Path(base).resolve()
        if not (rp == broot or broot in rp.parents):
            raise SystemExit(f"[centinela] ruta fuera de {base}: {p}")
    if must_exist and not rp.is_file():
        raise SystemExit(f"[centinela] no existe o no es archivo: {p}")
    return str(rp)


def valid_iface(iface: str | None) -> str | None:
    """Valida la interfaz contra las reales del sistema (M-4)."""
    if not iface:
        return None
    ifaces: set[str] = set()
    sysnet = Path("/sys/class/net")
    if sysnet.is_dir():
        ifaces = {p.name for p in sysnet.iterdir()}
    else:
        try:
            from scapy.all import get_if_list  # type: ignore
            ifaces = set(get_if_list())
        except Exception:
            return iface  # no podemos validar; confiamos en el operador
    if iface not in ifaces:
        raise SystemExit(
            f"[centinela] interfaz desconocida: {iface} "
            f"(disponibles: {', '.join(sorted(ifaces)) or 'ninguna'})")
    return iface
