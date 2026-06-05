"""Utilidades de endurecimiento: drop de privilegios y validación de rutas.

Centinel necesita root SOLO para abrir el socket de captura (scapy) y leer
auth.log. Tras abrir esos recursos, suelta privilegios para que el resto del
pipeline (parser de input hostil, correlación, DNS, render) no corra como root.
"""
from __future__ import annotations

import os
from pathlib import Path


def drop_privileges(user: str = "nobody", group: str = "nogroup") -> tuple[bool, str]:
    """Baja a un usuario sin privilegios. Devuelve (bajó, motivo).

    Llamar DESPUÉS de abrir el sniffer y el fd de auth.log. No-op fuera de
    Linux/si no se es root o si el usuario no existe. NUNCA hace SystemExit:
    el llamador decide qué hacer si falla, así un drop fallido no tumba la
    app (que es justo el escenario en el que el operador necesita root para
    diagnosticar)."""
    if os.name != "posix":
        return False, "no-posix"
    if os.getuid() != 0:
        return False, "no-root"
    try:
        import grp
        import pwd
    except ImportError:
        return False, "sin pwd/grp"
    try:
        pw = pwd.getpwnam(user)
        gr = grp.getgrnam(group)
    except KeyError:
        return False, f"usuario/grupo '{user}'/'{group}' no existe"
    try:
        os.setgroups([])
        os.setgid(gr.gr_gid)
        os.setuid(pw.pw_uid)
        os.umask(0o077)
    except OSError as exc:
        return False, f"setuid/setgid falló: {exc}"
    if os.getuid() == 0:
        return False, "uid sigue siendo 0 tras setuid"
    return True, f"bajado a {user}"


def layers_need_sustained_root(args) -> list[str]:
    """Capas que requieren root mantenido tras el arranque. Si alguna está
    activa, NO debe soltarse el privilegio o quedarán degradadas en silencio."""
    need = []
    if getattr(args, "respond_live", False):
        need.append("--respond-live (nft/iptables)")
    if getattr(args, "rootcheck", False):
        need.append("--rootcheck (cron/SUID de root, integridad)")
    if getattr(args, "netwatch", False):
        need.append("--netwatch (visibilidad total de procesos)")
    if getattr(args, "dnswatch", False):
        need.append("--dnswatch (CAP_NET_RAW para sniff de DNS)")
    if getattr(args, "sniff", False):
        need.append("--sniff (CAP_NET_RAW para captura de paquetes)")
    return need


def safe_path(p: str, *, must_exist: bool = False,
              base: str | None = None) -> str:
    """Normaliza y valida una ruta (M-4: path traversal / lectura arbitraria)."""
    rp = Path(p).resolve()
    if base:
        broot = Path(base).resolve()
        if not (rp == broot or broot in rp.parents):
            raise SystemExit(f"[centinel] ruta fuera de {base}: {p}")
    if must_exist and not rp.is_file():
        raise SystemExit(f"[centinel] no existe o no es archivo: {p}")
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
            f"[centinel] interfaz desconocida: {iface} "
            f"(disponibles: {', '.join(sorted(ifaces)) or 'ninguna'})")
    return iface
