"""Colector de intentos de autenticación (SSH/PAM/sudo) en Linux.

Hace tail en vivo de /var/log/auth.log (Debian/Ubuntu) o /var/log/secure
(RHEL). Extrae IP, usuario y resultado de cada intento de login.

MODELO DE AMENAZA: el atacante remoto controla parcialmente el contenido de
auth.log (su username SSH se escribe literal). Por eso los patrones están
ANCLADOS al prefijo real de sshd (`sshd[pid]:`) y al fin de mensaje, el
username está restringido a una whitelist sin espacios, y la IP extraída se
revalida con `ipaddress`. Así un username tipo
`pwn from 9.9.9.9 port 22 ; Failed password ...` no puede inyectar IP/usuario.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import re

from ..core import Severity, ThreatEvent
from .base import Collector

# Componentes anclados al formato real de syslog + sshd.
_PREFIX = r"sshd\[\d+\]:\s"
_USER = r"(?P<user>[A-Za-z0-9._@-]{1,64})"   # whitelist: sin espacios ni control
_IP = r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
_PORT = r"(?P<port>\d{1,5})"

_FAILED = re.compile(
    rf"{_PREFIX}Failed password for (?:invalid user )?{_USER} "
    rf"from {_IP} port {_PORT}\b"
)
_INVALID = re.compile(
    rf"{_PREFIX}Invalid user {_USER} from {_IP}\b"
)
_ACCEPTED = re.compile(
    rf"{_PREFIX}Accepted (?:password|publickey) for {_USER} "
    rf"from {_IP} port {_PORT}\b"
)

_MAX_LINE = 4096
_DEFAULT_PATHS = ("/var/log/auth.log", "/var/log/secure")


def _valid_ip(ip: str) -> str | None:
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return None


class AuthLogCollector(Collector):
    name = "authlog"

    def __init__(self, bus, path: str | None = None) -> None:
        super().__init__(bus)
        self.path = path or self._detect_path()

    @staticmethod
    def _detect_path() -> str | None:
        for p in _DEFAULT_PATHS:
            if os.path.exists(p):
                return p
        return None

    def available(self) -> bool:
        return bool(self.path) and os.access(self.path, os.R_OK)

    async def run(self) -> None:
        if not self.available():
            return
        async for line in self._tail(self.path):
            ev = self._parse(line)
            if ev:
                await self.emit(ev)

    def _parse(self, line: str) -> ThreatEvent | None:
        # A-1: acota la línea antes de aplicar regex (limita coste por línea hostil).
        if len(line) > _MAX_LINE:
            line = line[:_MAX_LINE]

        m = _FAILED.search(line)
        if m and (ip := _valid_ip(m["ip"])):
            return ThreatEvent(
                kind="login_fail", src_ip=ip, user=m["user"],
                src_port=int(m["port"]), severity=Severity.LOW,
                message=f"Fallo de contraseña SSH user={m['user']}",
                tags={"auth", "ssh"}, raw=line.strip()[:_MAX_LINE],
            )
        m = _INVALID.search(line)
        if m and (ip := _valid_ip(m["ip"])):
            return ThreatEvent(
                kind="login_invalid_user", src_ip=ip, user=m["user"],
                severity=Severity.MEDIUM,
                message=f"Usuario inexistente probado: {m['user']}",
                tags={"auth", "ssh", "recon"}, raw=line.strip()[:_MAX_LINE],
            )
        m = _ACCEPTED.search(line)
        if m and (ip := _valid_ip(m["ip"])):
            return ThreatEvent(
                kind="login_success", src_ip=ip, user=m["user"],
                src_port=int(m["port"]), severity=Severity.INFO,
                message=f"Login exitoso user={m['user']}",
                tags={"auth", "ssh"}, raw=line.strip()[:_MAX_LINE],
            )
        return None

    def _open(self, path: str):
        """Abre el log sin seguir symlinks en el componente final (B-4)."""
        flags = os.O_RDONLY
        flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        st = os.fstat(fd)
        # Rechaza si no es archivo regular (evita FIFOs/devices apuntados por symlink swap).
        import stat as _stat
        if not _stat.S_ISREG(st.st_mode):
            os.close(fd)
            raise OSError(f"{path} no es un archivo regular")
        return os.fdopen(fd, "r", errors="replace"), st.st_ino

    async def _tail(self, path: str):
        """Tail asíncrono estilo `tail -F`, resistente a rotación y truncado."""
        loop = asyncio.get_event_loop()
        f, inode = self._open(path)
        f.seek(0, os.SEEK_END)
        pos = f.tell()
        try:
            while True:
                line = await loop.run_in_executor(None, f.readline)
                if line:
                    pos = f.tell()
                    yield line
                    continue
                await asyncio.sleep(0.4)
                try:
                    st = os.stat(path)
                    # B-2: truncado en sitio (mismo inode, archivo encogió) -> rebobina.
                    if st.st_ino == inode and st.st_size < pos:
                        f.seek(0)
                        pos = 0
                    # Rotación: inode distinto -> reabrir.
                    elif st.st_ino != inode:
                        f.close()
                        f, inode = self._open(path)
                        pos = 0
                except FileNotFoundError:
                    await asyncio.sleep(1)
                except OSError:
                    await asyncio.sleep(1)
        finally:
            f.close()
