"""Colector de intentos de autenticación (SSH/PAM/sudo) en Linux.

Hace tail en vivo de /var/log/auth.log (Debian/Ubuntu) o journald si está
disponible. Extrae IP, usuario y resultado de cada intento de login.
"""
from __future__ import annotations

import asyncio
import os
import re

from ..core import Severity, ThreatEvent
from .base import Collector

# Patrones típicos de sshd
_FAILED = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)"
)
_INVALID = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
_ACCEPTED = re.compile(
    r"Accepted password for (?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)"
)

_DEFAULT_PATHS = ("/var/log/auth.log", "/var/log/secure")


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
        m = _FAILED.search(line)
        if m:
            return ThreatEvent(
                kind="login_fail", src_ip=m["ip"], user=m["user"],
                src_port=int(m["port"]), severity=Severity.LOW,
                message=f"Fallo de contraseña SSH user={m['user']}",
                tags={"auth", "ssh"}, raw=line.strip(),
            )
        m = _INVALID.search(line)
        if m:
            return ThreatEvent(
                kind="login_invalid_user", src_ip=m["ip"], user=m["user"],
                severity=Severity.MEDIUM,
                message=f"Usuario inexistente probado: {m['user']}",
                tags={"auth", "ssh", "recon"}, raw=line.strip(),
            )
        m = _ACCEPTED.search(line)
        if m:
            return ThreatEvent(
                kind="login_success", src_ip=m["ip"], user=m["user"],
                src_port=int(m["port"]), severity=Severity.INFO,
                message=f"Login exitoso user={m['user']}",
                tags={"auth", "ssh"}, raw=line.strip(),
            )
        return None

    async def _tail(self, path: str):
        """Tail asíncrono estilo `tail -F`, resistente a rotación de logs."""
        loop = asyncio.get_event_loop()
        f = open(path, "r", errors="replace")
        f.seek(0, os.SEEK_END)
        inode = os.fstat(f.fileno()).st_ino
        try:
            while True:
                line = await loop.run_in_executor(None, f.readline)
                if line:
                    yield line
                    continue
                await asyncio.sleep(0.4)
                # ¿Rotó el archivo?
                try:
                    if os.stat(path).st_ino != inode:
                        f.close()
                        f = open(path, "r", errors="replace")
                        inode = os.fstat(f.fileno()).st_ino
                except FileNotFoundError:
                    await asyncio.sleep(1)
        finally:
            f.close()
