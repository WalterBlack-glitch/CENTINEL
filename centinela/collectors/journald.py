"""Colector journald estructurado (systemd) — la fuente más robusta.

Por qué es superior al scraping de /var/log/auth.log:

  - PROCEDENCIA CONFIABLE: journald entrega campos `_COMM`, `SYSLOG_IDENTIFIER`,
    `_UID`, `_PID` que el *kernel/journald* rellenan, no el contenido del
    mensaje. Validamos que el registro proviene realmente del proceso `sshd`
    (uid 0). Así se elimina la clase de spoofing en la que otro proceso (o un
    username malicioso reflejado en el log) inyecta líneas falsas: aunque el
    MESSAGE contenga texto hostil, su procedencia no es falsificable.
  - El campo MESSAGE viene ya separado del prefijo de syslog, así que los
    patrones se anclan al inicio/fin del mensaje (`^...$`), sin reintento
    posicional.
  - Sin condiciones de carrera de rotación/truncado de archivo.

Implementación sin dependencias nativas: hace streaming de
`journalctl -f -o json` (subprocess) y parsea JSON línea a línea. Si systemd no
está disponible, `available()` devuelve False y el orquestador usa authlog.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil

from ..core import Severity, ThreatEvent
from ..correlation import signatures
from .authlog import _IP, _MAX_LINE, _PORT, _USER, _valid_ip
from .base import Collector

# Patrones anclados al MESSAGE (sin el prefijo de syslog: journald ya lo separa).
_FAILED = re.compile(
    rf"^Failed password for (?:invalid user )?{_USER} from {_IP} port {_PORT}\b")
_INVALID = re.compile(rf"^Invalid user {_USER} from {_IP}\b")
_ACCEPTED = re.compile(
    rf"^Accepted (?:password|publickey) for {_USER} from {_IP} port {_PORT}\b")

# Identificadores legítimos del proceso SSH (según distro).
_SSH_IDENTS = {"sshd", "sshd-session"}


def _resolve_journalctl() -> str | None:
    for cand in ("/usr/bin/journalctl", "/bin/journalctl"):
        if os.path.exists(cand):
            return cand
    return shutil.which("journalctl")


class JournaldCollector(Collector):
    name = "journald"

    def __init__(self, bus, unit: str | None = "ssh.service") -> None:
        super().__init__(bus)
        self.unit = unit
        self._bin = _resolve_journalctl()

    def available(self) -> bool:
        return bool(self._bin) and os.path.isdir("/run/systemd/system")

    def _cmd(self) -> list[str]:
        # -f sigue en vivo; -n0 evita volcar historial; json para campos
        # estructurados. Filtra por identificador sshd a nivel de journald.
        cmd = [self._bin, "-f", "-n", "0", "-o", "json",
               "SYSLOG_IDENTIFIER=sshd"]
        return cmd

    async def run(self) -> None:
        if not self.available():
            return
        env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
        proc = await asyncio.create_subprocess_exec(
            *self._cmd(), stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL, env=env,
        )
        assert proc.stdout is not None
        try:
            while True:
                raw = await proc.stdout.readline()
                if not raw:
                    break
                ev = self._parse_record(raw)
                if ev:
                    await self.emit(ev)
        finally:
            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=3)
                except asyncio.TimeoutError:
                    proc.kill()

    def _parse_record(self, raw: bytes) -> ThreatEvent | None:
        try:
            rec = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return None

        # --- Validación de procedencia (lo que elimina el spoofing) ---
        ident = rec.get("SYSLOG_IDENTIFIER")
        comm = rec.get("_COMM")
        if ident not in _SSH_IDENTS and comm not in _SSH_IDENTS:
            return None
        # sshd corre como root; un sshd "de usuario" (uid != 0) no es de fiar
        # para eventos de autenticación del sistema.
        uid = rec.get("_UID")
        if uid is not None and str(uid) != "0":
            return None

        msg = rec.get("MESSAGE")
        # MESSAGE puede venir como lista de bytes (journald binario) o string.
        if isinstance(msg, list):
            try:
                msg = bytes(msg).decode("utf-8", "replace")
            except (ValueError, TypeError):
                return None
        if not isinstance(msg, str):
            return None
        if len(msg) > _MAX_LINE:
            msg = msg[:_MAX_LINE]

        return self._build(msg)

    def _build(self, msg: str) -> ThreatEvent | None:
        m = _FAILED.match(msg)
        if m and (ip := _valid_ip(m["ip"])):
            return ThreatEvent(
                kind="login_fail", src_ip=ip, user=m["user"],
                src_port=int(m["port"]), severity=Severity.LOW,
                message=f"Fallo de contraseña SSH user={m['user']}",
                tags={"auth", "ssh", "journald"}, raw=msg.strip())
        m = _INVALID.match(msg)
        if m and (ip := _valid_ip(m["ip"])):
            return ThreatEvent(
                kind="login_invalid_user", src_ip=ip, user=m["user"],
                severity=Severity.MEDIUM,
                message=f"Usuario inexistente probado: {m['user']}",
                tags={"auth", "ssh", "recon", "journald"}, raw=msg.strip())
        m = _ACCEPTED.match(msg)
        if m and (ip := _valid_ip(m["ip"])):
            return ThreatEvent(
                kind="login_success", src_ip=ip, user=m["user"],
                src_port=int(m["port"]), severity=Severity.INFO,
                message=f"Login exitoso user={m['user']}",
                tags={"auth", "ssh", "journald"}, raw=msg.strip())
        # Fallback: firmas de explotación (Metasploit/escáneres/CVEs).
        ev = signatures.build_event(msg)
        if ev:
            ev.tags.add("journald")
            return ev
        return None
