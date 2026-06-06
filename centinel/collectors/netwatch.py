"""NetWatch: correlaciona procesos/archivos locales con sus conexiones externas.

La idea (defensa contra compromiso de root): un backdoor, web-shell o malware
de C2 deja una huella inevitable — un PROCESO con un ARCHIVO en disco que
mantiene una CONEXIÓN saliente a una IP. Este colector empareja, leyendo solo
`/proc` (sin subprocess, sin shell):

    conexión externa  <->  inode  <->  pid  <->  binario en disco

y marca como malicioso el proceso cuyo binario es sospechoso (borrado, en
/tmp//dev/shm, world-writable, oculto, o un listener 0.0.0.0 atípico). El evento
sale con la IP remota como `src_ip`, así pasa por geo/rDNS/KEV y la correlación:
el C2 del backdoor queda geolocalizado y puntuado como un actor más.

Privilegios: como root ve TODOS los procesos; tras soltar privilegios solo ve
los del usuario destino. Para cobertura total de un posible root comprometido,
ejecútalo como root (o con CAP_SYS_PTRACE). Degrada con elegancia: alerta de lo
que puede ver, nunca revienta.

Solo lectura. No abre sockets, no ejecuta binarios, no hace red. Sin dependencias.
"""
from __future__ import annotations

import asyncio
import os
import re
import time

from ..core import Severity, ThreatEvent
from .base import Collector
# Parsing de /proc/net compartido con beacon (sin duplicar lógica).
from ._proc_net import parse_hex_addr as _parse_addr, is_external_ip as _is_external

# Estado TCP ESTABLISHED en /proc/net/tcp (hex)
_ESTABLISHED = "01"

# Directorios desde los que un binario en ejecución es de por sí sospechoso.
_SUSPECT_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/", "/run/shm/")
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_MAX_PIDS = 20000          # cota de barrido de /proc
_MAX_CONNS = 4096          # cota de conexiones procesadas por escaneo
_ALERT_TTL = 300.0         # no repetir la misma (pid,ip) en este tiempo


def _clean(s: str, limit: int = 256) -> str:
    return _CTRL.sub("", s)[:limit]


class NetWatchCollector(Collector):
    name = "netwatch"

    def __init__(self, bus, interval: float = 10.0) -> None:
        super().__init__(bus)
        self.interval = max(2.0, interval)
        self._alerted: dict[tuple[int, str], float] = {}

    def available(self) -> bool:
        return os.name == "posix" and os.path.isdir("/proc/net") \
            and os.path.exists("/proc/net/tcp")

    async def run(self) -> None:
        while True:
            try:
                events = await asyncio.to_thread(self._scan_blocking)
                for ev in events:
                    await self.emit(ev)
            except Exception:   # noqa: BLE001 — nunca tumbar el colector
                pass
            await asyncio.sleep(self.interval)

    # ---- el escaneo (I/O de /proc) corre en hilo y DEVUELVE eventos ----

    def _scan_blocking(self) -> list[ThreatEvent]:
        now = time.time()
        self._gc(now)
        inode_pid = self._inode_to_pid()
        events: list[ThreatEvent] = []
        for ip, lport, rport, inode in self._connections():
            if len(events) >= 64:
                break
            pid = inode_pid.get(inode)
            if pid is None:
                continue
            info = self._proc_info(pid)
            if info is None:
                continue
            flags = self._suspect_flags(info)
            if not flags:
                continue
            key = (pid, ip)
            last = self._alerted.get(key)
            if last is not None and now - last < _ALERT_TTL:
                continue
            self._alerted[key] = now
            events.append(ThreatEvent(
                kind="malicious_process", src_ip=ip,
                src_port=rport, dst_port=lport, severity=Severity.HIGH,
                message=(f"Proceso sospechoso '{_clean(info['comm'],64)}' "
                         f"(pid {pid}, {_clean(info['exe'],120)}) con conexión "
                         f"externa a {ip} — {', '.join(flags)}"),
                tags={"proc", "backdoor", "l7"},
                enrichment={"pid": pid, "exe": _clean(info["exe"], 200),
                            "cmdline": _clean(info["cmdline"], 200),
                            "comm": _clean(info["comm"], 64),
                            "proc_flags": list(flags),
                            "lport": lport, "rport": rport}))
        return events

    def _gc(self, now: float) -> None:
        if len(self._alerted) > 4096:
            self._alerted = {k: t for k, t in self._alerted.items()
                             if now - t < _ALERT_TTL}

    # ---- lectura de /proc ----

    def _connections(self):
        """Genera (rip, lport, rport, inode) de conexiones ESTABLISHED externas."""
        count = 0
        for path in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                with open(path) as f:
                    next(f, None)   # cabecera
                    for line in f:
                        if count >= _MAX_CONNS:
                            return
                        parts = line.split()
                        if len(parts) < 10 or parts[3] != _ESTABLISHED:
                            continue
                        rem = _parse_addr(parts[2])
                        loc = _parse_addr(parts[1])
                        if not rem or not loc:
                            continue
                        rip, rport = rem
                        lip, lport = loc
                        if not _is_external(rip):
                            continue
                        try:
                            inode = int(parts[9])
                        except ValueError:
                            continue
                        count += 1
                        yield (rip, lport, rport, inode)
            except OSError:
                continue

    def _inode_to_pid(self) -> dict[int, int]:
        """Mapa inode_socket -> pid leyendo /proc/<pid>/fd/*."""
        out: dict[int, int] = {}
        seen = 0
        for name in os.listdir("/proc"):
            if not name.isdigit():
                continue
            seen += 1
            if seen > _MAX_PIDS:
                break
            pid = int(name)
            fddir = f"/proc/{pid}/fd"
            try:
                fds = os.listdir(fddir)
            except OSError:
                continue   # sin permiso (otro usuario) o el proceso murió
            for fd in fds:
                try:
                    target = os.readlink(f"{fddir}/{fd}")
                except OSError:
                    continue
                if target.startswith("socket:["):
                    try:
                        out[int(target[8:-1])] = pid
                    except ValueError:
                        continue
        return out

    def _proc_info(self, pid: int) -> dict | None:
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            exe = ""   # sin permiso o kernel thread
        try:
            with open(f"/proc/{pid}/comm") as f:
                comm = f.read().strip()
        except OSError:
            comm = ""
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmdline = f.read().replace(b"\x00", b" ").decode(
                    "utf-8", "replace").strip()
        except OSError:
            cmdline = ""
        return {"exe": exe, "comm": comm, "cmdline": cmdline}

    def _suspect_flags(self, info: dict) -> list[str]:
        flags: list[str] = []
        exe = info["exe"]
        if exe.endswith("(deleted)"):
            flags.append("binario borrado en disco")
        real = exe.replace(" (deleted)", "")
        if any(real.startswith(d) for d in _SUSPECT_DIRS):
            flags.append("binario en directorio efímero")
        base = os.path.basename(real)
        if (base.startswith(".") and base) or info["comm"].startswith("."):
            flags.append("binario/nombre oculto")
        # world-writable: cualquiera podría haberlo sustituido
        try:
            if real and os.stat(real).st_mode & 0o002:
                flags.append("binario world-writable")
        except OSError:
            pass
        # Backdoors como SCRIPT (exe=intérprete legítimo): mira el cmdline en
        # busca de un fichero ejecutado desde un directorio efímero u oculto.
        for tok in info["cmdline"].split():
            if any(tok.startswith(d) for d in _SUSPECT_DIRS):
                flags.append("script en directorio efímero")
                break
            tb = os.path.basename(tok)
            if tb.startswith(".") and ("/" in tok or tok.startswith(".")) \
                    and len(tb) > 1:
                flags.append("script oculto")
                break
        return flags
