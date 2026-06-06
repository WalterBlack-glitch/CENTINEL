"""ExecWatch: caza ejecuciones sospechosas vigilando la aparición de procesos.

Complementa a netwatch (que empareja proceso↔conexión) detectando el ACTO de
ejecución en sí — antes incluso de que abra una conexión, o cuando no la abre.
Es la red contra los ataques "fileless" / LOLBins más comunes en una intrusión
de Linux:

  - reverse shells         (bash -i >& /dev/tcp/…, nc -e, mkfifo|sh, python pty…)
  - descarga-y-ejecución   (curl|sh, wget|bash, base64 -d|sh)
  - exec desde efímeros    (/tmp, /dev/shm, binario borrado, nombre oculto)
  - servicio que abre shell (sshd/nginx/postgres → bash: huella clásica de RCE)

Funciona por POLLING de /proc (sin subprocess, sin shell, sin dependencias):
en cada barrido detecta los PIDs nuevos y clasifica su exe/cmdline/padre. La
lógica de clasificación (`classify`) es PURA y se testea sin /proc.

Limitación honesta: el polling puede perder un proceso ultra-efímero que nazca
y muera entre dos barridos. Las shells interactivas y la mayoría de droppers
persisten lo suficiente; para captura total de TODO exec, parea con auditd
(execve). El intervalo bajo (1-2s) reduce la ventana ciega.

Privilegios: como root ve TODOS los procesos; tras soltar privilegios solo los
del usuario destino. Solo lectura. Degrada con elegancia.
"""
from __future__ import annotations

import asyncio
import os
import re
import time

from ..core import Severity, ThreatEvent
from .base import Collector

_SUSPECT_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/")
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_MAX_PIDS = 20000
_ALERT_TTL = 600.0          # no repetir el mismo patrón en este tiempo
_MAX_EVENTS_PER_SCAN = 32

# Intérpretes que, lanzados de cierta forma, son una shell.
_SHELLS = ("sh", "bash", "dash", "zsh", "ash", "ksh", "csh", "tcsh")
_INTERPRETERS = _SHELLS + ("python", "python2", "python3", "perl", "ruby",
                           "php", "lua", "node")
# Demonios de red: si uno de estos es el PADRE de una shell, huele a RCE/webshell.
_NET_DAEMONS = ("sshd", "nginx", "apache2", "httpd", "lighttpd", "php-fpm",
                "postgres", "mysqld", "mariadbd", "redis-server", "memcached",
                "vsftpd", "proftpd", "smbd", "tomcat", "java")


def _clean(s: str, limit: int = 256) -> str:
    return _CTRL.sub("", s)[:limit]


def _basename(path: str) -> str:
    return os.path.basename(path.replace(" (deleted)", ""))


def _looks_like_shell(comm: str, exe: str) -> bool:
    base = _basename(exe) or comm
    return base in _SHELLS or comm in _SHELLS


def classify(info: dict, parent_comm: str = "") -> tuple[list[str], int]:
    """Clasifica un proceso. Devuelve (flags, severidad_int).

    `info` = {exe, comm, cmdline}. Lógica pura, sin I/O, testeable a mano.
    """
    exe = info.get("exe", "") or ""
    comm = info.get("comm", "") or ""
    # Acota el cmdline: los patrones de ataque viven al principio y así un
    # cmdline patológicamente largo no encarece el matching (defensa anti-DoS).
    cmd = (info.get("cmdline", "") or "")[:4096]
    low = cmd.lower()
    flags: list[str] = []
    sev = 0

    def bump(flag: str, level: int) -> None:
        nonlocal sev
        flags.append(flag)
        sev = max(sev, level)

    # --- reverse shells (CRÍTICO) ---
    real = exe.replace(" (deleted)", "")
    if "/dev/tcp/" in low or "/dev/udp/" in low:
        bump("redirección a /dev/tcp (reverse shell)", int(Severity.CRITICAL))
    if re.search(r"\b(n?cat|nc|ncat)\b.*\s-e\b", low) or " -e /bin/" in low:
        bump("netcat con -e (reverse shell)", int(Severity.CRITICAL))
    if "mkfifo" in low and any(s in low for s in ("|sh", "| sh", "|bash",
                                                  "| bash", "nc ", "ncat ")):
        bump("mkfifo + shell/netcat (reverse shell)", int(Severity.CRITICAL))
    if ("pty.spawn" in low or ("import socket" in low and "dup2" in low)
            or ("socket(" in low and "dup2" in low)):
        bump("socket+dup2/pty.spawn (reverse shell en intérprete)",
             int(Severity.CRITICAL))
    if "socat" in low and "exec" in low:
        bump("socat EXEC (reverse shell)", int(Severity.CRITICAL))
    if re.search(r"\b(ba)?sh\b\s+-i\b", low) and (">&" in low or "0>&1" in low
                                                  or "/dev/tcp/" in low):
        bump("shell interactiva redirigida (reverse shell)",
             int(Severity.CRITICAL))

    # --- descarga y ejecución (ALTO) ---
    pipes_to_shell = any(p in low for p in ("|sh", "| sh", "|bash", "| bash",
                                            "| python", "|python"))
    if any(d in low for d in ("curl ", "wget ", "curl;", "wget;")) and \
            pipes_to_shell:
        bump("descarga curl/wget tuberizada a shell", int(Severity.HIGH))
    if ("base64" in low and ("-d" in low or "--decode" in low)
            and pipes_to_shell):
        bump("base64 -d tuberizado a shell (ofuscación)", int(Severity.HIGH))
    if pipes_to_shell and any(b in low for b in ("base64", "xxd", "openssl enc")):
        bump("payload decodificado y ejecutado", int(Severity.HIGH))

    # --- servicio de red que lanza una shell (CRÍTICO: posible RCE) ---
    pcomm = (parent_comm or "").lower()
    if pcomm and _looks_like_shell(comm, exe):
        if any(pcomm == d or pcomm.startswith(d) for d in _NET_DAEMONS):
            bump(f"shell lanzada por demonio de red '{parent_comm}' "
                 f"(posible RCE/webshell)", int(Severity.CRITICAL))

    # --- exec desde directorio efímero / binario borrado / oculto (ALTO) ---
    if exe.endswith("(deleted)"):
        bump("binario borrado en disco", int(Severity.HIGH))
    if any(real.startswith(d) for d in _SUSPECT_DIRS):
        bump("exec desde directorio efímero", int(Severity.HIGH))
    base = _basename(exe)
    if (base.startswith(".") and len(base) > 1) or \
            (comm.startswith(".") and len(comm) > 1):
        bump("binario/nombre oculto", int(Severity.HIGH))
    # script desde efímero/oculto aunque el intérprete sea legítimo
    if base in _INTERPRETERS or comm in _INTERPRETERS:
        for tok in cmd.split():
            tb = _basename(tok)
            if any(tok.startswith(d) for d in _SUSPECT_DIRS):
                bump("script desde directorio efímero", int(Severity.HIGH))
                break
            if tb.startswith(".") and len(tb) > 1 and ("/" in tok
                                                       or tok.startswith(".")):
                bump("script oculto", int(Severity.HIGH))
                break

    return flags, sev


class ExecWatchCollector(Collector):
    name = "execwatch"

    def __init__(self, bus, interval: float = 2.0) -> None:
        super().__init__(bus)
        self.interval = max(1.0, interval)
        self._seen_pids: set[int] = set()
        self._alerted: dict[str, float] = {}
        self._primed = False

    def available(self) -> bool:
        return os.name == "posix" and os.path.isdir("/proc")

    async def run(self) -> None:
        if not self.available():
            return
        while True:
            try:
                events = await asyncio.to_thread(self._scan_blocking)
                for ev in events:
                    await self.emit(ev)
            except Exception:   # noqa: BLE001 — nunca tumbar el colector
                pass
            await asyncio.sleep(self.interval)

    # ---- escaneo (I/O de /proc) en hilo; DEVUELVE eventos ----

    def _scan_blocking(self) -> list[ThreatEvent]:
        now = time.time()
        self._gc(now)
        current = self._list_pids()
        new = current - self._seen_pids
        self._seen_pids = current
        # Primer barrido: solo cimienta el conjunto base, no alertamos de los
        # procesos preexistentes (no son "nuevos" para nosotros).
        if not self._primed:
            self._primed = True
            return []
        events: list[ThreatEvent] = []
        for pid in new:
            if len(events) >= _MAX_EVENTS_PER_SCAN:
                break
            info = self._read_proc(pid)
            if info is None:
                continue
            parent_comm = self._comm_of(info.get("ppid"))
            flags, sev = classify(info, parent_comm)
            if not flags:
                continue
            key = f"{info['exe']}\x1f{info['cmdline']}"[:512]
            last = self._alerted.get(key)
            if last is not None and now - last < _ALERT_TTL:
                continue
            self._alerted[key] = now
            events.append(self._event(pid, info, parent_comm, flags, sev))
        return events

    def _event(self, pid: int, info: dict, parent_comm: str,
               flags: list[str], sev: int) -> ThreatEvent:
        return ThreatEvent(
            kind="exec_suspicious", severity=Severity(sev),
            message=(f"Ejecución sospechosa: '{_clean(info['comm'], 64)}' "
                     f"(pid {pid}, padre '{_clean(parent_comm, 40)}') — "
                     f"{'; '.join(flags)}"),
            tags={"exec", "proc", "l7"},
            enrichment={"pid": pid, "ppid": info.get("ppid"),
                        "exe": _clean(info["exe"], 200),
                        "cmdline": _clean(info["cmdline"], 300),
                        "comm": _clean(info["comm"], 64),
                        "parent_comm": _clean(parent_comm, 64),
                        "exec_flags": list(flags)})

    # ---- lectura de /proc ----

    def _list_pids(self) -> set[int]:
        out: set[int] = set()
        try:
            names = os.listdir("/proc")
        except OSError:
            return out
        for i, name in enumerate(names):
            if i > _MAX_PIDS:
                break
            if name.isdigit():
                out.add(int(name))
        return out

    def _read_proc(self, pid: int) -> dict | None:
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
        ppid = self._ppid(pid)
        if not exe and not comm and not cmdline:
            return None
        return {"exe": exe, "comm": comm, "cmdline": cmdline, "ppid": ppid}

    def _ppid(self, pid: int) -> int | None:
        """PPID desde /proc/<pid>/stat. comm va entre paréntesis y puede tener
        espacios/paréntesis: se parsea desde el ÚLTIMO ')' para no romperse."""
        try:
            with open(f"/proc/{pid}/stat") as f:
                data = f.read()
        except OSError:
            return None
        rparen = data.rfind(")")
        if rparen == -1:
            return None
        rest = data[rparen + 2:].split()
        # rest[0] = state, rest[1] = ppid
        try:
            return int(rest[1])
        except (IndexError, ValueError):
            return None

    def _comm_of(self, pid: int | None) -> str:
        if not pid:
            return ""
        try:
            with open(f"/proc/{pid}/comm") as f:
                return f.read().strip()
        except OSError:
            return ""

    def _gc(self, now: float) -> None:
        if len(self._alerted) > 4096:
            self._alerted = {k: t for k, t in self._alerted.items()
                             if now - t < _ALERT_TTL}
