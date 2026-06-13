"""HijackWatch: caza vectores de hijacking en host Linux.

Cubre lo que execwatch/rootcheck no ven directamente: inyección de librería
(LD_PRELOAD), tracing/process hijacking (ptrace), secuestro de PATH y la
defensa propia de CENTINEL (alguien intentando adjuntarse al pid de centinel).

Vectores detectados:

  - **LD_PRELOAD** en entorno de un proceso vivo, apuntando a un directorio
    efímero (/tmp, /dev/shm, /home/*) o world-writable. Patrón clásico de
    rootkit en user-space para hookear libc (getpwnam, accept, etc.).
  - **PATH hijack**: PATH del proceso antepone un directorio efímero o
    world-writable a /usr/bin — el siguiente exec resuelve al binario del
    atacante. Combina mal con sudo NOPASSWD.
  - **ptrace activo**: TracerPid != 0 en /proc/<pid>/status. Vector de
    inyección de código (CVE-2024-…), credential dump y session hijack.
  - **Self-defense**: si alguien adjunta un tracer al propio CENTINEL, lo
    reporta como CRITICAL antes de morir.

Funciona por POLLING de /proc, sin subprocess, sin shell, solo lectura.
La clasificación es pura (testeable sin /proc real).
"""
from __future__ import annotations

import asyncio
import os
import stat
import time

from ..core import Severity, ThreatEvent
from .base import Collector

_EPHEMERAL = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/run/user/")
_SAFE_PRELOAD = ("/usr/lib/", "/lib/", "/lib64/", "/usr/lib64/", "/usr/local/lib/")
_TRUSTED_TRACERS = ("gdb", "strace", "ltrace", "lldb", "rr")  # sesiones legítimas

_ALERT_TTL = 300.0          # no repetir el mismo (pid, kind) en este tiempo
_MAX_EVENTS_PER_SCAN = 32


def _parse_environ(blob: bytes) -> dict[str, str]:
    """Parsea /proc/<pid>/environ (NUL-separated KEY=VALUE)."""
    out: dict[str, str] = {}
    for chunk in blob.split(b"\x00"):
        if not chunk or b"=" not in chunk:
            continue
        k, _, v = chunk.partition(b"=")
        try:
            out[k.decode("utf-8", "replace")] = v.decode("utf-8", "replace")
        except Exception:
            pass
    return out


def classify_preload(value: str, *, world_writable: bool = False) -> tuple[bool, str]:
    """¿LD_PRELOAD sospechoso?  → (es_amenaza, razón)."""
    if not value or not value.strip():
        return False, ""
    # Acepta múltiples paths separados por espacio o ':'.
    parts = [p for p in value.replace(":", " ").split() if p]
    for p in parts:
        # Anclajes sospechosos primero — el atacante usa directorios efímeros.
        if any(p.startswith(d) for d in _EPHEMERAL):
            return True, f"LD_PRELOAD desde directorio efímero: {p}"
        if p.startswith("/home/"):
            return True, f"LD_PRELOAD desde $HOME: {p}"
        if world_writable:
            return True, f"LD_PRELOAD apunta a fichero world-writable: {p}"
        # No marcamos /usr/lib/* — son extensiones legítimas (libnss, etc.).
        if not any(p.startswith(d) for d in _SAFE_PRELOAD) and p.startswith("/"):
            return True, f"LD_PRELOAD fuera de rutas confiables: {p}"
    return False, ""


def classify_path(value: str) -> tuple[bool, str]:
    """¿PATH antepone un directorio peligroso a /usr/bin?"""
    if not value:
        return False, ""
    parts = value.split(":")
    seen_safe = False
    for p in parts:
        # Si ya hemos visto /usr/bin o /bin, el resto importa menos.
        if p in ("/usr/bin", "/bin", "/usr/sbin", "/sbin"):
            seen_safe = True
            continue
        if seen_safe:
            continue
        # Antes que /usr/bin: cualquier dir efímero o $HOME es hijack candidato.
        if any(p.startswith(d) or p == d.rstrip("/") for d in _EPHEMERAL):
            return True, f"PATH antepone efímero a /usr/bin: {p}"
        if p.startswith("/home/") or p == ".":
            return True, f"PATH antepone $HOME/CWD a /usr/bin: {p}"
    return False, ""


def is_world_writable(path: str) -> bool:
    try:
        return bool(os.stat(path).st_mode & stat.S_IWOTH)
    except OSError:
        return False


def _read_status(pid: int) -> dict[str, str]:
    try:
        with open(f"/proc/{pid}/status", "r", errors="replace") as f:
            return dict(line.split(":", 1) for line in f if ":" in line)
    except OSError:
        return {}


def _tracer_name(tracer_pid: int) -> str:
    if tracer_pid <= 0:
        return ""
    try:
        with open(f"/proc/{tracer_pid}/comm", "r") as f:
            return f.read().strip()
    except OSError:
        return f"pid={tracer_pid}"


class HijackWatch(Collector):
    name = "hijackwatch"

    def __init__(self, bus, interval: float = 3.0, self_pid: int | None = None) -> None:
        super().__init__(bus)
        self.interval = max(1.0, float(interval))
        self.self_pid = self_pid or os.getpid()
        self._seen: dict[tuple[int, str], float] = {}

    def available(self) -> bool:
        return os.path.isdir("/proc")

    async def run(self) -> None:
        while True:
            try:
                await asyncio.to_thread(self._scan_and_emit_sync)
            except Exception:  # noqa: BLE001
                pass
            await asyncio.sleep(self.interval)

    def _scan_and_emit_sync(self) -> None:
        # Se ejecuta en un thread para no bloquear el loop con I/O de /proc.
        loop = asyncio.get_event_loop()
        pending: list[ThreatEvent] = []
        now = time.time()
        try:
            pids = [int(d) for d in os.listdir("/proc") if d.isdigit()]
        except OSError:
            return
        for pid in pids[:_MAX_EVENTS_PER_SCAN * 50]:
            for ev in self._scan_pid(pid, now):
                pending.append(ev)
                if len(pending) >= _MAX_EVENTS_PER_SCAN:
                    break
            if len(pending) >= _MAX_EVENTS_PER_SCAN:
                break
        # Purga TTL.
        self._seen = {k: t for k, t in self._seen.items() if now - t < _ALERT_TTL}
        for ev in pending:
            asyncio.run_coroutine_threadsafe(self.emit(ev), loop)

    def _scan_pid(self, pid: int, now: float) -> list[ThreatEvent]:
        out: list[ThreatEvent] = []

        # 1) Self-defense: ¿alguien rastrea al propio CENTINEL?
        if pid == self.self_pid:
            st = _read_status(pid)
            try:
                tracer = int(st.get("TracerPid", "0").strip())
            except ValueError:
                tracer = 0
            if tracer > 0 and self._fresh((pid, "self_traced"), now):
                tname = _tracer_name(tracer)
                if tname not in _TRUSTED_TRACERS:
                    out.append(ThreatEvent(
                        kind="hijack_self_traced", severity=Severity.CRITICAL,
                        message=f"ptrace adjuntado al propio centinel por '{tname}' (pid {tracer})",
                        tags={"hijack", "self_defense", "T1055"}))

        # 2) ptrace activo sobre otro proceso (excluye trazadores confiables
        #    como gdb/strace; alerta el resto).
        st = _read_status(pid)
        if st:
            try:
                tracer = int(st.get("TracerPid", "0").strip())
            except ValueError:
                tracer = 0
            if tracer > 0:
                tname = _tracer_name(tracer)
                if tname and tname not in _TRUSTED_TRACERS \
                   and self._fresh((pid, "traced"), now):
                    target = (st.get("Name", "?").strip())
                    out.append(ThreatEvent(
                        kind="hijack_ptrace", severity=Severity.HIGH,
                        message=f"ptrace activo: '{tname}' rastrea '{target}' (pid {pid})",
                        tags={"hijack", "ptrace", "T1055.008"}))

        # 3) LD_PRELOAD / PATH hijack en environ.
        try:
            with open(f"/proc/{pid}/environ", "rb") as f:
                env = _parse_environ(f.read())
        except OSError:
            return out
        preload = env.get("LD_PRELOAD", "")
        if preload:
            # Comprueba world-writable solo del primer path (cheap).
            first = preload.split()[0].split(":")[0] if preload.strip() else ""
            ww = is_world_writable(first) if first.startswith("/") else False
            bad, why = classify_preload(preload, world_writable=ww)
            if bad and self._fresh((pid, "preload"), now):
                out.append(ThreatEvent(
                    kind="hijack_preload", severity=Severity.CRITICAL,
                    message=f"{why} (pid {pid})",
                    tags={"hijack", "ld_preload", "T1574.006"}))

        path = env.get("PATH", "")
        bad, why = classify_path(path)
        if bad and self._fresh((pid, "path"), now):
            out.append(ThreatEvent(
                kind="hijack_path", severity=Severity.HIGH,
                message=f"{why} (pid {pid})",
                tags={"hijack", "path", "T1574.007"}))

        return out

    def _fresh(self, key: tuple[int, str], now: float) -> bool:
        if now - self._seen.get(key, 0.0) < _ALERT_TTL:
            return False
        self._seen[key] = now
        return True
