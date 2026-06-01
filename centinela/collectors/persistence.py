"""Persistence: caza los mecanismos de persistencia típicos de un rootkit.

Tras entrar, el atacante quiere QUEDARSE. Los tres vectores clásicos en Linux:

  1. Un binario SUID/SGID nuevo o en un sitio raro (escala a root cuando quiera).
  2. Una tarea cron que descarga y ejecuta (curl|sh, reverse shell, base64).
  3. Una unidad systemd que relanza el implante en cada arranque.

Este colector los revisa periódicamente leyendo solo el disco (sin subprocess,
sin shell). Mantiene una BASELINE de los SUID/SGID vistos: la APARICIÓN de uno
nuevo es la señal fuerte. Además, cualquier SUID en /tmp·/home·/dev/shm o
world-writable, y cualquier cron/unit con patrón de backdoor, se marca siempre.

No tiene IP asociada (son hallazgos de host): salen como alertas de compromiso
local de severidad alta. Solo lectura; nunca modifica ni ejecuta nada. Para ver
todo el sistema necesita root (si no, ve lo que su usuario pueda leer).
"""
from __future__ import annotations

import asyncio
import os
import re
import stat
import time

from ..core import Severity, ThreatEvent
from .base import Collector

# Directorios legítimos de binarios SUID; uno NUEVO aquí también se reporta.
_BIN_DIRS = ("/usr/bin", "/bin", "/usr/sbin", "/sbin",
             "/usr/local/bin", "/usr/local/sbin")
# Un SUID aquí es intrínsecamente sospechoso (no deberían existir).
_BAD_SUID_DIRS = ("/tmp", "/var/tmp", "/dev/shm", "/home", "/run")

_CRON_PATHS = ("/etc/crontab",)
_CRON_DIRS = ("/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
              "/etc/cron.weekly", "/etc/cron.monthly",
              "/var/spool/cron", "/var/spool/cron/crontabs")
_UNIT_DIRS = ("/etc/systemd/system", "/run/systemd/system",
              "/usr/local/lib/systemd/system")

# Patrones de backdoor en cron/unit (descarga-ejecuta, reverse shell, ofuscación).
_BAD = re.compile(
    r"(curl|wget)\b[^\n|]*\|\s*(sh|bash)"      # curl ... | sh
    r"|/dev/tcp/"                               # bash reverse shell
    r"|\bnc(at)?\b[^\n]*\s-e"                   # nc -e
    r"|\bbash\b\s+-i"                           # bash -i
    r"|\bmkfifo\b"                              # fifo reverse shell
    r"|base64\s+-d|b64decode"                   # payload ofuscado
    r"|/tmp/|/dev/shm/|/var/tmp/",              # ejecuta desde dir efímero
    re.IGNORECASE)
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_MAX_FILES = 8000
_TTL = 600.0


def _clean(s: str, n: int = 200) -> str:
    return _CTRL.sub("", s)[:n]


class PersistenceCollector(Collector):
    name = "persistence"

    def __init__(self, bus, interval: float = 60.0) -> None:
        super().__init__(bus)
        self.interval = max(10.0, interval)
        self._suid_baseline: set[str] | None = None
        self._alerted: dict[str, float] = {}

    def available(self) -> bool:
        return os.name == "posix" and os.path.isdir("/etc")

    async def run(self) -> None:
        while True:
            try:
                events = await asyncio.to_thread(self._scan)
                for ev in events:
                    await self.emit(ev)
            except Exception:   # noqa: BLE001 — nunca tumbar el colector
                pass
            await asyncio.sleep(self.interval)

    def _scan(self) -> list[ThreatEvent]:
        now = time.time()
        if len(self._alerted) > 4096:
            self._alerted = {k: t for k, t in self._alerted.items()
                             if now - t < _TTL}
        out: list[ThreatEvent] = []
        out += self._scan_suid(now)
        out += self._scan_cron(now)
        out += self._scan_units(now)
        return out[:64]

    def _fire(self, now: float, key: str) -> bool:
        last = self._alerted.get(key)
        if last is not None and now - last < _TTL:
            return False
        self._alerted[key] = now
        return True

    # ---- 1) SUID/SGID ----

    def _iter_suid(self):
        seen = 0
        for d in (*_BIN_DIRS, *_BAD_SUID_DIRS):
            try:
                walk = os.walk(d) if d in _BAD_SUID_DIRS else [(d, [], os.listdir(d))]
            except OSError:
                continue
            for root, _dirs, files in walk:
                for fn in files:
                    seen += 1
                    if seen > _MAX_FILES:
                        return
                    p = os.path.join(root, fn)
                    try:
                        st = os.lstat(p)
                    except OSError:
                        continue
                    if not stat.S_ISREG(st.st_mode):
                        continue
                    if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                        yield p, st

    def _scan_suid(self, now: float) -> list[ThreatEvent]:
        current = {}
        for p, st in self._iter_suid():
            current[p] = st
        out: list[ThreatEvent] = []
        if self._suid_baseline is None:
            # Primer escaneo: fija baseline. Reporta solo los intrínsecamente malos.
            self._suid_baseline = set(current)
            for p, st in current.items():
                if self._suid_bad_location(p, st) and self._fire(now, "suid:" + p):
                    out.append(self._suid_event(p, st, nuevo=False))
            return out
        for p, st in current.items():
            new = p not in self._suid_baseline
            if (new or self._suid_bad_location(p, st)) and self._fire(now, "suid:" + p):
                out.append(self._suid_event(p, st, nuevo=new))
        self._suid_baseline |= set(current)
        return out

    @staticmethod
    def _suid_bad_location(p: str, st) -> bool:
        if any(p.startswith(d + "/") for d in _BAD_SUID_DIRS):
            return True
        if st.st_mode & stat.S_IWOTH:        # SUID y world-writable: crítico
            return True
        return os.path.basename(p).startswith(".")

    def _suid_event(self, p: str, st, nuevo: bool) -> ThreatEvent:
        kind_bits = "SUID" if st.st_mode & stat.S_ISUID else "SGID"
        why = "NUEVO" if nuevo else "ubicación sospechosa"
        sev = Severity.CRITICAL if (nuevo or st.st_mode & stat.S_IWOTH) else Severity.HIGH
        return ThreatEvent(
            kind="persistence_suid", severity=sev,
            message=f"Binario {kind_bits} {why}: {_clean(p, 180)} "
                    f"(uid_owner={st.st_uid}, mode={oct(st.st_mode & 0o7777)})",
            tags={"persistence", "privesc", "host"},
            enrichment={"path": _clean(p, 200), "suid": True,
                        "nuevo": nuevo, "owner_uid": st.st_uid})

    # ---- 2) cron ----

    def _scan_cron(self, now: float) -> list[ThreatEvent]:
        out: list[ThreatEvent] = []
        files: list[str] = [p for p in _CRON_PATHS if os.path.isfile(p)]
        for d in _CRON_DIRS:
            try:
                for fn in os.listdir(d):
                    fp = os.path.join(d, fn)
                    if os.path.isfile(fp):
                        files.append(fp)
            except OSError:
                continue
        for fp in files[:_MAX_FILES]:
            hit = self._grep_bad(fp)
            if hit and self._fire(now, "cron:" + fp):
                out.append(ThreatEvent(
                    kind="persistence_cron", severity=Severity.HIGH,
                    message=f"Cron sospechoso en {_clean(fp,140)}: {_clean(hit,120)}",
                    tags={"persistence", "cron", "host"},
                    enrichment={"path": _clean(fp, 200), "match": _clean(hit, 200)}))
        return out

    # ---- 3) systemd ----

    def _scan_units(self, now: float) -> list[ThreatEvent]:
        out: list[ThreatEvent] = []
        for d in _UNIT_DIRS:
            try:
                names = os.listdir(d)
            except OSError:
                continue
            for fn in names:
                if not fn.endswith((".service", ".timer")):
                    continue
                fp = os.path.join(d, fn)
                if not os.path.isfile(fp):
                    continue
                hit = self._grep_bad(fp, only=("ExecStart", "ExecStartPre"))
                if hit and self._fire(now, "unit:" + fp):
                    out.append(ThreatEvent(
                        kind="persistence_systemd", severity=Severity.HIGH,
                        message=f"Unidad systemd sospechosa {_clean(fn,80)}: "
                                f"{_clean(hit,120)}",
                        tags={"persistence", "systemd", "host"},
                        enrichment={"path": _clean(fp, 200), "match": _clean(hit, 200)}))
        return out

    # ---- util ----

    @staticmethod
    def _grep_bad(path: str, only: tuple[str, ...] | None = None) -> str | None:
        try:
            with open(path, "r", errors="replace") as f:
                for line in f:
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    if only and not any(s.startswith(k) for k in only):
                        continue
                    if _BAD.search(s):
                        return s
        except OSError:
            return None
        return None
