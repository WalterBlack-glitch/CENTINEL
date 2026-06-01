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
              "/var/spool/cron", "/var/spool/cron/crontabs",
              "/var/spool/at", "/var/spool/cron/atjobs")
_UNIT_DIRS = ("/etc/systemd/system", "/run/systemd/system",
              "/usr/local/lib/systemd/system")

# Capa LD_PRELOAD: en un sistema sano /etc/ld.so.preload casi nunca existe;
# cualquier línea es un rootkit candidato (hooking de libc para ocultarse).
_PRELOAD_FILES = ("/etc/ld.so.preload",)

# Capa "ejecutado al iniciar sesión / arranque": perfiles de shell, rc, motd,
# udev. Se revisan por patrones de backdoor (mismos que cron/unit).
_INIT_FILES = ("/etc/profile", "/etc/bash.bashrc", "/etc/zsh/zshrc",
               "/etc/rc.local", "/etc/rc.d/rc.local")
_INIT_DIRS = ("/etc/profile.d", "/etc/update-motd.d", "/etc/init.d",
              "/etc/udev/rules.d", "/lib/udev/rules.d",
              "/etc/modprobe.d", "/etc/modules-load.d")
# Dotfiles de shell por usuario (relativos al home).
_DOTFILES = (".bashrc", ".bash_profile", ".profile", ".bash_login",
             ".zshrc", ".zprofile", ".bash_aliases", ".xprofile")
_SUDOERS = ("/etc/sudoers",)
_SUDOERS_DIRS = ("/etc/sudoers.d",)

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
        # Capas (cebolla): cada una vigila un vector de persistencia distinto.
        out += self._scan_suid(now)
        out += self._scan_cron(now)
        out += self._scan_units(now)
        out += self._scan_preload(now)
        out += self._scan_init(now)
        out += self._scan_dotfiles(now)
        out += self._scan_accounts(now)
        out += self._scan_sudoers(now)
        out += self._scan_authkeys(now)
        return out[:64]

    @staticmethod
    def _home_dirs() -> list[str]:
        homes = ["/root"]
        try:
            for u in sorted(os.listdir("/home"))[:200]:
                d = os.path.join("/home", u)
                if os.path.isdir(d):
                    homes.append(d)
        except OSError:
            pass
        return homes

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

    # ---- 4) LD_PRELOAD (rootkit que hookea libc para ocultarse) ----

    def _scan_preload(self, now: float) -> list[ThreatEvent]:
        out: list[ThreatEvent] = []
        for fp in _PRELOAD_FILES:
            if not os.path.isfile(fp):
                continue
            try:
                with open(fp, "r", errors="replace") as f:
                    libs = [ln.strip() for ln in f
                            if ln.strip() and not ln.strip().startswith("#")]
            except OSError:
                continue
            if libs and self._fire(now, "preload:" + fp):
                out.append(ThreatEvent(
                    kind="persistence_ld_preload", severity=Severity.CRITICAL,
                    message=f"{fp} carga librerías globalmente (LD_PRELOAD): "
                            f"{_clean(' '.join(libs), 160)} — rootkit candidato",
                    tags={"persistence", "rootkit", "host"},
                    enrichment={"path": fp, "libs": [_clean(x, 120) for x in libs[:8]]}))
        return out

    # ---- 5) inicio: perfiles de shell, rc, motd, udev, modprobe ----

    def _scan_init(self, now: float) -> list[ThreatEvent]:
        out: list[ThreatEvent] = []
        files = [p for p in _INIT_FILES if os.path.isfile(p)]
        for d in _INIT_DIRS:
            try:
                for fn in os.listdir(d):
                    fp = os.path.join(d, fn)
                    if os.path.isfile(fp):
                        files.append(fp)
            except OSError:
                continue
        for fp in files[:_MAX_FILES]:
            hit = self._grep_bad(fp)
            if hit and self._fire(now, "init:" + fp):
                out.append(ThreatEvent(
                    kind="persistence_init", severity=Severity.HIGH,
                    message=f"Script de inicio sospechoso en {_clean(fp,140)}: "
                            f"{_clean(hit,120)}",
                    tags={"persistence", "autostart", "host"},
                    enrichment={"path": _clean(fp, 200), "match": _clean(hit, 200)}))
        return out

    # ---- 6) dotfiles de shell por usuario (~/.bashrc, ~/.profile...) ----

    def _scan_dotfiles(self, now: float) -> list[ThreatEvent]:
        out: list[ThreatEvent] = []
        for home in self._home_dirs():
            for name in _DOTFILES:
                fp = os.path.join(home, name)
                if not os.path.isfile(fp):
                    continue
                hit = self._grep_bad(fp)
                if hit and self._fire(now, "dot:" + fp):
                    out.append(ThreatEvent(
                        kind="persistence_profile", severity=Severity.HIGH,
                        message=f"Perfil de shell con backdoor {_clean(fp,140)}: "
                                f"{_clean(hit,120)}",
                        tags={"persistence", "shellrc", "host"},
                        enrichment={"path": _clean(fp, 200), "match": _clean(hit, 200)}))
        return out

    # ---- 7) cuentas: UID 0 fantasma y contraseñas vacías ----

    def _scan_accounts(self, now: float) -> list[ThreatEvent]:
        out: list[ThreatEvent] = []
        try:
            with open("/etc/passwd", "r", errors="replace") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) < 7:
                        continue
                    user, uid = parts[0], parts[2]
                    if uid == "0" and user != "root" and self._fire(now, "uid0:" + user):
                        out.append(ThreatEvent(
                            kind="persistence_account", severity=Severity.CRITICAL,
                            message=f"Cuenta con UID 0 (root) además de root: "
                                    f"'{_clean(user,64)}' — puerta trasera de privilegio",
                            tags={"persistence", "account", "host"},
                            enrichment={"user": _clean(user, 64), "uid": 0}))
        except OSError:
            pass
        # Shadow: contraseñas vacías (login sin clave). Requiere root para leerlo.
        try:
            with open("/etc/shadow", "r", errors="replace") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) < 2:
                        continue
                    user, pw = parts[0], parts[1]
                    if pw == "" and self._fire(now, "nopass:" + user):
                        out.append(ThreatEvent(
                            kind="persistence_account", severity=Severity.HIGH,
                            message=f"Cuenta '{_clean(user,64)}' sin contraseña "
                                    f"(login directo)",
                            tags={"persistence", "account", "host"},
                            enrichment={"user": _clean(user, 64), "empty_password": True}))
        except OSError:
            pass
        return out

    # ---- 8) sudoers: NOPASSWD: ALL (escalada silenciosa) ----

    def _scan_sudoers(self, now: float) -> list[ThreatEvent]:
        out: list[ThreatEvent] = []
        files = [p for p in _SUDOERS if os.path.isfile(p)]
        for d in _SUDOERS_DIRS:
            try:
                for fn in os.listdir(d):
                    fp = os.path.join(d, fn)
                    if os.path.isfile(fp):
                        files.append(fp)
            except OSError:
                continue
        nopass = re.compile(r"NOPASSWD\s*:\s*ALL", re.IGNORECASE)
        for fp in files[:_MAX_FILES]:
            try:
                with open(fp, "r", errors="replace") as f:
                    for line in f:
                        s = line.strip()
                        if s and not s.startswith("#") and nopass.search(s) \
                                and self._fire(now, "sudo:" + fp + ":" + s[:40]):
                            out.append(ThreatEvent(
                                kind="persistence_sudoers", severity=Severity.MEDIUM,
                                message=f"sudoers permite NOPASSWD:ALL en "
                                        f"{_clean(fp,120)}: {_clean(s,100)}",
                                tags={"persistence", "privesc", "host"},
                                enrichment={"path": _clean(fp, 200), "rule": _clean(s, 200)}))
            except OSError:
                continue
        return out

    # ---- 9) authorized_keys: claves SSH y forced-commands backdoor ----

    def _scan_authkeys(self, now: float) -> list[ThreatEvent]:
        out: list[ThreatEvent] = []
        for home in self._home_dirs():
            for name in ("authorized_keys", "authorized_keys2"):
                fp = os.path.join(home, ".ssh", name)
                if not os.path.isfile(fp):
                    continue
                # Fichero world-writable = cualquiera añade su clave.
                try:
                    if os.stat(fp).st_mode & stat.S_IWOTH and self._fire(now, "akw:" + fp):
                        out.append(ThreatEvent(
                            kind="persistence_authkeys", severity=Severity.HIGH,
                            message=f"authorized_keys world-writable: {_clean(fp,140)}",
                            tags={"persistence", "ssh", "host"},
                            enrichment={"path": _clean(fp, 200), "world_writable": True}))
                except OSError:
                    pass
                hit = self._grep_bad(fp)   # forced-command con curl|sh, /dev/tcp...
                if hit and self._fire(now, "ak:" + fp):
                    out.append(ThreatEvent(
                        kind="persistence_authkeys", severity=Severity.HIGH,
                        message=f"authorized_keys con forced-command sospechoso "
                                f"{_clean(fp,120)}: {_clean(hit,100)}",
                        tags={"persistence", "ssh", "host"},
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
