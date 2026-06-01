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
import hashlib
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

# Capa de integridad: binarios del sistema que un rootkit clásico troyaniza
# para ocultarse a sí mismo (ls/ps/netstat sin ver el implante, sshd con
# puerta trasera, etc.). Mantenemos baseline SHA-256 + tamaño + mtime: el
# cambio sin que el paquete se haya actualizado es la señal.
_INTEGRITY_BINS = (
    "/bin/ls", "/usr/bin/ls",
    "/bin/ps", "/usr/bin/ps",
    "/bin/netstat", "/usr/bin/netstat",
    "/bin/ss", "/usr/bin/ss",
    "/bin/find", "/usr/bin/find",
    "/bin/lsof", "/usr/bin/lsof",
    "/bin/who", "/usr/bin/who", "/usr/bin/w",
    "/bin/login", "/usr/bin/login",
    "/usr/bin/passwd", "/usr/bin/sudo", "/usr/bin/su",
    "/usr/sbin/sshd", "/usr/sbin/crond",
    "/bin/bash", "/usr/bin/bash", "/bin/sh",
    "/bin/cat", "/usr/bin/cat",
    "/bin/grep", "/usr/bin/grep",
    "/sbin/init", "/usr/sbin/init",
)
_INTEG_MAX_BYTES = 64 * 1024 * 1024   # nunca hasheamos más de 64 MB por archivo

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
        # Baseline de integridad: path -> (sha256, size, mtime). Se fija en el
        # primer escaneo: a partir de ahí, cualquier divergencia es alerta.
        self._integ_baseline: dict[str, tuple[str, int, float]] | None = None
        # Baseline de capacidades de fichero (xattr security.capability): un
        # binario con CAP_NET_RAW/CAP_SYS_ADMIN sin SUID es invisible al escáner
        # SUID clásico y permite escalada igual de letal. Vector usado por
        # rootkits modernos (ej. CAP_SYS_PTRACE para leer memoria de otros
        # procesos sin ser root).
        self._fcaps_baseline: set[str] | None = None

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
        out += self._scan_integrity(now)
        out += self._scan_fcaps(now)
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

    # ---- 10) integridad de binarios del sistema (anti-rootkit clásico) ----
    #
    # El rootkit que se respeta troyaniza ls/ps/netstat para no verse a sí mismo
    # y sshd para tener puerta trasera. Mantenemos una BASELINE (sha256 + tamaño
    # + mtime) de un puñado de binarios críticos; cualquier divergencia futura
    # es alerta. Si un binario APARECE donde antes no estaba (nuevo path
    # critico), también es señal — los rootkits a veces inyectan sus propios.

    def _scan_integrity(self, now: float) -> list[ThreatEvent]:
        current = self._integrity_snapshot()
        out: list[ThreatEvent] = []
        if self._integ_baseline is None:
            self._integ_baseline = current
            return out
        for path, (h, sz, mt) in current.items():
            old = self._integ_baseline.get(path)
            if old is None:
                # Binario NUEVO en una ruta crítica vigilada (raro).
                if self._fire(now, "integ-new:" + path):
                    out.append(ThreatEvent(
                        kind="persistence_integrity", severity=Severity.HIGH,
                        message=f"Binario crítico aparece donde no estaba: "
                                f"{_clean(path,140)} (sha256={h[:12]}…)",
                        tags={"persistence", "rootkit", "integrity", "host"},
                        enrichment={"path": _clean(path, 200), "sha256": h,
                                    "size": sz, "nuevo": True}))
                continue
            old_h, old_sz, old_mt = old
            if h != old_h:
                # Cambió el contenido. Diferencia de tamaño = inflación típica
                # de un troyano (libc o backdoor inyectado).
                grew = sz - old_sz
                detail = f"sha256 {old_h[:12]}…→{h[:12]}…, tamaño {old_sz}→{sz}"
                if abs(grew) > 1024:
                    detail += f" (Δ {grew:+d} bytes)"
                if self._fire(now, "integ:" + path):
                    out.append(ThreatEvent(
                        kind="persistence_integrity", severity=Severity.CRITICAL,
                        message=f"Binario del sistema MODIFICADO sin tu permiso: "
                                f"{_clean(path,140)} — {detail} — posible "
                                f"troyanización (rootkit)",
                        tags={"persistence", "rootkit", "integrity", "host"},
                        enrichment={"path": _clean(path, 200),
                                    "sha256_old": old_h, "sha256_new": h,
                                    "size_old": old_sz, "size_new": sz,
                                    "mtime_old": old_mt, "mtime_new": mt}))
                # Actualiza baseline para no alertar en bucle del mismo cambio.
                self._integ_baseline[path] = (h, sz, mt)
        # Binario DESAPARECIDO de una ruta crítica (rootkit que esconde su
        # presencia o atacante que reemplaza con symlink raro).
        for path in list(self._integ_baseline):
            if path not in current and self._fire(now, "integ-gone:" + path):
                out.append(ThreatEvent(
                    kind="persistence_integrity", severity=Severity.HIGH,
                    message=f"Binario crítico DESAPARECE: {_clean(path,140)} "
                            f"— sustituido/ocultado",
                    tags={"persistence", "rootkit", "integrity", "host"},
                    enrichment={"path": _clean(path, 200), "desaparecido": True}))
                # Lo quitamos del baseline para no spamear.
                self._integ_baseline.pop(path, None)
        return out

    def _integrity_snapshot(self) -> dict[str, tuple[str, int, float]]:
        snap: dict[str, tuple[str, int, float]] = {}
        for p in _INTEGRITY_BINS:
            try:
                st = os.lstat(p)
            except OSError:
                continue
            # Solo archivos regulares (no symlinks: el symlink en sí no se
            # troyaniza, lo importante es el binario al que apunta — pero
            # un cambio de symlink a un binario distinto SÍ cambia el hash).
            if not stat.S_ISREG(st.st_mode):
                # Intenta resolver: si el destino es regular y razonable, hashea.
                try:
                    real = os.path.realpath(p)
                    rst = os.stat(real)
                    if not stat.S_ISREG(rst.st_mode):
                        continue
                    st = rst
                    p_to_hash = real
                except OSError:
                    continue
            else:
                p_to_hash = p
            if st.st_size > _INTEG_MAX_BYTES:
                continue
            h = self._sha256(p_to_hash)
            if h is None:
                continue
            snap[p] = (h, st.st_size, st.st_mtime)
        return snap

    @staticmethod
    def _sha256(path: str) -> str | None:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.hexdigest()
        except OSError:
            return None

    # ---- capa 11: capacidades de fichero (xattr security.capability) ----

    def _scan_fcaps(self, now: float) -> list[ThreatEvent]:
        """Detecta binarios con file capabilities — escalada sin SUID.

        Un atacante puede dejar `python3` con CAP_NET_RAW+CAP_SYS_PTRACE: no
        aparece en `find -perm /4000`, pero abre sockets crudos y lee memoria
        de otros procesos como si fuera root. La baseline registra los que ya
        tienen capacidades al primer escaneo; cualquier NUEVO es alerta.
        """
        if not hasattr(os, "getxattr"):
            return []
        current = self._fcaps_snapshot()
        out: list[ThreatEvent] = []
        if self._fcaps_baseline is None:
            self._fcaps_baseline = current
            return out
        for path in current - self._fcaps_baseline:
            in_bad = any(path.startswith(d + "/") for d in _BAD_SUID_DIRS)
            sev = Severity.CRITICAL if in_bad else Severity.HIGH
            tag = "fcap-bad:" if in_bad else "fcap-new:"
            if self._fire(now, tag + path):
                msg = (f"Capacidad de fichero NUEVA en {_clean(path)} "
                       f"(escalada sin SUID — posible rootkit)")
                out.append(ThreatEvent(
                    kind="persistence_fcaps", severity=sev,
                    message=msg,
                    tags={"persistence", "privesc", "host", "fcaps"},
                    enrichment={"path": _clean(path, 200), "fcaps": True}))
                self._fcaps_baseline.add(path)
        return out

    def _fcaps_snapshot(self) -> set[str]:
        found: set[str] = set()
        scan_dirs = _BIN_DIRS + _BAD_SUID_DIRS
        for d in scan_dirs:
            try:
                for name in os.listdir(d):
                    p = os.path.join(d, name)
                    try:
                        if not os.path.isfile(p):
                            continue
                        # getxattr lanza OSError si no existe el atributo
                        os.getxattr(p, "security.capability")
                        found.add(p)
                    except OSError:
                        continue
                    if len(found) > _MAX_FILES:
                        return found
            except OSError:
                continue
        return found

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
