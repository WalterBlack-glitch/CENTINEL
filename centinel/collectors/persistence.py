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

# Ficheros críticos de autenticación cuyo hash NUNCA cambia entre `passwd`/`useradd`
# legítimos sin que lo sepamos. La modificación silenciosa es señal fuerte.
_AUTH_FILES = ("/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
               "/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf",
               "/etc/pam.conf")
_PAM_DIRS = ("/etc/pam.d",)
# Módulos PAM legítimos típicos; si aparece uno fuera de esta lista en un stack
# crítico (system-auth, common-auth, sshd, login, sudo) es backdoor candidato.
_PAM_CRIT_STACKS = ("system-auth", "common-auth", "common-account",
                    "common-password", "common-session", "sshd",
                    "login", "sudo", "su")
# Patrón: línea PAM que carga un .so fuera de las rutas estándar.
_PAM_BAD_SO = re.compile(
    r"\s(auth|account|password|session)\s.*?\s"
    r"(?!pam_[a-z0-9_]+\.so\b)"                         # no es pam_xxx.so estándar
    r"(/[^\s]+\.so\b|[A-Za-z0-9_./-]+\.so\b)")
_PROC_MAX_PID = 4194304   # PID_MAX_LIMIT en kernels modernos; clamp más abajo

# Patrones de backdoor en cron/unit (descarga-ejecuta, reverse shell, ofuscación).
_BAD = re.compile(
    r"(curl|wget)\b[^\n|]*\|\s*(sh|bash)"      # curl ... | sh
    r"|/dev/tcp/"                               # bash reverse shell
    r"|\bnc(at)?\b[^\n]*\s-e"                   # nc -e
    r"|\bbash\b\s+-i"                           # bash -i
    r"|\bmkfifo\b"                              # fifo reverse shell
    r"|base64\s+-d|b64decode"                   # payload ofuscado
    # Ejecución desde dir efímero: el path va precedido de ejecución (.,sh,bash,
    # exec, sourcing) o seguido de cmdline. Evita falsos positivos cuando es
    # solo un valor de variable (DIR="/tmp/$1" en x11-common).
    r"|(?:^|[\s;|&`$(])(?:\.|sh|bash|source|exec|/bin/sh|/bin/bash)\s+"
    r"(?:/tmp/|/dev/shm/|/var/tmp/)\S+"
    r"|=(?:/tmp/|/dev/shm/|/var/tmp/)\S+"    # systemd ExecStart=/tmp/...
    r"|^(?:/tmp/|/dev/shm/|/var/tmp/)\S+",   # cron: linea empieza con /tmp/...
    re.IGNORECASE)
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_MAX_FILES = 8000
_TTL = 600.0


def _clean(s: str, n: int = 200) -> str:
    return _CTRL.sub("", s)[:n]


class PersistenceCollector(Collector):
    name = "persistence"

    def __init__(self, bus, interval: float = 60.0,
                 store_dir: str | None = None,
                 maintenance=None) -> None:
        super().__init__(bus)
        self.interval = max(10.0, interval)
        self._alerted: dict[str, float] = {}
        # Contexto de mantenimiento: silencia alertas durante apt/dpkg, git pull
        # de Centinel, o el periodo de gracia inicial. Si no se pasa, todas
        # las alertas pasan tal cual (modo paranoico).
        if maintenance is None:
            from ..maintenance import MaintenanceContext
            maintenance = MaintenanceContext()
        self._maint = maintenance
        # Buffer para coalescer ráfagas: si llegan >20 eventos del mismo kind
        # en 60s, se agrupan en uno solo "ráfaga: 23 cambios — probablemente
        # mantenimiento".
        self._burst: dict[str, list[float]] = {}
        # Baselines persistentes y firmadas (HMAC): sobreviven a reinicios y
        # detectan manipulación. Si store_dir es None, se queda solo en RAM.
        self._store = None
        if store_dir:
            try:
                from ..baseline_store import BaselineStore
                self._store = BaselineStore(store_dir)
            except Exception:   # noqa: BLE001
                self._store = None
        self._suid_baseline: set[str] | None = self._bload("suid", as_set=True)
        # Baseline de integridad: path -> (sha256, size, mtime). Se fija en el
        # primer escaneo: a partir de ahí, cualquier divergencia es alerta.
        self._integ_baseline: dict[str, tuple[str, int, float]] | None = None
        # Baseline de capacidades de fichero (xattr security.capability): un
        # binario con CAP_NET_RAW/CAP_SYS_ADMIN sin SUID es invisible al escáner
        # SUID clásico y permite escalada igual de letal. Vector usado por
        # rootkits modernos (ej. CAP_SYS_PTRACE para leer memoria de otros
        # procesos sin ser root).
        self._fcaps_baseline: set[str] | None = None
        # Baselines de las capas 12-18 (nuevas):
        self._kmod_baseline: set[str] | None = None        # /proc/modules
        self._auth_baseline: dict[str, str] | None = None  # /etc/passwd ... -> sha256
        self._pam_baseline: dict[str, str] | None = None   # /etc/pam.d/* -> sha256
        self._bpf_baseline: set[str] | None = None         # /sys/fs/bpf pinned
        # Estado para detectar PIDs ocultos (rootkit que hookea getdents).
        # Si en un escaneo /proc dice "no existe" pero kill(pid,0) dice ESRCH=False
        # (existe), hay PID escondido. Solo lo intentamos como root.
        self._hidden_pid_alerted: set[int] = set()
        self._self_baseline: dict[str, str] | None = self._bload("selfhash")
        # Recupera el resto de baselines firmadas (si existen)
        _ib = self._bload("integrity")
        self._integ_baseline = ({k: tuple(v) for k, v in _ib.items()}
                                if isinstance(_ib, dict) else None)
        self._fcaps_baseline = self._bload("fcaps", as_set=True)
        self._kmod_baseline = self._bload("kmod", as_set=True)
        self._auth_baseline = self._bload("authfiles")
        self._pam_baseline = self._bload("pam")
        self._bpf_baseline = self._bload("bpf", as_set=True)
        # Capas 19-20: autostart (XDG .desktop + systemd user) y huérfanos.
        self._auto_baseline: dict[str, str] | None = self._bload("autostart")
        self._orphan_alerted: set[str] = set()

    def _bload(self, name: str, as_set: bool = False):
        if not self._store:
            return None
        data = self._store.load(name)
        if data is None:
            return None
        return set(data) if as_set else data

    def _bsave(self, name: str, value) -> None:
        if self._store and value is not None:
            try:
                self._store.save(name, value)
            except Exception:   # noqa: BLE001
                pass

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
        # BUGFIX: si estamos en el grace period, NO escaneamos. Si scaneáramos
        # y luego filtráramos por "gracia", la baseline se actualizaría con los
        # cambios reales y nunca volveríamos a alertar de ellos (el SUID nuevo
        # entraría como legítimo en el primer ciclo). Mejor: esperar.
        if self._maint and self._maint.in_grace_period():
            return []
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
        out += self._scan_kmods(now)        # capa 12: módulos del kernel
        out += self._scan_authfiles(now)    # capa 13: /etc/passwd/shadow/hosts...
        out += self._scan_pam(now)          # capa 14: stack PAM
        out += self._scan_immutable(now)    # capa 15: chattr +i sellando líneas
        out += self._scan_hidden_pids(now)  # capa 16: PIDs ocultos por rootkit
        out += self._scan_bpf(now)          # capa 17: eBPF pinneado
        out += self._scan_self(now)         # capa 18: integridad del propio Centinel
        out += self._scan_autostart(now)    # capa 19: autostart GUI/usuario
        out += self._scan_orphans(now)      # capa 20: procesos PPID=1 sospechosos
        # Persiste baselines firmadas tras este escaneo (best-effort).
        self._bsave("suid", self._suid_baseline)
        self._bsave("integrity", self._integ_baseline)
        self._bsave("fcaps", self._fcaps_baseline)
        self._bsave("kmod", self._kmod_baseline)
        self._bsave("authfiles", self._auth_baseline)
        self._bsave("pam", self._pam_baseline)
        self._bsave("bpf", self._bpf_baseline)
        self._bsave("selfhash", self._self_baseline)
        self._bsave("autostart", self._auto_baseline)
        # Filtro de mantenimiento: degrada/descarta alertas legítimas.
        out = self._filter_maintenance(out, now)
        return out[:128]

    def _filter_maintenance(self, events: list[ThreatEvent],
                            now: float) -> list[ThreatEvent]:
        """Descarta o degrada eventos que coincidan con mantenimiento
        legítimo (dpkg/apt, git pull de Centinel, periodo de gracia).
        Además coalesce ráfagas del mismo kind: >20 en 60s se reducen a uno."""
        kept: list[ThreatEvent] = []
        for ev in events:
            path = (ev.enrichment or {}).get("path") if hasattr(ev, "enrichment") \
                else None
            legit, why = self._maint.is_legitimate(ev.kind, path)
            if legit:
                # Silencia: solo log discreto, no se publica al bus.
                # (Si quieres verlo, sube el verbose; hoy lo descartamos.)
                continue
            kept.append(ev)
        # Coalescing por kind: ráfaga = mantenimiento no clasificado.
        bucket: dict[str, list[ThreatEvent]] = {}
        for ev in kept:
            bucket.setdefault(ev.kind, []).append(ev)
        final: list[ThreatEvent] = []
        for kind, evs in bucket.items():
            if len(evs) > 20:
                # Demasiados a la vez = casi seguro mantenimiento masivo.
                sample = ", ".join(_clean((e.enrichment or {}).get("path") or
                                          e.message, 40)
                                   for e in evs[:3])
                final.append(ThreatEvent(
                    kind=kind, severity=Severity.MEDIUM,
                    message=f"Ráfaga de {len(evs)} cambios {kind} "
                            f"(probable mantenimiento): {sample}…",
                    tags={"persistence", "burst", "maintenance"},
                    enrichment={"count": len(evs)}))
            else:
                final.extend(evs)
        return final

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

    # ---- capa 12: módulos del kernel (LKM rootkit clásico) ----

    def _scan_kmods(self, now: float) -> list[ThreatEvent]:
        """Un LKM nuevo entre escaneos = rootkit candidato. /proc/modules es
        legible por cualquier UID. Si /proc/modules no existe (BSD, contenedor
        sin /proc montado), la capa se autodesactiva."""
        try:
            with open("/proc/modules") as f:
                mods = {ln.split()[0] for ln in f if ln.strip()}
        except OSError:
            return []
        if self._kmod_baseline is None:
            self._kmod_baseline = mods
            return []
        out: list[ThreatEvent] = []
        for m in mods - self._kmod_baseline:
            if self._fire(now, "kmod:" + m):
                out.append(ThreatEvent(
                    kind="persistence_kmod", severity=Severity.CRITICAL,
                    message=f"Módulo de kernel NUEVO cargado: {_clean(m, 80)} "
                            f"(LKM rootkit candidato)",
                    tags={"persistence", "kernel", "rootkit"},
                    enrichment={"module": _clean(m, 80)}))
        self._kmod_baseline = mods
        return out

    # ---- capa 13: integridad de ficheros de autenticación / resolución ----

    def _scan_authfiles(self, now: float) -> list[ThreatEvent]:
        """Hashea /etc/passwd, shadow, group, hosts, resolv.conf, nsswitch.
        Una modificación silenciosa de cualquiera de estos = compromiso."""
        cur: dict[str, str] = {}
        for p in _AUTH_FILES:
            h = self._sha256(p)
            if h:
                cur[p] = h
        if self._auth_baseline is None:
            self._auth_baseline = cur
            return []
        out: list[ThreatEvent] = []
        for p, h in cur.items():
            old = self._auth_baseline.get(p)
            if old and old != h and self._fire(now, "auth:" + p):
                out.append(ThreatEvent(
                    kind="persistence_authfile", severity=Severity.CRITICAL,
                    message=f"Fichero crítico MODIFICADO: {p} "
                            f"(sha256 {old[:10]}…→{h[:10]}…)",
                    tags={"persistence", "authfile", "host"},
                    enrichment={"path": p, "old": old, "new": h}))
        self._auth_baseline = cur
        return out

    # ---- capa 14: stack PAM (backdoor de login universal) ----

    def _scan_pam(self, now: float) -> list[ThreatEvent]:
        out: list[ThreatEvent] = []
        cur: dict[str, str] = {}
        for d in _PAM_DIRS:
            try:
                names = os.listdir(d)
            except OSError:
                continue
            for name in names:
                p = os.path.join(d, name)
                h = self._sha256(p)
                if not h:
                    continue
                cur[p] = h
                # Patrón sospechoso: línea PAM cargando un .so fuera de rutas
                # estándar (rootkit dropea su .so en /lib/security/.evil.so).
                if name in _PAM_CRIT_STACKS or any(name.startswith(s)
                                                   for s in _PAM_CRIT_STACKS):
                    try:
                        with open(p, errors="replace") as f:
                            for ln in f:
                                s = ln.strip()
                                if not s or s.startswith("#"):
                                    continue
                                m = _PAM_BAD_SO.search(s)
                                if m and ("/tmp/" in s or "/dev/shm" in s
                                          or "/var/tmp" in s):
                                    if self._fire(now, "pam-bad:" + p):
                                        out.append(ThreatEvent(
                                            kind="persistence_pam",
                                            severity=Severity.CRITICAL,
                                            message=f"PAM con módulo sospechoso "
                                                    f"en {p}: {_clean(s, 120)}",
                                            tags={"persistence", "pam", "auth"},
                                            enrichment={"path": p,
                                                        "line": _clean(s, 200)}))
                                    break
                    except OSError:
                        pass
        if self._pam_baseline is None:
            self._pam_baseline = cur
            return out
        for p, h in cur.items():
            old = self._pam_baseline.get(p)
            if old is None and self._fire(now, "pam-new:" + p):
                out.append(ThreatEvent(
                    kind="persistence_pam", severity=Severity.HIGH,
                    message=f"Stack PAM NUEVO: {p}",
                    tags={"persistence", "pam"}, enrichment={"path": p}))
            elif old and old != h and self._fire(now, "pam-mod:" + p):
                out.append(ThreatEvent(
                    kind="persistence_pam", severity=Severity.CRITICAL,
                    message=f"Stack PAM MODIFICADO: {p}",
                    tags={"persistence", "pam"}, enrichment={"path": p}))
        self._pam_baseline = cur
        return out

    # ---- capa 15: atributo immutable (chattr +i) en ficheros críticos ----

    def _scan_immutable(self, now: float) -> list[ThreatEvent]:
        """Un rootkit sella /etc/passwd con +i para que su línea UID 0
        sobreviva al limpiado. En un sistema sano, ninguno de estos ficheros
        debería tener el flag immutable."""
        if not hasattr(os, "open") or os.name != "posix":
            return []
        try:
            import fcntl, array
        except ImportError:
            return []
        FS_IOC_GETFLAGS = 0x80086601
        FS_IMMUTABLE_FL = 0x00000010
        out: list[ThreatEvent] = []
        for p in _AUTH_FILES:
            try:
                fd = os.open(p, os.O_RDONLY | os.O_NONBLOCK)
            except OSError:
                continue
            try:
                arg = array.array("L", [0])
                fcntl.ioctl(fd, FS_IOC_GETFLAGS, arg, True)
                if arg[0] & FS_IMMUTABLE_FL and self._fire(now, "immut:" + p):
                    out.append(ThreatEvent(
                        kind="persistence_immutable", severity=Severity.CRITICAL,
                        message=f"{p} tiene flag +i (immutable): rootkit "
                                f"sellando persistencia.",
                        tags={"persistence", "rootkit", "host"},
                        enrichment={"path": p}))
            except OSError:
                pass
            finally:
                os.close(fd)
        return out

    # ---- capa 16: PIDs ocultos (rootkit que hookea getdents) ----

    def _scan_hidden_pids(self, now: float) -> list[ThreatEvent]:
        """Cross-check: si kill(pid, 0) dice que el PID existe pero /proc/<pid>
        no aparece, posible rootkit. CUIDADO con falsos positivos:
          - Kernel threads bajo WSL/contenedores a veces no se listan en /proc.
          - TOCTOU: procesos cortos que mueren entre listdir y kill.
          - Sólo alerta si: PID >= 1000 (descarta kthreads), confirmamos en DOS
            escaneos consecutivos, y /proc/<pid> falla incluso al stat directo.
        """
        if not hasattr(os, "kill") or os.name != "posix":
            return []
        try:
            visible = {int(n) for n in os.listdir("/proc") if n.isdigit()}
        except OSError:
            return []
        if not visible:
            return []
        max_pid = max(visible)
        upper = min(max_pid + 1024, 65536)
        suspects: set[int] = set()
        for pid in range(1000, upper):     # < 1000: kthreads y servicios del sistema
            if pid in visible:
                continue
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                continue
            except PermissionError:
                pass
            except OSError:
                continue
            # Doble-check: ¿realmente no hay /proc/<pid>?
            if os.path.exists(f"/proc/{pid}"):
                continue
            suspects.add(pid)
        # Necesita dos pasadas para alertar (descarta procesos efímeros que
        # nacieron y murieron entre listdir y kill).
        prev = getattr(self, "_hidden_pid_prev", set())
        confirmed = suspects & prev
        self._hidden_pid_prev = suspects
        out: list[ThreatEvent] = []
        for pid in sorted(confirmed)[:8]:
            if pid in self._hidden_pid_alerted:
                continue
            self._hidden_pid_alerted.add(pid)
            out.append(ThreatEvent(
                kind="persistence_hidden_pid", severity=Severity.CRITICAL,
                message=f"PID {pid} existe (kill(0) ok) pero /proc/{pid} no "
                        f"aparece en DOS escaneos: rootkit ocultando procesos.",
                tags={"persistence", "rootkit", "kernel"},
                enrichment={"pid": pid}))
        return out

    # ---- capa 17: programas eBPF pinneados (rootkit moderno) ----

    def _scan_bpf(self, now: float) -> list[ThreatEvent]:
        """Lista objetos eBPF pinneados en /sys/fs/bpf/. Los rootkits
        modernos cargan BPF en vez de LKM (mejor camuflaje, no levanta
        verificación de firmas)."""
        found: set[str] = set()
        for root, _, files in os.walk("/sys/fs/bpf", topdown=True):
            for f in files:
                found.add(os.path.join(root, f))
            if len(found) > 256:
                break
        if self._bpf_baseline is None:
            self._bpf_baseline = found
            return []
        out: list[ThreatEvent] = []
        for p in found - self._bpf_baseline:
            if self._fire(now, "bpf:" + p):
                out.append(ThreatEvent(
                    kind="persistence_bpf", severity=Severity.HIGH,
                    message=f"Objeto eBPF NUEVO pinneado: {_clean(p, 120)} "
                            f"(rootkit eBPF candidato)",
                    tags={"persistence", "ebpf", "kernel"},
                    enrichment={"path": _clean(p, 200)}))
        self._bpf_baseline = found
        return out

    # ---- capa 18: auto-integridad del propio Centinel ----

    def _scan_self(self, now: float) -> list[ThreatEvent]:
        """Si modifican un fichero del propio paquete, dejaríamos de alertar
        en silencio. Se hashea el árbol del paquete al primer escaneo y se
        compara después."""
        import centinel
        root = os.path.dirname(os.path.abspath(centinel.__file__))
        cur: dict[str, str] = {}
        for r, _, files in os.walk(root):
            for f in files:
                if not f.endswith(".py"):
                    continue
                p = os.path.join(r, f)
                h = self._sha256(p)
                if h:
                    cur[p] = h
            if len(cur) > 512:
                break
        if not hasattr(self, "_self_baseline") or self._self_baseline is None:
            self._self_baseline = cur
            return []
        out: list[ThreatEvent] = []
        for p, h in cur.items():
            old = self._self_baseline.get(p)
            if old and old != h and self._fire(now, "self:" + p):
                out.append(ThreatEvent(
                    kind="persistence_selftamper", severity=Severity.CRITICAL,
                    message=f"Fichero de Centinel MODIFICADO en caliente: {p}",
                    tags={"persistence", "self", "tamper"},
                    enrichment={"path": p, "old": old, "new": h}))
        self._self_baseline = cur
        return out

    # ---- capa 19: autostart GUI/usuario (.desktop + systemd --user) ----

    _AUTOSTART_DIRS = ("/etc/xdg/autostart",)
    _USER_AUTO_REL = (".config/autostart", ".config/systemd/user",
                       ".local/share/systemd/user")

    def _scan_autostart(self, now: float) -> list[ThreatEvent]:
        """Detecta autostart de escritorio y servicios de usuario nuevos o
        modificados. Vector típico: 'cmd que se inicia y no sé de qué es'.
        Marca como CRITICAL si el Exec/ExecStart apunta a /tmp /dev/shm o a
        un binario borrado; HIGH si solo es nuevo en una ruta legítima."""
        cur: dict[str, str] = {}
        out: list[ThreatEvent] = []
        dirs = list(self._AUTOSTART_DIRS)
        for h in self._home_dirs():
            for r in self._USER_AUTO_REL:
                dirs.append(os.path.join(h, r))
        for d in dirs:
            try:
                names = os.listdir(d)
            except OSError:
                continue
            for name in names:
                p = os.path.join(d, name)
                if not p.endswith((".desktop", ".service", ".timer")):
                    continue
                h = self._sha256(p)
                if not h:
                    continue
                cur[p] = h
                # Patrón ofensivo en el contenido: Exec=/tmp/..., curl|sh, etc.
                hit = self._grep_bad(p, only=("Exec=", "ExecStart="))
                if hit and self._fire(now, "auto-bad:" + p):
                    out.append(ThreatEvent(
                        kind="persistence_autostart", severity=Severity.CRITICAL,
                        message=f"Autostart sospechoso: {p} -> {_clean(hit, 140)}",
                        tags={"persistence", "autostart"},
                        enrichment={"path": p, "line": _clean(hit, 200)}))
        if self._auto_baseline is None:
            self._auto_baseline = cur
            return out
        for p, h in cur.items():
            old = self._auto_baseline.get(p)
            if old is None and self._fire(now, "auto-new:" + p):
                out.append(ThreatEvent(
                    kind="persistence_autostart", severity=Severity.HIGH,
                    message=f"Autostart NUEVO: {p}",
                    tags={"persistence", "autostart"},
                    enrichment={"path": p}))
            elif old and old != h and self._fire(now, "auto-mod:" + p):
                out.append(ThreatEvent(
                    kind="persistence_autostart", severity=Severity.HIGH,
                    message=f"Autostart MODIFICADO: {p}",
                    tags={"persistence", "autostart"},
                    enrichment={"path": p}))
        self._auto_baseline = cur
        return out

    # ---- capa 20: procesos huérfanos sospechosos (PPID=1) ----

    _SAFE_EXE_PREFIXES = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/",
                           "/opt/", "/snap/", "/var/lib/snapd/")

    def _scan_orphans(self, now: float) -> list[ThreatEvent]:
        """Procesos con PPID=1 (re-parentados a init/systemd) cuyo binario
        vive en /tmp, /dev/shm, /var/tmp, en home oculto (.cache/.local/bin),
        o cuyo /proc/<pid>/exe apunta a un fichero borrado (' (deleted)').
        Es la firma típica del 'cmd raro que se inició solo y no sé de qué es'."""
        out: list[ThreatEvent] = []
        try:
            pids = [int(n) for n in os.listdir("/proc") if n.isdigit()]
        except OSError:
            return out
        per_exe: dict[str, list[int]] = {}
        for pid in pids:
            try:
                with open(f"/proc/{pid}/status") as f:
                    text = f.read()
            except OSError:
                continue
            ppid = 0
            for ln in text.splitlines():
                if ln.startswith("PPid:"):
                    try:
                        ppid = int(ln.split()[1])
                    except (ValueError, IndexError):
                        pass
                    break
            if ppid != 1:
                continue
            try:
                exe = os.readlink(f"/proc/{pid}/exe")
            except OSError:
                continue
            per_exe.setdefault(exe.split(" (deleted)")[0], []).append(pid)
            bad = (exe.endswith(" (deleted)")
                   or exe.startswith(("/tmp/", "/dev/shm/", "/var/tmp/"))
                   or "/.cache/" in exe
                   or not any(exe.startswith(p) for p in self._SAFE_EXE_PREFIXES))
            if not bad:
                continue
            key = f"orphan:{exe}:{pid}"
            if key in self._orphan_alerted:
                continue
            self._orphan_alerted.add(key)
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    cmdline = f.read().replace(b"\x00", b" ").decode(
                        errors="replace").strip()
            except OSError:
                cmdline = ""
            out.append(ThreatEvent(
                kind="persistence_orphan", severity=Severity.CRITICAL,
                message=f"Proceso huérfano (PPID=1) sospechoso PID {pid}: "
                        f"exe={_clean(exe, 120)} cmd={_clean(cmdline, 120)}",
                tags={"persistence", "orphan", "host"},
                enrichment={"pid": pid, "exe": _clean(exe, 200),
                            "cmdline": _clean(cmdline, 200)}))
            if len(out) >= 8:
                break
        # Múltiples instancias del mismo binario huérfano (>3) = anómalo.
        for exe, pids_e in per_exe.items():
            if len(pids_e) >= 4 and self._fire(now, "multi:" + exe):
                out.append(ThreatEvent(
                    kind="persistence_orphan", severity=Severity.HIGH,
                    message=f"{len(pids_e)} instancias huérfanas del mismo "
                            f"binario: {_clean(exe, 120)} (PIDs {pids_e[:5]})",
                    tags={"persistence", "orphan", "multi"},
                    enrichment={"exe": _clean(exe, 200), "count": len(pids_e)}))
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
