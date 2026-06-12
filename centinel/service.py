"""Instalación como servicio systemd con arranque primario y hardening.

Objetivos:
  - Arrancar ANTES de multi-user.target: ningún autostart de usuario (capa 19)
    ni proceso huérfano (capa 20) puede correr sin que CENTINEL haya
    baselineado el sistema primero.
  - Single-instance: lock en /run/centinel.pid con fcntl.flock. Si ya hay otra
    instancia corriendo, la segunda sale con código 0 y un aviso (evita
    overlaps que duplican alertas y corrompen baselines).
  - Hardening: si comprometen CENTINEL, que no puedan escalar. NoNewPrivileges,
    ProtectSystem=strict, ProtectHome=read-only, SystemCallArchitectures=native,
    RestrictSUIDSGID, LockPersonality, MemoryDenyWriteExecute.

Capabilities REALES que necesitamos sostener (no se sueltan):
  CAP_NET_ADMIN  -> nft/iptables (respond-live)
  CAP_NET_RAW    -> scapy / sniffer
  CAP_SYS_PTRACE -> /proc/<pid>/exe de procesos ajenos (capa 20)
  CAP_DAC_READ_SEARCH -> leer /etc/shadow, /proc/<pid>/* sin ser root

El resto se ELIMINA con CapabilityBoundingSet (incluso si root, no las tiene).
"""
from __future__ import annotations

import os
import sys


SERVICE_PATH = "/etc/systemd/system/centinel.service"
PID_PATH = "/run/centinel.pid"


def _python_exe() -> str:
    return os.path.realpath(sys.executable)


def _unit_text(args_line: str, early: bool = False) -> str:
    py = _python_exe()
    if early:
        # Early-boot: nivel sysinit. CENTINEL arranca ANTES que cualquier
        # servicio normal (todos ordenan After=basic.target): un malware
        # persistido como unidad systemd no llega a ejecutarse sin que el
        # baseline ya esté vigilando. Con DefaultDependencies=no hay que
        # declarar a mano las dependencias mínimas (journald + /var montado)
        # y el apagado limpio (Conflicts/Before shutdown.target).
        ordering = """After=local-fs.target systemd-journald.socket systemd-sysctl.service
Before=basic.target
DefaultDependencies=no
Conflicts=shutdown.target
Before=shutdown.target"""
        wanted_by = "sysinit.target"
        header = ("# Arranque EARLY-BOOT (--early-boot): antes que todos los "
                  "servicios normales.")
    else:
        ordering = """After=local-fs.target sysinit.target network-pre.target
Before=multi-user.target
DefaultDependencies=yes"""
        wanted_by = "multi-user.target"
        header = ("# Arranque primario: antes de multi-user.target (antes de "
                  "sesiones de usuario).")
    return f"""# Generado por: python -m centinel --install-service
{header}
[Unit]
Description=CENTINEL - rastreo multicapa de amenazas
Documentation=https://github.com/WalterBlack-glitch/CENTINEL
{ordering}
ConditionPathIsDirectory=/proc

[Service]
Type=simple
ExecStart={py} -m centinel {args_line}
Restart=on-failure
RestartSec=5
TimeoutStopSec=10
KillSignal=SIGINT

# Single-instance: si alguien lanza otra, sale solo.
# (El lock real lo hace el codigo Python en /run/centinel.pid.)
RuntimeDirectory=centinel
RuntimeDirectoryMode=0700

# Hardening: minimizar superficie si comprometen el proceso.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
PrivateTmp=false
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET

# Permitir leer/escribir solo lo necesario (baselines, BD, runtime dir).
ReadWritePaths=/var/lib/centinel /run/centinel
StateDirectory=centinel
StateDirectoryMode=0700

# Capabilities: el proceso conserva SOLO las que pide.
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_PTRACE CAP_DAC_READ_SEARCH

[Install]
WantedBy={wanted_by}
"""


def install(args_line: str = "--rootcheck --netwatch --web "
                              "--baseline-dir /var/lib/centinel/baselines "
                              "--db /var/lib/centinel/centinel.db",
            early: bool = False) -> int:
    if os.name != "posix" or not os.path.isdir("/etc/systemd/system"):
        print("[centinel] systemd no detectado (¿no es Linux con systemd?).")
        return 1
    if os.geteuid() != 0:
        print("[centinel] --install-service requiere root.")
        return 1
    unit = _unit_text(args_line, early=early)
    tmp = SERVICE_PATH + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    with os.fdopen(fd, "w") as f:
        f.write(unit)
    os.replace(tmp, SERVICE_PATH)
    print(f"[centinel] unidad escrita en {SERVICE_PATH}")
    # daemon-reload + enable + start
    rc = os.system("systemctl daemon-reload")
    rc |= os.system("systemctl enable centinel.service")
    rc |= os.system("systemctl restart centinel.service")
    if rc == 0:
        print("[centinel] servicio activo. Estado: systemctl status centinel")
    else:
        print(f"[centinel] systemctl devolvió código {rc}; revisa el estado.")
    return 0 if rc == 0 else 1


def uninstall() -> int:
    if os.geteuid() != 0:
        print("[centinel] --uninstall-service requiere root.")
        return 1
    os.system("systemctl stop centinel.service")
    os.system("systemctl disable centinel.service")
    try:
        os.unlink(SERVICE_PATH)
    except OSError:
        pass
    os.system("systemctl daemon-reload")
    print("[centinel] servicio desinstalado.")
    return 0


def status() -> int:
    return os.system("systemctl status centinel.service --no-pager")


# ---- single-instance lock ----

class SingleInstance:
    """Mantiene un lock exclusivo en /run/centinel.pid (o ~/.cache si no hay
    /run escribible). Si otro proceso ya lo tiene, acquire() devuelve False."""

    def __init__(self, path: str = PID_PATH) -> None:
        self.path = path if os.access(os.path.dirname(path) or "/", os.W_OK) \
            else os.path.join(os.path.expanduser("~"), ".cache", "centinel.pid")
        self._fd: int | None = None

    def acquire(self) -> tuple[bool, str]:
        try:
            os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
        except OSError:
            pass
        try:
            self._fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        except OSError as exc:
            return False, f"no pude abrir {self.path}: {exc}"
        try:
            import fcntl
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except ImportError:
            return True, "sin fcntl (no-Linux); lock simbólico"
        except OSError:
            # Hay otra instancia. Leemos su PID para el mensaje.
            try:
                with open(self.path) as f:
                    other = f.read().strip()
            except OSError:
                other = "?"
            os.close(self._fd)
            self._fd = None
            return False, f"otra instancia ya está corriendo (PID {other})"
        # Escribimos nuestro PID.
        os.ftruncate(self._fd, 0)
        os.write(self._fd, str(os.getpid()).encode())
        return True, "ok"

    def release(self) -> None:
        if self._fd is None:
            return
        try:
            import fcntl
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        except Exception:   # noqa: BLE001
            pass
        try:
            os.close(self._fd)
        except OSError:
            pass
        try:
            os.unlink(self.path)
        except OSError:
            pass
        self._fd = None
