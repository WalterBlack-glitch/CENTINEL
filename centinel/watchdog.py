"""Watchdog: revive CENTINEL si un atacante lo mata, deshabilita o enmascara.

El servicio principal ya lleva `Restart=on-failure`, que cubre un SIGKILL
(crash) — pero NO cubre a un atacante con root que hace:

  - `systemctl stop centinel`     → parada "limpia", no dispara Restart.
  - `systemctl disable centinel`  → sobrevive al reinicio? no: no arranca.
  - `systemctl mask centinel`     → deja el servicio muerto e inarrancable.

El watchdog es un **servicio hermano** (`centinel-watchdog.service`) con
`Restart=always` que, cada pocos segundos, comprueba el estado del principal
y lo re-arma: desenmascara, re-habilita y arranca. Cada intervención se
reporta como **CRITICAL** por journald (queda en el registro forense del
sistema): que alguien tocara el centinela ES la alerta.

La lógica de decisión (`decide_action`) es pura y testeable sin systemd.
La ejecución de `systemctl` va aparte.

MITRE: T1562.001 (Impair Defenses: Disable or Modify Tools).
"""
from __future__ import annotations

import os
import time
from typing import NamedTuple


UNIT = "centinel.service"
WATCHDOG_PATH = "/etc/systemd/system/centinel-watchdog.service"


class ServiceState(NamedTuple):
    active: bool      # ¿está corriendo?
    enabled: bool     # ¿arranca al boot?
    masked: bool      # ¿enmascarado (inarrancable)?


class Decision(NamedTuple):
    alert: bool               # ¿emitir CRITICAL?
    reason: str               # por qué
    commands: tuple[str, ...] # remediaciones a ejecutar, en orden


def decide_action(state: ServiceState) -> Decision:
    """Dado el estado del servicio, decide si hay que alertar y re-armar.

    Prioridad: masked (lo más hostil) > caído > solo deshabilitado > sano.
    """
    if state.masked:
        return Decision(
            alert=True,
            reason="alguien ENMASCARÓ centinel.service (systemctl mask) — "
                   "sabotaje deliberado de la defensa",
            commands=(
                f"systemctl unmask {UNIT}",
                f"systemctl enable {UNIT}",
                f"systemctl start {UNIT}",
            ))
    if not state.active:
        cmds = []
        if not state.enabled:
            cmds.append(f"systemctl enable {UNIT}")
        cmds.append(f"systemctl start {UNIT}")
        return Decision(
            alert=True,
            reason="centinel.service NO está activo — lo mataron o pararon; "
                   "reviviéndolo",
            commands=tuple(cmds))
    if not state.enabled:
        return Decision(
            alert=True,
            reason="centinel.service está activo pero DESHABILITADO — "
                   "no arrancaría tras un reinicio; re-habilitando",
            commands=(f"systemctl enable {UNIT}",))
    return Decision(alert=False, reason="sano", commands=())


# ---- consulta de estado real (systemd) ----

def _systemctl_out(arg: str, unit: str = UNIT) -> str:
    """Devuelve stdout de `systemctl <arg> <unit>` (best-effort, sin excepción)."""
    import subprocess
    try:
        r = subprocess.run(["systemctl", arg, unit],
                           capture_output=True, text=True, timeout=5)
        return (r.stdout or "").strip()
    except Exception:  # noqa: BLE001
        return ""


def query_state(unit: str = UNIT) -> ServiceState:
    active = _systemctl_out("is-active", unit) == "active"
    enabled_raw = _systemctl_out("is-enabled", unit)
    masked = enabled_raw == "masked"
    enabled = enabled_raw == "enabled"
    return ServiceState(active=active, enabled=enabled, masked=masked)


# ---- bucle del watchdog ----

def run(interval: float = 5.0, unit: str = UNIT,
        _once: bool = False) -> int:
    """Bucle: vigila el servicio principal y lo re-arma si lo tocan.

    Se ejecuta como `python -m centinel --watchdog`, normalmente bajo el
    servicio hermano centinel-watchdog.service.
    """
    if os.name != "posix":
        print("[watchdog] solo Linux con systemd.")
        return 1
    interval = max(2.0, float(interval))
    print(f"[watchdog] vigilando {unit} cada {interval:.0f}s")
    while True:
        state = query_state(unit)
        decision = decide_action(state)
        if decision.alert:
            # journald captura stdout → queda en el registro forense.
            print(f"[watchdog] CRITICAL: {decision.reason}", flush=True)
            for cmd in decision.commands:
                rc = os.system(cmd)
                print(f"[watchdog]   -> {cmd}  (rc={rc})", flush=True)
        if _once:
            return 0
        time.sleep(interval)


# ---- instalación del servicio hermano ----

def _watchdog_unit_text(py: str, interval: float = 5.0) -> str:
    return f"""# Generado por: python -m centinel --install-watchdog
# Revive CENTINEL si lo matan / deshabilitan / enmascaran (T1562.001).
[Unit]
Description=CENTINEL watchdog - protege al centinela de sabotaje
Documentation=https://github.com/WalterBlack-glitch/CENTINEL
After={UNIT}
# NO usar BindsTo/PartOf: el watchdog debe sobrevivir aunque el principal caiga.

[Service]
Type=simple
ExecStart={py} -m centinel --watchdog --watchdog-interval {interval:g}
Restart=always
RestartSec=3

# Necesita hablar con systemd (PID 1) para re-armar el servicio: corre como
# root, con hardening mínimo compatible con systemctl.
NoNewPrivileges=true
ProtectHome=read-only
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
"""


def install_watchdog(interval: float = 5.0) -> int:
    if os.name != "posix" or not os.path.isdir("/etc/systemd/system"):
        print("[watchdog] systemd no detectado.")
        return 1
    if os.geteuid() != 0:
        print("[watchdog] --install-watchdog requiere root.")
        return 1
    import sys
    py = os.path.realpath(sys.executable)
    unit = _watchdog_unit_text(py, interval=interval)
    tmp = WATCHDOG_PATH + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    with os.fdopen(fd, "w") as f:
        f.write(unit)
    os.replace(tmp, WATCHDOG_PATH)
    print(f"[watchdog] unidad escrita en {WATCHDOG_PATH}")
    rc = os.system("systemctl daemon-reload")
    rc |= os.system("systemctl enable centinel-watchdog.service")
    rc |= os.system("systemctl restart centinel-watchdog.service")
    if rc == 0:
        print("[watchdog] activo. Estado: systemctl status centinel-watchdog")
    else:
        print(f"[watchdog] systemctl devolvió {rc}; revisa el estado.")
    return 0 if rc == 0 else 1


def uninstall_watchdog() -> int:
    if os.geteuid() != 0:
        print("[watchdog] --uninstall-watchdog requiere root.")
        return 1
    os.system("systemctl stop centinel-watchdog.service")
    os.system("systemctl disable centinel-watchdog.service")
    try:
        os.unlink(WATCHDOG_PATH)
    except OSError:
        pass
    os.system("systemctl daemon-reload")
    print("[watchdog] desinstalado.")
    return 0
