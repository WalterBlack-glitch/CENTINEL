"""Preflight: verifica que las herramientas, permisos y wordlists estén listos.

`preflight` es la lógica pura (entra el estado del entorno, sale una lista de
chequeos). `run_preflight` recoge el estado real del sistema y la invoca.
"""
from __future__ import annotations

from pathlib import Path

from . import tools
from .config import Config

# (nombre, ok, detalle, severidad)  severidad: "ok" | "warn" | "err"
Check = tuple[str, bool, str, str]


def preflight(*, tool_avail: dict[str, bool], is_root: bool,
              cfg: Config) -> list[Check]:
    """Construye la lista de chequeos a partir del estado. Pura y testeable."""
    checks: list[Check] = []
    for name, avail in tool_avail.items():
        why = tools.REQUIRED_TOOLS.get(name, "")
        checks.append((
            f"herramienta: {name}", avail,
            f"disponible ({why})" if avail else f"NO instalada — {why}",
            "ok" if avail else ("err" if name == "nmap" else "warn")))
    checks.append((
        "privilegios root", is_root,
        "elevado (scan sigiloso disponible)" if is_root
        else "sin root (scan -sS deshabilitado)",
        "ok" if is_root else "warn"))
    for label, path in (("wordlist dirs", cfg.wordlist_dir),
                        ("wordlist subs", cfg.wordlist_sub)):
        if not path:
            checks.append((label, False, "sin configurar (config)", "warn"))
        elif Path(path).is_file():
            checks.append((label, True, path, "ok"))
        else:
            checks.append((label, False, f"no existe: {path}", "err"))
    checks.append((
        "interfaz sniffer", bool(cfg.interface),
        cfg.interface or "sin fijar (set interface)",
        "ok" if cfg.interface else "warn"))
    return checks


def run_preflight(cfg: Config) -> list[Check]:
    """Recoge el estado real del sistema y evalúa el preflight. I/O ligero."""
    return preflight(tool_avail=tools.tool_status(), is_root=tools.is_root(),
                     cfg=cfg)
