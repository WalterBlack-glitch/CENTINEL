"""Detección de herramientas externas y utilidades de privilegios. I/O ligero."""
from __future__ import annotations

import os
import shutil

# Herramientas que PARANOID orquesta y para qué sirve cada una.
REQUIRED_TOOLS: dict[str, str] = {
    "nmap": "escaneo de puertos y servicios",
    "ffuf": "fuzzing de directorios y subdominios",
    "tcpdump": "sniffer pasivo / telemetría",
}


def have(binary: str) -> bool:
    """¿Está el binario en el PATH?"""
    return shutil.which(binary) is not None


def which(binary: str) -> str | None:
    return shutil.which(binary)


def tool_status() -> dict[str, bool]:
    """Mapa herramienta -> disponible, para verify/preflight."""
    return {name: have(name) for name in REQUIRED_TOOLS}


def is_root() -> bool:
    """¿Corremos con privilegios elevados? (root en POSIX, admin en Windows)."""
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:   # noqa: BLE001
            return False
    try:
        return os.geteuid() == 0   # type: ignore[attr-defined]
    except AttributeError:
        return False
