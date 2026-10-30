"""Rutas XDG donde el modo recon guarda config, datos e historial.

Linux/mac: respeta XDG_*. Windows: cae a %APPDATA% / %LOCALAPPDATA%. Todo bajo
`centinel/recon` (namespaced dentro de CENTINEL, separado de las baselines del
IDS). No crea nada hasta que se llama a `ensure_dirs`.
"""
from __future__ import annotations

import os
from pathlib import Path


def _base(env: str, default_posix: str, win_env: str) -> Path:
    if os.name == "nt":
        root = os.environ.get(win_env) or os.environ.get("APPDATA") \
            or str(Path.home())
        return Path(root) / "centinel" / "recon"
    root = os.environ.get(env) or str(Path.home() / default_posix)
    return Path(root) / "centinel" / "recon"


def config_dir() -> Path:
    return _base("XDG_CONFIG_HOME", ".config", "APPDATA")


def data_dir() -> Path:
    return _base("XDG_DATA_HOME", ".local/share", "LOCALAPPDATA")


def config_file() -> Path:
    return config_dir() / "config.json"


def history_file() -> Path:
    return data_dir() / "history.jsonl"


def results_dir() -> Path:
    return data_dir() / "results"


def session_dir(name: str) -> Path:
    return results_dir() / name


def ensure_dirs() -> None:
    for d in (config_dir(), data_dir(), results_dir()):
        d.mkdir(parents=True, exist_ok=True)
