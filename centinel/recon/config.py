"""Config persistente en JSON (tema, interfaz, wordlists, última sesión).

Carga tolerante a fallos (si el fichero está corrupto, vuelve a defaults) y
guardado atómico. Puro salvo las dos funciones de I/O `load`/`save`.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict, field
from pathlib import Path

from . import paths, theme


@dataclass
class Config:
    theme: str = theme.DEFAULT_THEME
    interface: str = ""                 # interfaz del sniffer pasivo
    last_session: str = ""              # sesión a reactivar al abrir
    wordlist_dir: str = ""              # wordlist para 'scan dir'
    wordlist_sub: str = ""              # wordlist para 'scan subdomain'
    extra: dict = field(default_factory=dict)

    def sanitized(self) -> "Config":
        """Corrige valores inválidos (tema inexistente -> default)."""
        if self.theme not in theme.THEMES:
            self.theme = theme.DEFAULT_THEME
        return self


def load() -> Config:
    f = paths.config_file()
    if not f.is_file():
        return Config()
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return Config()
    if not isinstance(data, dict):
        return Config()
    known = {k: data[k] for k in Config().__dict__ if k in data}
    try:
        return Config(**known).sanitized()
    except TypeError:
        return Config()


def save(cfg: Config) -> None:
    paths.ensure_dirs()
    f = paths.config_file()
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(asdict(cfg), indent=2, ensure_ascii=False),
                   encoding="utf-8")
    os.replace(tmp, f)
