"""Dos registros distintos:

- **RunLog**: acciones de ESTA corrida, en memoria (el comando `logs`).
- **historial persistente**: append-only JSONL en disco que sobrevive al cierre
  (el comando `history`).
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

from . import paths


@dataclass
class RunLog:
    """Log en memoria de la sesión de TUI actual."""
    entries: list[tuple[float, str]] = field(default_factory=list)

    def add(self, msg: str) -> None:
        self.entries.append((time.time(), msg))

    def tail(self, n: int = 50) -> list[str]:
        out = []
        for ts, msg in self.entries[-n:]:
            out.append(f"{time.strftime('%H:%M:%S', time.localtime(ts))}  {msg}")
        return out


def append_history(session: str, action: str, detail: str = "") -> None:
    """Añade una línea al historial persistente. Tolerante a fallos de I/O."""
    paths.ensure_dirs()
    rec = {"ts": time.time(), "session": session, "action": action,
           "detail": detail}
    try:
        with paths.history_file().open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass


def read_history(n: int = 100, *, session: str | None = None) -> list[dict]:
    """Lee las últimas `n` entradas del historial persistente (opcional: filtra
    por sesión). Más recientes al final."""
    f = paths.history_file()
    if not f.is_file():
        return []
    out: list[dict] = []
    try:
        for line in f.read_text(encoding="utf-8").splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if session and rec.get("session") != session:
                continue
            out.append(rec)
    except OSError:
        return []
    return out[-n:]
