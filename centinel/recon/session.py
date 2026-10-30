"""Sesiones de recon: agrupan objetivo, hallazgos y ficheros en un directorio.

Una sesión es una carpeta bajo `results/<slug>` con un `session.json` (metadatos
+ hallazgos) y los ficheros crudos de cada herramienta. `slugify` y la
validación de nombres son puras; el store toca disco.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

from . import paths
from .model import Finding

_SLUG_RE = re.compile(r"[^a-z0-9_-]+")


def slugify(name: str) -> str:
    """Normaliza un nombre de sesión a un slug seguro para carpeta. Puro."""
    s = _SLUG_RE.sub("-", name.strip().lower()).strip("-")
    return s or "sesion"


@dataclass
class Session:
    name: str
    target: str = ""
    created: float = field(default_factory=time.time)
    updated: float = field(default_factory=time.time)
    findings: list[Finding] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)   # historial de comandos

    @property
    def dir(self) -> Path:
        return paths.session_dir(self.name)

    def add_findings(self, new: list[Finding]) -> int:
        """Añade hallazgos evitando duplicados. Devuelve cuántos son nuevos."""
        from .parse import dedupe
        before = len(self.findings)
        self.findings = dedupe(self.findings + new)
        self.updated = time.time()
        return len(self.findings) - before


# --------------------------------------------------------------------------
# Store (I/O)
# --------------------------------------------------------------------------

def _meta_file(name: str) -> Path:
    return paths.session_dir(name) / "session.json"


def create(name: str, *, target: str = "") -> Session:
    slug = slugify(name)
    s = Session(name=slug, target=target)
    s.dir.mkdir(parents=True, exist_ok=True)
    save(s)
    return s


def exists(name: str) -> bool:
    return _meta_file(slugify(name)).is_file()


def save(s: Session) -> None:
    s.dir.mkdir(parents=True, exist_ok=True)
    data = asdict(s)
    data["findings"] = [f.to_dict() for f in s.findings]
    _meta_file(s.name).write_text(
        json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def load(name: str) -> Session | None:
    f = _meta_file(slugify(name))
    if not f.is_file():
        return None
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    finds = [Finding(**{k: v for k, v in d.items() if k in Finding.__annotations__})
             for d in data.get("findings", []) if isinstance(d, dict)]
    return Session(
        name=data.get("name", slugify(name)), target=data.get("target", ""),
        created=data.get("created", time.time()),
        updated=data.get("updated", time.time()),
        findings=finds, commands=list(data.get("commands", [])))


def listing() -> list[dict]:
    """Lista sesiones existentes con metadatos ligeros, más recientes primero."""
    root = paths.results_dir()
    if not root.is_dir():
        return []
    out: list[dict] = []
    for d in root.iterdir():
        meta = d / "session.json"
        if not meta.is_file():
            continue
        try:
            data = json.loads(meta.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        out.append({"name": data.get("name", d.name),
                    "target": data.get("target", ""),
                    "updated": data.get("updated", 0),
                    "findings": len(data.get("findings", []))})
    out.sort(key=lambda x: x["updated"], reverse=True)
    return out
