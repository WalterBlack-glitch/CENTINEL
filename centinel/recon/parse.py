"""Parseo puro de la salida de nmap y ffuf a `Finding`. Sin I/O.

El corazón testeable del recon: entra texto/JSON crudo de la herramienta,
salen hallazgos normalizados. No ejecuta nada.
"""
from __future__ import annotations

import json
import re

from .model import Finding

# Línea de puerto de nmap normal (-oN):  "22/tcp   open  ssh   OpenSSH 8.9p1"
_NMAP_PORT = re.compile(
    r"^(?P<port>\d+)/(?P<proto>tcp|udp)\s+"
    r"(?P<state>open|filtered|closed|open\|filtered)\s+"
    r"(?P<service>\S+)(?:\s+(?P<version>.*\S))?\s*$",
    re.IGNORECASE,
)


def parse_nmap(text: str, *, only_open: bool = True) -> list[Finding]:
    """Extrae puertos de la salida normal de nmap. Puro."""
    out: list[Finding] = []
    for line in text.splitlines():
        m = _NMAP_PORT.match(line.strip())
        if not m:
            continue
        state = m.group("state").lower()
        if only_open and not state.startswith("open"):
            continue
        out.append(Finding(
            kind="port",
            port=int(m.group("port")),
            proto=m.group("proto").lower(),
            state=state,
            service=(m.group("service") or "").lower(),
            version=(m.group("version") or "").strip(),
        ))
    return out


def parse_ffuf(json_text: str, *, kind: str = "path") -> list[Finding]:
    """Extrae rutas/subdominios del JSON de ffuf (`-of json`). Puro.

    `kind` es "path" para fuzzing de directorios y "subdomain" para el de
    subdominios; solo cambia la etiqueta del hallazgo.
    """
    try:
        data = json.loads(json_text or "{}")
    except json.JSONDecodeError:
        return []
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        return []
    out: list[Finding] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        inp = r.get("input") if isinstance(r.get("input"), dict) else {}
        out.append(Finding(
            kind=kind,
            url=str(r.get("url", "")),
            status=_as_int(r.get("status")),
            length=_as_int(r.get("length")),
            words=_as_int(r.get("words")),
            fuzz=str(inp.get("FUZZ", "")),
        ))
    return out


def _as_int(v: object) -> int | None:
    try:
        return int(v)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Quita duplicados conservando el orden (por clave natural del hallazgo)."""
    seen: set[tuple] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.kind, f.port, f.proto, f.url, f.fuzz)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
