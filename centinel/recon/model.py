"""Modelos de datos compartidos. Sin I/O ni dependencias del SO."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Finding:
    """Un hallazgo normalizado del recon (puerto abierto, ruta, subdominio…)."""
    kind: str                     # "port" | "path" | "subdomain"
    # --- puerto (nmap) ---
    port: int | None = None
    proto: str = ""               # tcp | udp
    state: str = ""               # open | filtered | closed
    service: str = ""             # ssh, http…
    version: str = ""             # "OpenSSH 8.9p1"
    # --- ruta / subdominio (ffuf) ---
    url: str = ""
    status: int | None = None     # código HTTP
    length: int | None = None     # tamaño respuesta
    words: int | None = None
    fuzz: str = ""                # el término que casó (FUZZ)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v not in ("", None, {})}


@dataclass
class ScanResult:
    """Resultado de una corrida de herramienta: comando, hallazgos y crudo."""
    tool: str                     # nmap | ffuf | tcpdump
    kind: str                     # quick | full | service | stealth | dir | ...
    target: str
    command: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    raw: str = ""                 # salida cruda de la herramienta
    returncode: int | None = None
    error: str = ""               # motivo si no se pudo ejecutar
    ts: float = 0.0

    @property
    def ok(self) -> bool:
        return not self.error and self.returncode == 0
