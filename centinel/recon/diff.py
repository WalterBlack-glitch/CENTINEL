"""Diff entre dos conjuntos de hallazgos. Puro, sin I/O.

Responde a «¿qué es nuevo desde la corrida anterior?» y «¿en qué cambió esta
sesión frente a aquella?». La identidad de un hallazgo es la misma clave natural
que usa `parse.dedupe` — nunca algo volátil como el PID o el orden —, así un
puerto que sigue abierto entre dos corridas se reconoce como el mismo y no
aparece como «nuevo» cada vez.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .model import Finding


def key(f: Finding) -> tuple:
    """Clave de identidad de un hallazgo (igual que `parse.dedupe`)."""
    return (f.kind, f.port, f.proto, f.url, f.fuzz)


@dataclass
class DiffResult:
    nuevos: list[Finding] = field(default_factory=list)   # están ahora, no antes
    idos: list[Finding] = field(default_factory=list)     # estaban antes, ya no
    comunes: list[Finding] = field(default_factory=list)  # en ambos

    @property
    def sin_cambios(self) -> bool:
        return not self.nuevos and not self.idos


def diff_findings(antes: list[Finding], ahora: list[Finding]) -> DiffResult:
    """Compara dos listas de hallazgos por su clave natural. Puro."""
    a = {key(f): f for f in antes}
    b = {key(f): f for f in ahora}
    return DiffResult(
        nuevos=[f for k, f in b.items() if k not in a],
        idos=[f for k, f in a.items() if k not in b],
        comunes=[f for k, f in b.items() if k in a],
    )


def _etiqueta(f: Finding) -> str:
    if f.kind == "port":
        v = f" {f.version}" if f.version else ""
        return f"{f.port}/{f.proto} {f.service}{v}".strip()
    if f.kind == "subdomain":
        return f"{f.fuzz} ({f.url})"
    return f"[{f.status}] {f.url}"


def headline(d: DiffResult) -> str:
    """Frase de cabecera, al estilo del historial del IDS."""
    if d.sin_cambios:
        return "Sin cambios desde la corrida anterior."
    trozos = []
    if d.nuevos:
        trozos.append(f"{len(d.nuevos)} nuevo{'s' if len(d.nuevos) != 1 else ''}")
    if d.idos:
        trozos.append(f"{len(d.idos)} desaparecido{'s' if len(d.idos) != 1 else ''}")
    return "Desde la corrida anterior: " + ", ".join(trozos) + "."


def render_txt(d: DiffResult) -> str:
    """Resumen legible del diff. Puro."""
    lines = [headline(d)]
    if d.nuevos:
        lines.append("")
        lines.append(f"NUEVOS ({len(d.nuevos)})")
        lines += [f"  + {_etiqueta(f)}" for f in d.nuevos]
    if d.idos:
        lines.append("")
        lines.append(f"DESAPARECIDOS ({len(d.idos)})")
        lines += [f"  - {_etiqueta(f)}" for f in d.idos]
    return "\n".join(lines) + "\n"
