"""Reporte del recon: render puro a texto y Markdown, más export a disco.

`render_txt` y `render_md` son puras (entra la sesión, sale el texto). `export`
las vuelca al PWD del usuario. Nada de esto ejecuta herramientas.
"""
from __future__ import annotations

import time
from pathlib import Path

from .model import Finding
from .session import Session


def _group(findings: list[Finding]) -> dict[str, list[Finding]]:
    g: dict[str, list[Finding]] = {"port": [], "path": [], "subdomain": []}
    for f in findings:
        g.setdefault(f.kind, []).append(f)
    g["port"].sort(key=lambda f: (f.port or 0))
    g["path"].sort(key=lambda f: (f.status or 0, f.url))
    g["subdomain"].sort(key=lambda f: f.fuzz)
    return g


def render_txt(s: Session) -> str:
    g = _group(s.findings)
    lines = [
        "PARANOID — reporte de recon",
        f"Sesión : {s.name}",
        f"Objetivo: {s.target or '(sin fijar)'}",
        f"Fecha  : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(s.updated))}",
        f"Total  : {len(s.findings)} hallazgos",
        "=" * 60, "",
    ]
    if g["port"]:
        lines.append(f"PUERTOS ABIERTOS ({len(g['port'])})")
        for f in g["port"]:
            v = f" {f.version}" if f.version else ""
            lines.append(f"  {f.port}/{f.proto:<3} {f.state:<8} "
                         f"{f.service}{v}")
        lines.append("")
    if g["path"]:
        lines.append(f"RUTAS ({len(g['path'])})")
        for f in g["path"]:
            lines.append(f"  [{f.status}] {f.url}  (len={f.length})")
        lines.append("")
    if g["subdomain"]:
        lines.append(f"SUBDOMINIOS ({len(g['subdomain'])})")
        for f in g["subdomain"]:
            lines.append(f"  [{f.status}] {f.fuzz}  ({f.url})")
        lines.append("")
    if not s.findings:
        lines.append("(sin hallazgos todavía)")
    if s.commands:
        lines += ["", "COMANDOS EJECUTADOS", *(f"  $ {c}" for c in s.commands)]
    return "\n".join(lines) + "\n"


def render_md(s: Session) -> str:
    g = _group(s.findings)
    out = [f"# PARANOID — recon `{s.name}`", "",
           f"- **Objetivo:** `{s.target or '(sin fijar)'}`",
           f"- **Fecha:** {time.strftime('%Y-%m-%d %H:%M', time.localtime(s.updated))}",
           f"- **Hallazgos:** {len(s.findings)}", ""]
    if g["port"]:
        out += ["## Puertos abiertos", "",
                "| Puerto | Proto | Estado | Servicio | Versión |",
                "|---|---|---|---|---|"]
        out += [f"| {f.port} | {f.proto} | {f.state} | {f.service} | "
                f"{f.version or ''} |" for f in g["port"]]
        out.append("")
    if g["path"]:
        out += ["## Rutas", "", "| Código | URL | Tamaño |", "|---|---|---|"]
        out += [f"| {f.status} | `{f.url}` | {f.length or ''} |"
                for f in g["path"]]
        out.append("")
    if g["subdomain"]:
        out += ["## Subdominios", "", "| Código | Subdominio | URL |",
                "|---|---|---|"]
        out += [f"| {f.status} | `{f.fuzz}` | `{f.url}` |"
                for f in g["subdomain"]]
        out.append("")
    if not s.findings:
        out.append("_Sin hallazgos todavía._")
    return "\n".join(out) + "\n"


def export(s: Session, dest_dir: Path) -> list[Path]:
    """Escribe reporte txt+md en `dest_dir` (típicamente el PWD). Devuelve rutas."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime())
    txt = dest_dir / f"paranoid_{s.name}_{stamp}.txt"
    md = dest_dir / f"paranoid_{s.name}_{stamp}.md"
    txt.write_text(render_txt(s), encoding="utf-8")
    md.write_text(render_md(s), encoding="utf-8")
    return [txt, md]
