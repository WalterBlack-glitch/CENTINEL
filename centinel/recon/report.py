"""Reporte del recon: render puro a texto y Markdown, más export a disco.

`render_txt` y `render_md` son puras (entra la sesión, sale el texto). `export`
las vuelca al PWD del usuario. Nada de esto ejecuta herramientas.
"""
from __future__ import annotations

import html
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


_HTML_CSS = """
:root { --bg:#f7f7f8; --fg:#1b1b1f; --card:#fff; --line:#e3e3e8;
        --head:#2b2b35; --accent:#0a7; --mut:#6b6b76; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#121216; --fg:#e8e8ec; --card:#1b1b22; --line:#2c2c36;
          --head:#c7c7d2; --accent:#3dd68c; --mut:#8a8a96; } }
* { box-sizing:border-box; }
body { margin:0; padding:24px; background:var(--bg); color:var(--fg);
       font:15px/1.5 system-ui,Segoe UI,Roboto,sans-serif; }
h1 { font-size:20px; margin:0 0 4px; }
.meta { color:var(--mut); margin-bottom:20px; }
.meta code { color:var(--fg); }
h2 { font-size:15px; text-transform:uppercase; letter-spacing:.04em;
     color:var(--head); margin:24px 0 8px; }
table { width:100%; border-collapse:collapse; background:var(--card);
        border:1px solid var(--line); border-radius:8px; overflow:hidden; }
th,td { text-align:left; padding:8px 12px; border-bottom:1px solid var(--line);
        font-variant-numeric:tabular-nums; }
th { color:var(--mut); font-weight:600; font-size:13px; }
tr:last-child td { border-bottom:none; }
.empty { color:var(--mut); font-style:italic; }
footer { margin-top:28px; color:var(--mut); font-size:13px; }
footer code { display:block; white-space:pre-wrap; margin-top:4px; }
"""


def _esc(v: object) -> str:
    """Escapa a HTML. El contenido lo escribe en parte el objetivo escaneado
    (versiones de servicio, URLs): un servicio llamado `<img onerror=…>` no debe
    convertir el informe en el segundo vector del ataque."""
    return html.escape("" if v is None else str(v), quote=True)


def render_html(s: Session) -> str:
    """Informe HTML autocontenido, tema claro/oscuro. Puro. Todo valor escapado."""
    g = _group(s.findings)
    fecha = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(s.updated))
    out = ["<!doctype html><html lang=es><head><meta charset=utf-8>",
           "<meta name=viewport content='width=device-width,initial-scale=1'>",
           f"<title>PARANOID recon — {_esc(s.name)}</title>",
           f"<style>{_HTML_CSS}</style></head><body>",
           f"<h1>PARANOID — reporte de recon</h1>",
           f"<div class=meta>Sesión <code>{_esc(s.name)}</code> · "
           f"objetivo <code>{_esc(s.target or '(sin fijar)')}</code> · "
           f"{_esc(fecha)} · {len(s.findings)} hallazgos</div>"]
    if g["port"]:
        out.append(f"<h2>Puertos abiertos ({len(g['port'])})</h2>")
        out.append("<table><tr><th>Puerto</th><th>Proto</th><th>Estado</th>"
                   "<th>Servicio</th><th>Versión</th></tr>")
        for f in g["port"]:
            out.append(f"<tr><td>{_esc(f.port)}</td><td>{_esc(f.proto)}</td>"
                       f"<td>{_esc(f.state)}</td><td>{_esc(f.service)}</td>"
                       f"<td>{_esc(f.version)}</td></tr>")
        out.append("</table>")
    if g["path"]:
        out.append(f"<h2>Rutas ({len(g['path'])})</h2>")
        out.append("<table><tr><th>Código</th><th>URL</th><th>Tamaño</th></tr>")
        for f in g["path"]:
            out.append(f"<tr><td>{_esc(f.status)}</td><td>{_esc(f.url)}</td>"
                       f"<td>{_esc(f.length)}</td></tr>")
        out.append("</table>")
    if g["subdomain"]:
        out.append(f"<h2>Subdominios ({len(g['subdomain'])})</h2>")
        out.append("<table><tr><th>Código</th><th>Subdominio</th><th>URL</th></tr>")
        for f in g["subdomain"]:
            out.append(f"<tr><td>{_esc(f.status)}</td><td>{_esc(f.fuzz)}</td>"
                       f"<td>{_esc(f.url)}</td></tr>")
        out.append("</table>")
    if not s.findings:
        out.append("<p class=empty>Sin hallazgos todavía.</p>")
    if s.commands:
        cmds = "\n".join("$ " + _esc(c) for c in s.commands)
        out.append(f"<footer>Comandos ejecutados:<code>{cmds}</code></footer>")
    out.append("</body></html>")
    return "\n".join(out) + "\n"


def export(s: Session, dest_dir: Path) -> list[Path]:
    """Escribe reporte txt+md en `dest_dir` (típicamente el PWD). Devuelve rutas."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime())
    txt = dest_dir / f"paranoid_{s.name}_{stamp}.txt"
    md = dest_dir / f"paranoid_{s.name}_{stamp}.md"
    htmlf = dest_dir / f"paranoid_{s.name}_{stamp}.html"
    txt.write_text(render_txt(s), encoding="utf-8")
    md.write_text(render_md(s), encoding="utf-8")
    htmlf.write_text(render_html(s), encoding="utf-8")
    return [txt, md, htmlf]
