"""Exportar un escaneo como informe: JSON, CSV o HTML con marca de tiempo.

Para guardar evidencia, mandársela a alguien o comparar en el tiempo. Toma el
retrato de `snapshots` (y opcionalmente el diff) y escribe un fichero cuyo
nombre lleva la fecha: `centinel-2026-10-08_142530.html`.

Dos cuidados que un informe de seguridad **tiene** que tener, porque el
contenido lo escribe en parte el atacante (nombres de proceso, rutas, motivos):

  - HTML: todo valor va por `html.escape`. Un proceso llamado
    `<img src=x onerror=...>` convertiría el informe en una página que ejecuta
    código en el navegador de quien lo abra — el informe de la intrusión
    siendo el segundo vector de la intrusión.
  - CSV: un campo que empieza por `=`, `+`, `-`, `@`, tab o CR lo interpreta
    Excel/LibreOffice como fórmula (`=cmd|'/c calc'!A1` es el clásico), así que
    se le antepone un apóstrofe. Es *CSV injection*, y una exportación de
    seguridad que la ignore es un arma cargada apuntando al analista.
"""
from __future__ import annotations

import csv
import html
import io
import json
import os
import time

from ..core import Severity

_PELIGRO_CSV = ("=", "+", "-", "@", "\t", "\r")
_SEV_COLOR = {4: "#c0392b", 3: "#e67e22", 2: "#f1c40f", 1: "#3498db", 0: "#7f8c8d"}
_COLUMNAS = ("severidad", "tipo", "proceso", "pid", "ruta", "motivos", "estado")


def _sev_name(v) -> str:
    try:
        return Severity(int(v)).name
    except (ValueError, TypeError):
        return str(v)


def _fmt_ts(ts: float | None) -> str:
    if not ts:
        return "—"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(ts)))


def stamp(ts: float | None = None) -> str:
    """Marca de tiempo para nombres de fichero: ordenable y sin caracteres raros."""
    return time.strftime("%Y-%m-%d_%H%M%S",
                         time.localtime(ts if ts is not None else time.time()))


def _estados(d) -> dict[str, str]:
    """Mapa identidad -> estado ('nuevo', 'agravado', 'sin cambio', 'resuelto')."""
    if d is None:
        return {}
    out: dict[str, str] = {}
    for f in getattr(d, "persistentes", ()):
        out[f.key] = "sin cambio"
    for f in getattr(d, "nuevos", ()):
        out[f.key] = "nuevo"
    for _viejo, nuevo in getattr(d, "agravados", ()):
        out[nuevo.key] = "agravado"
    for f in getattr(d, "resueltos", ()):
        out[f.key] = "resuelto"
    return out


def _filas(snap: dict, d=None) -> list[dict]:
    """Filas del informe: los hallazgos actuales más los resueltos del diff."""
    estado = _estados(d)
    filas = []
    for f in snap.get("findings") or ():
        filas.append({
            "severidad": _sev_name(f.get("severity")),
            "tipo": f.get("kind") or "",
            "proceso": f.get("name") or "",
            "pid": "" if f.get("pid") is None else f.get("pid"),
            "ruta": f.get("path") or "",
            "motivos": "; ".join(f.get("reasons") or ()),
            "estado": estado.get(f.get("key"), ""),
            "_sev": int(f.get("severity") or 0),
        })
    for f in getattr(d, "resueltos", ()) if d is not None else ():
        filas.append({
            "severidad": _sev_name(f.severity), "tipo": f.kind,
            "proceso": f.name, "pid": "" if f.pid is None else f.pid,
            "ruta": f.path, "motivos": "; ".join(f.reasons),
            "estado": "resuelto", "_sev": int(f.severity)})
    filas.sort(key=lambda r: (-r["_sev"], r["proceso"]))
    return filas


# ------------------------------------------------------------------- JSON
def to_json(snap: dict, d=None, *, host: str = "", indent: int = 2) -> str:
    """Informe completo en JSON. El formato más fiel: no pierde nada."""
    doc = {
        "generado": _fmt_ts(time.time()),
        "generado_ts": time.time(),
        "host": host or snap.get("host", ""),
        "escaneo_ts": snap.get("ts"),
        "escaneo": _fmt_ts(snap.get("ts")),
        "total": len(snap.get("findings") or ()),
        "findings": snap.get("findings") or [],
    }
    if d is not None:
        doc["diff"] = {
            "resumen": d.resumen(),
            "anterior_ts": d.prev_ts,
            "anterior": _fmt_ts(d.prev_ts),
            "nuevos": [f.to_dict() for f in d.nuevos],
            "agravados": [{"antes": v.to_dict(), "ahora": n.to_dict()}
                          for v, n in d.agravados],
            "resueltos": [f.to_dict() for f in d.resueltos],
            "persistentes": [f.to_dict() for f in d.persistentes],
        }
    return json.dumps(doc, indent=indent, ensure_ascii=False, sort_keys=True)


# -------------------------------------------------------------------- CSV
def csv_safe(valor) -> str:
    """Neutraliza CSV injection sin perder el valor original."""
    s = "" if valor is None else str(valor)
    if s[:1] in _PELIGRO_CSV:
        return "'" + s
    return s


def to_csv(snap: dict, d=None) -> str:
    """Informe en CSV, para abrirlo en una hoja de cálculo sin sustos."""
    buf = io.StringIO(newline="")
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(_COLUMNAS)
    for fila in _filas(snap, d):
        w.writerow([csv_safe(fila[c]) for c in _COLUMNAS])
    return buf.getvalue()


# ------------------------------------------------------------------- HTML
_CSS = """
:root{color-scheme:light dark}
body{font:14px/1.5 "Segoe UI",system-ui,sans-serif;margin:0;padding:24px;
     background:#fff;color:#1a1a1a}
h1{font-size:20px;margin:0 0 4px}
.meta{color:#666;font-size:12px;margin-bottom:16px}
.resumen{padding:10px 14px;border-left:4px solid #3498db;background:#f4f8fb;
         margin:0 0 18px;border-radius:0 4px 4px 0}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #e3e3e3;
      vertical-align:top}
th{background:#f7f7f7;font-weight:600;position:sticky;top:0}
td.ruta,td.motivos{font-family:Consolas,monospace;font-size:12px;
                   word-break:break-all}
.sev{font-weight:700;white-space:nowrap}
.badge{display:inline-block;padding:1px 7px;border-radius:10px;font-size:11px;
       background:#eee;color:#333}
.badge.nuevo{background:#c0392b;color:#fff}
.badge.agravado{background:#e67e22;color:#fff}
.badge.resuelto{background:#27ae60;color:#fff}
.limpio{padding:16px;background:#eafaf1;border-left:4px solid #27ae60;
        border-radius:0 4px 4px 0}
@media(prefers-color-scheme:dark){
  body{background:#16181c;color:#e8e8e8}
  th{background:#22252b}th,td{border-bottom-color:#2e3238}
  .resumen{background:#1b2a35}.limpio{background:#16281e}
  .badge{background:#2e3238;color:#ddd}
}
"""


def to_html(snap: dict, d=None, *, host: str = "", title: str = "") -> str:
    """Informe autocontenido en HTML. Todo valor va escapado."""
    e = html.escape
    filas = _filas(snap, d)
    host = host or snap.get("host", "")
    titulo = title or "CENTINEL — informe de escaneo"
    partes = [
        "<!doctype html><html lang=\"es\"><head><meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
        f"<title>{e(titulo)}</title><style>{_CSS}</style></head><body>",
        f"<h1>{e(titulo)}</h1>",
        "<p class=\"meta\">Escaneo: {} &middot; generado: {}{}</p>".format(
            e(_fmt_ts(snap.get("ts"))), e(_fmt_ts(time.time())),
            " &middot; equipo: " + e(host) if host else ""),
    ]
    if d is not None:
        partes.append(f"<p class=\"resumen\">{e(d.resumen())}</p>")
    if not filas:
        partes.append("<p class=\"limpio\"><strong>Sin hallazgos.</strong> "
                      "Ningún proceso suplantando a Windows ni módulo anómalo.</p>")
    else:
        partes.append("<table><thead><tr>"
                      + "".join(f"<th>{e(c.capitalize())}</th>" for c in _COLUMNAS)
                      + "</tr></thead><tbody>")
        for f in filas:
            color = _SEV_COLOR.get(f["_sev"], "#333")
            estado = f["estado"]
            clase = estado if estado in ("nuevo", "agravado", "resuelto") else ""
            badge = (f"<span class=\"badge {clase}\">{e(estado)}</span>"
                     if estado else "")
            partes.append(
                "<tr>"
                f"<td class=\"sev\" style=\"color:{color}\">{e(f['severidad'])}</td>"
                f"<td>{e(f['tipo'])}</td><td>{e(f['proceso'])}</td>"
                f"<td>{e(str(f['pid']))}</td>"
                f"<td class=\"ruta\">{e(f['ruta'])}</td>"
                f"<td class=\"motivos\">{e(f['motivos'])}</td>"
                f"<td>{badge}</td></tr>")
        partes.append("</tbody></table>")
    partes.append("</body></html>")
    return "".join(partes)


# -------------------------------------------------------------------- I/O
_FORMATOS = {"json": (to_json, ".json"), "csv": (to_csv, ".csv"),
             "html": (to_html, ".html")}

FORMATOS = tuple(_FORMATOS)


def render(fmt: str, snap: dict, d=None, *, host: str = "") -> str:
    """Informe en el formato pedido. Puro."""
    try:
        fn, _ext = _FORMATOS[fmt.lower()]
    except KeyError:
        raise ValueError("formato desconocido: {} (usa {})".format(
            fmt, ", ".join(FORMATOS))) from None
    if fmt.lower() == "csv":
        return fn(snap, d)
    return fn(snap, d, host=host)


def write_report(snap: dict, d=None, *, fmt: str = "html", outdir: str = ".",
                 host: str = "", ts: float | None = None) -> str:
    """Escribe el informe y devuelve la ruta. El nombre lleva la fecha."""
    texto = render(fmt, snap, d, host=host)
    _fn, ext = _FORMATOS[fmt.lower()]
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, "centinel-{}{}".format(
        stamp(ts if ts is not None else snap.get("ts")), ext))
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(texto)
    return path
