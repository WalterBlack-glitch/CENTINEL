"""Informe de feedback: lo que la app NO pudo arreglar sola, listo para pegar.

Cuando el doctor auto-cura lo que puede pero quedan errores (o algo revienta en
ejecución), Centinela escribe un informe estructurado en texto plano con:
  - el entorno (SO, Python, plataforma, privilegios),
  - los hallazgos sin resolver y su arreglo sugerido,
  - cualquier traza de excepción capturada.

El usuario solo tiene que pegar ese archivo a su asistente para que lo arregle.
No incluye secretos: solo metadatos de entorno y mensajes de diagnóstico.
"""
from __future__ import annotations

import os
import platform
import sys
import time
import traceback

REPORT_NAME = "centinela_feedback.txt"


def _env() -> list[str]:
    try:
        euid = os.geteuid() if hasattr(os, "geteuid") else "n/a"
    except Exception:
        euid = "n/a"
    return [
        f"fecha:      {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"python:     {sys.version.split()[0]}",
        f"plataforma: {platform.platform()}",
        f"sistema:    {platform.system()} {platform.release()}",
        f"euid:       {euid}",
        f"cwd:        {os.getcwd()}",
        f"argv:       {' '.join(sys.argv)}",
    ]


def write_report(findings: list[dict] | None = None,
                 exc: BaseException | None = None,
                 extra: str | None = None,
                 path: str | None = None) -> str:
    """Escribe el informe y devuelve su ruta. Nunca lanza (best-effort)."""
    path = path or REPORT_NAME
    lines: list[str] = []
    add = lines.append
    add("=" * 70)
    add("INFORME DE FEEDBACK DE CENTINELA")
    add("Pega este archivo completo a tu asistente para que lo arregle.")
    add("=" * 70)
    add("")
    add("## Entorno")
    lines.extend("  " + x for x in _env())
    add("")

    unresolved = [f for f in (findings or [])
                  if f.get("level") in ("error", "warn")]
    if unresolved:
        add("## Lo que la app NO pudo arreglar sola")
        for f in unresolved:
            mark = "ERROR" if f["level"] == "error" else "AVISO"
            add(f"  [{mark}] {f['msg']}")
            if f.get("fix"):
                add(f"         arreglo sugerido: {f['fix']}")
        add("")

    fixed = [f for f in (findings or []) if f.get("level") == "fixed"]
    if fixed:
        add("## Lo que la app arregló automáticamente")
        for f in fixed:
            add(f"  [OK] {f['msg']}")
        add("")

    if exc is not None:
        add("## Excepción en ejecución (traza)")
        tb = "".join(traceback.format_exception(
            type(exc), exc, exc.__traceback__))
        lines.extend("  " + ln for ln in tb.rstrip().splitlines())
        add("")

    if extra:
        add("## Detalle adicional")
        lines.extend("  " + ln for ln in extra.splitlines())
        add("")

    add("=" * 70)
    add("Fin del informe.")
    text = "\n".join(lines) + "\n"
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except OSError:
        # Si no se puede escribir, al menos vuélcalo por stderr.
        print(text, file=sys.stderr)
    return path
