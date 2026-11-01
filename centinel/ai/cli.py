"""Glue del modo `--explain`: lee el event store y explica las alertas.

Solo lectura sobre la BD, como `--report`. Toma los últimos eventos por encima
de un umbral y los pasa por el explicador local (Ollama). Si Ollama no está, se
degrada al resumen-plantilla local — nunca falla ni bloquea.
"""
from __future__ import annotations

from ..core import Severity
from .explainer import OllamaExplainer, template_summary

_RULE = "─" * 62
_SEV = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def _sev_label(ev) -> str:
    try:
        return _SEV[min(int(ev.severity), 4)]
    except (TypeError, ValueError):
        return "INFO"


def explain_report(db_path: str, *, model: str, url: str, timeout: float = 20.0,
                   allow_remote: bool = False, limit: int = 10,
                   min_severity: int = int(Severity.MEDIUM)) -> str:
    """Texto con la explicación en lenguaje natural de las alertas recientes."""
    from ..storage.db import EventStore

    st = EventStore(db_path)
    try:
        events = st.recent(limit=limit, min_severity=min_severity)
    finally:
        st.close()

    L = [_RULE, "  CENTINEL · explicador de alertas (IA local)", _RULE]
    expl = OllamaExplainer(model=model, url=url, timeout=timeout,
                           allow_remote=allow_remote)
    if not expl.available():
        L.append(f"  [!] {expl.reason}")
        L.append("      Se usa el resumen-plantilla local en su lugar.")
    elif not events:
        L.append("  (no hay alertas que explicar con ese umbral)")
        L.append(_RULE)
        return "\n".join(L)

    if not events:
        L.append("")
        L.append("  (event store vacío o sin alertas sobre el umbral)")
        L.append(_RULE)
        return "\n".join(L)

    # Un aviso si Ollama está desactivado o no responde en el primero: evita
    # repetir el motivo en cada alerta.
    degradado = not expl.available()
    for i, ev in enumerate(events, 1):
        texto = expl.explain(ev) if expl.available() else None
        if texto is None:
            texto = template_summary(ev)
            if expl.available():
                degradado = True
        L.append("")
        L.append(f"  [{i}] {_sev_label(ev)} · {ev.kind or 'evento'}")
        for linea in texto.splitlines() or [texto]:
            L.append(f"      {linea}")

    if degradado and expl.available():
        L.append("")
        L.append("  [i] Ollama no respondió para alguna alerta; se mostró el "
                 "resumen-plantilla local.")
        L.append(f"      (modelo '{expl.model}' en {expl.url} — "
                 "¿está corriendo `ollama serve`?)")
    L.append(_RULE)
    return "\n".join(L)
