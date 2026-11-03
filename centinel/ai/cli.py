"""Glue del modo `--explain`: lee el event store y explica las alertas.

Solo lectura sobre la BD, como `--report`. Toma los últimos eventos por encima
de un umbral y los pasa por el explicador local (Ollama). Si Ollama no está, se
degrada al resumen-plantilla local — nunca falla ni bloquea.
"""
from __future__ import annotations

from ..core import Severity
from .explainer import OllamaExplainer, _sev_label, template_summary

_RULE = "─" * 62


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
    enabled = expl.available()
    if not enabled:
        L.append(f"  [!] {expl.reason}")
        L.append("      Se usa el resumen-plantilla local en su lugar.")
    else:
        # El loopback no autentica quién escucha: si el puerto lo tiene otro
        # usuario, no le mandamos los datos del store (ver peer_trusted).
        ok, motivo = expl.peer_trusted()
        if not ok:
            enabled = False
            L.append(f"  [!] {motivo}")
            L.append("      Se usa el resumen-plantilla local en su lugar.")

    if not events:
        L.append("")
        L.append("  (event store vacío o sin alertas sobre el umbral)")
        L.append(_RULE)
        return "\n".join(L)

    degradado = False
    for i, ev in enumerate(events, 1):
        if enabled:
            texto = expl.explain(ev)
            if texto is None:
                # Primera falla de Ollama: dejamos de intentar y plantilleamos el
                # resto, para no esperar limit×timeout (nunca bloquea de más).
                enabled = False
                degradado = True
                texto = template_summary(ev)
        else:
            texto = template_summary(ev)
        L.append("")
        L.append(f"  [{i}] {_sev_label(ev)} · {ev.kind or 'evento'}")
        for linea in texto.splitlines() or [texto]:
            L.append(f"      {linea}")

    if degradado:
        L.append("")
        L.append("  [i] Ollama no respondió; se mostró el resumen-plantilla "
                 "local para el resto.")
        L.append(f"      (modelo '{expl.model}' en {expl.url} — "
                 "¿está corriendo `ollama serve`?)")
    L.append(_RULE)
    return "\n".join(L)
