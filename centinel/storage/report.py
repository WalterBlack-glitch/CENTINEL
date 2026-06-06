"""Informe forense y verificación de integridad desde la CLI.

  centinel --report       -> resumen legible del event store (sin arrancar capas)
  centinel --verify-log    -> recorre la cadena HMAC y dice si tocaron la BD

Solo lectura sobre la BD; reutiliza EventStore (misma clave HMAC, misma lógica
de cadena) para que la verificación use exactamente el mismo cálculo que la
escritura.
"""
from __future__ import annotations

import os
import time

from .db import EventStore

_SEV = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
_RULE = "─" * 62


def _mitre(kind: str) -> str | None:
    from ..alerter import mitre_for   # import perezoso: evita ciclo
    return mitre_for(kind)


def _fmt_ts(ts: float | None) -> str:
    if not ts:
        return "—"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def _fmt_dur(secs: float) -> str:
    secs = int(max(0, secs))
    d, secs = divmod(secs, 86400)
    h, secs = divmod(secs, 3600)
    m, s = divmod(secs, 60)
    parts = []
    if d:
        parts.append(f"{d}d")
    if h:
        parts.append(f"{h}h")
    if m:
        parts.append(f"{m}m")
    parts.append(f"{s}s")
    return " ".join(parts)


def _bar(n: int, total: int, width: int = 24) -> str:
    if total <= 0:
        return ""
    filled = round(width * n / total)
    return "█" * filled + "·" * (width - filled)


def _chain_lines(chain: dict, head: str) -> list[str]:
    out = ["", "  integridad de la cadena:"]
    if chain["ok"]:
        out.append(f"    [OK] intacta — {chain['checked']} fila(s) "
                   f"encadenada(s) verificada(s)")
        if chain.get("gaps"):
            out.append(f"    [!]  {len(chain['gaps'])} hueco(s) de id detectado(s): "
                       f"posible borrado con clave comprometida")
            for a, b in chain["gaps"][:5]:
                out.append(f"         entre id {a} y id {b}")
        if chain.get("legacy"):
            out.append(f"    [·]  {chain['legacy']} fila(s) antiguas sin encadenar "
                       f"(anteriores a la feature; no verificables)")
    else:
        out.append(f"    [X]  MANIPULACIÓN DETECTADA — {chain.get('reason')}")
        out.append(f"         primera fila afectada: id={chain.get('broken_at')}")
        out.append(f"         filas íntegras antes del corte: {chain['checked']}")
    out.append(f"    head: {head}")
    out.append("    (ancla este head fuera de la máquina para defensa anti-root)")
    return out


def forensic_report(db_path: str) -> str:
    """Genera el informe forense completo como texto."""
    st = EventStore(db_path)
    try:
        total = st.count()
        lo, hi = st.time_range()
        sev = st.by_severity()
        kinds = st.by_kind()
        actors = st.top_actors(10)
        chain = st.verify_chain()
        head = st.head_hash()
    finally:
        st.close()

    L = [_RULE, "  CENTINEL · informe forense", _RULE]
    L.append(f"  base de datos : {db_path}")
    L.append(f"  eventos       : {total}")
    if lo and hi:
        L.append(f"  rango temporal: {_fmt_ts(lo)}  ->  {_fmt_ts(hi)}")
        L.append(f"  duración      : {_fmt_dur(hi - lo)}")

    if not total:
        L.append("")
        L.append("  (event store vacío: aún no se ha registrado ningún evento)")
        L += _chain_lines(chain, head)
        L.append(_RULE)
        return "\n".join(L)

    if sev:
        L.append("")
        L.append("  severidad:")
        for s in sorted(sev, reverse=True):
            label = _SEV[min(s, 4)]
            L.append(f"    {label:<9} {sev[s]:>7}  {_bar(sev[s], total)}")

    if kinds:
        L.append("")
        L.append("  tipos de evento (top):")
        for k in kinds:
            ttp = _mitre(k["kind"])
            tag = f"  [{ttp}]" if ttp else ""
            L.append(f"    {str(k['kind']):<26} {k['n']:>6}{tag}")

    if actors:
        L.append("")
        L.append("  actores principales (por score):")
        for a in actors:
            ip = str(a.get("src_ip"))
            score = a.get("s") or 0.0
            L.append(f"    {ip:<20} score={score:>6.1f}  eventos={a.get('n'):>5}")

    L += _chain_lines(chain, head)
    L.append(_RULE)
    return "\n".join(L)


def verify_log(db_path: str) -> tuple[bool, str]:
    """Verifica solo la integridad. Devuelve (ok, texto)."""
    if not os.path.exists(db_path):
        return False, f"[centinel] no existe la BD: {db_path}"
    st = EventStore(db_path)
    try:
        chain = st.verify_chain()
        head = st.head_hash()
        total = st.count()
    finally:
        st.close()
    lines = [f"[centinel] verificación de integridad de {db_path} "
             f"({total} eventos):"]
    lines += _chain_lines(chain, head)
    ok = chain["ok"] and not chain.get("gaps")
    return ok, "\n".join(lines)
