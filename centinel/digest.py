"""Digest periódico: resumen de actividad empujado a un webhook.

Cuando nadie mira el dashboard, una ráfaga de eventos MEDIUM puede pasar
inadvertida porque ninguno cruza el umbral de alerta inmediata. El digest
resuelve eso enviando, cada N horas, un resumen de lo ocurrido en la ventana:
totales, reparto por severidad, top de tipos (con TTP de MITRE) y top de
actores, más el estado de la cadena HMAC (¿sigue íntegra la BD?).

Reutiliza piezas existentes y NO añade dependencias:
  - storage.db.EventStore.summary_since  -> datos (solo lectura, parametrizado)
  - alerter.post_json / _validate_webhook_url -> red endurecida (anti-SSRF)

Best-effort: si el webhook falla, no tumba nada. El servicio degrada con
elegancia si la URL es peligrosa (available() = False).
"""
from __future__ import annotations

import asyncio
import time

from .alerter import _validate_webhook_url, post_json
from .storage.db import EventStore

_SEV = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def _sev_label(n: int) -> str:
    return _SEV[min(max(int(n), 0), 4)]


def build_digest(summary: dict, *, window_h: float, db_path: str = "",
                 chain: dict | None = None) -> dict:
    """Construye el payload del digest a partir del resumen de la BD.

    Función pura: recibe el dict de `EventStore.summary_since` (+ estado de
    cadena opcional) y devuelve {text, centinel}. Testeable sin red ni BD.
    """
    total = int(summary.get("total", 0))
    sev = summary.get("severity", {}) or {}
    kinds = summary.get("kinds", []) or []
    actors = summary.get("actors", []) or []

    crit = int(sev.get(4, 0))
    high = int(sev.get(3, 0))
    head = ""
    chain_ok = True
    if chain is not None:
        chain_ok = bool(chain.get("ok", True))
        head = str(chain.get("head", "") or "")

    lines = [f"[CENTINEL] digest · últimas {window_h:g}h",
             f"eventos: {total}  (CRITICAL {crit} · HIGH {high})"]
    if total:
        sev_txt = " · ".join(f"{_sev_label(s)} {sev[s]}"
                             for s in sorted(sev, reverse=True))
        lines.append(f"severidad: {sev_txt}")
        if kinds:
            top = ", ".join(f"{k['kind']}×{k['n']}" for k in kinds[:5])
            lines.append(f"tipos: {top}")
        if actors:
            top = ", ".join(
                f"{a['src_ip']}({a.get('n', 0)})" for a in actors[:5]
                if a.get("src_ip"))
            if top:
                lines.append(f"actores: {top}")
    else:
        lines.append("(sin eventos en la ventana)")
    lines.append(f"cadena: {'íntegra' if chain_ok else '⚠ MANIPULADA'}"
                 + (f" · head {head[:16]}…" if head else ""))

    return {
        "text": "\n".join(lines),
        "centinel": {
            "digest": True,
            "window_hours": window_h,
            "total": total,
            "critical": crit,
            "high": high,
            "severity": {str(k): v for k, v in sev.items()},
            "kinds": [{"kind": k["kind"], "count": k["n"]} for k in kinds],
            "actors": [{"ip": a.get("src_ip"), "count": a.get("n")}
                       for a in actors if a.get("src_ip")],
            "chain_ok": chain_ok,
            "chain_head": head,
            "db": db_path,
            "generated_at": time.time(),
        },
    }


class DigestService:
    """Servicio asíncrono que cada `interval_h` horas envía un digest al webhook.

    Lee la BD en una conexión propia (SQLite WAL admite lectores concurrentes
    con el escritor principal). No requiere root ni acceso al bus de eventos.
    """
    name = "digest"

    def __init__(self, db_path: str, url: str, interval_h: float = 24.0,
                 timeout: float = 6.0) -> None:
        self.db_path = db_path
        ok, why = _validate_webhook_url(url)
        if not ok:
            print(f"[centinel] digest: URL rechazada ({why}); digest desactivado.")
            self.url = ""
        else:
            self.url = url
        self.interval = max(60.0, float(interval_h) * 3600.0)
        self.timeout = timeout

    def available(self) -> bool:
        return bool(self.url)

    def _build_blocking(self) -> dict:
        since = time.time() - self.interval
        st = EventStore(self.db_path)
        try:
            summary = st.summary_since(since)
            chain = st.verify_chain()
        finally:
            st.close()
        return build_digest(summary, window_h=self.interval / 3600.0,
                            db_path=self.db_path, chain=chain)

    async def run(self) -> None:
        if not self.available():
            return
        while True:
            await asyncio.sleep(self.interval)
            try:
                payload = await asyncio.to_thread(self._build_blocking)
                await asyncio.to_thread(post_json, self.url, payload, self.timeout)
            except asyncio.CancelledError:
                raise
            except Exception:   # noqa: BLE001 — nunca tumbar el servicio
                pass
