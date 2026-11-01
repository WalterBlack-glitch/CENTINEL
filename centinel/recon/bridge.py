"""Puente opt-in RECON → event store firmado del IDS.

Permite que los hallazgos de una sesión de recon entren en la MISMA línea de
tiempo tamper-evident que el resto de eventos del IDS, para correlacionarlos
junto a la actividad en vivo del host.

Dos capas, separadas a propósito (como el resto del repo):

  - **Lógica pura** (`finding_to_event` / `findings_to_events`): traduce un
    `Finding` de recon a un `ThreatEvent` del núcleo. Determinista, sin disco,
    sin red, sin reloj implícito (el `ts` entra como parámetro). Es lo que
    atacan los tests directamente.
  - **Persistencia delgada** (`persist_findings` / `persist_events`): reutiliza
    el `EventStore` existente SIN duplicar su lógica de cadena HMAC. Degrada sin
    tumbar: si el store no está disponible o falla, se loguea y la sesión de
    recon sigue viva.

Identidad de un hallazgo = clave natural `tipo|puerto|proto|url|fuzz` (la misma
de `parse.dedupe` y `diff.key`, nunca un PID ni algo efímero). Se reutiliza para
deduplicar antes de insertar y se graba en `enrichment["recon_key"]` para que la
correlación pueda cruzarla.
"""
from __future__ import annotations

from typing import Callable, Iterable

from ..core import Severity, ThreatEvent
from .diff import key as _key_tuple
from .model import Finding
from .parse import dedupe

# Prefijo de `source` para distinguir el origen recon en el store y las queries.
SOURCE = "recon"


def natural_key(f: Finding) -> str:
    """Clave natural del hallazgo como cadena estable `tipo|puerto|proto|url|fuzz`.

    Deriva de la misma tupla que `diff.key`/`parse.dedupe`; aquí se serializa a
    texto para guardarla en el evento y poder cruzarla en la correlación. Pura.
    """
    kind, port, proto, url, fuzz = _key_tuple(f)
    return "|".join((kind or "", "" if port is None else str(port),
                     proto or "", url or "", fuzz or ""))


def _severity(f: Finding) -> Severity:
    """Severidad determinista de un hallazgo de recon.

    El recon es informativo por naturaleza: un puerto abierto en un objetivo
    autorizado no es un ataque. Se marca LOW lo accionable (superficie expuesta:
    puertos abiertos, rutas/subdominios hallados) e INFO lo demás. Puro.
    """
    if f.kind == "port":
        return Severity.LOW if f.state.startswith("open") else Severity.INFO
    if f.kind in ("path", "subdomain"):
        return Severity.LOW
    return Severity.INFO


def _message(f: Finding, target: str, tool: str) -> str:
    """Resumen legible de un hallazgo para el campo `message`. Puro."""
    pre = f"{tool} " if tool else ""
    if f.kind == "port":
        v = f" {f.version}" if f.version else ""
        return (f"{pre}{target}: puerto {f.port}/{f.proto} {f.state} "
                f"{f.service}{v}").strip()
    if f.kind == "subdomain":
        return f"{pre}{target}: subdominio {f.fuzz} ({f.url}) [{f.status}]".strip()
    if f.kind == "path":
        return f"{pre}{target}: ruta {f.url} [{f.status}] len={f.length}".strip()
    return f"{pre}{target}: {f.kind}".strip()


def finding_to_event(f: Finding, *, target: str, tool: str = "",
                     scan_kind: str = "", ts: float = 0.0) -> ThreatEvent:
    """Traduce un `Finding` de recon a un `ThreatEvent`. Pura y determinista.

    `ts` entra como parámetro (no se llama al reloj aquí) para que la traducción
    sea testeable sin mocks. La capa de persistencia pasa el `ts` real del scan.
    """
    nk = natural_key(f)
    tags = {"recon"}
    if tool:
        tags.add(tool)
    enrichment = {
        "recon_key": nk,
        "target": target,
        "tool": tool,
        "scan_kind": scan_kind,
        **f.to_dict(),
    }
    return ThreatEvent(
        ts=float(ts),
        source=SOURCE,
        kind=f"recon_{f.kind}" if f.kind else "recon",
        dst_ip=target or None,
        dst_port=f.port,
        severity=_severity(f),
        message=_message(f, target, tool),
        enrichment=enrichment,
        tags=tags,
    )


def findings_to_events(findings: Iterable[Finding], *, target: str,
                       tool: str = "", scan_kind: str = "",
                       ts: float = 0.0) -> list[ThreatEvent]:
    """Deduplica por clave natural y traduce a eventos. Pura.

    El dedupe reutiliza `parse.dedupe` (misma clave natural), así un puerto que
    ya se vio no genera un evento repetido en la misma tanda.
    """
    return [finding_to_event(f, target=target, tool=tool, scan_kind=scan_kind,
                             ts=ts)
            for f in dedupe(list(findings))]


# --------------------------------------------------------------------------
# Persistencia delgada (I/O) — reutiliza el EventStore, nunca lo reimplementa.
# --------------------------------------------------------------------------

def _noop(_msg: str) -> None:
    pass


def persist_events(events: list[ThreatEvent], *, db_path: str = "centinel.db",
                   log: Callable[[str], None] | None = None) -> dict:
    """Guarda eventos ya traducidos en el event store firmado. Degrada sin tumbar.

    Devuelve un dict `{"ok", "saved", "head", "error"}`. Ante CUALQUIER fallo del
    store (no disponible, corrupto, permisos) no lanza: loguea vía `log` y vuelve
    con `ok=False`, para que la sesión de recon siga viva.
    """
    out = {"ok": False, "saved": 0, "head": None, "error": ""}
    logf = log or _noop
    if not events:
        out["ok"] = True
        return out
    try:
        import asyncio

        from ..storage.db import EventStore
    except Exception as e:  # noqa: BLE001 — import puede fallar en entorno mínimo
        out["error"] = f"event store no disponible: {e}"
        logf(out["error"])
        return out

    store = None
    try:
        store = EventStore(db_path)

        async def _save_all() -> None:
            for ev in events:
                await store.save(ev)

        asyncio.run(_save_all())
        out["saved"] = len(events)
        out["head"] = store.head_hash()
        out["ok"] = True
    except Exception as e:  # noqa: BLE001 — jamás tumbar el recon por el store
        out["error"] = f"no se pudo escribir en el event store: {e}"
        logf(out["error"])
    finally:
        if store is not None:
            try:
                store.close()
            except Exception:  # noqa: BLE001
                pass
    return out


def persist_findings(findings: Iterable[Finding], *, target: str, tool: str = "",
                     scan_kind: str = "", ts: float = 0.0,
                     db_path: str = "centinel.db",
                     log: Callable[[str], None] | None = None) -> dict:
    """Traduce (puro) y persiste (I/O) hallazgos de recon en una llamada."""
    events = findings_to_events(findings, target=target, tool=tool,
                                scan_kind=scan_kind, ts=ts)
    return persist_events(events, db_path=db_path, log=log)
