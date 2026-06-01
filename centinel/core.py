"""Núcleo de Centinel: modelo de evento unificado y bus asíncrono.

Todas las capas hablan a través de `ThreatEvent`. Los colectores publican,
el enriquecimiento y la correlación transforman/anotan, y la presentación
consume. El bus es un fan-out async sin dependencias externas.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Any, AsyncIterator


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class ThreatEvent:
    """Evento normalizado que fluye por todas las capas."""

    ts: float = field(default_factory=time.time)
    source: str = ""          # qué colector lo generó (authlog, sniffer, arp...)
    kind: str = ""            # login_fail, port_scan, arp_announce, http_probe...
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    mac: str | None = None    # MAC de origen si es visible (solo LAN)
    user: str | None = None   # usuario objetivo si aplica
    severity: Severity = Severity.INFO
    score: float = 0.0        # score acumulado de amenaza (lo fija la correlación)
    message: str = ""
    enrichment: dict[str, Any] = field(default_factory=dict)  # geo, asn, rdns...
    tags: set[str] = field(default_factory=set)
    raw: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = int(self.severity)
        d["tags"] = sorted(self.tags)
        return d


class EventBus:
    """Bus pub/sub async con fan-out a múltiples suscriptores."""

    def __init__(self) -> None:
        self._subscribers: list[asyncio.Queue[ThreatEvent]] = []
        self.dropped = 0  # B-3: eventos descartados bajo presión (posible evasión)

    def subscribe(self, maxsize: int = 1000) -> asyncio.Queue[ThreatEvent]:
        q: asyncio.Queue[ThreatEvent] = asyncio.Queue(maxsize=maxsize)
        self._subscribers.append(q)
        return q

    async def publish(self, event: ThreatEvent) -> None:
        for q in self._subscribers:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                # Bajo presión preferimos descartar lo viejo del consumidor lento.
                try:
                    q.get_nowait()       # descarta el más viejo del lento
                    self.dropped += 1
                    q.put_nowait(event)
                except asyncio.QueueEmpty:
                    pass

    async def stream(self, maxsize: int = 1000) -> AsyncIterator[ThreatEvent]:
        q = self.subscribe(maxsize)
        while True:
            yield await q.get()
