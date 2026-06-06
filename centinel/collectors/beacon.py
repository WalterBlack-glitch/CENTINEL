"""BeaconCollector: muestrea conexiones salientes y delega en BeaconAnalyzer.

Detección por flanco de aparición: en cada barrido calcula el conjunto de IPs
remotas externas con conexión ESTABLISHED; las que NO estaban en el barrido
anterior cuentan como un "contacto nuevo" y se le pasan al analizador. Así un
beacon que se reconecta cada periodo genera un contacto por periodo aunque la
conexión sea breve.

Solo lectura de /proc. Sin subprocess, sin red, sin dependencias. Degrada con
elegancia: si no puede leer /proc, available()=False; si un barrido falla, lo
ignora y sigue.
"""
from __future__ import annotations

import asyncio
import os
import time

from ..core import Severity, ThreatEvent
from ..correlation.beacon import BeaconAnalyzer, BeaconVerdict
from .base import Collector
from ._proc_net import established_remote_ips


class BeaconCollector(Collector):
    name = "beacon"

    def __init__(self, bus, interval: float = 5.0,
                 analyzer: BeaconAnalyzer | None = None) -> None:
        super().__init__(bus)
        self.interval = max(1.0, interval)
        self.analyzer = analyzer or BeaconAnalyzer()
        self._present: set[str] = set()

    def available(self) -> bool:
        return os.name == "posix" and os.path.exists("/proc/net/tcp")

    async def run(self) -> None:
        if not self.available():
            return
        while True:
            try:
                now_ips = await asyncio.to_thread(established_remote_ips)
                for ev in self._step(now_ips, time.time()):
                    await self.emit(ev)
            except Exception:   # noqa: BLE001 — nunca tumbar el colector
                pass
            await asyncio.sleep(self.interval)

    def _step(self, now_ips: set[str], ts: float) -> list[ThreatEvent]:
        """Detección por flanco: IPs nuevas respecto al barrido previo -> contacto.

        Aislado de la I/O de /proc para poder testear la periodicidad sin red."""
        new = now_ips - self._present
        self._present = set(now_ips)
        events: list[ThreatEvent] = []
        for ip in new:
            verdict = self.analyzer.observe(ip, ts)
            if verdict is not None:
                events.append(self._event(verdict))
        self.analyzer.gc(ts)
        return events

    @staticmethod
    def _event(v: BeaconVerdict) -> ThreatEvent:
        # src_ip = IP remota: así fluye por geo/rDNS/KEV y la correlación la
        # puntúa como un actor más (consistente con netwatch).
        return ThreatEvent(
            kind="beacon_c2", src_ip=v.dst, severity=Severity(v.severity),
            message=(f"Posible beacon C2 a {v.dst}: {v.hits} contactos a "
                     f"intervalos regulares (~{v.period:.0f}s, jitter "
                     f"{v.jitter * 100:.0f}%) — patrón de callback automatizado"),
            tags={"beacon", "c2", "l4"},
            enrichment={"period_s": round(v.period, 1),
                        "jitter": round(v.jitter, 3),
                        "hits": v.hits, "pattern": "periodic_callback"})
