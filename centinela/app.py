"""Orquestador: arranca todas las capas y conecta el pipeline.

Pipeline:  Colectores -> Bus -> [Enriquecimiento -> Correlación -> Persistencia] -> Bus -> Presentación

El procesador central consume eventos crudos del bus, los enriquece, los pasa
por la correlación (que puede re-publicar alertas) y los persiste. La
presentación se suscribe al mismo bus y ve tanto eventos crudos enriquecidos
como las alertas sintéticas.
"""
from __future__ import annotations

import asyncio
import argparse

from .core import EventBus
from .collectors.authlog import AuthLogCollector
from .collectors.sniffer import SnifferCollector
from .collectors.simulator import SimulatorCollector
from .enrichment.resolver import Enricher
from .correlation.engine import CorrelationEngine
from .storage.db import EventStore
from .presentation.terminal import TerminalDashboard


class Centinela:
    def __init__(self, args) -> None:
        self.bus = EventBus()
        self.enricher = Enricher(oui_db=_load_oui(args.oui),
                                 resolve_rdns=args.rdns)
        self.engine = CorrelationEngine(self.bus)
        self.store = EventStore(args.db)
        self.dashboard = TerminalDashboard(self.bus, self.engine)
        self.collectors = []
        if args.simulate:
            self.collectors.append(SimulatorCollector(self.bus))
        if not args.no_authlog:
            self.collectors.append(AuthLogCollector(self.bus, args.authlog_path))
        if args.sniff:
            self.collectors.append(SnifferCollector(self.bus, args.iface))

    async def _pipeline(self) -> None:
        """Consume crudos -> enriquece -> correla -> persiste."""
        queue = self.bus.subscribe()
        while True:
            ev = await queue.get()
            if ev.source == "correlation":   # alertas ya procesadas: solo persistir
                await self.store.save(ev)
                continue
            ev = await self.enricher.enrich(ev)
            ev = await self.engine.process(ev)
            await self.store.save(ev)

    async def run(self) -> None:
        tasks = [asyncio.create_task(self._pipeline()),
                 asyncio.create_task(self.dashboard.run())]
        active = []
        for c in self.collectors:
            if c.available():
                active.append(c.name)
                tasks.append(asyncio.create_task(c.run()))
        if not active:
            print("[centinela] Aviso: ningún colector disponible "
                  "(¿permisos? ¿auth.log? ¿scapy?). Corriendo en vacío.")
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            pass
        finally:
            self.store.close()


def _load_oui(path: str | None) -> dict[str, str]:
    if not path:
        return {}
    import csv
    db = {}
    try:
        with open(path, newline="") as f:
            for row in csv.reader(f):
                if len(row) >= 2:
                    db[row[0].strip().lower()] = row[1].strip()
    except OSError:
        pass
    return db


def main() -> None:
    p = argparse.ArgumentParser(prog="centinela",
        description="Centinela — rastreo multicapa de amenazas en tiempo real")
    p.add_argument("--db", default="centinela.db", help="ruta del event store")
    p.add_argument("--simulate", action="store_true",
                   help="generar ataques sintéticos (demo sin root)")
    p.add_argument("--sniff", action="store_true",
                   help="activar captura de paquetes (requiere root + scapy)")
    p.add_argument("--iface", default=None, help="interfaz para el sniffer")
    p.add_argument("--no-authlog", action="store_true",
                   help="desactivar colector de auth.log")
    p.add_argument("--authlog-path", default=None, help="ruta a auth.log/secure")
    p.add_argument("--rdns", action="store_true",
                   help="resolver DNS inverso en background (más contexto)")
    p.add_argument("--oui", default=None,
                   help="CSV de OUI (prefijo_mac,fabricante) para resolver vendor")
    args = p.parse_args()
    try:
        asyncio.run(Centinela(args).run())
    except KeyboardInterrupt:
        print("\n[centinela] detenido")


if __name__ == "__main__":
    main()
