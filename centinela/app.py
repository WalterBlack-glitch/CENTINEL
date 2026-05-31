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
from .collectors.journald import JournaldCollector
from .collectors.sniffer import SnifferCollector
from .collectors.simulator import SimulatorCollector
from .enrichment.resolver import Enricher
from .enrichment.geo import GeoResolver
from .correlation.engine import CorrelationEngine
from .storage.db import EventStore
from .presentation.terminal import TerminalDashboard
from .presentation.assess import AssessmentDashboard
from .presentation.web import WebDashboard
from .response.firewall import Firewall
from .response.responder import Responder
from .security import drop_privileges, safe_path, valid_iface


class Centinela:
    def __init__(self, args) -> None:
        self.args = args
        # Dos buses: bus_in recibe eventos crudos de colectores (y alertas de la
        # correlación); el pipeline enriquece+correla y republica en bus_out, al
        # que se suscribe la presentación. Así la UI nunca ve un evento a medio
        # enriquecer (sin geo/MAC) — elimina la carrera de mutación in-place.
        self.bus = EventBus()       # entrada
        self.bus_out = EventBus()   # salida (ya enriquecido)
        oui = safe_path(args.oui, must_exist=True) if args.oui else None
        geo = GeoResolver(safe_path(args.geo, must_exist=True)) \
            if args.geo else None
        self.enricher = Enricher(oui_db=_load_oui(oui),
                                 resolve_rdns=args.rdns, geo=geo)
        self.engine = CorrelationEngine(self.bus)
        self.store = EventStore(safe_path(args.db))
        if args.web:
            self.dashboard = WebDashboard(self.bus_out, self.engine,
                                          host=args.web_host, port=args.web_port)
        elif args.assess:
            fw = Firewall(mode="live" if args.respond_live else "dry-run",
                          allowlist=args.allow or [])
            responder = Responder(self.engine, fw, threshold=args.block_threshold)
            self.dashboard = AssessmentDashboard(self.bus_out, responder,
                                                 window=args.assess_window)
        else:
            self.dashboard = TerminalDashboard(self.bus_out, self.engine)
        self.collectors = []
        if args.simulate:
            self.collectors.append(SimulatorCollector(self.bus))
        if not args.no_authlog:
            # Preferir journald (procedencia confiable) si está disponible;
            # caer a auth.log en su defecto. --authlog fuerza el archivo plano.
            jd = JournaldCollector(self.bus)
            if jd.available() and not args.authlog:
                self.collectors.append(jd)
            else:
                apath = safe_path(args.authlog_path, must_exist=True) \
                    if args.authlog_path else None
                self.collectors.append(AuthLogCollector(self.bus, apath))
        if args.sniff:
            self.collectors.append(
                SnifferCollector(self.bus, valid_iface(args.iface)))

    async def _pipeline(self) -> None:
        """Consume crudos de bus_in -> enriquece -> correla -> persiste ->
        republica enriquecido en bus_out (lo que ve la presentación)."""
        queue = self.bus.subscribe()
        while True:
            ev = await queue.get()
            if ev.source == "correlation":   # alerta ya procesada: persiste y reenvía
                await self.store.save(ev)
                await self.bus_out.publish(ev)
                continue
            ev = await self.enricher.enrich(ev)
            ev = await self.engine.process(ev)
            await self.store.save(ev)
            await self.bus_out.publish(ev)

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
        # A-2: soltar privilegios una vez los colectores abrieron sus recursos
        # privilegiados (socket de captura / fd de auth.log).
        if not self.args.no_drop:
            await asyncio.sleep(0.5)
            if drop_privileges(self.args.user):
                print(f"[centinela] privilegios soltados a '{self.args.user}'")
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
                   help="desactivar el colector de logs de autenticación")
    p.add_argument("--authlog", action="store_true",
                   help="forzar lectura de /var/log/auth.log en vez de journald")
    p.add_argument("--authlog-path", default=None, help="ruta a auth.log/secure")
    p.add_argument("--rdns", action="store_true",
                   help="resolver DNS inverso en background (más contexto)")
    p.add_argument("--oui", default=None,
                   help="CSV de OUI (prefijo_mac,fabricante) para resolver vendor")
    p.add_argument("--web", action="store_true",
                   help="dashboard web en vivo (WebSocket + mapa geo)")
    p.add_argument("--web-host", default="127.0.0.1", help="host del dashboard web")
    p.add_argument("--web-port", type=int, default=8787, help="puerto del web")
    p.add_argument("--geo", default=None,
                   help="ruta a GeoLite2-City.mmdb para geolocalizar IPs")
    p.add_argument("--assess", action="store_true",
                   help="modo examen: monitorea, prioriza, corrige y sigue")
    p.add_argument("--assess-window", type=float, default=15.0,
                   help="segundos de cada ciclo de examen")
    p.add_argument("--block-threshold", type=float, default=70.0,
                   help="score a partir del cual se bloquea a un actor")
    p.add_argument("--respond-live", action="store_true",
                   help="aplicar bloqueos REALES en firewall (default: dry-run)")
    p.add_argument("--allow", action="append", default=None,
                   help="IP/red que nunca se bloquea (repetible)")
    p.add_argument("--user", default="nobody",
                   help="usuario al que soltar privilegios tras abrir recursos")
    p.add_argument("--no-drop", action="store_true",
                   help="no soltar privilegios (no recomendado)")
    args = p.parse_args()
    if args.simulate and args.respond_live:
        p.error("--respond-live no se permite con --simulate "
                "(evita bloquear IPs reales con tráfico ficticio)")
    try:
        asyncio.run(Centinela(args).run())
    except KeyboardInterrupt:
        print("\n[centinela] detenido")


if __name__ == "__main__":
    main()
