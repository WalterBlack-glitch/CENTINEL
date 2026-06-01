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
import os
import sys

from .core import EventBus
from .collectors.authlog import AuthLogCollector
from .collectors.journald import JournaldCollector
from .collectors.sniffer import SnifferCollector
from .collectors.simulator import SimulatorCollector
from .collectors.honeypot import HoneypotCollector
from .collectors.netwatch import NetWatchCollector
from .collectors.persistence import PersistenceCollector
from .enrichment.resolver import Enricher
from .enrichment.geo import GeoResolver
from .intel.kev import KevCatalog
from .correlation.engine import CorrelationEngine
from .storage.db import EventStore
from .presentation.terminal import TerminalDashboard
from .presentation.assess import AssessmentDashboard
from .presentation.web import WebDashboard
from .response.firewall import Firewall
from .response.responder import Responder
from .security import drop_privileges, layers_need_sustained_root, safe_path, valid_iface


class Centinel:
    def __init__(self, args) -> None:
        self.args = args
        self.runtime_errors: list[str] = []   # fallos en ejecución -> informe
        # Dos buses: bus_in recibe eventos crudos de colectores (y alertas de la
        # correlación); el pipeline enriquece+correla y republica en bus_out, al
        # que se suscribe la presentación. Así la UI nunca ve un evento a medio
        # enriquecer (sin geo/MAC) — elimina la carrera de mutación in-place.
        self.bus = EventBus()       # entrada
        self.bus_out = EventBus()   # salida (ya enriquecido)
        oui = safe_path(args.oui, must_exist=True) if args.oui else None
        geo = GeoResolver(safe_path(args.geo, must_exist=True)) \
            if args.geo else None
        self.kev = self._setup_kev(args)
        self.enricher = Enricher(oui_db=_load_oui(oui),
                                 resolve_rdns=args.rdns, geo=geo, kev=self.kev)
        canary = {u.strip() for u in (args.canary or "").split(",") if u.strip()}
        self.engine = CorrelationEngine(self.bus, canary_users=canary)
        self.store = EventStore(safe_path(args.db))
        if args.web:
            # Respuesta activa para el dashboard: dry-run por defecto (registra
            # sin tocar el firewall); --respond-live aplica nft/iptables de verdad.
            fw = Firewall(mode="live" if args.respond_live else "dry-run",
                          allowlist=args.allow or [])
            responder = Responder(self.engine, fw, threshold=args.block_threshold)
            self.dashboard = WebDashboard(self.bus_out, self.engine,
                                          host=args.web_host, port=args.web_port,
                                          responder=responder,
                                          auth_token=args.web_token)
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
        if args.honeypot:
            ports = [p for p in (args.honeypot or "").split(",") if p.strip()]
            self.collectors.append(
                HoneypotCollector(self.bus, ports, host=args.honeypot_host))
        if args.netwatch:
            self.collectors.append(
                NetWatchCollector(self.bus, interval=args.netwatch_interval))
        if args.rootcheck:
            from .maintenance import MaintenanceContext
            maint = None if args.maintenance_off else MaintenanceContext(
                grace_seconds=args.maintenance_grace)
            self.collectors.append(
                PersistenceCollector(self.bus,
                                     interval=args.rootcheck_interval,
                                     store_dir=args.baseline_dir,
                                     maintenance=maint))

    def _setup_kev(self, args):
        if not (args.kev_cache or args.kev_update):
            return None
        cache = args.kev_cache or "kev.json"
        kev = KevCatalog(cache)
        if args.kev_update:
            ok, detail = kev.update()   # descarga al arranque (fuera del hot-path)
            print(f"[centinel] {detail}")
        if kev.available:
            print(f"[centinel] KEV cargado: {kev.count} CVEs explotados")
        else:
            print("[centinel] KEV sin datos (usa --kev-update para descargar)")
        return kev

    async def _pipeline(self) -> None:
        """Consume crudos de bus_in -> enriquece -> correla -> persiste ->
        republica enriquecido en bus_out (lo que ve la presentación).

        Cada evento se procesa en su propio try: un evento que reviente se
        descarta y se registra, pero NUNCA tumba el pipeline entero."""
        queue = self.bus.subscribe()
        while True:
            ev = await queue.get()
            try:
                if ev.source == "correlation":   # alerta ya procesada
                    await self.store.save(ev)
                    await self.bus_out.publish(ev)
                    continue
                ev = await self.enricher.enrich(ev)
                ev = await self.engine.process(ev)
                await self.store.save(ev)
                await self.bus_out.publish(ev)
            except asyncio.CancelledError:
                raise
            except Exception as exc:   # noqa: BLE001
                self._note_error("pipeline", exc)

    def _note_error(self, where: str, exc: BaseException) -> None:
        """Registra un fallo en ejecución (acotado) para el informe final."""
        msg = f"{where}: {type(exc).__name__}: {exc}"
        if msg not in self.runtime_errors:
            self.runtime_errors.append(msg)
            if len(self.runtime_errors) > 50:
                self.runtime_errors.pop(0)
            print(f"[centinel] aviso: {msg} (capa degradada, app sigue)")

    async def _guard(self, name: str, coro) -> None:
        """Envuelve una capa: si revienta, se desactiva sin tumbar el resto.

        Captura BaseException (no solo Exception) porque uvicorn lanza SystemExit
        al fallar el bind del puerto: eso NO debe tumbar la app entera. Solo se
        repropagan la cancelación y el Ctrl+C."""
        try:
            await coro
        except (asyncio.CancelledError, KeyboardInterrupt):
            raise
        except BaseException as exc:   # noqa: BLE001
            self._note_error(f"capa '{name}'", exc)

    async def run(self) -> None:
        tasks = [asyncio.create_task(self._pipeline()),
                 asyncio.create_task(self._guard("dashboard", self.dashboard.run()))]
        active = []
        for c in self.collectors:
            try:
                ok = c.available()
            except Exception as exc:   # noqa: BLE001
                self._note_error(f"colector '{c.name}'.available()", exc)
                ok = False
            if ok:
                active.append(c.name)
                tasks.append(asyncio.create_task(self._guard(c.name, c.run())))
        if not active:
            print("[centinel] Aviso: ningún colector disponible "
                  "(¿permisos? ¿auth.log? ¿scapy?). Corriendo en vacío.")
        # A-2: soltar privilegios una vez los colectores abrieron sus recursos
        # privilegiados (socket de captura / fd de auth.log).
        #
        # Bug crítico fixed: ANTES soltaba a 'nobody' incluso cuando la app
        # arrancaba degradada (sin colectores, capas reventadas, o pidiendo
        # respond-live/rootcheck/netwatch que necesitan root mantenido). El
        # operador se quedaba sin privilegios para diagnosticar y los bloqueos
        # nft fallaban en silencio. Ahora se omite el drop en esos casos y se
        # explica por qué.
        if not self.args.no_drop:
            await asyncio.sleep(0.5)
            need = layers_need_sustained_root(self.args)
            if not active:
                self._note_error("drop_privileges",
                    RuntimeError("omitido: ninguna capa activa (modo degradado, "
                                 "root retenido para diagnóstico)"))
            elif need:
                print(f"[centinel] privilegios retenidos: requieren root sostenido "
                      f"-> {', '.join(need)}. Usa --force-drop para forzar el drop.")
                if getattr(self.args, "force_drop", False):
                    ok, why = drop_privileges(self.args.user)
                    print(f"[centinel] drop forzado: {why}")
            elif self.runtime_errors:
                print(f"[centinel] privilegios retenidos: ya hay fallos de capa; "
                      f"root se mantiene para que puedas inspeccionar.")
            else:
                ok, why = drop_privileges(self.args.user)
                if ok:
                    print(f"[centinel] privilegios soltados a '{self.args.user}'")
                else:
                    self._note_error("drop_privileges",
                        RuntimeError(f"no se pudo soltar ({why}); sigo con root."))
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            pass
        finally:
            self.store.close()
            if self.runtime_errors:
                from .feedback import write_report
                extra = "\n".join(self.runtime_errors)
                path = write_report(extra="Fallos de capas en ejecución:\n" + extra)
                print(f"[centinel] {len(self.runtime_errors)} fallo(s) de capa "
                      f"durante la sesión. Informe para tu asistente en: {path}")


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
    p = argparse.ArgumentParser(prog="centinel",
        description="Centinel — rastreo multicapa de amenazas en tiempo real")
    p.add_argument("--db", default="centinel.db", help="ruta del event store")
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
    p.add_argument("--honeypot", default=None,
                   help="puertos-trampa separados por coma, p.ej. 2222,2323 "
                        "(toda conexión es maliciosa)")
    p.add_argument("--honeypot-host", default="0.0.0.0",
                   help="interfaz donde escucha el honeypot")
    p.add_argument("--netwatch", action="store_true",
                   help="rastrear procesos locales con conexión externa y marcar "
                        "binarios sospechosos (backdoors/C2). Root = visión total")
    p.add_argument("--netwatch-interval", type=float, default=10.0,
                   help="segundos entre escaneos de /proc del netwatch")
    p.add_argument("--rootcheck", action="store_true",
                   help="vigilar persistencia: SUID/SGID nuevos o en sitios raros "
                        "y cron/systemd con patrones de backdoor")
    p.add_argument("--rootcheck-interval", type=float, default=60.0,
                   help="segundos entre escaneos de persistencia")
    p.add_argument("--canary", default=None,
                   help="usuarios-cebo separados por coma; cualquier intento "
                        "contra ellos es CRÍTICO (defensa anti-IA)")
    p.add_argument("--oui", default=None,
                   help="CSV de OUI (prefijo_mac,fabricante) para resolver vendor")
    p.add_argument("--web", action="store_true",
                   help="dashboard web en vivo (WebSocket + mapa geo)")
    p.add_argument("--web-host", default="127.0.0.1", help="host del dashboard web")
    p.add_argument("--web-port", type=int, default=8787, help="puerto del web")
    p.add_argument("--geo", default=None,
                   help="ruta a GeoLite2-City.mmdb para geolocalizar IPs")
    p.add_argument("--kev-cache", default=None,
                   help="ruta de la caché del feed KEV de CISA (offline)")
    p.add_argument("--kev-update", action="store_true",
                   help="descargar/actualizar el feed KEV de CISA al arrancar")
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
    p.add_argument("--web-token", default=None,
                   help="token Bearer obligatorio para el dashboard. Si "
                        "expones --web-host fuera de loopback y no lo pasas, "
                        "se autogenera y se imprime al arranque.")
    p.add_argument("--ack-baseline", action="store_true",
                   help="acepta el estado actual como nueva baseline limpia "
                        "(borra las baselines firmadas y vuelve a fijarlas en "
                        "el próximo arranque). Úsalo tras hacer apt upgrade "
                        "consciente, o git pull de Centinel.")
    p.add_argument("--maintenance-grace", type=float, default=90.0,
                   help="segundos tras el arranque sin emitir alertas de "
                        "persistencia (deja que las baselines se estabilicen).")
    p.add_argument("--maintenance-off", action="store_true",
                   help="MODO PARANOICO: ignora apt/dpkg/git pull y emite "
                        "TODA alerta (más falsos positivos).")
    p.add_argument("--baseline-dir", default=None,
                   help="directorio para baselines firmadas (HMAC) del rootcheck. "
                        "Sin esto, las baselines viven solo en RAM y se pierden "
                        "al reiniciar (un atacante puede provocar reinicio y "
                        "blanquear su persistencia).")
    p.add_argument("--force-drop", action="store_true",
                   help="soltar privilegios aunque haya capas que requieran "
                        "root sostenido (degradará respond-live/rootcheck/netwatch)")
    p.add_argument("--no-doctor", action="store_true",
                   help="omitir el diagnóstico previo de errores")
    p.add_argument("--doctor", action="store_true",
                   help="solo ejecutar el diagnóstico y salir")
    args = p.parse_args()
    if args.simulate and args.respond_live:
        p.error("--respond-live no se permite con --simulate "
                "(evita bloquear IPs reales con tráfico ficticio)")
    from .doctor import run as doctor_run, has_blocking_errors
    from .feedback import write_report

    if args.ack_baseline:
        # Borra baselines firmadas: el próximo escaneo fija una nueva limpia.
        import shutil
        bd = args.baseline_dir or os.path.join(os.path.expanduser("~"),
                                               ".local", "share", "centinel",
                                               "baselines")
        if os.path.isdir(bd):
            shutil.rmtree(bd, ignore_errors=True)
            print(f"[centinel] baselines borradas en {bd}. "
                  f"En el próximo arranque se fijarán nuevas con el estado actual.")
        else:
            print(f"[centinel] no había baselines en {bd}; nada que hacer.")
        sys.exit(0)

    if args.doctor:
        findings = doctor_run(args)
        unresolved = [f for f in findings if f["level"] in ("error", "warn")]
        if unresolved:
            path = write_report(findings)
            print(f"[centinel] informe de feedback escrito en: {path}")
        sys.exit(1 if has_blocking_errors(findings) else 0)

    findings = []
    if not args.no_doctor:
        # El doctor auto-cura lo que puede (puerto, BD, permisos) y MUTA args.
        findings = doctor_run(args)
        unresolved = [f for f in findings if f["level"] in ("error", "warn")]
        if unresolved:
            path = write_report(findings)
            print(f"[centinel] {len(unresolved)} cosa(s) que no pude arreglar "
                  f"solo. Informe para tu asistente en: {path}")
            print("[centinel] continúo en modo best-effort "
                  "(las capas que fallen se desactivan, no tumban la app).")

    try:
        asyncio.run(Centinel(args).run())
    except KeyboardInterrupt:
        print("\n[centinel] detenido")
    except Exception as exc:   # noqa: BLE001 — captura para feedback, no crash mudo
        path = write_report(findings, exc=exc)
        print(f"[centinel] error inesperado en ejecución. "
              f"Informe para tu asistente en: {path}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
