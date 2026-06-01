"""Modo EXAMEN: monitorea en vivo, y cada ventana muestra lo más importante a
corregir, lo corrige (respuesta activa) y continúa el ciclo.

Flujo por ciclo:
  1. EXAMEN   — imprime eventos en vivo durante `window` segundos.
  2. INFORME  — ranking de actores por score de amenaza.
  3. CORRIGE  — bloquea en firewall a quien supere el umbral (dry-run o live).
  4. SIGUE    — repite.
"""
from __future__ import annotations

import asyncio
import sys
import time

from ..core import EventBus, Severity, ThreatEvent
from ..response.responder import Responder

# Evita UnicodeEncodeError en consolas no-UTF8 (p.ej. cp1252 en Windows):
# los caracteres no representables se sustituyen en vez de crashear.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # py>=3.7
except (AttributeError, ValueError):
    pass

_C = {  # colores ANSI mínimos (sin dependencias)
    "reset": "\033[0m", "dim": "\033[2m", "red": "\033[31m",
    "yellow": "\033[33m", "green": "\033[32m", "cyan": "\033[36m",
    "bold": "\033[1m", "redbg": "\033[41m\033[97m",
}
_SEV_COL = {
    Severity.INFO: _C["dim"], Severity.LOW: _C["cyan"],
    Severity.MEDIUM: _C["yellow"], Severity.HIGH: _C["red"],
    Severity.CRITICAL: _C["redbg"],
}

import re as _re
_CTRL = _re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _safe(s, n: int = 60) -> str:
    return _CTRL.sub("", str(s or "—"))[:n]


class AssessmentDashboard:
    def __init__(self, bus: EventBus, responder: Responder,
                 window: float = 15.0) -> None:
        self.bus = bus
        self.responder = responder
        self.engine = responder.engine
        self.window = window
        self.cycle = 0
        self.seen = 0

    async def run(self) -> None:
        q = self.bus.subscribe()
        print(f"{_C['bold']}🛰  Centinel — modo EXAMEN "
              f"(ventana {self.window:.0f}s, umbral bloqueo "
              f"{self.responder.threshold:.0f}, firewall: "
              f"{self.responder.fw.mode}/{self.responder.fw.backend or 'n/a'})"
              f"{_C['reset']}\n")
        next_report = time.monotonic() + self.window
        while True:
            timeout = max(0.05, next_report - time.monotonic())
            try:
                ev = await asyncio.wait_for(q.get(), timeout)
                self._print_event(ev)
            except asyncio.TimeoutError:
                pass
            if time.monotonic() >= next_report:
                self._report_and_fix()
                next_report = time.monotonic() + self.window

    def _print_event(self, ev: ThreatEvent) -> None:
        self.seen += 1
        col = _SEV_COL[Severity(ev.severity)]
        origin = _safe(ev.src_ip, 45)
        if ev.mac:
            origin += f" mac={_safe(ev.mac, 17)}"
        ts = time.strftime("%H:%M:%S", time.localtime(ev.ts))
        flag = "  ⚑" if ev.kind.startswith("alert_") else ""
        print(f"{_C['dim']}{ts}{_C['reset']} "
              f"{col}{Severity(ev.severity).name:8}{_C['reset']} "
              f"{_safe(ev.source,11):11} {_safe(ev.kind,22):22} "
              f"{origin:32} {_safe(ev.message,80)}{flag}")

    def _report_and_fix(self) -> None:
        self.cycle += 1
        prios = self.responder.priorities()
        print(f"\n{_C['bold']}{'═'*78}{_C['reset']}")
        print(f"{_C['bold']}📋  EXAMEN #{self.cycle} — lo más importante a "
              f"corregir  ({self.seen} eventos vistos){_C['reset']}")
        print(f"{_C['bold']}{'═'*78}{_C['reset']}")
        if not prios:
            print(f"{_C['green']}  Sin amenazas activas. Todo limpio.{_C['reset']}\n")
            return
        print(f"  {'#':>2} {'SCORE':>6}  {'IP':<18} {'MAC':<18} "
              f"{'FALLOS':>6} {'USERS':>5} {'PUERTOS':>7}")
        for i, a in enumerate(prios, 1):
            sev = self.engine._sev_from_score(a.score)
            col = _SEV_COL[sev]
            print(f"  {i:>2} {col}{a.score:>6.0f}{_C['reset']}  "
                  f"{_safe(a.ip,18):<18} {_safe(a.last_mac,18):<18} "
                  f"{len(a.fails):>6} {len(a.users):>5} {len(a.ports):>7}")

        # CORRIGE
        actions = self.responder.remediate()
        if actions:
            print(f"\n  {_C['bold']}⚙  CORRECCIÓN (umbral "
                  f"{self.responder.threshold:.0f}):{_C['reset']}")
            for act in actions:
                mark = (f"{_C['green']}✔{_C['reset']}" if act.executed
                        else f"{_C['yellow']}•{_C['reset']}")
                print(f"     {mark} {_safe(act.ip,18):<18} score={act.score:>4.0f}  "
                      f"{_safe(act.detail,70)}")
        else:
            print(f"\n  {_C['dim']}Nada supera el umbral de bloqueo todavía."
                  f"{_C['reset']}")
        if self.bus.dropped:
            print(f"  {_C['yellow']}⚠ {self.bus.dropped} eventos descartados "
                  f"bajo presión (posible evasión){_C['reset']}")
        print(f"\n  {_C['dim']}…continuando monitoreo en vivo…{_C['reset']}\n")
