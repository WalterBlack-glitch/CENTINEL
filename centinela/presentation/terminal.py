"""Capa de presentación: dashboard en vivo en la terminal con `rich`.

Muestra dos paneles: actores rankeados por score de amenaza (con IP, MAC,
fabricante, scope LAN/WAN, rDNS) y un feed de eventos recientes coloreado por
severidad. Si `rich` no está instalado, cae a salida de texto plana.
"""
from __future__ import annotations

import asyncio
from collections import deque

from ..core import EventBus, Severity, ThreatEvent
from ..correlation.engine import CorrelationEngine

try:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
    from rich.layout import Layout
    from rich.panel import Panel
    _HAS_RICH = True
except Exception:
    _HAS_RICH = False

_SEV_STYLE = {
    Severity.INFO: "dim",
    Severity.LOW: "cyan",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold white on red",
}


class TerminalDashboard:
    def __init__(self, bus: EventBus, engine: CorrelationEngine) -> None:
        self.bus = bus
        self.engine = engine
        self.feed: deque[ThreatEvent] = deque(maxlen=15)

    async def run(self) -> None:
        queue = self.bus.subscribe()
        if not _HAS_RICH:
            await self._run_plain(queue)
            return
        console = Console()
        with Live(self._render(), console=console, refresh_per_second=4,
                  screen=True) as live:
            while True:
                ev = await queue.get()
                self.feed.appendleft(ev)
                live.update(self._render())

    def _render(self):
        layout = Layout()
        layout.split_column(
            Layout(self._actors_table(), name="actors", ratio=1),
            Layout(self._feed_table(), name="feed", ratio=1),
        )
        return layout

    def _actors_table(self):
        t = Table(title="🛰  Actores por score de amenaza", expand=True)
        for col in ("Score", "IP", "MAC", "Fabricante", "Scope",
                    "Fallos", "Users", "Puertos", "rDNS"):
            t.add_column(col, overflow="fold")
        for a in self.engine.get_actors()[:12]:
            sev = self.engine._sev_from_score(a.score)
            t.add_row(
                f"[{_SEV_STYLE[sev]}]{a.score:.0f}[/]",
                a.ip, a.last_mac or "—", "—",
                "wan" if not a.ip.startswith(("10.", "192.168.", "172.")) else "lan",
                str(len(a.fails)), str(len(a.users)), str(len(a.ports)), "",
            )
        return Panel(t, border_style="blue")

    def _feed_table(self):
        t = Table(title="📡  Eventos en vivo", expand=True)
        for col in ("Hora", "Sev", "Fuente", "Tipo", "Origen", "Mensaje"):
            t.add_column(col, overflow="fold")
        import time as _t
        for ev in self.feed:
            style = _SEV_STYLE[Severity(ev.severity)]
            vendor = ev.enrichment.get("vendor")
            origin = ev.src_ip or "—"
            if ev.mac:
                origin += f" [{ev.mac}]"
            if vendor:
                origin += f" ({vendor})"
            t.add_row(
                _t.strftime("%H:%M:%S", _t.localtime(ev.ts)),
                f"[{style}]{Severity(ev.severity).name}[/]",
                ev.source, ev.kind, origin, ev.message,
            )
        return Panel(t, border_style="green")

    async def _run_plain(self, queue: asyncio.Queue) -> None:
        import time as _t
        print("[centinela] rich no instalado — modo texto plano")
        while True:
            ev = await queue.get()
            origin = ev.src_ip or "-"
            if ev.mac:
                origin += f" [{ev.mac}]"
            print(f"{_t.strftime('%H:%M:%S')} {Severity(ev.severity).name:8} "
                  f"{ev.source:11} {ev.kind:20} {origin:30} {ev.message}")
