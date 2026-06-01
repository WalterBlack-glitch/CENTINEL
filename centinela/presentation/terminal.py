"""Capa de presentación: dashboard en vivo en la terminal con `rich`.

Muestra dos paneles: actores rankeados por score de amenaza (con IP, MAC,
fabricante, scope LAN/WAN, rDNS) y un feed de eventos recientes coloreado por
severidad. Si `rich` no está instalado, cae a salida de texto plana.
"""
from __future__ import annotations

import asyncio
import re
from collections import deque

from ..core import EventBus, Severity, ThreatEvent
from ..correlation.engine import CorrelationEngine

try:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.markup import escape as _rich_escape
    _HAS_RICH = True
except Exception:
    _HAS_RICH = False

    def _rich_escape(s):  # type: ignore
        return s

# A-3: strip de caracteres de control (escapes ANSI/OSC) en todo string que
# derive del atacante (username, rDNS/PTR, vendor) antes de renderizar.
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _safe(s, limit: int = 200) -> str:
    if not s:
        return "—"
    return _rich_escape(_CTRL.sub("", str(s))[:limit])

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
        self.remed: deque = deque(maxlen=4)   # últimos playbooks de remediación
        self._remed_seen: set = set()

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
                self._capture_remed(ev)
                live.update(self._render())

    def _capture_remed(self, ev) -> None:
        rem = ev.enrichment.get("remediation") if ev.enrichment else None
        if not rem:
            return
        key = f"{ev.kind}|{ev.src_ip}"
        if key in self._remed_seen:
            return
        self._remed_seen.add(key)
        if len(self._remed_seen) > 256:
            self._remed_seen.clear()
        self.remed.appendleft((ev.src_ip, rem))

    def _render(self):
        layout = Layout()
        rows = [Layout(self._actors_table(), name="actors", ratio=2),
                Layout(self._feed_table(), name="feed", ratio=2)]
        if self.remed:
            rows.append(Layout(self._remed_panel(), name="remed", ratio=1))
        layout.split_column(*rows)
        return layout

    def _remed_panel(self):
        t = Table(title="🛠  Cómo remediar (acciones recomendadas)", expand=True)
        for col in ("Urg.", "Amenaza", "IP", "Primeros pasos"):
            t.add_column(col, overflow="fold")
        _uc = {"critica": "bold white on red", "alta": "red", "media": "yellow"}
        for ip, rem in self.remed:
            steps = "  ".join(f"{i+1}. {_safe(s['text'], 70)}"
                              for i, s in enumerate(rem["steps"][:3]))
            t.add_row(f"[{_uc.get(rem['urgency'],'red')}]{rem['urgency']}[/]",
                      _safe(rem["title"], 50), _safe(ip, 45), steps)
        return Panel(t, border_style="red")

    def _actors_table(self):
        t = Table(title="🛰  Actores por score de amenaza", expand=True)
        for col in ("Score", "IP", "MAC", "Fabricante", "Scope",
                    "Fallos", "Users", "Puertos", "rDNS"):
            t.add_column(col, overflow="fold")
        for a in self.engine.get_actors()[:12]:
            sev = self.engine._sev_from_score(a.score)
            t.add_row(
                f"[{_SEV_STYLE[sev]}]{a.score:.0f}[/]",
                _safe(a.ip, 45), _safe(a.last_mac, 17), "—",
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
            origin = _safe(ev.src_ip, 45)
            if ev.mac:
                origin += f" mac={_safe(ev.mac, 17)}"
            if vendor:
                origin += f" ({_safe(vendor, 40)})"
            t.add_row(
                _t.strftime("%H:%M:%S", _t.localtime(ev.ts)),
                f"[{style}]{Severity(ev.severity).name}[/]",
                _safe(ev.source, 16), _safe(ev.kind, 24), origin,
                _safe(ev.message, 200),
            )
        return Panel(t, border_style="green")

    async def _run_plain(self, queue: asyncio.Queue) -> None:
        import time as _t
        print("[centinela] rich no instalado — modo texto plano")
        while True:
            ev = await queue.get()
            # _safe quita escapes ANSI; en texto plano no hay markup que escapar.
            origin = _CTRL.sub("", ev.src_ip or "-")
            if ev.mac:
                origin += f" mac={_CTRL.sub('', ev.mac)}"
            msg = _CTRL.sub("", ev.message)[:200]
            print(f"{_t.strftime('%H:%M:%S')} {Severity(ev.severity).name:8} "
                  f"{_CTRL.sub('', ev.source):11} {_CTRL.sub('', ev.kind):20} "
                  f"{origin:30} {msg}")
