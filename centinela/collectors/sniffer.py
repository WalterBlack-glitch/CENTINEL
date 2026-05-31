"""Colector de captura de paquetes (capa 2/3) usando scapy.

Esta es la capa que aporta la MAC real: solo es visible para dispositivos
en el mismo dominio de broadcast (tu LAN). Para tráfico de internet la MAC
de origen siempre será la del router/gateway — eso se anota explícitamente.

Detecta además barridos de puertos (SYN sin handshake) de forma incremental.
"""
from __future__ import annotations

import asyncio
import time
from collections import defaultdict

from ..core import Severity, ThreatEvent
from .base import Collector

try:
    from scapy.all import AsyncSniffer, IP, TCP, Ether  # type: ignore
    _HAS_SCAPY = True
except Exception:  # pragma: no cover - scapy opcional
    _HAS_SCAPY = False


class SnifferCollector(Collector):
    name = "sniffer"

    def __init__(self, bus, iface: str | None = None, bpf: str = "tcp") -> None:
        super().__init__(bus)
        self.iface = iface
        self.bpf = bpf
        self._loop: asyncio.AbstractEventLoop | None = None
        # ip_origen -> set(puertos destino) en ventana, para detectar scans
        self._syn_targets: dict[str, set[int]] = defaultdict(set)
        self._window_start = time.time()

    def available(self) -> bool:
        return _HAS_SCAPY

    async def run(self) -> None:
        if not self.available():
            return
        self._loop = asyncio.get_event_loop()
        sniffer = AsyncSniffer(
            iface=self.iface, filter=self.bpf,
            prn=self._on_packet, store=False,
        )
        sniffer.start()
        try:
            while True:
                await asyncio.sleep(5)
                self._flush_scan_window()
        finally:
            sniffer.stop()

    def _on_packet(self, pkt) -> None:
        if IP not in pkt:
            return
        ip = pkt[IP]
        mac = pkt[Ether].src if Ether in pkt else None
        # Solo SYN puros (intento de conexión nueva)
        if TCP in pkt and pkt[TCP].flags == "S":
            self._syn_targets[ip.src].add(int(pkt[TCP].dport))
            ev = ThreatEvent(
                kind="tcp_syn", src_ip=ip.src, dst_ip=ip.dst,
                dst_port=int(pkt[TCP].dport), mac=mac, severity=Severity.INFO,
                message=f"SYN {ip.src} -> {ip.dst}:{pkt[TCP].dport}",
                tags={"l3", "tcp"},
            )
            self._publish_threadsafe(ev)

    def _flush_scan_window(self) -> None:
        """Cada ventana, marca como port-scan a quien tocó muchos puertos."""
        for ip, ports in list(self._syn_targets.items()):
            if len(ports) >= 15:
                ev = ThreatEvent(
                    kind="port_scan", src_ip=ip, severity=Severity.HIGH,
                    message=f"Posible port scan: {len(ports)} puertos en ventana",
                    tags={"l3", "recon", "scan"},
                    enrichment={"ports_hit": sorted(ports)[:50]},
                )
                self._publish_threadsafe(ev)
        self._syn_targets.clear()
        self._window_start = time.time()

    def _publish_threadsafe(self, ev: ThreatEvent) -> None:
        if self._loop is None:
            return
        ev.source = self.name
        asyncio.run_coroutine_threadsafe(self.bus.publish(ev), self._loop)
