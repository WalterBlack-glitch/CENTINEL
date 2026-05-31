"""Capa de enriquecimiento: convierte una IP/MAC en contexto accionable.

- IP -> MAC vía tabla ARP local (solo funciona para hosts de la misma LAN).
- MAC -> fabricante vía prefijo OUI (los primeros 3 octetos).
- IP -> rDNS (reverse DNS) con cache y timeout.
- IP privada/pública y clasificación rápida.

Sin dependencias externas ni llamadas a APIs de terceros por defecto: todo
lo resoluble localmente se resuelve local. Geo/ASN se dejan como hook opcional.
"""
from __future__ import annotations

import asyncio
import functools
import ipaddress
import re
import socket
import subprocess
import time

from ..core import ThreatEvent

_ARP_LINE = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?(?P<mac>[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"
)


class Enricher:
    def __init__(self, oui_db: dict[str, str] | None = None,
                 resolve_rdns: bool = False) -> None:
        self._arp_cache: dict[str, str] = {}
        self._arp_ts = 0.0
        self._rdns_cache: dict[str, str] = {}
        self._oui = oui_db or {}
        # rDNS es opt-in: un gethostbyaddr puede bloquear ~2s y serializa el
        # pipeline. Cuando se activa, se resuelve en background sin frenar el flujo.
        self.resolve_rdns = resolve_rdns
        self._rdns_pending: set[str] = set()

    async def enrich(self, ev: ThreatEvent) -> ThreatEvent:
        if ev.src_ip:
            self._classify_ip(ev)
            if not ev.mac:
                ev.mac = self._arp_lookup(ev.src_ip)
            if self.resolve_rdns:
                cached = self._rdns_cache.get(ev.src_ip)
                if cached is not None:
                    ev.enrichment["rdns"] = cached
                else:
                    self._schedule_rdns(ev.src_ip)  # no bloquea el pipeline
        if ev.mac:
            ev.enrichment.setdefault("vendor", self._vendor(ev.mac))
        return ev

    def _classify_ip(self, ev: ThreatEvent) -> None:
        try:
            ip = ipaddress.ip_address(ev.src_ip)
        except ValueError:
            return
        ev.enrichment["private"] = ip.is_private
        ev.enrichment["scope"] = "lan" if ip.is_private else "internet"
        if ip.is_private:
            ev.tags.add("lan")
        else:
            ev.tags.add("wan")

    def _arp_lookup(self, ip: str) -> str | None:
        self._refresh_arp()
        return self._arp_cache.get(ip)

    def _refresh_arp(self, ttl: float = 10.0) -> None:
        if time.time() - self._arp_ts < ttl:
            return
        self._arp_ts = time.time()
        try:
            out = subprocess.run(
                ["ip", "neigh"], capture_output=True, text=True, timeout=2
            ).stdout or ""
            if not out:
                out = subprocess.run(
                    ["arp", "-an"], capture_output=True, text=True, timeout=2
                ).stdout or ""
        except (OSError, subprocess.SubprocessError):
            return
        cache = {}
        for line in out.splitlines():
            m = _ARP_LINE.search(line)
            if m:
                cache[m["ip"]] = m["mac"].lower()
        if cache:
            self._arp_cache = cache

    def _vendor(self, mac: str) -> str | None:
        prefix = mac.lower().replace("-", ":")[:8]
        return self._oui.get(prefix)

    def _schedule_rdns(self, ip: str) -> None:
        """Lanza la resolución rDNS en background y cachea el resultado."""
        if ip in self._rdns_pending:
            return
        self._rdns_pending.add(ip)
        asyncio.create_task(self._rdns(ip))

    async def _rdns(self, ip: str) -> str | None:
        if ip in self._rdns_cache:
            return self._rdns_cache[ip]
        loop = asyncio.get_event_loop()
        try:
            host = await asyncio.wait_for(
                loop.run_in_executor(
                    None, functools.partial(socket.gethostbyaddr, ip)
                ),
                timeout=2.0,
            )
            name = host[0]
        except (socket.herror, socket.gaierror, asyncio.TimeoutError, OSError):
            name = None
        self._rdns_cache[ip] = name
        self._rdns_pending.discard(ip)
        return name
