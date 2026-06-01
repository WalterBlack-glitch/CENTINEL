"""Capa de enriquecimiento: convierte una IP/MAC en contexto accionable.

- IP -> MAC vía tabla ARP local (solo funciona para hosts de la misma LAN).
- MAC -> fabricante vía prefijo OUI (los primeros 3 octetos).
- IP -> rDNS (reverse DNS) con cache LRU+TTL y timeout, en background.
- IP privada/pública y clasificación rápida.

Sin dependencias externas ni llamadas a APIs de terceros por defecto: todo
lo resoluble localmente se resuelve local. Geo/ASN se dejan como hook opcional.

Endurecimiento: las cachés están acotadas (no crecen sin límite ante IPs
spoofeadas), los subprocess usan rutas absolutas y PATH controlado (no
hijacking como root), y las tasks de rDNS se retienen para no perderse al GC.
"""
from __future__ import annotations

import asyncio
import functools
import ipaddress
import os
import re
import shutil
import socket
import subprocess
import time
from collections import OrderedDict

from ..core import Severity, ThreatEvent

_ARP_LINE = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?(?P<mac>[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"
)

_RDNS_MAX = 10_000      # tope de cache rDNS (M-1)
_RDNS_TTL = 3600.0      # 1 h
_SAFE_ENV = {"PATH": "/usr/sbin:/sbin:/usr/bin:/bin", "LC_ALL": "C"}


def _resolve_bin(name: str) -> str:
    """Ruta absoluta de un binario, evitando PATH hijacking (M-3)."""
    for cand in (f"/usr/sbin/{name}", f"/sbin/{name}",
                 f"/usr/bin/{name}", f"/bin/{name}"):
        if os.path.exists(cand):
            return cand
    return shutil.which(name) or name


_IP_BIN = _resolve_bin("ip")
_ARP_BIN = _resolve_bin("arp")


class Enricher:
    def __init__(self, oui_db: dict[str, str] | None = None,
                 resolve_rdns: bool = False, geo=None, kev=None) -> None:
        self._geo = geo  # GeoResolver opcional
        self._kev = kev  # KevCatalog opcional
        self._arp_cache: dict[str, str] = {}
        self._arp_ts = 0.0
        # cache LRU con TTL: ip -> (nombre|None, ts)
        self._rdns_cache: OrderedDict[str, tuple[str | None, float]] = OrderedDict()
        self._oui = oui_db or {}
        self.resolve_rdns = resolve_rdns
        self._rdns_pending: set[str] = set()
        self._tasks: set[asyncio.Task] = set()  # M-2: retiene refs

    async def enrich(self, ev: ThreatEvent) -> ThreatEvent:
        if ev.src_ip:
            self._classify_ip(ev)
            if not ev.mac:
                ev.mac = self._arp_lookup(ev.src_ip)
            if self.resolve_rdns:
                cached = self._rdns_get(ev.src_ip)
                if cached is not None:
                    ev.enrichment["rdns"] = cached[0]
                else:
                    self._schedule_rdns(ev.src_ip)  # no bloquea el pipeline
        if ev.mac:
            ev.enrichment.setdefault("vendor", self._vendor(ev.mac))
        if self._geo is not None and ev.src_ip and "geo" not in ev.enrichment:
            g = self._geo.lookup(ev.src_ip)
            if g:
                ev.enrichment["geo"] = g
        # KEV: si el evento referencia un CVE con explotación confirmada, sube
        # severidad y lo marca (lo más explotado en el mundo real ahora mismo).
        cve = ev.enrichment.get("cve")
        if self._kev is not None and cve and self._kev.contains(cve):
            rec = self._kev.get(cve) or {}
            ev.enrichment["kev"] = True
            ev.tags.add("kev")
            ev.severity = max(ev.severity, Severity.HIGH)
            if rec.get("ransomware"):
                ev.tags.add("ransomware")
                ev.severity = Severity.CRITICAL
        return ev

    def _classify_ip(self, ev: ThreatEvent) -> None:
        try:
            ip = ipaddress.ip_address(ev.src_ip)
        except ValueError:
            return
        ev.enrichment["private"] = ip.is_private
        ev.enrichment["scope"] = "lan" if ip.is_private else "internet"
        ev.tags.add("lan" if ip.is_private else "wan")

    def _arp_lookup(self, ip: str) -> str | None:
        self._refresh_arp()
        return self._arp_cache.get(ip)

    def _refresh_arp(self, ttl: float = 10.0) -> None:
        if time.time() - self._arp_ts < ttl:
            return
        self._arp_ts = time.time()
        try:
            out = subprocess.run(
                [_IP_BIN, "neigh"], capture_output=True, text=True,
                timeout=2, env=_SAFE_ENV,
            ).stdout or ""
            if not out:
                out = subprocess.run(
                    [_ARP_BIN, "-an"], capture_output=True, text=True,
                    timeout=2, env=_SAFE_ENV,
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

    # ---- rDNS con cache LRU + TTL y tasks retenidas ----

    def _rdns_get(self, ip: str) -> tuple[str | None, float] | None:
        entry = self._rdns_cache.get(ip)
        if entry is None:
            return None
        if time.time() - entry[1] > _RDNS_TTL:
            del self._rdns_cache[ip]
            return None
        self._rdns_cache.move_to_end(ip)
        return entry

    def _rdns_put(self, ip: str, name: str | None) -> None:
        self._rdns_cache[ip] = (name, time.time())
        self._rdns_cache.move_to_end(ip)
        while len(self._rdns_cache) > _RDNS_MAX:
            self._rdns_cache.popitem(last=False)

    def _schedule_rdns(self, ip: str) -> None:
        if ip in self._rdns_pending:
            return
        self._rdns_pending.add(ip)
        t = asyncio.create_task(self._rdns(ip))
        self._tasks.add(t)
        t.add_done_callback(self._on_rdns_done(ip))

    def _on_rdns_done(self, ip: str):
        def _cb(fut: asyncio.Task) -> None:
            self._tasks.discard(fut)
            self._rdns_pending.discard(ip)  # se limpia pase lo que pase (M-2)
        return _cb

    async def _rdns(self, ip: str) -> str | None:
        cached = self._rdns_get(ip)
        if cached is not None:
            return cached[0]
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
        self._rdns_put(ip, name)
        return name
