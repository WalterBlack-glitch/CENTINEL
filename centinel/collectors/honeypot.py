"""Honeypot SSH de baja interacción (colector activo).

Escucha en uno o más puertos-trampa. Cualquier conexión es maliciosa por
definición (ningún cliente legítimo se conecta a un servicio señuelo), así que
es la señal de mayor relación señal/ruido del sistema.

Baja interacción a propósito: envía un banner SSH falso, lee UN bloque acotado
de lo que mande el cliente (su propio banner suele delatar la herramienta:
libssh, paramiko, zgrab, Go...), lo cruza con las firmas de explotación, y
cierra. NUNCA ejecuta nada ni implementa el protocolo: no hay superficie de RCE.

Endurecido desde el diseño (es código que escucha en la red):
  - Semáforo de conexiones concurrentes (anti-agotamiento de FD/RAM).
  - Timeout de lectura/escritura y tope de bytes por conexión (anti-slowloris).
  - Rate-limit de emisión de eventos por IP (anti-flood del pipeline).
  - Estructuras acotadas con purga. Entrada del atacante saneada antes de loguear.
"""
from __future__ import annotations

import asyncio
import re
import time

from ..core import Severity, ThreatEvent
from ..correlation import signatures
from .base import Collector

_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_DEFAULT_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"


def _clean(b: bytes, limit: int = 200) -> str:
    return _CTRL.sub("", b.decode("utf-8", "replace"))[:limit]


class HoneypotCollector(Collector):
    name = "honeypot"

    def __init__(self, bus, ports, host: str = "0.0.0.0",
                 banner: bytes | None = None, max_conns: int = 200,
                 max_per_ip: int = 10, read_timeout: float = 5.0,
                 max_bytes: int = 4096, emit_cooldown: float = 2.0) -> None:
        super().__init__(bus)
        self.ports = [int(p) for p in ports]
        self.host = host
        self.banner = banner or _DEFAULT_BANNER
        # Límites explícitos (no un semáforo bloqueante): rechazamos al instante
        # cuando se superan, sin encolar coroutines que retendrían FD/RAM (H-1).
        self.max_conns = max_conns
        self.max_per_ip = max_per_ip           # tope por IP (H-2)
        self._active = 0
        self._per_ip: dict[str, int] = {}
        self.read_timeout = read_timeout
        self.max_bytes = max_bytes
        self.emit_cooldown = emit_cooldown
        self._last_emit: dict[str, float] = {}

    def available(self) -> bool:
        return bool(self.ports)

    async def run(self) -> None:
        servers = []
        for port in self.ports:
            try:
                srv = await asyncio.start_server(self._handle, self.host, port)
                servers.append(srv)
                print(f"[centinel] honeypot escuchando en {self.host}:{port}")
            except OSError as e:
                print(f"[centinel] honeypot no pudo abrir {self.host}:{port}: {e}")
        if not servers:
            return
        try:
            # return_exceptions: que un listener que falle no tumbe a los demás (H-8).
            await asyncio.gather(*(s.serve_forever() for s in servers),
                                 return_exceptions=True)
        finally:
            for s in servers:
                s.close()

    async def _handle(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("?", 0)
        sock = writer.get_extra_info("sockname") or ("?", 0)
        ip = peer[0] if isinstance(peer, (tuple, list)) else "?"
        sport = peer[1] if isinstance(peer, (tuple, list)) and len(peer) > 1 else 0
        dport = sock[1] if isinstance(sock, (tuple, list)) and len(sock) > 1 else 0

        # Rechazo inmediato si se supera el cupo global o por-IP (no se encola).
        if self._active >= self.max_conns or \
                self._per_ip.get(ip, 0) >= self.max_per_ip:
            writer.close()
            return
        self._active += 1
        self._per_ip[ip] = self._per_ip.get(ip, 0) + 1
        client_data = b""
        try:
            try:
                writer.write(self.banner)
                await asyncio.wait_for(writer.drain(), timeout=self.read_timeout)
                client_data = await asyncio.wait_for(
                    reader.read(self.max_bytes), timeout=self.read_timeout)
            except (asyncio.TimeoutError, OSError, ConnectionError):
                pass
            finally:
                try:
                    writer.close()
                    await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
                except (asyncio.TimeoutError, OSError, ConnectionError):
                    pass
            try:
                await self._emit_hit(ip, sport, dport, client_data)
            except Exception:
                pass   # emitir nunca debe tumbar el handler
        finally:
            self._active -= 1
            n = self._per_ip.get(ip, 0) - 1
            if n <= 0:
                self._per_ip.pop(ip, None)
            else:
                self._per_ip[ip] = n

    async def _emit_hit(self, ip: str, sport: int, dport: int,
                        data: bytes) -> None:
        now = time.time()
        # Rate-limit por IP para no inundar el pipeline ante un escaneo agresivo.
        last = self._last_emit.get(ip)
        if last is not None and now - last < self.emit_cooldown:
            return
        self._prune(now)
        self._last_emit[ip] = now

        banner = _clean(data) if data else ""
        enrich = {"honeypot_port": dport}
        if banner:
            enrich["client_banner"] = banner
        msg = f"Conexión a honeypot :{dport}"
        if banner:
            msg += f" — banner cliente: {banner!r}"
        # Cruza el banner con las firmas (delata la herramienta ofensiva).
        sig = signatures.scan(f"Connection from {ip}: client software version {banner}") \
            if banner else None
        tags = {"honeypot", "trap"}
        if sig:
            enrich["signature"] = sig.name
            if sig.cve:
                enrich["cve"] = sig.cve
                tags.add(sig.cve)
            tags.add("exploit-sig")

        await self.emit(ThreatEvent(
            ts=now, kind="honeypot_hit", src_ip=ip, src_port=sport,
            dst_port=dport, severity=Severity.HIGH, message=msg,
            tags=tags, enrichment=enrich, raw=_clean(data, 1000)))

    def _prune(self, now: float) -> None:
        if len(self._last_emit) < 50_000:
            return
        self._last_emit = {ip: t for ip, t in self._last_emit.items()
                           if now - t < 300}
