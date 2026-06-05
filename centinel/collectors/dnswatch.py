"""DNSWatch: caza exfiltración de datos por consultas DNS.

Técnica clásica de C2/exfiltración (MITRE T1048.003): codificar datos en el
label izquierdo de un FQDN y resolverlo contra un servidor autoritativo
controlado por el atacante. Como el tráfico DNS suele estar permitido en
casi cualquier red, es un canal favorito de dnscat2, iodine, sliver,
Cobalt Strike DNS Beacon, etc.

CENTINEL escucha UDP/53 (y TCP/53 como fallback) y agrupa por **dominio
padre** (eTLD+1 aproximado: últimas dos etiquetas). Por cada dominio
calcula en ventana deslizante de 60s:

  - número de subdominios únicos
  - entropía Shannon del label más largo
  - longitud del label más largo
  - proporción de queries TXT/NULL (canales de exfil)

Reglas (cualquier match -> evento):
  - label > 50 chars y entropía > 4.0    -> HIGH   (codificación en subdominio)
  - >25 subdominios únicos en 60s         -> HIGH   (DNS tunnel activo)
  - >40% TXT/NULL queries en ventana, n>=5 -> CRITICAL (canal de exfil clásico)
  - label de 63 chars (límite RFC1035)    -> HIGH   (relleno típico de iodine)
  - cualquier subdominio que coincida con
    dgs conocidos (cobaltstrike, dnscat,
    iodine) en TXT                        -> CRITICAL

Rate-limit interno: 1 alerta por (dominio_padre, regla) cada 5 minutos.

Requisitos: scapy + CAP_NET_RAW (o root). Si no, available()=False.
"""
from __future__ import annotations

import asyncio
import math
import time
from collections import defaultdict, deque

from ..core import Severity, ThreatEvent
from .base import Collector

try:
    from scapy.all import AsyncSniffer, DNS, DNSQR, IP, IPv6, UDP  # type: ignore
    _HAS_SCAPY = True
except Exception:   # pragma: no cover - scapy opcional
    _HAS_SCAPY = False


# Umbrales
_WINDOW = 60.0          # s
_RATE_LIMIT = 300.0     # s entre alertas iguales
_ENTROPY_THRESH = 4.0   # bits/símbolo
_LABEL_LEN_SUSPECT = 50
_LABEL_LEN_CRIT = 63    # límite RFC1035 → relleno máximo, casi siempre exfil
_UNIQUE_SUB_THRESH = 25
_TXT_RATIO_THRESH = 0.40
_TXT_MIN_QUERIES = 5

# qtypes: 16=TXT, 10=NULL, 12=PTR, 1=A, 28=AAAA. TXT y NULL son los canales
# más usados para exfiltrar (gran payload arbitrario).
_EXFIL_QTYPES = {16, 10}

# nombres canary que delatan herramientas conocidas (case-insensitive)
_KNOWN_C2_MARKERS = ("dnscat", "iodine", "sliver", "cobaltstrike", "msfdns")


def _shannon(s: str) -> float:
    """Entropía Shannon en bits/símbolo. Texto inglés ~3.5, base64 ~5.5."""
    if not s:
        return 0.0
    from collections import Counter
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _parent(qname: str) -> str:
    """eTLD+1 aproximado: últimas dos etiquetas. Sirve para agrupar."""
    name = qname.rstrip(".")
    parts = name.split(".")
    if len(parts) <= 2:
        return name
    return ".".join(parts[-2:])


def _longest_label(qname: str) -> str:
    parts = qname.rstrip(".").split(".")
    return max(parts, key=len) if parts else ""


class DNSWatchCollector(Collector):
    name = "dnswatch"

    def __init__(self, bus, iface: str | None = None) -> None:
        super().__init__(bus)
        self.iface = iface
        self._loop: asyncio.AbstractEventLoop | None = None
        # parent -> deque[(ts, qname, qtype)]
        self._win: dict[str, deque] = defaultdict(deque)
        # (parent, rule) -> last_alert_ts
        self._alerted: dict[tuple[str, str], float] = {}

    def available(self) -> bool:
        return _HAS_SCAPY

    async def run(self) -> None:
        if not self.available():
            return
        self._loop = asyncio.get_event_loop()
        sniffer = AsyncSniffer(
            iface=self.iface,
            filter="udp port 53 or tcp port 53",
            prn=self._on_packet, store=False,
        )
        sniffer.start()
        try:
            while True:
                await asyncio.sleep(10.0)
                self._gc(time.time())
        finally:
            sniffer.stop()

    # ---- callback de scapy (hilo del sniffer) ----

    def _on_packet(self, pkt) -> None:
        if DNS not in pkt:
            return
        dns = pkt[DNS]
        if dns.qr != 0:    # solo queries (qr=0). Las respuestas no exfiltran.
            return
        if dns.qdcount < 1 or dns.qd is None:
            return
        try:
            qname = (dns.qd.qname.decode("idna", "replace")
                     if isinstance(dns.qd.qname, bytes) else str(dns.qd.qname))
        except Exception:   # noqa: BLE001
            return
        qtype = int(getattr(dns.qd, "qtype", 0))
        src = None
        if IP in pkt:
            src = pkt[IP].src
        elif IPv6 in pkt:
            src = pkt[IPv6].src
        self._observe(qname, qtype, src or "?")

    def _observe(self, qname: str, qtype: int, src: str) -> None:
        now = time.time()
        parent = _parent(qname)
        dq = self._win[parent]
        dq.append((now, qname, qtype))
        # Poda ventana (>60s)
        while dq and now - dq[0][0] > _WINDOW:
            dq.popleft()
        # Reglas locales (por query)
        label = _longest_label(qname)
        ent = _shannon(label) if len(label) >= 8 else 0.0
        rules: list[tuple[str, int, str]] = []   # (rule_id, severity, message)
        if len(label) >= _LABEL_LEN_CRIT:
            rules.append(("label_max",
                int(Severity.HIGH),
                f"label DNS de longitud máxima ({len(label)} chars) en "
                f"{qname[:120]} — patrón de relleno iodine/dnscat"))
        elif len(label) >= _LABEL_LEN_SUSPECT and ent >= _ENTROPY_THRESH:
            rules.append(("label_entropy",
                int(Severity.HIGH),
                f"label DNS largo y de alta entropía ({len(label)} chars, "
                f"H={ent:.2f}) en {qname[:120]} — codificación en subdominio"))
        low = qname.lower()
        for marker in _KNOWN_C2_MARKERS:
            if marker in low:
                rules.append((f"c2_{marker}",
                    int(Severity.CRITICAL),
                    f"marcador C2 conocido '{marker}' en query DNS {qname[:120]}"))
                break
        # Reglas agregadas (por ventana)
        if len(dq) >= 5:
            unique_subs = {q for _, q, _ in dq}
            if len(unique_subs) >= _UNIQUE_SUB_THRESH:
                rules.append(("tunnel_volume",
                    int(Severity.HIGH),
                    f"{len(unique_subs)} subdominios únicos de {parent} en "
                    f"{_WINDOW:.0f}s — túnel DNS activo"))
            txt_count = sum(1 for _, _, t in dq if t in _EXFIL_QTYPES)
            ratio = txt_count / len(dq)
            if ratio >= _TXT_RATIO_THRESH and len(dq) >= _TXT_MIN_QUERIES:
                rules.append(("txt_exfil",
                    int(Severity.CRITICAL),
                    f"{int(ratio*100)}% de queries TXT/NULL a {parent} "
                    f"({txt_count}/{len(dq)}) — canal de exfiltración DNS"))
        # Emit (con rate-limit)
        for rule_id, sev, msg in rules:
            self._emit(parent, qname, qtype, src, rule_id, sev, msg)

    def _emit(self, parent: str, qname: str, qtype: int, src: str,
              rule: str, severity: int, message: str) -> None:
        now = time.time()
        key = (parent, rule)
        last = self._alerted.get(key, 0.0)
        if now - last < _RATE_LIMIT:
            return
        self._alerted[key] = now
        ev = ThreatEvent(
            kind="exfil_dns", src_ip=src, severity=Severity(severity),
            message=message,
            tags={"dns", "exfil", "l7"},
            enrichment={"qname": qname[:255], "qtype": qtype,
                        "parent": parent, "rule": rule},
        )
        self._publish_threadsafe(ev)

    def _publish_threadsafe(self, ev: ThreatEvent) -> None:
        if self._loop is None:
            return
        ev.source = self.name
        asyncio.run_coroutine_threadsafe(self.bus.publish(ev), self._loop)

    def _gc(self, now: float) -> None:
        # Limpia ventanas vacías y rate-limit caducado para no crecer en
        # ataques largos.
        for p in list(self._win):
            dq = self._win[p]
            while dq and now - dq[0][0] > _WINDOW:
                dq.popleft()
            if not dq:
                del self._win[p]
        if len(self._alerted) > 4096:
            self._alerted = {k: t for k, t in self._alerted.items()
                             if now - t < _RATE_LIMIT}
