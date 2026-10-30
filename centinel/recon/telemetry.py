"""Sniffer pasivo (tcpdump) y telemetría de la captura.

`build_sniff_cmd` es pura. `capture` ejecuta tcpdump N segundos (I/O).
`summarize_capture` es pura: entra la salida cruda de tcpdump, sale un resumen
(protocolos, top hablantes, consultas DNS) — el corazón testeable del panel.
"""
from __future__ import annotations

import re
import subprocess
import time
from collections import Counter

from .tools import have

# Suprime la consola que Windows abre por subprocess desde una app con GUI.
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# IP (v4) origen > destino que tcpdump imprime en modo -nn:  "10.0.0.1.443 > 10.0.0.2.51000:"
_LINE = re.compile(
    r"\s(?P<src>\d{1,3}(?:\.\d{1,3}){3})\.(?P<sport>\d+)\s>\s"
    r"(?P<dst>\d{1,3}(?:\.\d{1,3}){3})\.(?P<dport>\d+):"
)
# IPv6 en modo -nn: "2001:db8::1.443 > 2001:db8::2.51000:". La dirección lleva
# dos puntos y el puerto va tras el último punto; exigir al menos un ':' la
# distingue de una línea IPv4.
_LINE6 = re.compile(
    r"\s(?P<src>[0-9a-fA-F:]+:[0-9a-fA-F:]*)\.(?P<sport>\d+)\s>\s"
    r"(?P<dst>[0-9a-fA-F:]+:[0-9a-fA-F:]*)\.(?P<dport>\d+):"
)
_DNS = re.compile(r"\bA[AAA]*\?\s+(?P<name>[\w.\-]+)\.")


def build_sniff_cmd(iface: str, *, count: int = 200, pcap: str | None = None,
                    binary: str = "tcpdump") -> list[str]:
    """Argumentos de tcpdump para una captura pasiva y acotada. Pura.

    `pcap` graba la captura cruda a ese fichero (`-w`) para abrirla luego en
    Wireshark; captura IPv4 e IPv6 por igual (tcpdump no necesita flag de v6).
    """
    if not iface:
        raise ValueError("interfaz vacía")
    # -nn sin resolver DNS/puertos, -q silencioso, -c limita paquetes.
    cmd = [binary, "-i", iface, "-nn", "-q", "-c", str(int(count))]
    if pcap:
        cmd += ["-w", pcap]
    return cmd


def _proto_of(dport: int, sport: int) -> str:
    well_known = {80: "http", 443: "https", 22: "ssh", 53: "dns", 21: "ftp",
                  25: "smtp", 110: "pop3", 143: "imap", 3389: "rdp",
                  445: "smb", 3306: "mysql", 5432: "postgres"}
    for port in (dport, sport):
        if port in well_known:
            return well_known[port]
    return "otros"


def summarize_capture(text: str) -> dict:
    """Resume la salida cruda de tcpdump. Puro y testeable."""
    by_proto: Counter = Counter()
    talkers: Counter = Counter()
    dns: Counter = Counter()
    packets = 0
    for line in text.splitlines():
        m = _LINE.search(line) or _LINE6.search(line)
        if m:
            packets += 1
            talkers[m.group("src")] += 1
            talkers[m.group("dst")] += 1
            by_proto[_proto_of(int(m.group("dport")),
                               int(m.group("sport")))] += 1
        d = _DNS.search(line)
        if d:
            dns[d.group("name")] += 1
    return {
        "packets": packets,
        "by_proto": dict(by_proto.most_common()),
        "top_talkers": talkers.most_common(10),
        "dns_queries": dns.most_common(15),
    }


def capture(iface: str, *, count: int = 200, timeout: float = 30.0,
            pcap: str | None = None) -> dict:
    """Captura pasiva real (I/O). Devuelve {raw, summary, pcap, error}.

    Con `pcap`, tcpdump escribe la captura binaria a ese fichero; en ese modo no
    hay texto que resumir (la salida va al `.pcap`), así que `summary` queda
    vacío y se devuelve la ruta para abrirla en Wireshark.
    """
    if not have("tcpdump"):
        return {"raw": "", "summary": {}, "error":
                "tcpdump no está instalado (instálalo o usa 'verify')"}
    cmd = build_sniff_cmd(iface, count=count, pcap=pcap)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           creationflags=NO_WINDOW)
        raw = p.stdout or ""
    except subprocess.TimeoutExpired as e:
        raw = (e.stdout or b"").decode(errors="replace") \
            if isinstance(e.stdout, bytes) else (e.stdout or "")
    except OSError as e:
        return {"raw": "", "summary": {}, "error": f"fallo tcpdump: {e}"}
    return {"raw": "" if pcap else raw,
            "summary": {} if pcap else summarize_capture(raw),
            "pcap": pcap or "", "error": "", "ts": time.time()}
