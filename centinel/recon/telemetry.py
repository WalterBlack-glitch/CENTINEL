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
_DNS = re.compile(r"\bA[AAA]*\?\s+(?P<name>[\w.\-]+)\.")


def build_sniff_cmd(iface: str, *, count: int = 200,
                    binary: str = "tcpdump") -> list[str]:
    """Argumentos de tcpdump para una captura pasiva y acotada. Pura."""
    if not iface:
        raise ValueError("interfaz vacía")
    # -nn sin resolver DNS/puertos, -q silencioso, -c limita paquetes.
    return [binary, "-i", iface, "-nn", "-q", "-c", str(int(count))]


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
        m = _LINE.search(line)
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


def capture(iface: str, *, count: int = 200, timeout: float = 30.0) -> dict:
    """Captura pasiva real (I/O). Devuelve {raw, summary, error}."""
    if not have("tcpdump"):
        return {"raw": "", "summary": {}, "error":
                "tcpdump no está instalado (instálalo o usa 'verify')"}
    cmd = build_sniff_cmd(iface, count=count)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           creationflags=NO_WINDOW)
        raw = p.stdout or ""
    except subprocess.TimeoutExpired as e:
        raw = (e.stdout or b"").decode(errors="replace") \
            if isinstance(e.stdout, bytes) else (e.stdout or "")
    except OSError as e:
        return {"raw": "", "summary": {}, "error": f"fallo tcpdump: {e}"}
    return {"raw": raw, "summary": summarize_capture(raw), "error": "",
            "ts": time.time()}
