"""Tests del honeypot SSH de baja interacción."""
import asyncio
import socket

import pytest

from centinela.core import EventBus, Severity
from centinela.collectors.honeypot import HoneypotCollector, _clean
from centinela.correlation.engine import CorrelationEngine


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_clean_quita_control_chars():
    # Quita bytes de control (ESC, NUL); los imprimibles '[31m' permanecen.
    assert _clean(b"SSH-2.0-\x1b[31mlibssh\x00") == "SSH-2.0-[31mlibssh"
    assert "\x1b" not in _clean(b"\x1b[2J\x1b[31mEVIL")
    assert _clean(b"x" * 500, limit=10) == "x" * 10


async def _run_hp(port, client_sends: bytes | None):
    bus = EventBus()
    eng = CorrelationEngine(bus)
    events = []
    q = bus.subscribe()

    async def pipe():
        while True:
            ev = await q.get()
            await eng.process(ev)
            if ev.source != "correlation":
                events.append(ev)

    hp = HoneypotCollector(bus, ports=[port], host="127.0.0.1")
    t1 = asyncio.create_task(hp.run())
    t2 = asyncio.create_task(pipe())
    await asyncio.sleep(0.3)
    r, w = await asyncio.open_connection("127.0.0.1", port)
    await r.read(100)                       # banner del señuelo
    if client_sends is not None:
        w.write(client_sends)
        await w.drain()
    await asyncio.sleep(0.2)
    w.close()
    await asyncio.sleep(0.3)
    t1.cancel()
    t2.cancel()
    return events, eng


@pytest.mark.asyncio
async def test_conexion_genera_hit_critico_de_severidad_alta():
    port = _free_port()
    events, eng = await _run_hp(port, b"SSH-2.0-Go\r\n")
    hits = [e for e in events if e.kind == "honeypot_hit"]
    assert hits, "debe emitir honeypot_hit"
    ev = hits[0]
    assert ev.severity == Severity.HIGH
    assert ev.src_ip == "127.0.0.1"
    assert ev.enrichment["honeypot_port"] == port
    assert "honeypot" in eng.actors["127.0.0.1"].flags
    assert eng.actors["127.0.0.1"].score >= 70   # flag honeypot pondera fuerte


@pytest.mark.asyncio
async def test_banner_atacante_cruza_firmas():
    port = _free_port()
    events, _ = await _run_hp(port, b"SSH-2.0-libssh_0.9.6\r\n")
    hits = [e for e in events if e.kind == "honeypot_hit"]
    assert hits and hits[0].enrichment.get("cve") == "CVE-2018-10933"


@pytest.mark.asyncio
async def test_sin_datos_igual_registra():
    port = _free_port()
    events, _ = await _run_hp(port, None)   # conecta y no manda nada
    assert any(e.kind == "honeypot_hit" for e in events)


def test_disponible_solo_con_puertos():
    bus = EventBus()
    assert HoneypotCollector(bus, ports=[2222]).available() is True
    assert HoneypotCollector(bus, ports=[]).available() is False


@pytest.mark.asyncio
async def test_limite_por_ip_rechaza_exceso():
    # Con max_per_ip=2, la 3ª conexión simultánea de la misma IP se rechaza al
    # instante (no se encola ni retiene recursos).
    port = _free_port()
    bus = EventBus()
    hp = HoneypotCollector(bus, ports=[port], host="127.0.0.1",
                           max_per_ip=2, read_timeout=2.0)
    t = asyncio.create_task(hp.run())
    await asyncio.sleep(0.3)
    conns = []
    for _ in range(2):
        conns.append(await asyncio.open_connection("127.0.0.1", port))
        await asyncio.sleep(0.05)
    assert hp._per_ip.get("127.0.0.1", 0) == 2
    # La 3ª se acepta a nivel TCP pero el handler la cierra de inmediato.
    r3, w3 = await asyncio.open_connection("127.0.0.1", port)
    await asyncio.sleep(0.2)
    assert hp._per_ip.get("127.0.0.1", 0) == 2   # no subió a 3
    for r, w in conns:
        w.close()
    w3.close()
    t.cancel()
