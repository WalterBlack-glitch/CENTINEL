"""Tests del detector de exfiltración por DNS."""
import asyncio
import time

import pytest

from centinel.collectors.dnswatch import (
    _shannon, _parent, _longest_label, DNSWatchCollector,
)
from centinel.core import EventBus, Severity


def test_shannon_string_vacio_cero():
    assert _shannon("") == 0.0


def test_shannon_repetido_bajo():
    # "aaaaaaaa" tiene entropía 0 (un solo símbolo)
    assert _shannon("a" * 16) == 0.0


def test_shannon_base64_alto():
    # base64 random ~5.5 bits/char
    h = _shannon("Z2VuZXJpY19zdHJpbmdfb2ZfYmFzZTY0X2RhdGE")
    assert h > 4.0


def test_parent_dominio_simple():
    assert _parent("example.com") == "example.com"


def test_parent_subdominios():
    assert _parent("a.b.c.example.com.") == "example.com"


def test_longest_label():
    assert _longest_label("a.b.muylargolabel.example.com") == "muylargolabel"


def test_label_entropia_alta_emite_high():
    """Un subdominio largo + entropía alta debe disparar HIGH."""
    bus = EventBus()
    col = DNSWatchCollector(bus)
    loop = asyncio.new_event_loop()
    col._loop = loop
    events: list = []

    async def consumer():
        q = bus.subscribe()
        try:
            ev = await asyncio.wait_for(q.get(), timeout=1.0)
            events.append(ev)
        except asyncio.TimeoutError:
            pass

    async def producer():
        # label > 50 chars de base64 -> entropía > 4.0
        col._observe(
            "aGVsbG93b3JsZHRoaXNpc2V4ZmlsdHJhdGlvbmRhdGFiY2RlZmdoaWprbG1ub3A.evil.com",
            1, "10.0.0.5")
        await asyncio.sleep(0)

    async def main():
        t = asyncio.create_task(consumer())
        await producer()
        await asyncio.sleep(0.05)
        t.cancel()
        try: await t
        except: pass

    loop.run_until_complete(main())
    loop.close()
    assert events, "no se emitió evento para label entrópico"
    ev = events[0]
    assert ev.kind == "exfil_dns"
    assert int(ev.severity) >= int(Severity.HIGH)
    assert "evil.com" in ev.enrichment["parent"]


def test_marcador_c2_conocido_es_critico():
    bus = EventBus()
    col = DNSWatchCollector(bus)
    loop = asyncio.new_event_loop()
    col._loop = loop
    seen: list = []

    async def main():
        q = bus.subscribe()
        col._observe("dnscat.attacker.tld", 16, "1.2.3.4")
        try:
            ev = await asyncio.wait_for(q.get(), timeout=0.5)
            seen.append(ev)
        except asyncio.TimeoutError:
            pass

    loop.run_until_complete(main())
    loop.close()
    assert seen and int(seen[0].severity) == int(Severity.CRITICAL)
    assert "dnscat" in seen[0].message.lower()


def test_volumen_subdominios_unicos_dispara():
    """>25 subdominios únicos del mismo padre en ventana -> HIGH tunnel_volume."""
    bus = EventBus()
    col = DNSWatchCollector(bus)
    loop = asyncio.new_event_loop()
    col._loop = loop
    seen: list = []

    async def main():
        q = bus.subscribe()
        for i in range(30):
            col._observe(f"sub{i}.tunnel.com", 1, "10.0.0.9")
        # consumir todos los eventos emitidos
        for _ in range(40):
            try:
                ev = await asyncio.wait_for(q.get(), timeout=0.05)
                seen.append(ev)
            except asyncio.TimeoutError:
                break

    loop.run_until_complete(main())
    loop.close()
    rules = {ev.enrichment.get("rule") for ev in seen}
    assert "tunnel_volume" in rules


def test_rate_limit_evita_inundacion():
    """Dos eventos seguidos del mismo (parent, rule) no se duplican."""
    bus = EventBus()
    col = DNSWatchCollector(bus)
    loop = asyncio.new_event_loop()
    col._loop = loop
    seen: list = []

    async def main():
        q = bus.subscribe()
        col._observe("dnscat.foo.tld", 16, "1.1.1.1")
        col._observe("dnscat.foo.tld", 16, "1.1.1.1")
        for _ in range(5):
            try:
                ev = await asyncio.wait_for(q.get(), timeout=0.05)
                seen.append(ev)
            except asyncio.TimeoutError:
                break

    loop.run_until_complete(main())
    loop.close()
    # Solo una alerta para el mismo (parent, rule) en la ventana de rate-limit
    c2_events = [e for e in seen if e.enrichment.get("rule", "").startswith("c2_")]
    assert len(c2_events) == 1


def test_dnswatch_en_layers_need_sustained_root():
    """dnswatch debe figurar en las capas que requieren root sostenido,
    para que CENTINEL no suelte privilegios y revente el sniff."""
    from centinel.security import layers_need_sustained_root

    class Args:
        dnswatch = True
        netwatch = False
        rootcheck = False
        respond_live = False
        sniff = False

    need = layers_need_sustained_root(Args())
    assert any("dnswatch" in n for n in need)
