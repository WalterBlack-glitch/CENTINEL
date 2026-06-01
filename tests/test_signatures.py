"""Tests de las firmas de explotación (Metasploit/escáneres/CVEs)."""
import asyncio

import pytest

from centinel.core import EventBus, Severity, ThreatEvent
from centinel.correlation import signatures as S
from centinel.correlation.engine import CorrelationEngine


def test_http_probe_on_ssh():
    ev = S.build_event("Bad protocol version identification 'GET / HTTP/1.1' "
                       "from 203.0.113.7 port 5555")
    assert ev and ev.enrichment["signature"] == "http_probe_on_ssh"
    assert ev.src_ip == "203.0.113.7" and ev.severity == Severity.HIGH


def test_offensive_tool_banner():
    ev = S.build_event("Bad protocol version identification "
                       "'SSH-2.0-libssh_0.9.6' from 45.135.232.17 port 4444")
    assert ev and ev.enrichment["signature"] == "offensive_tool_banner"


def test_regresshion_cve():
    ev = S.build_event("Timeout before authentication for 185.234.219.84 port 60000")
    assert ev and ev.enrichment["cve"] == "CVE-2024-6387"
    assert "CVE-2024-6387" in ev.tags


def test_libssh_cve():
    ev = S.build_event("Connection from 8.8.8.8 port 1: client software "
                       "version libssh-0.8")
    assert ev and ev.enrichment["cve"] == "CVE-2018-10933"


def test_max_auth_exceeded():
    ev = S.build_event("error: maximum authentication attempts exceeded for "
                       "root from 6.6.6.6 port 22 ssh2")
    assert ev and ev.enrichment["signature"] == "max_auth_exceeded"


def test_login_normal_no_es_firma():
    # Una línea de login normal NO debe matchear ninguna firma de explotación.
    assert S.build_event("Failed password for root from 7.7.7.7 port 22") is None


def test_sin_ip_no_emite():
    # Sin IP extraíble no se emite evento (evita falta de atribución).
    assert S.build_event("Bad protocol version identification 'GET /'") is None


def test_mensaje_vacio():
    assert S.build_event("") is None
    assert S.scan("") is None


@pytest.mark.asyncio
async def test_engine_escala_exploit_attempt():
    bus = EventBus()
    eng = CorrelationEngine(bus)
    ev = S.build_event("Timeout before authentication for 5.5.5.5 port 1")
    ev = await eng.process(ev)
    actor = eng.actors["5.5.5.5"]
    assert "exploit" in actor.flags
    assert actor.score >= 25   # el flag exploit pondera el score


@pytest.mark.asyncio
async def test_engine_rafaga_regresshion_escala_a_critico():
    bus = EventBus()
    eng = CorrelationEngine(bus)
    last = None
    for i in range(12):
        ev = S.build_event(f"Timeout before authentication for 5.5.5.5 port {i}")
        last = await eng.process(ev)
    # ráfaga (cuenta como fails) + flag exploit -> severidad alta
    assert last.severity >= Severity.HIGH
