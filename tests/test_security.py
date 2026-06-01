"""Tests de regresión de seguridad — protegen las defensas de la auditoría."""
import json

import pytest

from centinel.core import EventBus, Severity, ThreatEvent
from centinel.collectors.authlog import AuthLogCollector
from centinel.collectors.journald import JournaldCollector
from centinel.correlation.engine import CorrelationEngine, MAX_ACTORS
from centinel.response.firewall import Firewall


# ---- C-2 / B-1: anti-spoofing e IP inválida en auth.log ----

def _authparser():
    return AuthLogCollector.__new__(AuthLogCollector)


def test_authlog_injection_no_forja_ip_ni_usuario():
    c = _authparser()
    line = ("May 31 12:00:00 h sshd[123]: Invalid user "
            "pwn from 1.2.3.4 port 22 Failed password for root from 9.9.9.9 port 22")
    ev = c._parse(line)
    assert ev is not None
    assert ev.src_ip == "1.2.3.4"      # la IP real de sshd, no la inyectada
    assert ev.user == "pwn"            # username cortado en el espacio
    assert ev.src_ip != "9.9.9.9"


def test_authlog_rechaza_ip_invalida():
    c = _authparser()
    line = "x sshd[1]: Failed password for root from 999.999.999.999 port 22"
    assert c._parse(line) is None


def test_authlog_requiere_prefijo_sshd():
    c = _authparser()
    # Sin el prefijo sshd[pid]: no debe parsear (evita inyección por otro daemon).
    line = "Failed password for root from 1.2.3.4 port 22"
    assert c._parse(line) is None


def test_authlog_username_con_escape_ansi_no_rompe():
    c = _authparser()
    line = "x sshd[1]: Failed password for a\x1b[31mb from 1.2.3.4 port 22"
    ev = c._parse(line)
    # El \x1b no está en la whitelist -> el username no llega a 'from', no matchea.
    assert ev is None


# ---- journald: procedencia confiable ----

def _jparser():
    return JournaldCollector.__new__(JournaldCollector)


def _rec(**k):
    return json.dumps(k).encode()


def test_journald_acepta_sshd_uid0():
    c = _jparser()
    ev = c._parse_record(_rec(SYSLOG_IDENTIFIER="sshd", _UID="0",
        MESSAGE="Failed password for root from 203.0.113.9 port 5555"))
    assert ev and ev.src_ip == "203.0.113.9" and ev.user == "root"


def test_journald_rechaza_procedencia_falsa():
    c = _jparser()
    ev = c._parse_record(_rec(SYSLOG_IDENTIFIER="evil", _UID="1000",
        MESSAGE="Failed password for root from 9.9.9.9 port 22"))
    assert ev is None


def test_journald_rechaza_uid_no_root():
    c = _jparser()
    ev = c._parse_record(_rec(SYSLOG_IDENTIFIER="sshd", _UID="1000",
        MESSAGE="Accepted password for admin from 1.2.3.4 port 22"))
    assert ev is None


def test_journald_message_como_bytes():
    c = _jparser()
    msg = list(b"Invalid user oracle from 198.51.100.5")
    ev = c._parse_record(_rec(SYSLOG_IDENTIFIER="sshd", _UID="0", MESSAGE=msg))
    assert ev and ev.kind == "login_invalid_user" and ev.user == "oracle"


# ---- Firewall: salvaguardas de respuesta activa ----

def test_firewall_nunca_bloquea_lan():
    fw = Firewall(mode="dry-run")
    ok, detail = fw.block("192.168.1.10")
    assert ok is False and "privada" in detail


def test_firewall_nunca_bloquea_loopback():
    fw = Firewall(mode="dry-run")
    ok, _ = fw.block("127.0.0.1")
    assert ok is False


def test_firewall_respeta_allowlist():
    fw = Firewall(mode="dry-run", allowlist=["45.0.0.0/8"])
    ok, detail = fw.block("45.135.232.17")
    assert ok is False and "allowlist" in detail


def test_firewall_bloquea_publica_en_dryrun():
    fw = Firewall(mode="dry-run")
    ok, detail = fw.block("203.0.113.250") if False else fw.block("8.8.8.8")
    assert ok is True and "DRY-RUN" in detail


def test_firewall_idempotente():
    fw = Firewall(mode="dry-run")
    assert fw.block("8.8.8.8")[0] is True
    ok, detail = fw.block("8.8.8.8")
    assert ok is False and "ya bloqueada" in detail


# ---- Correlación: detección y anti-DoS de memoria ----

@pytest.mark.asyncio
async def test_correlacion_detecta_bruteforce():
    bus = EventBus()
    eng = CorrelationEngine(bus)
    alerts = []
    q = bus.subscribe()

    async def collect():
        while True:
            ev = await q.get()
            if ev.source == "correlation":
                alerts.append(ev)

    import asyncio
    t = asyncio.create_task(collect())
    for i in range(12):
        await eng.process(ThreatEvent(kind="login_fail", src_ip="5.6.7.8",
                                      user=f"u{i}"))
    await asyncio.sleep(0.05)
    t.cancel()
    kinds = {a.kind for a in alerts}
    assert "alert_bruteforce" in kinds


@pytest.mark.asyncio
async def test_correlacion_purga_actores_inactivos():
    bus = EventBus()
    eng = CorrelationEngine(bus)
    # Actor viejo con score 0 debe purgarse cuando llega uno nuevo.
    await eng.process(ThreatEvent(ts=0.0, kind="tcp_syn", src_ip="1.1.1.1",
                                  dst_port=80))
    eng.actors["1.1.1.1"].score = 0
    eng.actors["1.1.1.1"].last_seen = 0.0
    # Evento nuevo "mucho" después -> dispara _evict.
    await eng.process(ThreatEvent(ts=10_000.0, kind="tcp_syn", src_ip="2.2.2.2",
                                  dst_port=80))
    assert "1.1.1.1" not in eng.actors
    assert "2.2.2.2" in eng.actors
