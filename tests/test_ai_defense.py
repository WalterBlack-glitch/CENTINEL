"""Tests de las defensas contra ataques dirigidos por IA."""
import asyncio

import pytest

from centinela.core import EventBus, ThreatEvent
from centinela.correlation.engine import CorrelationEngine
from centinela.correlation.ai_defense import timing_cv, CampaignTracker, ROBOTIC_CV


async def _run(engine, events):
    alerts = []
    q = engine.bus.subscribe()

    async def collect():
        while True:
            e = await q.get()
            if e.source == "correlation":
                alerts.append(e.kind)

    t = asyncio.create_task(collect())
    for ev in events:
        await engine.process(ev)
    await asyncio.sleep(0.03)
    t.cancel()
    return alerts


# ---- timing_cv ----

def test_timing_cv_cadencia_perfecta_es_baja():
    cv = timing_cv([2.0] * 12)
    assert cv == 0.0


def test_timing_cv_aleatorio_es_alto():
    import random
    random.seed(1)
    cv = timing_cv([random.expovariate(1.0) for _ in range(60)])
    assert cv > ROBOTIC_CV


def test_timing_cv_pocas_muestras_none():
    assert timing_cv([1.0, 2.0]) is None


# ---- canary ----

@pytest.mark.asyncio
async def test_canary_dispara_critico_en_un_intento():
    bus = EventBus()
    eng = CorrelationEngine(bus, canary_users={"svc_backup"})
    alerts = await _run(eng, [
        ThreatEvent(kind="login_invalid_user", src_ip="5.5.5.5",
                    user="svc_backup", ts=1_000_000.0)])
    assert "alert_canary" in alerts
    assert "canary" in eng.actors["5.5.5.5"].flags


@pytest.mark.asyncio
async def test_canary_case_insensitive():
    bus = EventBus()
    eng = CorrelationEngine(bus, canary_users={"Honey"})
    alerts = await _run(eng, [
        ThreatEvent(kind="login_fail", src_ip="6.6.6.6", user="HONEY",
                    ts=1_000_000.0)])
    assert "alert_canary" in alerts


# ---- campaña distribuida (botnet low-and-slow) ----

@pytest.mark.asyncio
async def test_credential_stuffing_distribuido():
    bus = EventBus()
    eng = CorrelationEngine(bus)
    # 8 IPs distintas, 1 intento cada una contra el mismo usuario.
    evs = [ThreatEvent(kind="login_fail", src_ip=f"77.0.0.{i}", user="root",
                       ts=1_000_000.0 + i) for i in range(8)]
    alerts = await _run(eng, evs)
    assert "alert_credential_stuffing_distribuido" in alerts


@pytest.mark.asyncio
async def test_botnet_subred():
    bus = EventBus()
    eng = CorrelationEngine(bus)
    # 12 IPs de la misma /24 con usuarios distintos (no dispara user, sí subred).
    evs = [ThreatEvent(kind="login_fail", src_ip=f"88.88.88.{i}", user=f"u{i}",
                       ts=1_000_000.0 + i) for i in range(12)]
    alerts = await _run(eng, evs)
    assert "alert_botnet_subred" in alerts


# ---- timing robótico ----

@pytest.mark.asyncio
async def test_timing_robotico_detectado():
    bus = EventBus()
    eng = CorrelationEngine(bus)
    evs = [ThreatEvent(kind="login_fail", src_ip="9.9.9.9", user=f"u{i%3}",
                       ts=1_000_000.0 + i * 2.0) for i in range(12)]
    alerts = await _run(eng, evs)
    assert "alert_robotic_timing" in alerts
    assert "robotico" in eng.actors["9.9.9.9"].flags


# ---- anti-DoS del tracker ----

def test_campaign_tracker_purga():
    t = CampaignTracker()
    t.observe("1.2.3.4", "root", now=1000.0)
    assert t.by_user
    # mucho después -> purga al observar de nuevo
    t._last_prune = 0.0
    t.observe("9.8.7.6", "admin", now=1000.0 + 10_000)
    assert "root" not in t.by_user
