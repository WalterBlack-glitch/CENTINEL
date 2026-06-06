"""Tests del detector de beaconing C2 (analizador de periodicidad + colector)."""
import random

from centinel.core import Severity
from centinel.correlation.beacon import BeaconAnalyzer
from centinel.collectors.beacon import BeaconCollector


# ---- BeaconAnalyzer: la matemática de periodicidad ----

def test_beacon_perfectamente_regular_es_high():
    an = BeaconAnalyzer()
    fired = [r for i in range(8)
             if (r := an.observe("45.10.10.10", ts=1000 + i * 60))]
    assert fired, "un beacon de reloj perfecto debe dispararse"
    v = fired[0]
    assert v.dst == "45.10.10.10"
    assert abs(v.period - 60) < 1e-6
    assert v.jitter < 0.01
    assert v.severity == int(Severity.HIGH)


def test_trafico_irregular_no_dispara():
    an = BeaconAnalyzer()
    random.seed(1)
    t = 0.0
    last = None
    for _ in range(14):
        t += random.uniform(1, 400)   # intervalos muy dispares
        last = an.observe("8.8.4.4", ts=t)
    assert last is None


def test_pocos_contactos_no_dispara():
    an = BeaconAnalyzer()
    out = [an.observe("1.2.3.4", ts=i * 30) for i in range(4)]
    assert all(o is None for o in out)


def test_intervalo_demasiado_corto_es_chatter():
    an = BeaconAnalyzer()
    v = None
    for i in range(12):
        v = an.observe("9.9.9.9", ts=i * 0.2)   # 5 contactos/s -> chatter
    assert v is None


def test_intervalo_demasiado_largo_se_ignora():
    an = BeaconAnalyzer(max_period=3600.0)
    v = None
    for i in range(8):
        v = an.observe("3.3.3.3", ts=i * 5400)   # cada 1.5h > max_period
    assert v is None


def test_rate_limit_no_repite_veredicto():
    an = BeaconAnalyzer(rate_limit=10_000)
    fired = []
    for i in range(8):
        r = an.observe("5.5.5.5", ts=1000 + i * 60)
        if r:
            fired.append(r)
    again = an.observe("5.5.5.5", ts=1000 + 8 * 60)
    assert len(fired) == 1 and again is None


# ---- BeaconCollector: detección por flanco de aparición ----

def test_collector_detecta_reconexiones_periodicas():
    """Una IP que aparece/desaparece cada 60s genera un beacon; una IP siempre
    presente (conexión persistente, no reconecta) no genera contactos nuevos."""
    col = BeaconCollector(bus=None)
    ts = 1000.0
    verdicts = []
    for i in range(13):
        # 'evil' reconecta cada barrido (flanco); 'cdn' está siempre presente.
        present = {"cdn.example"} | ({"45.66.77.88"} if i % 2 == 0 else set())
        evs = col._step(present, ts)
        verdicts += evs
        ts += 60.0
    assert any(e.kind == "beacon_c2" and e.src_ip == "45.66.77.88"
               for e in verdicts)
    # 'cdn.example' nunca desaparece -> nunca cuenta como contacto nuevo.
    assert all(e.src_ip != "cdn.example" for e in verdicts)


def test_collector_event_lleva_enrichment_y_tags():
    col = BeaconCollector(bus=None)
    ts = 0.0
    out = []
    for i in range(12):
        present = {"9.9.9.10"} if i % 2 == 0 else set()
        out += col._step(present, ts)
        ts += 30.0
    assert out, "no se generó ningún beacon"
    ev = out[0]
    assert ev.kind == "beacon_c2"
    assert "beacon" in ev.tags
    assert ev.enrichment["pattern"] == "periodic_callback"
    assert ev.enrichment["period_s"] > 0


def test_beacon_en_layers_need_sustained_root():
    from centinel.security import layers_need_sustained_root

    class Args:
        beacon = True
        netwatch = False
        dnswatch = False
        rootcheck = False
        respond_live = False
        sniff = False

    need = layers_need_sustained_root(Args())
    assert any("beacon" in n for n in need)
