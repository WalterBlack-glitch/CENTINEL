"""Tests puros del scorer logístico: sin /proc, sin red, sin kernel.

Verifican monotonía (más señales -> más confianza), rango [0,1], la no
linealidad de combinar señales, y que las señales de confirmación
(canary/honeypot/intel) disparan alta confianza por sí solas.
"""
from centinel.ml.scoring import (
    confidence, extract_features, score_actor, HIGH_CONFIDENCE,
)


def test_actor_limpio_confianza_baja():
    c = score_actor()
    assert 0.0 <= c <= 1.0
    assert c < 0.1   # sin señales, casi seguro benigno


def test_rango_siempre_0_1():
    # Todo encendido al máximo no puede pasar de 1.0.
    c = score_actor(fails=999, users=999, ports=999,
                    flags={"robotico", "campaign", "canary",
                           "exploit", "honeypot"}, has_intel=True)
    assert 0.0 <= c <= 1.0
    assert c > 0.99


def test_mas_fallos_mas_confianza():
    poco = score_actor(fails=3)
    mucho = score_actor(fails=30)
    assert mucho > poco


def test_honeypot_solo_dispara_alta_confianza():
    # Tocar el señuelo es malicioso confirmado: alta confianza sin más señales.
    c = score_actor(flags={"honeypot"})
    assert c >= HIGH_CONFIDENCE


def test_canary_solo_dispara_alta_confianza():
    c = score_actor(flags={"canary"})
    assert c >= HIGH_CONFIDENCE


def test_intel_solo_sube_confianza():
    base = score_actor()
    con_intel = score_actor(has_intel=True)
    assert con_intel > base


def test_combinacion_no_lineal_supera_a_las_partes():
    # robótico + spraying juntos deben valer más que cualquiera por separado.
    solo_robotico = score_actor(flags={"robotico"})
    solo_spray = score_actor(users=8)
    juntos = score_actor(users=8, flags={"robotico"})
    assert juntos > solo_robotico
    assert juntos > solo_spray


def test_extract_features_satura_contadores():
    f = extract_features(fails=1000, users=1000, ports=1000)
    assert f["fails"] == 1.0
    assert f["users"] == 1.0
    assert f["ports"] == 1.0


def test_extract_features_multi_tech():
    solo_users = extract_features(users=5)
    ambos = extract_features(users=5, ports=5)
    assert solo_users["multi_tech"] == 0.0
    assert ambos["multi_tech"] == 1.0


def test_confidence_determinista():
    f = extract_features(fails=10, users=3, flags={"robotico"})
    assert confidence(f) == confidence(f)


def test_flags_desconocidos_no_rompen():
    c = score_actor(flags={"algo_raro", "robotico"})
    assert 0.0 <= c <= 1.0
