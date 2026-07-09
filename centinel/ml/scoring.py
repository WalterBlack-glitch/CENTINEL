"""Scoring con ML ligero: regresión logística pura, sin dependencias.

El motor de correlación ya deriva un score por **reglas** (if/else sumando
puntos). Eso funciona, pero tiene dos problemas que la FODA señaló:

  - **Evasión**: al ser umbrales legibles, un atacante que lee el código diseña
    payloads justo por debajo de cada umbral.
  - **Falsos positivos**: la suma lineal de puntos no captura que ciertas señales
    juntas valen mucho más que por separado (p.ej. cadencia robótica + spraying).

Esta capa añade un **modelo logístico** sobre las MISMAS features que ya
extraemos (fallos, usuarios, puertos, flags robótico/campaña/canary/exploit/
honeypot, intel de IP). Devuelve una **confianza 0..1** de que el actor sea
malicioso. No sustituye a las reglas: las complementa como segunda opinión.

Es "ML" honesto: un clasificador lineal cuyos pesos están calibrados a mano
(no hay pipeline de entrenamiento ni sklearn — 0 dependencias obligatorias).
Los pesos viven en `WEIGHTS` y se pueden recalibrar sin tocar la lógica. Todo
es **puro y testeable**: entra un dict de features, sale un float.

MITRE: transversal — mejora la calidad de detección de todas las capas.
"""
from __future__ import annotations

import math

# Nombres de feature -> peso del modelo logístico. Positivo = empuja a malicioso.
# Calibrados a mano sobre el comportamiento observado de las heurísticas: las
# señales de "confirmación" (canary/honeypot) pesan mucho; el volumen (fails)
# pesa poco por sí solo pero se combina de forma no lineal vía el sesgo.
WEIGHTS: dict[str, float] = {
    "fails":       1.4,   # fuerza bruta (feature saturada 0..1)
    "users":       2.2,   # spraying / enumeración
    "ports":       1.6,   # scanning
    "multi_tech":  1.8,   # recon + auth a la vez (campaña)
    "robotic":     2.0,   # cadencia automatizada
    "campaign":    2.6,   # botnet distribuida
    "canary":      4.8,   # tocó credencial-cebo => malicioso confirmado
    "exploit":     2.4,   # firma de explotación
    "honeypot":    4.8,   # tocó el señuelo => malicioso confirmado
    "intel":       3.0,   # IP en feed de C2/botnet
}
BIAS: float = -3.2   # sesgo: sin señales, la probabilidad base es baja (~0.04).

# Umbral por defecto para considerar la confianza "alta" (marca tag/enrichment).
HIGH_CONFIDENCE = 0.80


def _sat(n: int, cap: int) -> float:
    """Satura un contador a [0,1] dividiendo por su tope (evita que un flood
    domine el modelo linealmente)."""
    if n <= 0:
        return 0.0
    return min(n, cap) / cap


def extract_features(
    *,
    fails: int = 0,
    users: int = 0,
    ports: int = 0,
    flags: set[str] | frozenset[str] | None = None,
    has_intel: bool = False,
) -> dict[str, float]:
    """Convierte los contadores/flags de un actor en el vector de features 0..1.

    Pura: no toca /proc ni red. `flags` es el mismo set que usa el Actor de la
    correlación ("robotico", "campaign", "canary", "exploit", "honeypot").
    """
    flags = flags or set()
    f_fails = _sat(fails, 30)
    f_users = _sat(users, 20)
    f_ports = _sat(ports, 40)
    return {
        "fails": f_fails,
        "users": f_users,
        "ports": f_ports,
        "multi_tech": 1.0 if (users > 0 and ports > 0) else 0.0,
        "robotic": 1.0 if "robotico" in flags else 0.0,
        "campaign": 1.0 if "campaign" in flags else 0.0,
        "canary": 1.0 if "canary" in flags else 0.0,
        "exploit": 1.0 if "exploit" in flags else 0.0,
        "honeypot": 1.0 if "honeypot" in flags else 0.0,
        "intel": 1.0 if has_intel else 0.0,
    }


def confidence(features: dict[str, float]) -> float:
    """Confianza logística 0..1 de que el actor sea malicioso.

    z = bias + Σ w_i · x_i ;  conf = sigmoid(z). Pura y determinista.
    """
    z = BIAS
    for name, w in WEIGHTS.items():
        z += w * features.get(name, 0.0)
    # sigmoide numéricamente estable
    if z >= 0:
        return round(1.0 / (1.0 + math.exp(-z)), 4)
    ez = math.exp(z)
    return round(ez / (1.0 + ez), 4)


def score_actor(
    *,
    fails: int = 0,
    users: int = 0,
    ports: int = 0,
    flags: set[str] | frozenset[str] | None = None,
    has_intel: bool = False,
) -> float:
    """Atajo: features + confianza en una llamada."""
    return confidence(extract_features(
        fails=fails, users=users, ports=ports,
        flags=flags, has_intel=has_intel))
