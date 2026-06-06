"""Beacon: detecta callbacks C2 por su REGULARIDAD temporal.

El malware moderno (Cobalt Strike, Sliver, Mythic, Empire, agentes propios)
"llama a casa" a intervalos casi fijos — cada 30s, cada 5min, cada hora —
para pedir órdenes. Ese latido periódico es justo lo que un humano NO hace:
el tráfico legítimo es irregular y a ráfagas. Aquí está la señal.

CENTINEL muestrea las conexiones TCP salientes (lectura de /proc/net, sin
subprocess) y registra, por IP remota, los instantes en que aparece una nueva
conexión. Cuando una IP acumula suficientes contactos, analiza los intervalos
entre ellos: si el coeficiente de variación (desviación/​media) es muy bajo,
el patrón es un beacon automatizado (MITRE T1071 / T1571).

Limitación honesta: el muestreo de /proc ve una conexión solo si está activa
en el instante del barrido. Un beacon ultra-corto (conecta, manda 1 byte y
cierra en <intervalo de barrido) puede escapar a algún muestreo; por eso se
detecta por **flanco de aparición** (no estaba → está) y se baja el intervalo
de barrido. Combinar con --sniff/conntrack daría fidelidad total. El núcleo
de análisis (`BeaconAnalyzer`) es independiente y se testea con timestamps
sintéticos.
"""
from __future__ import annotations

import asyncio
import os
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from ..core import Severity, ThreatEvent

# Defaults del analizador.
_MIN_HITS = 6          # nº de contactos para arriesgar un veredicto
_MIN_PERIOD = 1.0      # s: por debajo es chatter, no un beacon
_MAX_PERIOD = 7200.0   # s: por encima (2h) no nos interesa perseguir
_JITTER = 0.20         # CoV máximo (stdev/media) para llamarlo "regular"
_WINDOW = 7200.0       # s de historia por destino
_MAX_TS = 64           # tope de timestamps guardados por destino
_RATE_LIMIT = 1800.0   # s entre alertas del mismo destino


@dataclass
class BeaconVerdict:
    dst: str
    hits: int
    period: float     # intervalo medio (s)
    jitter: float     # coeficiente de variación (0 = reloj perfecto)
    severity: int


class BeaconAnalyzer:
    """Lógica pura de periodicidad. Sin I/O — testeable con timestamps a mano."""

    def __init__(self, min_hits: int = _MIN_HITS, min_period: float = _MIN_PERIOD,
                 max_period: float = _MAX_PERIOD, jitter: float = _JITTER,
                 window: float = _WINDOW, rate_limit: float = _RATE_LIMIT) -> None:
        self.min_hits = max(3, min_hits)
        self.min_period = min_period
        self.max_period = max_period
        self.jitter = jitter
        self.window = window
        self.rate_limit = rate_limit
        self._hist: dict[str, deque[float]] = defaultdict(deque)
        self._alerted: dict[str, float] = {}

    def observe(self, dst: str, ts: float | None = None) -> BeaconVerdict | None:
        """Registra un contacto con `dst` y devuelve un veredicto si hay beacon."""
        ts = time.time() if ts is None else ts
        dq = self._hist[dst]
        dq.append(ts)
        while dq and ts - dq[0] > self.window:
            dq.popleft()
        while len(dq) > _MAX_TS:
            dq.popleft()
        if len(dq) < self.min_hits:
            return None
        seq = list(dq)
        deltas = [b - a for a, b in zip(seq, seq[1:])]
        if len(deltas) < self.min_hits - 1:
            return None
        mean = sum(deltas) / len(deltas)
        if mean < self.min_period or mean > self.max_period:
            return None
        var = sum((d - mean) ** 2 for d in deltas) / len(deltas)
        cov = (var ** 0.5) / mean if mean else 1.0
        if cov > self.jitter:
            return None
        last = self._alerted.get(dst)
        if last is not None and ts - last < self.rate_limit:
            return None
        self._alerted[dst] = ts
        return BeaconVerdict(dst=dst, hits=len(dq), period=mean, jitter=cov,
                             severity=self._severity(cov, len(dq)))

    @staticmethod
    def _severity(cov: float, hits: int) -> int:
        # Reloj casi perfecto + muchas muestras = alta confianza.
        if cov <= 0.08 and hits >= 8:
            return int(Severity.HIGH)
        if cov <= 0.12:
            return int(Severity.HIGH)
        return int(Severity.MEDIUM)

    def gc(self, now: float | None = None) -> None:
        now = time.time() if now is None else now
        for dst in list(self._hist):
            dq = self._hist[dst]
            while dq and now - dq[0] > self.window:
                dq.popleft()
            if not dq:
                del self._hist[dst]
        if len(self._alerted) > 4096:
            self._alerted = {k: t for k, t in self._alerted.items()
                             if now - t < self.rate_limit}


# El colector vive en collectors/, pero el análisis pertenece a correlation/.
# Para no romper el patrón "un colector por archivo en collectors/", exponemos
# aquí solo el analizador; el BeaconCollector lo importa.
