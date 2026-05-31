"""Capa de respuesta activa: decide a quién corregir y lo ejecuta.

Toma el estado de la correlación, selecciona los actores que superan el umbral
de score (o que dispararon una alerta de compromiso) y los pasa al firewall.
Devuelve un informe de acciones para que la presentación lo muestre.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..correlation.engine import Actor, CorrelationEngine
from .firewall import Firewall


@dataclass
class Action:
    ip: str
    score: float
    executed: bool
    detail: str


class Responder:
    def __init__(self, engine: CorrelationEngine, firewall: Firewall,
                 threshold: float = 70.0) -> None:
        self.engine = engine
        self.fw = firewall
        self.threshold = threshold

    def priorities(self, top: int = 10) -> list[Actor]:
        """Lo más importante a corregir: actores rankeados por score."""
        return [a for a in self.engine.get_actors()[:top] if a.score > 0]

    def remediate(self) -> list[Action]:
        """Bloquea a quien supere el umbral. Idempotente."""
        actions: list[Action] = []
        for a in self.engine.get_actors():
            if a.score < self.threshold:
                break  # vienen ordenados desc: el resto también está por debajo
            executed, detail = self.fw.block(a.ip)
            actions.append(Action(a.ip, a.score, executed, detail))
        return actions
