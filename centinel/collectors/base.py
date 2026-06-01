"""Contrato base de un colector. Cada fuente es una capa pluggable."""
from __future__ import annotations

import abc

from ..core import EventBus, ThreatEvent


class Collector(abc.ABC):
    name: str = "base"

    def __init__(self, bus: EventBus) -> None:
        self.bus = bus

    async def emit(self, event: ThreatEvent) -> None:
        event.source = self.name
        await self.bus.publish(event)

    @abc.abstractmethod
    async def run(self) -> None:
        """Bucle infinito que lee la fuente y publica eventos."""
        raise NotImplementedError

    def available(self) -> bool:
        """¿Puede correr en este host? (permisos, SO, dependencias)."""
        return True
