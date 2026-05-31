"""Capa de correlación: el cerebro. Va más allá de contar fallos.

Mantiene estado por IP (actor) y deriva un score de amenaza combinando varias
señales en ventanas deslizantes:

  - Tasa de fallos de login (fuerza bruta clásica).
  - Diversidad de usuarios probados (password spraying / enumeración).
  - Diversidad de puertos (port scan).
  - Mezcla de técnicas (recon + auth = escalada de campaña).
  - Éxito tras muchos fallos (posible compromiso -> CRITICAL).

Emite eventos sintéticos de alerta cuando un actor cruza umbrales, sin
re-emitir ruido: usa cooldown por (ip, tipo de alerta).
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field

from ..core import EventBus, Severity, ThreatEvent

WINDOW = 120.0       # segundos de memoria por actor
MAX_ACTORS = 50_000  # tope duro: evita agotamiento de RAM (C-1)
MAX_USERS = 256      # cota por actor para usuarios/puertos rastreados
MAX_PORTS = 1024


@dataclass
class Actor:
    ip: str
    fails: deque = field(default_factory=lambda: deque())
    users: dict[str, float] = field(default_factory=dict)
    ports: dict[int, float] = field(default_factory=dict)
    kinds: set[str] = field(default_factory=set)
    last_mac: str | None = None
    last_alert: dict[str, float] = field(default_factory=dict)
    score: float = 0.0
    last_seen: float = 0.0

    def prune(self, now: float) -> None:
        while self.fails and now - self.fails[0] > WINDOW:
            self.fails.popleft()
        self.users = {u: t for u, t in self.users.items() if now - t <= WINDOW}
        self.ports = {p: t for p, t in self.ports.items() if now - t <= WINDOW}


class CorrelationEngine:
    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        self.actors: dict[str, Actor] = {}
        self._last_evict = 0.0

    def _evict(self, now: float, force: bool = False) -> None:
        """Purga actores inactivos (C-1). Throttle: como mucho cada 5 s."""
        if not force and now - self._last_evict < 5.0:
            return
        self._last_evict = now
        dead = [ip for ip, a in self.actors.items()
                if now - a.last_seen > WINDOW * 2 and a.score == 0]
        for ip in dead:
            del self.actors[ip]
        if force and self.actors:
            oldest = min(self.actors, key=lambda ip: self.actors[ip].last_seen)
            del self.actors[oldest]

    def get_actors(self) -> list[Actor]:
        return sorted(self.actors.values(), key=lambda a: a.score, reverse=True)

    async def process(self, ev: ThreatEvent) -> ThreatEvent:
        if not ev.src_ip:
            return ev
        now = ev.ts
        self._evict(now)
        actor = self.actors.get(ev.src_ip)
        if actor is None:
            if len(self.actors) >= MAX_ACTORS:
                self._evict(now, force=True)
                if len(self.actors) >= MAX_ACTORS:
                    return ev   # backpressure: bajo flood extremo, descarta
            actor = self.actors[ev.src_ip] = Actor(ip=ev.src_ip)
        actor.last_seen = now
        actor.kinds.add(ev.kind)
        if ev.mac:
            actor.last_mac = ev.mac

        if ev.kind in ("login_fail", "login_invalid_user"):
            actor.fails.append(now)
            if ev.user and len(actor.users) < MAX_USERS:
                actor.users[ev.user] = now
        if ev.dst_port and len(actor.ports) < MAX_PORTS:
            actor.ports[ev.dst_port] = now

        actor.prune(now)
        actor.score = self._score(actor)
        ev.score = actor.score

        # Compromiso: login exitoso tras muchos fallos recientes.
        if ev.kind == "login_success" and len(actor.fails) >= 5:
            await self._alert(actor, "compromise", Severity.CRITICAL,
                              f"Login EXITOSO tras {len(actor.fails)} fallos "
                              f"(user={ev.user}) — posible compromiso", now)

        await self._maybe_alert(actor, now)
        ev.severity = max(ev.severity, self._sev_from_score(actor.score))
        return ev

    def _score(self, a: Actor) -> float:
        s = 0.0
        s += min(len(a.fails), 30) * 2.0                  # fuerza bruta
        s += min(len(a.users), 20) * 4.0                  # spraying/enum
        s += min(len(a.ports), 40) * 1.5                  # scanning
        if {"recon", "auth"} <= {t for k in a.kinds for t in (k,)} or (
            a.users and a.ports
        ):
            s += 15                                        # campaña multi-técnica
        return round(s, 1)

    @staticmethod
    def _sev_from_score(score: float) -> Severity:
        if score >= 80:
            return Severity.CRITICAL
        if score >= 50:
            return Severity.HIGH
        if score >= 25:
            return Severity.MEDIUM
        if score >= 10:
            return Severity.LOW
        return Severity.INFO

    async def _maybe_alert(self, a: Actor, now: float) -> None:
        if len(a.fails) >= 10:
            await self._alert(a, "bruteforce", Severity.HIGH,
                              f"Fuerza bruta: {len(a.fails)} fallos/{int(WINDOW)}s", now)
        if len(a.users) >= 5:
            await self._alert(a, "spray", Severity.HIGH,
                              f"Password spraying: {len(a.users)} usuarios probados", now)
        if len(a.ports) >= 15:
            await self._alert(a, "scan", Severity.MEDIUM,
                              f"Port scan: {len(a.ports)} puertos", now)

    async def _alert(self, a: Actor, kind: str, sev: Severity,
                     msg: str, now: float, cooldown: float = 30.0) -> None:
        if now - a.last_alert.get(kind, 0) < cooldown:
            return
        a.last_alert[kind] = now
        await self.bus.publish(ThreatEvent(
            ts=now, source="correlation", kind=f"alert_{kind}",
            src_ip=a.ip, mac=a.last_mac, severity=sev, score=a.score,
            message=msg, tags={"alert", kind},
        ))
