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
from .ai_defense import CampaignTracker, timing_cv, ROBOTIC_CV, MIN_INTERVALS

WINDOW = 120.0       # segundos de memoria por actor
MAX_ACTORS = 50_000  # tope duro: evita agotamiento de RAM (C-1)
MAX_USERS = 256      # cota por actor para usuarios/puertos rastreados
MAX_PORTS = 1024
MAX_INTERVALS = 64   # muestras de temporización retenidas por actor


@dataclass
class Actor:
    ip: str
    fails: deque = field(default_factory=lambda: deque())
    users: dict[str, float] = field(default_factory=dict)
    ports: dict[int, float] = field(default_factory=dict)
    kinds: set[str] = field(default_factory=set)
    flags: set[str] = field(default_factory=set)   # "robotico", "campaign", "canary"
    intervals: deque = field(default_factory=lambda: deque(maxlen=MAX_INTERVALS))
    last_event_ts: float = 0.0
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
    def __init__(self, bus: EventBus, canary_users: set[str] | None = None) -> None:
        self.bus = bus
        self.actors: dict[str, Actor] = {}
        self._last_evict = 0.0
        # Defensas anti-IA
        self.canary_users = {u.lower() for u in (canary_users or set())}
        self.campaign = CampaignTracker()

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

        # Temporización: intervalo entre eventos de este actor (detección robótica).
        # Solo se acumulan intervalos dentro de la ventana: un hueco largo (típico
        # de low-and-slow) reinicia la muestra para que no se mezclen cadencias y
        # se pueda evadir/limpiar el flag robótico intercalando huecos.
        if actor.last_event_ts:
            gap = now - actor.last_event_ts
            if gap > WINDOW:
                actor.intervals.clear()
                actor.flags.discard("robotico")
            else:
                actor.intervals.append(gap)
        actor.last_event_ts = now

        is_auth = ev.kind in ("login_fail", "login_invalid_user")
        if is_auth:
            actor.fails.append(now)
            if ev.user and len(actor.users) < MAX_USERS:
                actor.users[ev.user] = now

        if ev.dst_port and len(actor.ports) < MAX_PORTS:
            actor.ports[ev.dst_port] = now

        # ---- Defensas anti-IA ----
        await self._ai_defenses(ev, actor, is_auth, now)

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

    async def _ai_defenses(self, ev: ThreatEvent, actor: "Actor",
                           is_auth: bool, now: float) -> None:
        # 1) Canary: credencial-cebo => malicioso por definición, CRITICAL.
        if ev.user and ev.user.lower() in self.canary_users:
            actor.flags.add("canary")
            ev.tags.add("canary")
            await self._alert(actor, "canary", Severity.CRITICAL,
                f"Acceso a credencial-cebo '{ev.user}' — actor malicioso "
                f"confirmado", now, cooldown=10.0)

        # 2) Timing robótico: cadencia demasiado regular = automatización.
        cv = timing_cv(actor.intervals)
        if cv is not None and cv < ROBOTIC_CV:
            if "robotico" not in actor.flags:
                actor.flags.add("robotico")
                ev.tags.add("robotico")
                await self._alert(actor, "robotic_timing", Severity.HIGH,
                    f"Cadencia robótica (CV={cv:.3f} sobre {len(actor.intervals)} "
                    f"intervalos) — bot/script automatizado", now, cooldown=120.0)
        elif cv is not None and cv >= ROBOTIC_CV:
            actor.flags.discard("robotico")

        # 3) Campaña distribuida (correlación GLOBAL entre IPs): detecta botnets
        #    low-and-slow que individualmente no cruzan el umbral por-IP.
        if is_auth:
            for c in self.campaign.observe(ev.src_ip, ev.user, now):
                actor.flags.add("campaign")
                await self.bus.publish(ThreatEvent(
                    ts=now, source="correlation", kind=f"alert_{c['kind']}",
                    src_ip=ev.src_ip, mac=actor.last_mac, severity=Severity.HIGH,
                    score=actor.score, message=c["message"],
                    tags={"alert", "ai-defense", c["kind"]},
                    enrichment={"sample_ips": c["sample_ips"]}))

    def _score(self, a: Actor) -> float:
        s = 0.0
        s += min(len(a.fails), 30) * 2.0                  # fuerza bruta
        s += min(len(a.users), 20) * 4.0                  # spraying/enum
        s += min(len(a.ports), 40) * 1.5                  # scanning
        if {"recon", "auth"} <= {t for k in a.kinds for t in (k,)} or (
            a.users and a.ports
        ):
            s += 15                                        # campaña multi-técnica
        # Señales anti-IA: elevan el score aunque el volumen por-IP sea bajo.
        if "robotico" in a.flags:
            s += 20
        if "campaign" in a.flags:
            s += 30
        if "canary" in a.flags:
            s += 60
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
        last = a.last_alert.get(kind)
        if last is not None and now - last < cooldown:
            return  # ya alertado recientemente; la PRIMERA vez siempre dispara
        a.last_alert[kind] = now
        await self.bus.publish(ThreatEvent(
            ts=now, source="correlation", kind=f"alert_{kind}",
            src_ip=a.ip, mac=a.last_mac, severity=sev, score=a.score,
            message=msg, tags={"alert", kind},
        ))
