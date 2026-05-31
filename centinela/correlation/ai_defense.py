"""Defensas contra ataques dirigidos por IA (capa de correlación avanzada).

Un atacante asistido por IA/LLM rompe las defensas clásicas porque:

  1. Distribuye el ataque entre una botnet y va "low-and-slow": cada IP queda
     POR DEBAJO del umbral por-IP, así que la detección clásica nunca dispara.
  2. Coordina qué usuarios/credenciales probar (credential stuffing dirigido),
     reusando filtraciones, en vez de fuerza bruta ciega.
  3. Tiene temporización artificial: o cadencia de máquina (muy regular) o
     jitter algorítmico para imitar a un humano.

Este módulo aporta tres detectores que NO dependen de un umbral por-IP:

  - CampaignTracker: correlación GLOBAL entre actores. Agrega por usuario
    objetivo (¿cuántas IPs distintas atacan al mismo usuario?) y por subred /24
    (¿cuántas IPs de la misma subred?). Detecta la botnet aunque cada nodo sea
    sigiloso.
  - TimingAnalyzer: regularidad de los intervalos entre intentos. Una cadencia
    de coeficiente de variación muy bajo delata automatización ("robótico").
  - canary users: credenciales-cebo que ningún usuario legítimo usa. Cualquier
    intento contra ellas es, por definición, malicioso → severidad inmediata.

Todo el estado está acotado (cotas duras + purga por ventana) para que el
propio detector no sea un vector de DoS de memoria.
"""
from __future__ import annotations

import ipaddress
import statistics
from collections import OrderedDict
from dataclasses import dataclass, field

WINDOW = 600.0          # 10 min de memoria global (low-and-slow necesita ventana amplia)
MAX_TRACKED_USERS = 20_000
MAX_TRACKED_SUBNETS = 20_000
DISTINCT_IPS_PER_USER = 8    # nº de IPs distintas atacando un user => campaña distribuida
DISTINCT_IPS_PER_SUBNET = 12 # nº de IPs distintas de una /24 => botnet de subred
MIN_INTERVALS = 8            # muestras mínimas para juzgar la temporización
ROBOTIC_CV = 0.06           # coef. de variación por debajo del cual es "robótico"


def _subnet(ip: str) -> str | None:
    """Agrupa IPv4 por /24 e IPv6 por /64 (sin /64, una botnet IPv6 nunca
    correlacionaría porque cada host tiene su propia /128)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    prefix = 24 if addr.version == 4 else 64
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False).network_address)


def timing_cv(intervals) -> float | None:
    """Coeficiente de variación (stddev/media) de los intervalos entre eventos.

    Cercano a 0 = cadencia de máquina. ~1 = proceso aleatorio (humano/Poisson).
    """
    vals = [x for x in intervals if x > 0]
    if len(vals) < MIN_INTERVALS:
        return None
    mean = statistics.fmean(vals)
    if mean <= 0:
        return None
    return statistics.pstdev(vals) / mean


@dataclass
class CampaignTracker:
    # user -> OrderedDict{ip: last_ts}.  LRU: al llenar, se expulsa el más
    # antiguo en vez de "dejar de admitir" (que cegaría el detector ante un
    # atacante que rota usernames durante toda la ventana de prune).
    by_user: "OrderedDict[str, dict[str, float]]" = field(default_factory=OrderedDict)
    by_subnet: "OrderedDict[str, dict[str, float]]" = field(default_factory=OrderedDict)
    last_alert: dict[str, float] = field(default_factory=dict)
    _last_prune: float = 0.0

    @staticmethod
    def _touch(table: "OrderedDict", key: str, cap: int) -> dict:
        ips = table.get(key)
        if ips is None:
            ips = table[key] = {}
            while len(table) > cap:
                table.popitem(last=False)   # expulsa el LRU
        table.move_to_end(key)
        return ips

    def observe(self, ip: str, user: str | None, now: float) -> list[dict]:
        """Registra un intento y devuelve alertas de campaña (con cooldown)."""
        self._prune(now)
        out: list[dict] = []

        if user:
            ips = self._touch(self.by_user, user, MAX_TRACKED_USERS)
            ips[ip] = now
            if len(ips) >= DISTINCT_IPS_PER_USER:
                # NOTA: sample_ips es informativo (priorización/forense), NUNCA
                # un disparador de bloqueo. La respuesta activa bloquea solo la
                # IP propia del actor por su score; así un atacante no puede
                # atribuir una "campaña" a IPs de víctimas para que se bloqueen.
                a = self._alert(f"user:{user}",
                    "credential_stuffing_distribuido",
                    f"{len(ips)} IPs distintas atacan al usuario '{user}' "
                    f"(low-and-slow / botnet)", now, sample=list(ips)[:10])
                if a:
                    out.append(a)

        sub = _subnet(ip)
        if sub:
            ips = self._touch(self.by_subnet, sub, MAX_TRACKED_SUBNETS)
            ips[ip] = now
            if len(ips) >= DISTINCT_IPS_PER_SUBNET:
                a = self._alert(f"subnet:{sub}", "botnet_subred",
                    f"{len(ips)} IPs de la subred {sub} atacando "
                    f"coordinadamente", now, sample=list(ips)[:10])
                if a:
                    out.append(a)
        return out

    def _alert(self, key: str, kind: str, msg: str, now: float,
               sample: list, cooldown: float = 60.0) -> dict | None:
        last = self.last_alert.get(key)
        if last is not None and now - last < cooldown:
            return None  # la PRIMERA campaña de esta clave siempre dispara
        self.last_alert[key] = now
        return {"kind": kind, "message": msg, "sample_ips": sample}

    def _prune(self, now: float) -> None:
        if now - self._last_prune < 30.0:
            return
        self._last_prune = now
        for table in (self.by_user, self.by_subnet):
            dead_keys = []
            for k, ips in table.items():
                for ip, ts in list(ips.items()):
                    if now - ts > WINDOW:
                        del ips[ip]
                if not ips:
                    dead_keys.append(k)
            for k in dead_keys:
                del table[k]
        self.last_alert = {k: t for k, t in self.last_alert.items()
                           if now - t < WINDOW}
