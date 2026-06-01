"""Atribución de actor entre IPs: agrupa IPs distintas en un mismo adversario.

La idea —poco habitual en un IDS ligero— es dejar de pensar "por IP" y pasar a
pensar "por adversario". Un atacante con IA distribuye su campaña entre decenas
de IPs (botnet, VPS, exit-nodes) para diluirse, pero todas comparten una HUELLA
de comportamiento: el mismo diccionario de usuarios objetivo, las mismas técnicas
y el mismo perfil de temporización. Si reconocemos esa huella, podemos atribuir
N IPs a un solo actor y defendernos de la campaña como una entidad única.

Algoritmo (acotado y barato, sin pairwise O(n²)):
  - Cada IP aporta su conjunto de usuarios objetivo (su "diccionario").
  - Un ÍNDICE INVERTIDO usuario -> clusters genera solo los clusters CANDIDATOS
    que comparten algún usuario con el actor (no se comparan todos).
  - Se mide la similitud de Jaccard del diccionario contra esos candidatos; si
    supera el umbral, la IP se une al cluster; si no, nace un cluster nuevo.
  - Todo está acotado: nº de clusters, usuarios por cluster, candidatos
    examinados, y purga por ventana. El propio clusterer no es un vector de DoS.

Un cluster que reúne >= ATTRIBUTION_MIN_IPS IPs distintas es una campaña
atribuida: una botnet identificada como un solo adversario.
"""
from __future__ import annotations

import itertools
from collections import OrderedDict
from dataclasses import dataclass, field

WINDOW = 1800.0             # 30 min: las campañas se reparten en el tiempo
MAX_CLUSTERS = 5_000
MAX_USERS_PER_CLUSTER = 512
MAX_IPS_PER_CLUSTER = 4_096
MAX_CANDIDATES = 40        # tope de clusters candidatos examinados por actor
MIN_JACCARD = 0.5          # similitud mínima de diccionario para unir
MIN_FINGERPRINT = 3        # usuarios mínimos para que la huella sea fiable
ATTRIBUTION_MIN_IPS = 5    # IPs distintas para declarar campaña atribuida


def _jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    if not inter:
        return 0.0
    return inter / len(a | b)


@dataclass
class Cluster:
    cid: int
    users: set = field(default_factory=set)
    ips: dict = field(default_factory=dict)        # ip -> last_ts
    flags: set = field(default_factory=set)
    score: float = 0.0
    first_seen: float = 0.0
    last_seen: float = 0.0
    alerted: bool = False

    def traits(self) -> dict:
        return {
            "cid": self.cid,
            "ips": list(self.ips)[:50],
            "ip_count": len(self.ips),
            "users": sorted(self.users)[:30],
            "flags": sorted(self.flags),
            "score": round(self.score, 1),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


class ActorClusterer:
    def __init__(self) -> None:
        # OrderedDict para expulsión LRU O(1) (el min() O(n) por evento era un
        # vector de ralentización ante un atacante que rota diccionarios).
        self.clusters: "OrderedDict[int, Cluster]" = OrderedDict()
        self._by_user: dict[str, set[int]] = {}   # índice invertido usuario->cids
        self._seq = itertools.count(1)
        self._last_prune = 0.0

    def get_clusters(self, min_ips: int = 2) -> list[Cluster]:
        return sorted(
            (c for c in self.clusters.values() if len(c.ips) >= min_ips),
            key=lambda c: (len(c.ips), c.score), reverse=True)

    def assign(self, ip: str, users: set[str], flags: set[str],
               score: float, now: float) -> dict | None:
        """Asocia la IP al cluster de su huella. Devuelve una alerta de campaña
        atribuida si el cluster cruza el umbral de IPs por primera vez."""
        self._prune(now)
        # Atribuir solo con una huella madura: un diccionario diminuto (p.ej.
        # un único 'root') daría Jaccard bajo y fragmentaría/duplicaría clusters.
        if len(users) < MIN_FINGERPRINT:
            return None

        cid = self._best_cluster(users)
        if cid is None:
            # Expulsa ANTES de insertar (y el nuevo nace con last_seen=now para
            # no auto-elegirse como víctima del evict).
            if len(self.clusters) >= MAX_CLUSTERS:
                self._evict_oldest()
            cid = next(self._seq)
            self.clusters[cid] = Cluster(cid=cid, first_seen=now, last_seen=now)

        c = self.clusters[cid]
        self.clusters.move_to_end(cid)   # marca como recién usado (LRU)
        crossed_before = len(c.ips) >= ATTRIBUTION_MIN_IPS
        if len(c.ips) < MAX_IPS_PER_CLUSTER:
            c.ips[ip] = now
        for u in itertools.islice(users, MAX_USERS_PER_CLUSTER):
            if len(c.users) >= MAX_USERS_PER_CLUSTER:
                break
            if u not in c.users:
                c.users.add(u)
                self._by_user.setdefault(u, set()).add(cid)
        c.flags |= flags
        c.score = max(c.score, score)
        c.last_seen = now

        if (not crossed_before and len(c.ips) >= ATTRIBUTION_MIN_IPS
                and not c.alerted):
            c.alerted = True
            return {
                "kind": "actor_atribuido",
                "cid": cid,
                "message": (f"Campaña atribuida: {len(c.ips)} IPs son el mismo "
                            f"adversario (diccionario/TTPs compartidos)"),
                "sample_ips": list(c.ips)[:10],
                "users": sorted(c.users)[:10],
            }
        return None

    def _best_cluster(self, users: set[str]) -> int | None:
        # Reúne candidatos vía índice invertido (solo clusters que comparten
        # algún usuario), acotado a MAX_CANDIDATES.
        seen: set[int] = set()
        candidates: list[int] = []
        for u in users:
            for cid in self._by_user.get(u, ()):  # type: ignore[arg-type]
                if cid not in seen:
                    seen.add(cid)
                    candidates.append(cid)
                    if len(candidates) >= MAX_CANDIDATES:
                        break
            if len(candidates) >= MAX_CANDIDATES:
                break
        best_cid, best_sim = None, MIN_JACCARD
        for cid in candidates:
            c = self.clusters.get(cid)
            if c is None:
                continue
            sim = _jaccard(users, c.users)
            if sim >= best_sim:
                best_sim, best_cid = sim, cid
        return best_cid

    def _evict_oldest(self) -> None:
        if not self.clusters:
            return
        # El primero del OrderedDict es el menos usado recientemente (LRU): O(1).
        oldest_cid = next(iter(self.clusters))
        self._drop(oldest_cid)

    def _drop(self, cid: int) -> None:
        c = self.clusters.pop(cid, None)
        if not c:
            return
        for u in c.users:
            s = self._by_user.get(u)
            if s:
                s.discard(cid)
                if not s:
                    del self._by_user[u]

    def _prune(self, now: float) -> None:
        if now - self._last_prune < 30.0:
            return
        self._last_prune = now
        for cid in [cid for cid, c in self.clusters.items()
                    if now - c.last_seen > WINDOW]:
            self._drop(cid)
