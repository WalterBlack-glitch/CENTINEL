"""Tests de la atribución de actor entre IPs (clustering de huella)."""
from centinel.correlation.cluster import (
    ActorClusterer, _jaccard, MIN_FINGERPRINT, ATTRIBUTION_MIN_IPS,
    MAX_CLUSTERS,
)


def test_jaccard():
    assert _jaccard({"a", "b"}, {"a", "b"}) == 1.0
    assert _jaccard({"a", "b"}, {"c", "d"}) == 0.0
    assert _jaccard(set(), {"a"}) == 0.0
    assert _jaccard({"a", "b", "c", "d"}, {"a", "b"}) == 0.5


def test_huella_pequena_no_atribuye():
    c = ActorClusterer()
    # Menos de MIN_FINGERPRINT usuarios -> no se intenta clusterizar.
    assert c.assign("1.1.1.1", {"root"}, set(), 10.0, now=1000.0) is None
    assert len(c.clusters) == 0


def test_botnet_mismo_diccionario_se_atribuye():
    c = ActorClusterer()
    dic = {"root", "admin", "oracle", "postgres"}
    alert = None
    for i in range(ATTRIBUTION_MIN_IPS):
        a = c.assign(f"66.0.0.{i}", set(dic), set(), 10.0, now=1000.0 + i)
        if a:
            alert = a
    assert alert is not None
    assert alert["kind"] == "actor_atribuido"
    assert len(c.get_clusters()[0].ips) == ATTRIBUTION_MIN_IPS


def test_diccionarios_distintos_no_se_agrupan():
    c = ActorClusterer()
    c.assign("1.1.1.1", {"alice", "bob", "carol"}, set(), 5.0, now=1000.0)
    c.assign("2.2.2.2", {"dave", "erin", "frank"}, set(), 5.0, now=1000.0)
    # Dos clusters separados, ninguno con 2+ IPs.
    assert all(len(cl.ips) == 1 for cl in c.clusters.values())
    assert c.get_clusters(min_ips=2) == []


def test_atribucion_solo_alerta_una_vez():
    c = ActorClusterer()
    dic = {"root", "admin", "oracle", "postgres"}
    alerts = 0
    for i in range(ATTRIBUTION_MIN_IPS + 4):
        a = c.assign(f"66.0.0.{i}", set(dic), set(), 10.0, now=1000.0 + i)
        if a:
            alerts += 1
    assert alerts == 1   # cooldown: la campaña se anuncia una sola vez


def test_purga_por_ventana():
    c = ActorClusterer()
    dic = {"root", "admin", "oracle"}
    c.assign("1.1.1.1", set(dic), set(), 5.0, now=1000.0)
    assert c.clusters
    c._last_prune = 0.0
    # mucho después -> el cluster viejo se purga y su índice se limpia
    c.assign("9.9.9.9", {"x", "y", "z"}, set(), 5.0, now=1000.0 + 100_000)
    assert "root" not in c._by_user            # índice invertido limpio
    assert all(cl.last_seen > 50_000 for cl in c.clusters.values())


def test_indice_invertido_acotado_en_evict():
    c = ActorClusterer()
    # Fuerza más clusters que el máximo y verifica que no desborda.
    for i in range(MAX_CLUSTERS + 50):
        c.assign(f"7.7.{i // 256}.{i % 256}",
                 {f"u{i}a", f"u{i}b", f"u{i}c"}, set(), 1.0, now=1000.0 + i * 0.001)
    assert len(c.clusters) <= MAX_CLUSTERS
