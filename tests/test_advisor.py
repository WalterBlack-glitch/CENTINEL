"""Tests del asesor de remediación."""
from centinel.advisor import advise, known_kinds, _MAX_STEPS, _clean


def test_kind_desconocido_devuelve_none():
    assert advise("alert_inexistente") is None
    assert advise("") is None
    assert advise(None) is None


def test_prefijo_alert_se_normaliza():
    a = advise("alert_bruteforce", {"ip": "1.2.3.4"})
    b = advise("bruteforce", {"ip": "1.2.3.4"})
    assert a is not None and b is not None
    assert a["title"] == b["title"]


def test_todos_los_playbooks_bien_formados():
    for k in known_kinds():
        r = advise(k, {"ip": "9.9.9.9", "user": "root", "subnet": "9.9.9.0/24"})
        assert r["title"] and r["urgency"] in ("alta", "media", "critica")
        assert 1 <= len(r["steps"]) <= _MAX_STEPS
        for s in r["steps"]:
            assert s["text"]
            assert "cmd" in s


def test_relleno_de_ip_y_usuario():
    r = advise("compromise", {"ip": "203.0.113.5", "user": "deploy"})
    blob = " ".join((s["cmd"] or "") for s in r["steps"])
    assert "203.0.113.5" in blob
    assert "deploy" in blob


def test_marcador_faltante_no_rompe_ni_deja_llave():
    # Sin ctx, los marcadores conocidos no deben quedar sin sustituir.
    r = advise("bruteforce", {})
    for s in r["steps"]:
        if s["cmd"]:
            assert "{ip}" not in s["cmd"] and "{user}" not in s["cmd"]


def test_llaves_literales_de_comandos_intactas():
    # El awk de 'spray' tiene '{print $1}': no debe mutilarse al rellenar.
    r = advise("spray", {"ip": "1.1.1.1"})
    blob = " ".join((s["cmd"] or "") for s in r["steps"])
    assert "{print $1}" in blob


def test_no_interpola_codigo_arbitrario():
    # Un "usuario" hostil con llaves de formato no debe romper ni inyectar.
    r = advise("compromise", {"ip": "1.1.1.1", "user": "{evil.__class__}"})
    assert r is not None  # no lanza


def test_clean_quita_metacaracteres_de_shell():
    # El saneador elimina todo lo que no sea charset seguro.
    assert _clean("root; rm -rf / #") == "rootrm-rf/"
    for bad in (";", "|", "&", "$", "`", "(", ")", " ", "'", '"', "\n"):
        assert bad not in _clean(f"a{bad}b")


def test_user_hostil_se_sanea_en_el_comando():
    # El valor inyectado aparece saneado, sin su payload de shell.
    r = advise("compromise", {"ip": "1.1.1.1", "user": "evil$(id);x"})
    blob = " ".join((s["cmd"] or "") for s in r["steps"])
    assert "$(id)" not in blob and "evil$(" not in blob
    assert "evilidx" in blob  # quedó como charset seguro
