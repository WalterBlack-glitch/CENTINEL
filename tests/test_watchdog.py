"""Tests puros de la lógica de decisión del watchdog (sin systemd)."""
from centinel.watchdog import ServiceState, decide_action, UNIT


def test_servicio_sano_no_alerta():
    d = decide_action(ServiceState(active=True, enabled=True, masked=False))
    assert not d.alert
    assert d.commands == ()
    assert d.reason == "sano"


def test_servicio_muerto_revive_y_alerta():
    d = decide_action(ServiceState(active=False, enabled=True, masked=False))
    assert d.alert
    # enabled ya, solo arranca.
    assert d.commands == (f"systemctl start {UNIT}",)
    assert "NO está activo" in d.reason


def test_servicio_muerto_y_deshabilitado_rehabilita_y_arranca():
    d = decide_action(ServiceState(active=False, enabled=False, masked=False))
    assert d.alert
    assert d.commands == (
        f"systemctl enable {UNIT}",
        f"systemctl start {UNIT}",
    )


def test_servicio_enmascarado_es_la_maxima_prioridad():
    # masked + inactive + disabled: gana la rama de mask.
    d = decide_action(ServiceState(active=False, enabled=False, masked=True))
    assert d.alert
    assert d.commands == (
        f"systemctl unmask {UNIT}",
        f"systemctl enable {UNIT}",
        f"systemctl start {UNIT}",
    )
    assert "ENMASCAR" in d.reason.upper()


def test_servicio_activo_pero_deshabilitado_rehabilita():
    d = decide_action(ServiceState(active=True, enabled=False, masked=False))
    assert d.alert
    assert d.commands == (f"systemctl enable {UNIT}",)
    assert "DESHABILITADO" in d.reason


def test_comandos_no_vacios_cuando_alerta():
    # Invariante: si alerta por sabotaje, siempre hay remediación.
    for st in (
        ServiceState(active=False, enabled=True, masked=False),
        ServiceState(active=False, enabled=False, masked=False),
        ServiceState(active=True, enabled=False, masked=False),
        ServiceState(active=False, enabled=False, masked=True),
    ):
        d = decide_action(st)
        assert d.alert and len(d.commands) >= 1
