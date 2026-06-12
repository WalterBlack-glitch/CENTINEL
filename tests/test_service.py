"""Tests de la unidad systemd generada (normal y early-boot)."""
from centinel.service import _unit_text


def test_unidad_normal_orden_primario():
    u = _unit_text("--rootcheck")
    assert "Before=multi-user.target" in u
    assert "DefaultDependencies=yes" in u
    assert "WantedBy=multi-user.target" in u
    # El hardening no depende del modo de arranque.
    assert "NoNewPrivileges=true" in u
    assert "CapabilityBoundingSet=" in u


def test_unidad_early_boot_arranca_antes_que_todo():
    u = _unit_text("--rootcheck", early=True)
    # Nivel sysinit: antes que cualquier servicio normal (After=basic.target).
    assert "Before=basic.target" in u
    assert "WantedBy=sysinit.target" in u
    assert "DefaultDependencies=no" in u
    # Con DefaultDependencies=no, el apagado limpio hay que declararlo a mano.
    assert "Conflicts=shutdown.target" in u
    assert "Before=shutdown.target" in u
    # Dependencias mínimas: journald y /var montado.
    assert "systemd-journald.socket" in u
    assert "local-fs.target" in u
    # El hardening se conserva intacto.
    assert "NoNewPrivileges=true" in u
    assert "ProtectSystem=strict" in u


def test_args_line_se_inyecta_en_execstart():
    u = _unit_text("--rootcheck --netwatch", early=True)
    assert "-m centinel --rootcheck --netwatch" in u
