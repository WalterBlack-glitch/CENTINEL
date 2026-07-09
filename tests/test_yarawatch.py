"""Tests puros de YaraWatch (sin yara-python instalado ni FS real)."""
import os

from centinel.core import Severity
from centinel.collectors.yarawatch import (
    should_scan_file,
    severity_for_match,
    _default_rules_path,
)


# --- should_scan_file --------------------------------------------------------

def test_fichero_normal_se_escanea():
    ok, _ = should_scan_file("/tmp/x", 1024)
    assert ok


def test_fichero_vacio_no_se_escanea():
    ok, why = should_scan_file("/tmp/x", 0)
    assert not ok
    assert "vacío" in why


def test_fichero_gigante_no_se_escanea():
    ok, why = should_scan_file("/tmp/big", 64 * 1024 * 1024)
    assert not ok
    assert "grande" in why


def test_limite_configurable():
    ok, _ = should_scan_file("/tmp/x", 500, max_bytes=100)
    assert not ok
    ok, _ = should_scan_file("/tmp/x", 50, max_bytes=100)
    assert ok


# --- severity_for_match ------------------------------------------------------

def test_severity_critical():
    assert severity_for_match({"severity": "critical"}) is Severity.CRITICAL


def test_severity_high_por_defecto_sin_meta():
    assert severity_for_match(None) is Severity.HIGH
    assert severity_for_match({}) is Severity.HIGH


def test_severity_valor_desconocido_cae_a_high():
    assert severity_for_match({"severity": "banana"}) is Severity.HIGH


def test_severity_case_insensitive():
    assert severity_for_match({"severity": "CRITICAL"}) is Severity.CRITICAL
    assert severity_for_match({"severity": "Medium"}) is Severity.MEDIUM


def test_severity_low_e_info():
    assert severity_for_match({"severity": "low"}) is Severity.LOW
    assert severity_for_match({"severity": "info"}) is Severity.INFO


# --- reglas empaquetadas -----------------------------------------------------

def test_reglas_por_defecto_existen():
    path = _default_rules_path()
    assert path.endswith(os.path.join("rules", "default.yar"))
    assert os.path.exists(path), "el fichero de reglas debe ir empaquetado"


def test_reglas_por_defecto_no_vacias():
    with open(_default_rules_path(), "r", encoding="utf-8") as f:
        txt = f.read()
    # Sanidad mínima: contiene reglas y meta.severity.
    assert "rule " in txt
    assert "severity" in txt
