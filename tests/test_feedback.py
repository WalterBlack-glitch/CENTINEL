"""Tests del informe de feedback."""
from centinel.feedback import write_report


def test_escribe_informe_con_hallazgos(tmp_path):
    p = tmp_path / "fb.txt"
    findings = [
        {"level": "error", "msg": "falta fastapi", "fix": "pip install '.[web]'"},
        {"level": "fixed", "msg": "BD reubicada"},
        {"level": "ok", "msg": "python 3.12"},
    ]
    out = write_report(findings, path=str(p))
    txt = p.read_text(encoding="utf-8")
    assert out == str(p)
    assert "INFORME DE FEEDBACK" in txt
    assert "falta fastapi" in txt and "pip install" in txt
    assert "BD reubicada" in txt
    assert "## Entorno" in txt


def test_incluye_traza_de_excepcion(tmp_path):
    p = tmp_path / "fb.txt"
    try:
        raise ValueError("boom")
    except ValueError as e:
        write_report([], exc=e, path=str(p))
    txt = p.read_text(encoding="utf-8")
    assert "Traceback" in txt or "ValueError" in txt
    assert "boom" in txt


def test_no_lanza_si_ruta_invalida():
    # Ruta imposible: debe degradar a stderr sin lanzar.
    out = write_report([{"level": "error", "msg": "x"}],
                       path="/ruta/que/no/existe/xyz/fb.txt")
    assert isinstance(out, str)
