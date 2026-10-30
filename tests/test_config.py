"""Configuración TOML: valores por defecto, validación y degradado honesto."""
from __future__ import annotations

import os

import pytest

from centinel.config import (
    Config, EJEMPLO, NOMBRE, candidate_paths, env_allow_paths, find_config,
    from_mapping, load_config, write_example,
)
from centinel.core import Severity


@pytest.fixture(autouse=True)
def entorno_limpio(monkeypatch, tmp_path):
    """Sin variables heredadas y con el cwd en un directorio vacío."""
    for v in ("CENTINEL_CONFIG", "CENTINEL_PROCWATCH_ALLOW"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def escribe(tmp_path, texto, nombre=NOMBRE):
    p = tmp_path / nombre
    p.write_text(texto, encoding="utf-8")
    return str(p)


# ----------------------------------------------------------------- defaults
class TestDefaults:
    def test_sin_fichero_todo_por_defecto(self):
        cfg = load_config()
        assert cfg.path == "" and cfg.errors == []
        assert cfg.min_severity == int(Severity.LOW)
        assert cfg.watch_injection is True and cfg.watch_hashes is False
        assert cfg.history_keep == 200 and cfg.report_format == "html"
        assert cfg.auto_scan_seconds == 0

    def test_nombre_legible_de_la_severidad(self):
        assert Config().min_severity_name == "LOW"

    def test_to_dict_omite_la_meta(self):
        d = Config(path="x", errors=["y"]).to_dict()
        assert "path" not in d and "errors" not in d
        assert d["allow_paths"] == []

    def test_ruta_explicita_inexistente_avisa_y_no_revienta(self, tmp_path):
        cfg = load_config(str(tmp_path / "no_existe.toml"))
        assert cfg.errors and "no existe" in cfg.errors[0]
        assert cfg.min_severity == int(Severity.LOW)


# ------------------------------------------------------------- localización
class TestLocalizacion:
    def test_encuentra_el_del_directorio_actual(self, tmp_path):
        escribe(tmp_path, "")
        assert find_config() == str(tmp_path / NOMBRE)

    def test_la_ruta_explicita_manda(self, tmp_path):
        escribe(tmp_path, "")
        otro = escribe(tmp_path, "", "otro.toml")
        assert find_config(otro) == otro

    def test_respeta_la_variable_de_entorno(self, tmp_path, monkeypatch):
        otro = escribe(tmp_path, "", "desde_env.toml")
        monkeypatch.setenv("CENTINEL_CONFIG", otro)
        assert find_config() == otro

    def test_candidatos_incluyen_appdata_en_windows(self, monkeypatch):
        monkeypatch.setattr(os, "name", "nt")
        monkeypatch.setenv("APPDATA", r"C:\Users\x\AppData\Roaming")
        assert any("CENTINEL" in p for p in candidate_paths())

    def test_candidatos_incluyen_xdg_fuera_de_windows(self, monkeypatch):
        monkeypatch.setattr(os, "name", "posix")
        monkeypatch.setenv("XDG_CONFIG_HOME", "/home/x/.config")
        assert any(p.startswith("/home/x/.config") for p in candidate_paths())

    def test_sin_nada_no_encuentra(self):
        assert find_config() is None


# -------------------------------------------------------------------- carga
class TestCarga:
    def test_lee_cada_seccion(self, tmp_path):
        p = escribe(tmp_path, """
[deteccion]
min_severity = "HIGH"
watch_hashes = true
watch_injection = false
[historial]
keep = 50
dir = "D:/hist"
[informe]
formato = "json"
dir = "D:/informes"
[escaneo]
auto_seconds = 300
""")
        cfg = load_config(p)
        assert cfg.errors == []
        assert cfg.min_severity == int(Severity.HIGH)
        assert cfg.watch_hashes is True and cfg.watch_injection is False
        assert cfg.history_keep == 50 and cfg.history_dir == "D:/hist"
        assert cfg.report_format == "json" and cfg.report_dir == "D:/informes"
        assert cfg.auto_scan_seconds == 300
        assert cfg.path == p

    def test_fichero_vacio_usa_defaults_sin_quejarse(self, tmp_path):
        cfg = load_config(escribe(tmp_path, ""))
        assert cfg.errors == [] and cfg.min_severity == int(Severity.LOW)

    def test_seccion_parcial_no_pisa_el_resto(self, tmp_path):
        cfg = load_config(escribe(tmp_path, "[historial]\nkeep = 7\n"))
        assert cfg.history_keep == 7 and cfg.report_format == "html"

    def test_el_ejemplo_que_generamos_es_valido(self, tmp_path):
        p = write_example(str(tmp_path / "gen" / NOMBRE))
        cfg = load_config(p)
        assert cfg.errors == []
        assert cfg.min_severity == int(Severity.LOW)

    def test_ejemplo_documenta_todas_las_secciones(self):
        for seccion in ("[deteccion]", "[historial]", "[informe]", "[escaneo]"):
            assert seccion in EJEMPLO

    def test_toml_roto_degrada_con_aviso(self, tmp_path):
        cfg = load_config(escribe(tmp_path, "[deteccion\nmin_severity = "))
        assert cfg.errors and "no es TOML válido" in cfg.errors[0]
        assert cfg.min_severity == int(Severity.LOW)

    def test_fichero_ilegible_degrada(self, tmp_path, monkeypatch):
        p = escribe(tmp_path, "")
        import builtins
        real = builtins.open

        def falla(path, *a, **k):
            if str(path) == p:
                raise OSError("permiso denegado")
            return real(path, *a, **k)
        monkeypatch.setattr(builtins, "open", falla)
        cfg = load_config(p)
        assert cfg.errors and "no se pudo leer" in cfg.errors[0]

    def test_sin_tomllib_avisa_claro(self, tmp_path, monkeypatch):
        import centinel.config as mod
        monkeypatch.setattr(mod, "tomllib", None)
        cfg = mod.load_config(escribe(tmp_path, '[deteccion]\nmin_severity="HIGH"'))
        assert cfg.errors and "tomllib" in cfg.errors[0]
        assert cfg.min_severity == int(Severity.LOW)   # sigue usable


# ---------------------------------------------------------------- validación
class TestValidacion:
    def test_severidad_por_nombre_y_por_numero(self):
        assert from_mapping({"deteccion": {"min_severity": "critical"}}).min_severity == 4
        assert from_mapping({"deteccion": {"min_severity": 3}}).min_severity == 3

    def test_severidad_invalida_avisa_y_conserva_el_defecto(self):
        cfg = from_mapping({"deteccion": {"min_severity": "URGENTE"}})
        assert cfg.min_severity == int(Severity.LOW)
        assert "no es una severidad" in cfg.errors[0]

    def test_severidad_fuera_de_rango(self):
        cfg = from_mapping({"deteccion": {"min_severity": 9}})
        assert cfg.min_severity == int(Severity.LOW)
        assert "fuera de rango" in cfg.errors[0]

    def test_booleano_mal_puesto(self):
        cfg = from_mapping({"deteccion": {"watch_hashes": "si"}})
        assert cfg.watch_hashes is False and cfg.errors

    def test_entero_mal_puesto(self):
        cfg = from_mapping({"historial": {"keep": "muchos"}})
        assert cfg.history_keep == 200 and cfg.errors

    def test_entero_negativo_se_rechaza(self):
        cfg = from_mapping({"escaneo": {"auto_seconds": -5}})
        assert cfg.auto_scan_seconds == 0 and "menor que" in cfg.errors[0]

    def test_booleano_no_cuela_como_entero(self):
        cfg = from_mapping({"historial": {"keep": True}})
        assert cfg.history_keep == 200 and cfg.errors

    def test_texto_mal_puesto(self):
        cfg = from_mapping({"informe": {"dir": 5}})
        assert cfg.report_dir == "." and cfg.errors

    def test_formato_de_informe_invalido_cae_a_html(self):
        cfg = from_mapping({"informe": {"formato": "pdf"}})
        assert cfg.report_format == "html"
        assert any("no es válido" in e for e in cfg.errors)

    def test_formato_en_mayusculas_se_acepta(self):
        assert from_mapping({"informe": {"formato": "JSON"}}).report_format == "json"

    def test_opcion_desconocida_avisa(self):
        cfg = from_mapping({"deteccion": {"inventada": 1}})
        assert "opción desconocida" in cfg.errors[0]

    def test_seccion_desconocida_avisa(self):
        assert "sección desconocida" in from_mapping({"otra": {"x": 1}}).errors[0]

    def test_seccion_que_no_es_tabla(self):
        cfg = from_mapping({"deteccion": 5})
        assert "se esperaba una sección" in cfg.errors[0]

    def test_contenido_que_no_es_tabla(self):
        assert from_mapping(["no", "es", "dict"]).errors

    def test_un_error_no_descarta_el_resto_del_fichero(self):
        cfg = from_mapping({"deteccion": {"min_severity": "MAL"},
                            "historial": {"keep": 42}})
        assert cfg.history_keep == 42 and cfg.errors


# ------------------------------------------------------------- allow_paths
class TestAllowPaths:
    def test_lista_de_rutas(self):
        cfg = from_mapping({"deteccion": {"allow_paths": ["C:/Tools", "C:/Dev"]}})
        assert len(cfg.allow_paths) == 2

    def test_una_sola_ruta_como_texto(self):
        assert len(from_mapping({"deteccion": {"allow_paths": "C:/Tools"}}).allow_paths) == 1

    def test_normaliza_para_comparar(self, monkeypatch):
        monkeypatch.setattr(os, "name", "nt")
        cfg = from_mapping({"deteccion": {"allow_paths": ["C:/Tools/Node"]}})
        assert cfg.allow_paths[0] == r"c:\tools\node"

    def test_expande_variables_de_entorno(self, monkeypatch):
        monkeypatch.setenv("MIAPP", "C:/MiApp")
        cfg = from_mapping({"deteccion": {"allow_paths": ["$MIAPP/bin"]}})
        assert "miapp" in cfg.allow_paths[0].lower()

    def test_entradas_no_texto_se_ignoran_con_aviso(self):
        cfg = from_mapping({"deteccion": {"allow_paths": ["C:/ok", 5, ""]}})
        assert len(cfg.allow_paths) == 1 and cfg.errors

    def test_tipo_equivocado_conserva_el_defecto(self):
        cfg = from_mapping({"deteccion": {"allow_paths": 5}})
        assert cfg.allow_paths == () and cfg.errors

    def test_el_entorno_se_suma_al_fichero(self, monkeypatch):
        monkeypatch.setenv("CENTINEL_PROCWATCH_ALLOW", os.pathsep.join(
            ["C:/DesdeEnv"]))
        cfg = from_mapping({"deteccion": {"allow_paths": ["C:/DesdeToml"]}})
        assert len(cfg.allow_paths) == 2
        bajas = [p.lower() for p in cfg.allow_paths]
        assert any("desdeenv" in p for p in bajas)
        assert any("desdetoml" in p for p in bajas)

    def test_no_duplica_si_coinciden(self, monkeypatch):
        monkeypatch.setenv("CENTINEL_PROCWATCH_ALLOW", "C:/Tools")
        cfg = from_mapping({"deteccion": {"allow_paths": ["C:/Tools"]}})
        assert len(cfg.allow_paths) == 1

    def test_sin_fichero_el_entorno_sigue_valiendo(self, monkeypatch):
        monkeypatch.setenv("CENTINEL_PROCWATCH_ALLOW", "C:/SoloEnv")
        assert load_config().allow_paths
        assert env_allow_paths()

    def test_entorno_vacio_no_mete_rutas_fantasma(self, monkeypatch):
        monkeypatch.setenv("CENTINEL_PROCWATCH_ALLOW", "")
        assert env_allow_paths() == ()


class TestWriteExample:
    def test_crea_el_fichero_y_el_directorio(self, tmp_path):
        p = write_example(str(tmp_path / "nueva" / NOMBRE))
        assert os.path.exists(p)
        assert "[deteccion]" in open(p, encoding="utf-8").read()
