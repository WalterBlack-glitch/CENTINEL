"""hashwatch: integridad en disco de binarios del sistema (hash + firma)."""
from __future__ import annotations

import hashlib
import os

import pytest

from centinel.core import Severity
from centinel.collectors.hashwatch import (
    FileHash, classify_hashes, collect_file_hashes, default_watched_paths,
    make_baseline, sha256_file, signatures_for, update_baseline,
)

MS = "CN=Microsoft Windows, O=Microsoft Corporation"


def fh(path=r"C:\Windows\System32\svchost.exe", sha="a" * 64, signer=MS,
       valid=True, size=100):
    return FileHash(path=path, sha256=sha, size=size, signer=signer,
                    sig_valid=valid)


def kinds(events):
    return [e.kind for e in events]


# -------------------------------------------------------------- línea base
class TestBaseline:
    def test_make_baseline_indexa_por_ruta_normalizada(self):
        b = make_baseline([fh(path=r"C:\Windows\System32\SVCHOST.EXE")])
        assert list(b) == [r"c:\windows\system32\svchost.exe"]

    def test_make_baseline_descarta_incompletos(self):
        assert make_baseline([fh(path=""), fh(sha="")]) == {}

    def test_round_trip_de_filehash(self):
        f = fh()
        assert FileHash.from_dict(f.to_dict()) == f

    def test_from_dict_tolera_basura(self):
        f = FileHash.from_dict({"size": None, "sig_valid": "x"})
        assert f.size == 0 and f.sig_valid is True and f.path == ""

    def test_primera_ejecucion_no_inventa_alertas(self):
        assert classify_hashes([fh()], None) == []
        assert classify_hashes([fh()], {}) == []

    def test_update_baseline_recoge_lo_actual(self):
        base = make_baseline([fh(sha="a" * 64)])
        nueva = update_baseline(base, [fh(sha="b" * 64)])
        assert nueva[r"c:\windows\system32\svchost.exe"]["sha256"] == "b" * 64

    def test_update_baseline_conserva_lo_que_no_se_reviso(self):
        base = make_baseline([fh(path=r"C:\a.exe"), fh(path=r"C:\b.exe")])
        nueva = update_baseline(base, [fh(path=r"C:\a.exe", sha="c" * 64)])
        assert r"c:\b.exe" in nueva


# --------------------------------------------------------- hash que cambia
class TestHashCambiado:
    def test_reemplazo_sin_firma_valida_es_critico(self):
        base = make_baseline([fh(sha="a" * 64)])
        ev = classify_hashes([fh(sha="b" * 64, valid=False)], base)
        assert kinds(ev) == ["file_integrity_tamper"]
        assert ev[0].severity == Severity.CRITICAL
        assert ev[0].enrichment["sha256_old"] == "a" * 64
        assert ev[0].enrichment["sha256_new"] == "b" * 64

    def test_reemplazo_firmado_por_desconocido_es_critico(self):
        base = make_baseline([fh(sha="a" * 64)])
        ev = classify_hashes([fh(sha="b" * 64, signer="CN=Pirata SL",
                                 valid=True)], base)
        assert ev[0].severity == Severity.CRITICAL

    def test_actualizacion_firmada_por_microsoft_es_informativa(self):
        base = make_baseline([fh(sha="a" * 64)])
        ev = classify_hashes([fh(sha="b" * 64, signer=MS, valid=True)], base)
        assert kinds(ev) == ["file_integrity_update"]
        assert ev[0].severity == Severity.LOW
        assert "actualización" in ev[0].message

    def test_firma_de_microsoft_pero_invalida_es_critico(self):
        base = make_baseline([fh(sha="a" * 64)])
        ev = classify_hashes([fh(sha="b" * 64, signer=MS, valid=False)], base)
        assert ev[0].severity == Severity.CRITICAL

    def test_mismo_hash_no_genera_nada(self):
        base = make_baseline([fh(sha="a" * 64)])
        assert classify_hashes([fh(sha="a" * 64)], base) == []

    def test_cambio_de_caso_en_la_ruta_no_es_un_fichero_distinto(self):
        base = make_baseline([fh(path=r"C:\Windows\System32\svchost.exe",
                                 sha="a" * 64)])
        ev = classify_hashes([fh(path=r"C:\WINDOWS\SYSTEM32\SVCHOST.EXE",
                                 sha="a" * 64)], base)
        assert ev == []


# ------------------------------------------------------------- nuevos / ausentes
class TestNuevosYAusentes:
    def test_binario_nuevo_sin_firma_es_medium(self):
        base = make_baseline([fh(path=r"C:\a.exe")])
        ev = classify_hashes([fh(path=r"C:\a.exe"),
                              fh(path=r"C:\raro.exe", valid=False)], base)
        assert kinds(ev) == ["file_integrity_new"]
        assert ev[0].severity == Severity.MEDIUM

    def test_binario_nuevo_firmado_por_microsoft_se_calla(self):
        base = make_baseline([fh(path=r"C:\a.exe")])
        ev = classify_hashes([fh(path=r"C:\a.exe"),
                              fh(path=r"C:\nuevo.exe", signer=MS, valid=True)],
                             base)
        assert ev == []

    def test_se_puede_silenciar_lo_nuevo(self):
        base = make_baseline([fh(path=r"C:\a.exe")])
        ev = classify_hashes([fh(path=r"C:\a.exe"),
                              fh(path=r"C:\raro.exe", valid=False)], base,
                             report_new=False)
        assert ev == []

    def test_binario_que_desaparece_es_medium(self):
        base = make_baseline([fh(path=r"C:\a.exe"), fh(path=r"C:\b.exe")])
        ev = classify_hashes([fh(path=r"C:\a.exe")], base)
        assert kinds(ev) == ["file_integrity_missing"]
        assert ev[0].severity == Severity.MEDIUM
        assert ev[0].enrichment["path"] == r"C:\b.exe"

    def test_se_puede_silenciar_lo_ausente(self):
        base = make_baseline([fh(path=r"C:\a.exe"), fh(path=r"C:\b.exe")])
        ev = classify_hashes([fh(path=r"C:\a.exe")], base, report_missing=False)
        assert ev == []

    def test_fichero_sin_hash_se_ignora_y_no_cuenta_como_visto(self):
        base = make_baseline([fh(path=r"C:\a.exe")])
        ev = classify_hashes([FileHash(path=r"C:\a.exe", sha256="")], base)
        assert kinds(ev) == ["file_integrity_missing"]

    def test_varios_hallazgos_a_la_vez(self):
        base = make_baseline([fh(path=r"C:\cambia.exe", sha="a" * 64),
                              fh(path=r"C:\falta.exe")])
        ev = classify_hashes([fh(path=r"C:\cambia.exe", sha="b" * 64, valid=False),
                              fh(path=r"C:\nuevo.exe", valid=False)], base)
        assert set(kinds(ev)) == {"file_integrity_tamper", "file_integrity_new",
                                  "file_integrity_missing"}


class TestEventos:
    def test_llevan_etiquetas_y_motivos(self):
        base = make_baseline([fh(sha="a" * 64)])
        ev = classify_hashes([fh(sha="b" * 64, valid=False)], base)[0]
        assert {"file", "host", "windows", "integrity"} <= ev.tags
        assert ev.enrichment["reasons"]

    def test_son_serializables(self):
        base = make_baseline([fh(sha="a" * 64)])
        for e in classify_hashes([fh(sha="b" * 64, valid=False)], base):
            assert isinstance(e.to_dict(), dict)


# ----------------------------------------------------------------- I/O real
class TestSha256File:
    def test_hashea_igual_que_hashlib(self, tmp_path):
        p = tmp_path / "x.bin"
        datos = os.urandom(3000)
        p.write_bytes(datos)
        assert sha256_file(str(p)) == hashlib.sha256(datos).hexdigest()

    def test_fichero_vacio(self, tmp_path):
        p = tmp_path / "v.bin"
        p.write_bytes(b"")
        assert sha256_file(str(p)) == hashlib.sha256(b"").hexdigest()

    def test_fichero_grande_por_trozos(self, tmp_path):
        p = tmp_path / "g.bin"
        datos = b"x" * (3 << 20)      # 3 MiB: fuerza varias lecturas
        p.write_bytes(datos)
        assert sha256_file(str(p)) == hashlib.sha256(datos).hexdigest()

    def test_inexistente_devuelve_none(self, tmp_path):
        assert sha256_file(str(tmp_path / "no_existe")) is None

    def test_respeta_el_tope_de_tamano(self, tmp_path):
        p = tmp_path / "enorme.bin"
        p.write_bytes(b"x" * 2048)
        assert sha256_file(str(p), max_bytes=1024) is None


class TestCollect:
    def test_hashea_lo_que_existe_e_ignora_lo_demas(self, tmp_path):
        a = tmp_path / "a.bin"
        a.write_bytes(b"hola")
        out = collect_file_hashes([str(a), str(tmp_path / "fantasma")],
                                  with_signatures=False)
        assert [f.path for f in out] == [str(a)]
        assert out[0].sha256 == hashlib.sha256(b"hola").hexdigest()
        assert out[0].size == 4

    def test_sin_firmas_no_llama_a_powershell(self, tmp_path, monkeypatch):
        import centinel.collectors.hashwatch as hw
        monkeypatch.setattr(hw, "signatures_for",
                            lambda *a, **k: pytest.fail("no debe pedir firmas"))
        a = tmp_path / "a.bin"
        a.write_bytes(b"x")
        assert collect_file_hashes([str(a)], with_signatures=False)

    def test_adjunta_las_firmas_a_cada_fichero(self, tmp_path, monkeypatch):
        import centinel.collectors.hashwatch as hw
        a = tmp_path / "a.bin"
        a.write_bytes(b"x")
        monkeypatch.setattr(os, "name", "nt")
        monkeypatch.setattr(hw, "signatures_for",
                            lambda paths, timeout=0: {hw.norm_path(str(a)): (MS, True)})
        out = collect_file_hashes([str(a)])
        assert out[0].signer == MS and out[0].sig_valid is True

    def test_lista_vacia(self):
        assert collect_file_hashes([], with_signatures=False) == []


class TestSignaturesFor:
    def test_sin_rutas_no_ejecuta_nada(self, monkeypatch):
        import subprocess as sp
        monkeypatch.setattr(sp, "run",
                            lambda *a, **k: pytest.fail("no debe ejecutarse"))
        assert signatures_for([]) == {}

    def test_parsea_la_salida_de_powershell(self, monkeypatch):
        import centinel.collectors.hashwatch as hw

        class Res:
            stdout = ('[{"path":"C:\\\\a.exe","signer":"CN=MS","valid":true},'
                      '{"path":"C:\\\\b.exe","signer":"","valid":false}]')
        monkeypatch.setattr(hw.subprocess, "run", lambda *a, **k: Res())
        out = signatures_for([r"C:\a.exe", r"C:\b.exe"])
        assert out[r"c:\a.exe"] == ("CN=MS", True)
        assert out[r"c:\b.exe"] == ("", False)

    def test_un_solo_resultado_llega_como_dict(self, monkeypatch):
        import centinel.collectors.hashwatch as hw

        class Res:
            stdout = '{"path":"C:\\\\a.exe","signer":"CN=MS","valid":true}'
        monkeypatch.setattr(hw.subprocess, "run", lambda *a, **k: Res())
        assert signatures_for([r"C:\a.exe"])[r"c:\a.exe"] == ("CN=MS", True)

    def test_salida_invalida_no_revienta(self, monkeypatch):
        import centinel.collectors.hashwatch as hw

        class Res:
            stdout = "no soy json"
        monkeypatch.setattr(hw.subprocess, "run", lambda *a, **k: Res())
        assert signatures_for([r"C:\a.exe"]) == {}

    def test_powershell_ausente_no_revienta(self, monkeypatch):
        import centinel.collectors.hashwatch as hw
        monkeypatch.setattr(hw.subprocess, "run",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("no ps")))
        assert signatures_for([r"C:\a.exe"]) == {}

    def test_timeout_no_revienta(self, monkeypatch):
        import subprocess as sp
        import centinel.collectors.hashwatch as hw

        def boom(*a, **k):
            raise sp.TimeoutExpired("powershell", 1)
        monkeypatch.setattr(hw.subprocess, "run", boom)
        assert signatures_for([r"C:\a.exe"]) == {}

    def test_filas_no_dict_se_ignoran(self, monkeypatch):
        import centinel.collectors.hashwatch as hw

        class Res:
            stdout = '["basura",{"path":"C:\\\\a.exe","signer":"x","valid":false}]'
        monkeypatch.setattr(hw.subprocess, "run", lambda *a, **k: Res())
        assert list(signatures_for([r"C:\a.exe"])) == [r"c:\a.exe"]


class TestRutasVigiladas:
    def test_incluye_los_procesos_de_sistema_y_explorer(self):
        # os.path.join usa el separador del SO donde corre el test (la CI es
        # Linux), así que comparamos sin dar por hecho el "\".
        rutas = [p.lower().replace("/", "\\")
                 for p in default_watched_paths(r"C:\Windows")]
        assert any("system32\\svchost.exe" in p for p in rutas)
        assert any("system32\\lsass.exe" in p for p in rutas)
        assert r"c:\windows\explorer.exe" in rutas

    def test_respeta_el_windir_que_le_pasan(self):
        assert all(p.startswith(r"D:\Win") for p in default_watched_paths(r"D:\Win"))

    def test_sin_argumento_usa_la_variable_de_entorno(self, monkeypatch):
        monkeypatch.setenv("WinDir", r"E:\Windows")
        assert default_watched_paths()[0].startswith(r"E:\Windows")


class TestScan:
    def test_primera_pasada_fija_base_sin_alertar(self, tmp_path):
        import centinel.collectors.hashwatch as hw
        a = tmp_path / "a.bin"
        a.write_bytes(b"uno")
        ev, base = hw.scan(None, paths=[str(a)], with_signatures=False)
        assert ev == [] and len(base) == 1

    def test_segunda_pasada_detecta_el_reemplazo(self, tmp_path):
        import centinel.collectors.hashwatch as hw
        a = tmp_path / "a.bin"
        a.write_bytes(b"uno")
        _, base = hw.scan(None, paths=[str(a)], with_signatures=False)
        a.write_bytes(b"dos")      # reemplazo en disco
        ev, base2 = hw.scan(base, paths=[str(a)], with_signatures=False)
        assert kinds(ev) == ["file_integrity_tamper"]
        assert base2[hw.norm_path(str(a))]["sha256"] != \
            base[hw.norm_path(str(a))]["sha256"]

    def test_sin_cambios_no_alerta_dos_veces(self, tmp_path):
        import centinel.collectors.hashwatch as hw
        a = tmp_path / "a.bin"
        a.write_bytes(b"uno")
        _, base = hw.scan(None, paths=[str(a)], with_signatures=False)
        ev, _ = hw.scan(base, paths=[str(a)], with_signatures=False)
        assert ev == []


class TestInvocacionDePowerShell:
    """Regresiones de dos bugs que solo se veían ejecutando de verdad."""

    def test_las_rutas_van_dentro_del_script_no_en_args(self, monkeypatch):
        # Bug: con `-Command` los argumentos tras `--` NO llegan a $args (eso
        # es cosa de `-File`), así que no se verificaba ninguna firma y la
        # función devolvía {} siempre.
        import centinel.collectors.hashwatch as hw
        visto = {}

        class Res:
            stdout = "[]"

        def fake_run(cmd, **kw):
            visto["cmd"] = cmd
            visto["kw"] = kw
            return Res()
        monkeypatch.setattr(hw.subprocess, "run", fake_run)
        hw.signatures_detail([r"C:\Windows\System32\svchost.exe"])
        script = visto["cmd"][-1]
        assert "svchost.exe" in script
        assert "--" not in visto["cmd"]

    def test_decodifica_en_utf8(self, monkeypatch):
        # Bug: text=True usa cp1252 en Windows y los subjects de certificado
        # con acentos lanzaban UnicodeDecodeError en el hilo lector, dejando
        # el escaneo sin datos.
        import centinel.collectors.hashwatch as hw
        visto = {}

        class Res:
            stdout = "[]"
        monkeypatch.setattr(hw.subprocess, "run",
                            lambda cmd, **kw: (visto.update(kw), Res())[1])
        hw.signatures_detail([r"C:\a.exe"])
        assert visto["encoding"] == "utf-8"
        assert visto["errors"] == "replace"

    def test_el_script_fuerza_salida_utf8(self):
        import centinel.collectors.hashwatch as hw
        assert "OutputEncoding" in hw._PS_SIGN

    def test_el_estado_valid_no_se_pierde_por_valer_cero(self):
        # Bug: `if($s.Status)` es falso para Valid, que es el 0 del enum, así
        # que todo salía como 'UnknownError'. Debe comprobarse el objeto.
        import centinel.collectors.hashwatch as hw
        assert "$null -ne $s" in hw._PS_SIGN


class TestPsLiteral:
    def test_array_de_powershell(self):
        from centinel.collectors.hashwatch import _ps_literal
        assert _ps_literal([r"C:\a.exe", r"C:\b.exe"]) == \
            r"@('C:\a.exe','C:\b.exe')"

    def test_escapa_la_comilla_simple_duplicandola(self):
        from centinel.collectors.hashwatch import _ps_literal
        assert _ps_literal([r"C:\O'Brien\a.exe"]) == r"@('C:\O''Brien\a.exe')"

    def test_no_interpola_nada_peligroso(self):
        from centinel.collectors.hashwatch import _ps_literal
        salida = _ps_literal([r"C:\$(whoami)\a.exe;calc"])
        assert salida.startswith("@('") and salida.endswith("')")
        assert salida.count("'") == 2      # nada rompe las comillas

    def test_lista_vacia(self):
        from centinel.collectors.hashwatch import _ps_literal
        assert _ps_literal([]) == "@()"
