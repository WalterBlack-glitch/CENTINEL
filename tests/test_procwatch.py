"""Tests del clasificador de suplantación de procesos (ProcWatch). Puros."""
from centinel.collectors.procwatch import (
    ProcInfo, classify_process, scan, norm_path,
)
from centinel.core import Severity

WIN = r"c:\windows"
WRITABLE = (
    r"c:\users\cris\appdata\local\temp",
    r"c:\users\cris\appdata\roaming",
    r"c:\users\cris\downloads",
    r"c:\programdata",
)


def _c(p: ProcInfo):
    return classify_process(p, win_dir=WIN, writable_dirs=WRITABLE)


def test_svchost_legitimo_no_alerta():
    p = ProcInfo(4, "svchost.exe", r"C:\Windows\System32\svchost.exe",
                 "Microsoft Windows Publisher", True, "services.exe")
    reasons, sev = _c(p)
    assert reasons == [] and sev == 0


def test_svchost_falso_sin_firma_es_critico():
    p = ProcInfo(6660, "svchost.exe",
                 r"C:\Users\Cris\AppData\Local\Temp\svchost.exe",
                 "", False, "explorer.exe")
    reasons, sev = _c(p)
    assert sev == int(Severity.CRITICAL)
    assert any("SUPLANTACIÓN" in r for r in reasons)


def test_svchost_padre_anomalo_aunque_ms_firmado():
    # Firmado por MS pero colgando de explorer => falso/lanzado por dropper.
    p = ProcInfo(6661, "svchost.exe", r"C:\Windows\System32\svchost.exe",
                 "Microsoft Windows Publisher", True, "explorer.exe")
    reasons, sev = _c(p)
    assert sev == int(Severity.CRITICAL)
    assert any("padre anómalo" in r for r in reasons)


def test_nombre_sistema_firmado_por_no_microsoft_es_suplantacion():
    p = ProcInfo(7000, "lsass.exe", r"C:\Temp\lsass.exe",
                 "Evil Corp S.A.", True, "cmd.exe")
    reasons, sev = _c(p)
    assert sev == int(Severity.CRITICAL)
    assert any("SUPLANTACIÓN" in r for r in reasons)


def test_proceso_sistema_sin_ruta_no_alerta():
    # Procesos protegidos (System, Registry) sin ruta legible no son sospechosos.
    p = ProcInfo(4, "svchost.exe", "", "", False, "services.exe")
    reasons, sev = _c(p)
    assert reasons == [] and sev == 0


def test_explorer_legitimo_no_alerta():
    p = ProcInfo(4200, "explorer.exe", r"C:\Windows\explorer.exe",
                 "Microsoft Windows", True, "userinit.exe")
    reasons, sev = _c(p)
    assert reasons == [] and sev == 0


def test_binario_sin_firma_en_downloads_es_alto():
    p = ProcInfo(9001, "totally_legit.exe",
                 r"C:\Users\Cris\Downloads\totally_legit.exe",
                 "", False, "explorer.exe")
    reasons, sev = _c(p)
    assert sev == int(Severity.HIGH)
    assert any("carpeta escribible" in r for r in reasons)


def test_app_firmada_de_confianza_en_appdata_no_alerta():
    # Claude Code vive en AppData\Roaming pero está firmado por Anthropic.
    p = ProcInfo(1100, "claude.exe",
                 r"C:\Users\Cris\AppData\Roaming\npm\claude.exe",
                 "Anthropic PBC", True, "powershell.exe")
    reasons, sev = _c(p)
    assert reasons == [] and sev == 0


def test_nombre_sistema_ms_firmado_fuera_de_windows_es_alto():
    p = ProcInfo(1200, "svchost.exe", r"D:\algo\svchost.exe",
                 "Microsoft Windows", True, "services.exe")
    reasons, sev = _c(p)
    assert sev == int(Severity.HIGH)
    assert any("fuera de" in r for r in reasons)


def test_norm_path_quita_prefijo_extendido():
    assert norm_path(r"\\?\C:\Windows\System32\conhost.exe") == \
        r"c:\windows\system32\conhost.exe"
    assert norm_path("") == ""


def test_conhost_con_prefijo_extendido_no_alerta():
    p = ProcInfo(1500, "conhost.exe",
                 r"\\?\C:\Windows\System32\conhost.exe",
                 "Microsoft Windows", True, "claude.exe")
    reasons, sev = _c(p)
    assert reasons == [] and sev == 0


def test_scan_construye_eventos():
    procs = [
        ProcInfo(4, "svchost.exe", r"C:\Windows\System32\svchost.exe",
                 "Microsoft Windows", True, "services.exe"),           # limpio
        ProcInfo(6660, "svchost.exe", r"C:\Temp\svchost.exe", "", False,
                 "explorer.exe"),                                       # malo
    ]
    events = scan(procs, win_dir=WIN, writable_dirs=WRITABLE)
    assert len(events) == 1
    ev = events[0]
    assert ev.kind == "proc_impersonation"
    assert ev.severity == Severity.CRITICAL
    assert ev.enrichment["pid"] == 6660
    assert "windows" in ev.tags


def test_multiples_motivos_toman_la_severidad_maxima():
    # Falso svchost en Temp (crítico por suplantar) + padre raro (crítico).
    p = ProcInfo(6662, "svchost.exe",
                 r"C:\Users\Cris\AppData\Local\Temp\svchost.exe",
                 "", False, "cmd.exe")
    reasons, sev = _c(p)
    assert sev == int(Severity.CRITICAL)
    assert len(reasons) >= 2
