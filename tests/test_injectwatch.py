"""Tests del clasificador de inyección de DLL / side-loading (InjectWatch). Puros."""
from centinel.collectors.injectwatch import (
    ModuleInfo, ProcModules, classify_modules, scan,
)
from centinel.core import Severity

WIN = r"c:\windows"
WRITABLE = (
    r"c:\users\cris\appdata\local\temp",
    r"c:\users\cris\appdata\roaming",
    r"c:\users\cris\downloads",
    r"c:\programdata",
)


def _c(p: ProcModules, **kw):
    return classify_modules(p, win_dir=WIN, writable_dirs=WRITABLE, **kw)


def _mod(name, path, signer="", valid=False):
    return ModuleInfo(name=name, path=path, signer=signer, sig_valid=valid)


def test_proceso_con_dlls_normales_no_alerta():
    p = ProcModules(1000, "notepad.exe", r"C:\Windows\System32\notepad.exe",
                    host_trusted=True, modules=(
        _mod("ntdll.dll", r"C:\Windows\System32\ntdll.dll", "Microsoft", True),
        _mod("kernel32.dll", r"C:\Windows\System32\kernel32.dll", "Microsoft", True),
    ))
    reasons, sev = _c(p)
    assert reasons == [] and sev == 0


def test_dll_de_sistema_fuera_de_system32_es_critico():
    # version.dll junto al .exe en Downloads = search-order hijacking clásico.
    p = ProcModules(2000, "app.exe", r"C:\Users\Cris\Downloads\app.exe",
                    host_trusted=False, modules=(
        _mod("version.dll", r"C:\Users\Cris\Downloads\version.dll"),
    ))
    reasons, sev = _c(p)
    assert sev == int(Severity.CRITICAL)
    assert any("fuera de System32" in r for r in reasons)


def test_dll_escribible_en_proceso_de_confianza_es_critico():
    # DLL no firmada desde %TEMP% inyectada en un proceso firmado = inyección.
    p = ProcModules(3000, "chrome.exe", r"C:\Program Files\Chrome\chrome.exe",
                    host_trusted=True, modules=(
        _mod("evil.dll", r"C:\Users\Cris\AppData\Local\Temp\evil.dll"),
    ))
    reasons, sev = _c(p)
    assert sev == int(Severity.CRITICAL)
    assert any("inyectada en proceso de confianza" in r for r in reasons)


def test_dll_escribible_en_proceso_normal_es_high():
    # Mismo dropper pero el anfitrión no es de confianza => HIGH, no CRITICAL.
    p = ProcModules(3100, "loader.exe", r"C:\Users\Cris\Downloads\loader.exe",
                    host_trusted=False, modules=(
        _mod("payload.dll", r"C:\Users\Cris\AppData\Roaming\payload.dll"),
    ))
    reasons, sev = _c(p)
    assert sev == int(Severity.HIGH)
    assert any("carpeta escribible" in r for r in reasons)


def test_dll_de_editor_de_confianza_en_appdata_no_alerta():
    # App portable legítima (p. ej. firmada por Spotify) en AppData: no es amenaza.
    p = ProcModules(3200, "spotify.exe", r"C:\Users\Cris\AppData\Roaming\Spotify\spotify.exe",
                    host_trusted=True, modules=(
        _mod("chrome_elf.dll", r"C:\Users\Cris\AppData\Roaming\Spotify\chrome_elf.dll",
             "Spotify AB", True),
    ))
    reasons, sev = _c(p)
    assert reasons == [] and sev == 0


def test_allowlist_por_ruta_silencia_dll_escribible():
    p = ProcModules(3300, "node.exe", r"C:\Users\Cris\AppData\Roaming\npm\node.exe",
                    host_trusted=False, modules=(
        _mod("addon.node.dll", r"C:\Users\Cris\AppData\Roaming\npm\addon.dll"),
    ))
    reasons, sev = _c(p, allowed_paths=(r"c:\users\cris\appdata\roaming\npm",))
    assert reasons == [] and sev == 0


def test_dll_de_sistema_no_se_exime_por_allowlist():
    # La allowlist solo tapa la regla de carpeta escribible, NO el hijacking de
    # una DLL de sistema fuera de sitio: eso sigue siendo CRITICAL.
    p = ProcModules(3400, "svc.exe", r"C:\ProgramData\svc.exe",
                    host_trusted=False, modules=(
        _mod("ntdll.dll", r"C:\ProgramData\ntdll.dll"),
    ))
    reasons, sev = _c(p, allowed_paths=(r"c:\programdata",))
    assert sev == int(Severity.CRITICAL)
    assert any("fuera de System32" in r for r in reasons)


def test_scan_emite_evento_con_enrichment():
    p = ProcModules(4000, "app.exe", r"C:\Users\Cris\Downloads\app.exe",
                    host_trusted=False, modules=(
        _mod("version.dll", r"C:\Users\Cris\Downloads\version.dll"),
    ))
    events = scan([p], win_dir=WIN, writable_dirs=WRITABLE)
    assert len(events) == 1
    ev = events[0]
    assert ev.kind == "dll_injection"
    assert ev.enrichment["pid"] == 4000
    assert "T1055.001" in ev.tags
