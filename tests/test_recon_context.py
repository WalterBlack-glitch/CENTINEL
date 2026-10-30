"""Tests de la lógica consciente del contexto (disponibilidad del menú)."""
from centinel.recon.context import Ctx, availability, all_items, item_by_id


def test_menu_tiene_los_items_de_la_pantalla():
    ids = {it.id for it in all_items()}
    for expected in ("scan_quick", "scan_full", "scan_service", "scan_stealth",
                     "scan_dir", "scan_subdomain", "set_target", "set_interface",
                     "telemetry_panel", "session_new", "session_use",
                     "session_close", "session_list", "session_info", "view",
                     "export", "theme", "config", "logs", "history", "verify",
                     "quit"):
        assert expected in ids


def test_scan_requiere_target():
    ok, why = availability("scan_quick", Ctx(has_target=False))
    assert not ok and "target" in why
    assert availability("scan_quick", Ctx(has_target=True))[0]


def test_stealth_requiere_root():
    assert not availability("scan_stealth", Ctx(has_target=True, is_root=False))[0]
    assert availability("scan_stealth", Ctx(has_target=True, is_root=True))[0]


def test_scan_dir_requiere_ffuf_y_wordlist():
    base = Ctx(has_target=True)
    assert not availability("scan_dir", base)[0]                    # sin ffuf
    assert not availability("scan_dir",
                            Ctx(has_target=True, ffuf_ready=True))[0]  # sin wl
    assert availability("scan_dir", Ctx(has_target=True, ffuf_ready=True,
                                        dir_wordlist=True))[0]


def test_telemetry_requiere_captura():
    assert not availability("telemetry_panel", Ctx(has_capture=False))[0]
    assert availability("telemetry_panel", Ctx(has_capture=True))[0]


def test_session_close_info_requieren_activa():
    assert not availability("session_close", Ctx(active_session=False))[0]
    assert availability("session_info", Ctx(active_session=True))[0]


def test_report_requiere_hallazgos():
    assert not availability("view", Ctx(has_findings=False))[0]
    assert availability("export", Ctx(has_findings=True))[0]


def test_quit_y_set_target_siempre_disponibles():
    assert availability("quit", Ctx())[0]
    assert availability("set_target", Ctx())[0]
    assert availability("theme", Ctx())[0]


def test_item_by_id():
    assert item_by_id("scan_quick").label == "scan quick"
    assert item_by_id("no_existe") is None
