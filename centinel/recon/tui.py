"""La cara del modo recon de CENTINEL: banner, menú navegable y despacho.

Rendering y bucle de entrada. Toda la lógica pura vive en otros módulos; aquí
solo se dibuja, se pregunta al usuario y se llaman las acciones.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

from . import (config, context, history, keys, paths, report, session,
               telemetry, theme, tools, verify)
from . import scanner
from .context import MENU, availability
from .model import Finding
from .state import AppState
from .theme import RESET, paint

BANNER = r"""
  ___  ___ _  _ _____ ___ _  _ ___ _
 / __|/ __| \| |_   _|_ _| \| | __| |
| (__| _|| .` | | |  | || .` | _|| |__
 \___|___|_|\_| |_| |___|_|\_|___|____|   · recon
"""


def clear() -> None:
    print("\x1b[2J\x1b[H", end="")


def _validate_target(t: str) -> bool:
    t = t.strip()
    return bool(t) and " " not in t and len(t) <= 253


def _ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        return ""


def _pause() -> None:
    try:
        input("\n  ↵ Enter para volver… ")
    except (EOFError, KeyboardInterrupt):
        pass


# --------------------------------------------------------------------------
# Render
# --------------------------------------------------------------------------

def render(st: AppState, cursor: int) -> None:
    th = theme.get(st.cfg.theme)
    ctx = st.ctx()
    clear()
    print(paint(BANNER, th.title))
    sub = "Context-aware recon · nmap · ffuf · sniffer pasivo"
    print("  " + paint(sub, th.help))
    rdir = paths.session_dir(st.session.name)
    tgt = st.session.target or "—"
    print("  " + paint(f"objetivo → {tgt}    sesión → {st.session.name}"
                       f"{'' if st.is_named else ' (efímera)'}", th.dim))
    print("  " + paint(f"resultados → {rdir}", th.dim))
    print()

    idx = 0
    for sec in MENU:
        print("  " + paint(f"▸ {sec.title}", th.section))
        for it in sec.items:
            ok, why = availability(it.id, ctx)
            selected = idx == cursor
            label = f"{it.label:<16}"
            help_txt = it.help if ok else f"{it.help}  · {why}"
            if selected:
                marker = paint(" ▎", th.accent)
                row = paint(f" {label} {help_txt} ", th.accent)
                print(f"  {marker}{row}")
            elif ok:
                print(f"    {paint(label, th.cmd)} {paint(help_txt, th.help)}")
            else:
                print(f"    {paint(label, th.dim)} {paint(help_txt, th.dim)}")
            idx += 1
        print()
    print("  " + paint("↑/↓ mover · Enter elegir · q salir", th.dim))


# --------------------------------------------------------------------------
# Acciones
# --------------------------------------------------------------------------

def _out_dir(st: AppState) -> Path:
    d = paths.session_dir(st.session.name)
    d.mkdir(parents=True, exist_ok=True)
    return d


def _absorb(st: AppState, res, th) -> None:
    """Integra un ScanResult en la sesión y muestra el resumen."""
    if res.error:
        print("  " + paint(f"✗ {res.error}", th.err))
        st.runlog.add(f"{res.tool} {res.kind}: ERROR {res.error}")
        return
    st.session.commands.append(" ".join(res.command))
    new = st.session.add_findings(res.findings)
    st.persist()
    history.append_history(st.session.name, f"{res.tool} {res.kind}",
                           f"{len(res.findings)} hallazgos, {new} nuevos")
    st.runlog.add(f"{res.tool} {res.kind}: {len(res.findings)} hallazgos "
                  f"({new} nuevos)")
    print("  " + paint(f"✓ {res.tool} {res.kind}: {len(res.findings)} "
                       f"hallazgos ({new} nuevos)", th.ok))
    for f in res.findings[:20]:
        print("    " + _fmt_finding(f))
    if len(res.findings) > 20:
        print(paint(f"    … y {len(res.findings) - 20} más (view)", th.dim))


def _fmt_finding(f: Finding) -> str:
    if f.kind == "port":
        v = f" {f.version}" if f.version else ""
        return f"{f.port}/{f.proto} {f.state} {f.service}{v}"
    if f.kind == "subdomain":
        return f"[{f.status}] {f.fuzz} ({f.url})"
    return f"[{f.status}] {f.url} (len={f.length})"


def act_scan(st: AppState, mode: str) -> None:
    th = theme.get(st.cfg.theme)
    if mode in scanner.NMAP_MODES:
        print(paint(f"\n  Ejecutando nmap {mode} sobre {st.session.target}…",
                    th.help))
        res = scanner.run_nmap(mode, st.session.target, out_dir=_out_dir(st),
                             is_root=st.root)
    else:
        wl = st.cfg.wordlist_dir if mode == "dir" else st.cfg.wordlist_sub
        print(paint(f"\n  Ejecutando ffuf {mode} sobre {st.session.target}…",
                    th.help))
        res = scanner.run_ffuf(mode, st.session.target, wl, out_dir=_out_dir(st))
    _absorb(st, res, th)


def act_set_target(st: AppState) -> None:
    th = theme.get(st.cfg.theme)
    t = _ask("  Nuevo target (IP / CIDR / hostname): ")
    if not t:
        return
    if not _validate_target(t):
        print("  " + paint("target inválido", th.err))
        return
    st.session.target = t
    st.persist()
    st.runlog.add(f"target = {t}")
    print("  " + paint(f"✓ target fijado: {t}", th.ok))


def act_set_interface(st: AppState) -> None:
    th = theme.get(st.cfg.theme)
    iface = _ask("  Interfaz del sniffer (eth0/tun0/wlan0…): ")
    if not iface:
        return
    st.cfg.interface = iface
    config.save(st.cfg)
    st.runlog.add(f"interfaz = {iface}")
    print("  " + paint(f"✓ interfaz: {iface}", th.ok))
    if _ask("  ¿Capturar ahora una muestra pasiva? (s/N): ").lower() == "s":
        act_sniff(st)


def act_sniff(st: AppState) -> None:
    th = theme.get(st.cfg.theme)
    print(paint("  Capturando (pasivo, hasta 200 paquetes / 30s)…", th.help))
    cap = telemetry.capture(st.cfg.interface, count=200, timeout=30.0)
    if cap.get("error"):
        print("  " + paint(f"✗ {cap['error']}", th.err))
        return
    st.last_capture = cap
    st.runlog.add(f"captura: {cap['summary'].get('packets', 0)} paquetes")
    act_telemetry(st)


def act_telemetry(st: AppState) -> None:
    th = theme.get(st.cfg.theme)
    if not st.last_capture:
        print("  " + paint("aún no hay captura", th.warn))
        return
    s = st.last_capture["summary"]
    print("\n  " + paint("TELEMETRÍA — última captura", th.section))
    print(f"    paquetes: {s.get('packets', 0)}")
    print("    protocolos: " + ", ".join(f"{k}={v}"
          for k, v in s.get("by_proto", {}).items()) or "    —")
    print("    top hablantes:")
    for ip, n in s.get("top_talkers", []):
        print(f"      {ip:<20} {n}")
    if s.get("dns_queries"):
        print("    consultas DNS:")
        for name, n in s["dns_queries"]:
            print(f"      {name} ({n})")


def act_session_new(st: AppState) -> None:
    th = theme.get(st.cfg.theme)
    name = _ask("  Nombre de la sesión: ")
    if not name:
        return
    s = session.create(name, target=st.session.target)
    st.use_session(s)
    history.append_history(s.name, "session new", s.target)
    st.runlog.add(f"sesión nueva: {s.name}")
    print("  " + paint(f"✓ sesión '{s.name}' creada y activa", th.ok))


def act_session_use(st: AppState) -> None:
    th = theme.get(st.cfg.theme)
    rows = session.listing()
    if not rows:
        print("  " + paint("no hay sesiones", th.warn))
        return
    for i, r in enumerate(rows, 1):
        print(f"    {i}. {r['name']:<20} {r['target']:<24} "
              f"{r['findings']} hallazgos")
    sel = _ask("  Nº o nombre: ")
    name = None
    if sel.isdigit() and 1 <= int(sel) <= len(rows):
        name = rows[int(sel) - 1]["name"]
    elif sel:
        name = sel
    if not name:
        return
    s = session.load(name)
    if not s:
        print("  " + paint(f"no existe: {name}", th.err))
        return
    st.use_session(s)
    st.runlog.add(f"sesión activa: {s.name}")
    print("  " + paint(f"✓ activada '{s.name}'", th.ok))


def act_session_close(st: AppState) -> None:
    th = theme.get(st.cfg.theme)
    st.persist()
    prev = st.session.name
    st.close_session()
    st.runlog.add(f"cerrada sesión {prev} → global")
    print("  " + paint(f"✓ '{prev}' cerrada; vuelves a global", th.ok))


def act_session_list(st: AppState) -> None:
    th = theme.get(st.cfg.theme)
    rows = session.listing()
    if not rows:
        print("  " + paint("no hay sesiones guardadas", th.warn))
        return
    print("\n  " + paint("SESIONES", th.section))
    for r in rows:
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(r["updated"]))
        print(f"    {r['name']:<20} {r['target']:<24} "
              f"{r['findings']:>3} hallazgos  {when}")


def act_session_info(st: AppState) -> None:
    th = theme.get(st.cfg.theme)
    s = st.session
    print("\n  " + paint(f"SESIÓN {s.name}", th.section))
    print(f"    objetivo : {s.target or '—'}")
    print(f"    hallazgos: {len(s.findings)}")
    print(f"    comandos : {len(s.commands)}")
    print(f"    carpeta  : {paths.session_dir(s.name)}")


def act_view(st: AppState) -> None:
    print("\n" + report.render_txt(st.session))


def act_export(st: AppState) -> None:
    th = theme.get(st.cfg.theme)
    files = report.export(st.session, Path.cwd())
    st.runlog.add(f"export → {', '.join(f.name for f in files)}")
    history.append_history(st.session.name, "export",
                           ", ".join(f.name for f in files))
    print("  " + paint("✓ exportado a tu carpeta actual:", th.ok))
    for f in files:
        print(f"    {f}")


def act_theme(st: AppState) -> None:
    th = theme.get(st.cfg.theme)
    ns = theme.names()
    print("\n  Temas: " + "  ".join(
        f"{i+1}.{paint(n, theme.get(n).cmd)}" for i, n in enumerate(ns)))
    sel = _ask("  Nº o nombre: ")
    name = ns[int(sel) - 1] if sel.isdigit() and 1 <= int(sel) <= len(ns) else sel
    if name in theme.THEMES:
        st.cfg.theme = name
        config.save(st.cfg)
        st.runlog.add(f"tema = {name}")


def act_config(st: AppState) -> None:
    th = theme.get(st.cfg.theme)
    c = st.cfg
    print("\n  " + paint("CONFIGURACIÓN", th.section))
    print(f"    tema          : {c.theme}")
    print(f"    interfaz      : {c.interface or '—'}")
    print(f"    wordlist dirs : {c.wordlist_dir or '—'}")
    print(f"    wordlist subs : {c.wordlist_sub or '—'}")
    print(f"    root          : {'sí' if st.root else 'no'}")
    print(f"    config file   : {paths.config_file()}")
    if _ask("  ¿Editar wordlists? (s/N): ").lower() == "s":
        d = _ask(f"  wordlist dirs [{c.wordlist_dir}]: ")
        s = _ask(f"  wordlist subs [{c.wordlist_sub}]: ")
        if d:
            c.wordlist_dir = d
        if s:
            c.wordlist_sub = s
        config.save(c)
        print("  " + paint("✓ guardado", th.ok))


def act_logs(st: AppState) -> None:
    th = theme.get(st.cfg.theme)
    print("\n  " + paint("LOG DE ESTA CORRIDA", th.section))
    lines = st.runlog.tail(50)
    print("\n".join(f"    {ln}" for ln in lines) if lines
          else "    (sin acciones aún)")


def act_history(st: AppState) -> None:
    th = theme.get(st.cfg.theme)
    print("\n  " + paint("HISTORIAL PERSISTENTE", th.section))
    rows = history.read_history(40)
    if not rows:
        print("    (vacío)")
        return
    for r in rows:
        when = time.strftime("%m-%d %H:%M", time.localtime(r.get("ts", 0)))
        print(f"    {when}  [{r.get('session', '?'):<12}] "
              f"{r.get('action', '')}  {r.get('detail', '')}")


def act_verify(st: AppState) -> None:
    th = theme.get(st.cfg.theme)
    print("\n  " + paint("PREFLIGHT", th.section))
    mark = {"ok": (th.ok, "✓"), "warn": (th.warn, "!"), "err": (th.err, "✗")}
    for name, ok, detail, sev in verify.run_preflight(st.cfg):
        col, sym = mark[sev]
        print(f"    {paint(sym, col)} {name:<20} {detail}")


DISPATCH = {
    "scan_quick": lambda st: act_scan(st, "quick"),
    "scan_full": lambda st: act_scan(st, "full"),
    "scan_service": lambda st: act_scan(st, "service"),
    "scan_stealth": lambda st: act_scan(st, "stealth"),
    "scan_dir": lambda st: act_scan(st, "dir"),
    "scan_subdomain": lambda st: act_scan(st, "subdomain"),
    "set_target": act_set_target,
    "set_interface": act_set_interface,
    "telemetry_panel": act_telemetry,
    "session_new": act_session_new,
    "session_use": act_session_use,
    "session_close": act_session_close,
    "session_list": act_session_list,
    "session_info": act_session_info,
    "view": act_view,
    "export": act_export,
    "theme": act_theme,
    "config": act_config,
    "logs": act_logs,
    "history": act_history,
    "verify": act_verify,
}


# --------------------------------------------------------------------------
# Bucle principal
# --------------------------------------------------------------------------

def run() -> int:
    paths.ensure_dirs()
    cfg = config.load()
    st = AppState(cfg=cfg)
    # Reactivar última sesión si existe.
    if cfg.last_session and session.exists(cfg.last_session):
        s = session.load(cfg.last_session)
        if s:
            st.use_session(s)

    items = context.all_items()
    if not keys.has_tty():
        # Sin terminal interactiva: dibuja una vez y sale (útil para smokes/CI).
        render(st, 0)
        return 0

    cursor = 0
    while True:
        render(st, cursor)
        k = keys.read_key()
        if k == keys.UP:
            cursor = (cursor - 1) % len(items)
        elif k == keys.DOWN:
            cursor = (cursor + 1) % len(items)
        elif k in ("q", "Q"):
            break
        elif k == keys.ENTER:
            item = items[cursor]
            if item.id == "quit":
                break
            ok, why = availability(item.id, st.ctx())
            th = theme.get(st.cfg.theme)
            print()
            if not ok:
                print("  " + paint(f"no disponible: {why}", th.warn))
            else:
                try:
                    DISPATCH[item.id](st)
                except Exception as e:   # noqa: BLE001 — nunca tumbar la TUI
                    print("  " + paint(f"error en la acción: {e}", th.err))
            _pause()

    # Recordar la última sesión con nombre.
    if st.is_named:
        st.cfg.last_session = st.session.name
        config.save(st.cfg)
    clear()
    print("CENTINEL recon cerrado. Mantente paranoico. 🐍")
    return 0
