"""CENTINEL Escritorio: ventana ligera de vigilancia para Windows.

CENTINEL como demonio es un IDS de Linux. Esta es su cara de escritorio para
Windows: una ventana que en un vistazo dice **si algún proceso se hace pasar por
Windows** (vía `procwatch`), **si alguien ha cargado DLLs donde no debe**
(`injectwatch`), **si han reemplazado un binario del sistema en disco**
(`hashwatch`, opcional) y **qué se está comiendo la RAM**. Usa solo `tkinter`
(viene con Python) — 0 dependencias, fiel a la filosofía del proyecto.

Cada escaneo se compara con el anterior (`snapshots`), así que la pregunta que
responde no es solo «qué hay» sino «qué es nuevo desde ayer», y queda anotado
en la bitácora JSONL (`storage/audit`).

Ejecutar:
    python -m centinel.desktop                # ventana
    python -m centinel.desktop --once         # un escaneo por consola, sin GUI
    python -m centinel.desktop --once --export html   # y deja el informe
    python -m centinel.desktop --write-config         # crea centinel.toml
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import threading

from .collectors.procwatch import (
    NO_WINDOW, enumerate_windows_procs, scan, default_win_dir,
    default_writable_dirs, default_allowed_paths,
)
from .collectors import hashwatch, injectwatch, winpersist
from .config import Config, load_config, write_example
from .core import Severity
from .baseline_store import BaselineStore
from .snapshots import (
    SnapshotStore, default_history_dir, finding_from_event, record_and_diff,
)
from .storage.audit import AuditLog, default_audit_path
from .storage.export import FORMATOS, write_report

_BASELINE_HASHES = "win_hashes"


# --- I/O de memoria (Windows, vía PowerShell; no puro) --------------------
_PS_MEM = r"""
$ErrorActionPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$os=Get-CimInstance Win32_OperatingSystem
$top=Get-Process|Group-Object ProcessName|%{[PSCustomObject]@{name=$_.Name;count=$_.Count;mb=[math]::Round((($_.Group|Measure-Object WorkingSet64 -Sum).Sum/1MB),1)}}|Sort-Object mb -Descending|Select-Object -First 15
[PSCustomObject]@{total_mb=[math]::Round($os.TotalVisibleMemorySize/1KB,0);free_mb=[math]::Round($os.FreePhysicalMemory/1KB,0);top=$top}|ConvertTo-Json -Compress -Depth 4
"""


def windows_memory_summary(timeout: float = 30.0) -> dict:
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_MEM],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
            creationflags=NO_WINDOW)
        data = json.loads((res.stdout or "").strip() or "{}")
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return {"total_mb": 0, "free_mb": 0, "top": []}
    if isinstance(data.get("top"), dict):
        data["top"] = [data["top"]]
    return data


def collect(cfg: Config | None = None) -> dict:
    """Escaneo completo (bloqueante): suplantación + inyección + arranque +
    integridad + RAM."""
    cfg = cfg or Config()
    win = default_win_dir()
    writable = default_writable_dirs()
    # Las rutas eximidas salen del config, que ya incluye lo que venga por la
    # variable de entorno de siempre.
    allowed = tuple(cfg.allow_paths) or default_allowed_paths()
    procs = enumerate_windows_procs()
    events = scan(procs, win_dir=win, writable_dirs=writable, allowed_paths=allowed)
    if cfg.watch_injection:
        # Inyección de DLL / side-loading (T1055/T1574): módulos cargados anómalos.
        inj = injectwatch.enumerate_module_candidates()
        events += injectwatch.scan(inj, win_dir=win, writable_dirs=writable,
                                   allowed_paths=allowed)
    if cfg.watch_persistence:
        # Vectores de arranque (Run/RunOnce, Startup, servicios, tareas).
        # Solo lectura: nada se desactiva ni se borra.
        events += winpersist.scan(win_dir=win, writable_dirs=writable,
                                  allowed_paths=allowed)
    if cfg.watch_hashes:
        events += _scan_hashes(cfg)
    mem = windows_memory_summary()
    return {"n_procs": len(procs), "events": events, "mem": mem}


def _scan_hashes(cfg: Config) -> list:
    """Integridad en disco, con la línea base firmada en BaselineStore."""
    try:
        store = BaselineStore(cfg.history_dir or default_history_dir())
    except RuntimeError:
        return []
    previa = store.load(_BASELINE_HASHES)
    events, nueva = hashwatch.scan(previa if isinstance(previa, dict) else None)
    store.save(_BASELINE_HASHES, nueva)
    return events


def visible_events(events, cfg: Config) -> list:
    """Filtra por el umbral de severidad del config."""
    return [e for e in events if int(e.severity) >= cfg.min_severity]


def run_scan(cfg: Config | None = None, *, store: SnapshotStore | None = None,
             audit: AuditLog | None = None, host: str = "") -> tuple[dict, object, dict]:
    """Escanea, compara con el escaneo anterior y lo deja anotado.

    Devuelve (datos, diff, retrato). Es la orquestación que comparten la
    ventana y el modo `--once`, para que las dos cuenten lo mismo.
    """
    cfg = cfg or Config()
    host = host or platform.node()
    data = collect(cfg)
    data["events"] = visible_events(data["events"], cfg)
    store = store or SnapshotStore(cfg.history_dir or default_history_dir())
    d, snap = record_and_diff(data["events"], store=store, host=host,
                              keep=cfg.history_keep)
    if audit is None:
        audit = AuditLog(default_audit_path())
    for ev in data["events"]:
        audit.log_event(ev)
    audit.log_scan(d, snap, host=host)
    data["diff"], data["snapshot"] = d, snap
    return data, d, snap


# --- GUI ------------------------------------------------------------------

_SEV_COLOR = {
    Severity.CRITICAL: "#c0392b", Severity.HIGH: "#e67e22",
    Severity.MEDIUM: "#f1c40f", Severity.LOW: "#3498db",
}
_ESTADO = {"nuevo": "NUEVO", "agravado": "AGRAVADO", "": ""}


def _estado_de(snap_key, d) -> str:
    if d is None or d.sin_historial:
        return ""
    for f in d.nuevos:
        if f.key == snap_key:
            return "nuevo"
    for _v, n in d.agravados:
        if n.key == snap_key:
            return "agravado"
    return ""


def _gui(cfg: Config) -> int:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except Exception:   # noqa: BLE001
        print("tkinter no disponible en esta instalación de Python.")
        return 1

    root = tk.Tk()
    root.title("CENTINEL — Escritorio (Windows)")
    root.geometry("980x680")
    root.minsize(760, 560)
    _ico = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                        "bin", "centinel.ico")
    try:
        root.iconbitmap(_ico)
    except tk.TclError:
        pass

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    estado_ultimo: dict = {"data": None}

    # Cabecera: veredicto + diff + barra de RAM.
    head = ttk.Frame(root, padding=12)
    head.pack(fill="x")
    verdict = tk.Label(head, text="Escaneando…", font=("Segoe UI", 16, "bold"),
                       anchor="w")
    verdict.pack(fill="x")
    cambios = ttk.Label(head, text="", foreground="#555")
    cambios.pack(fill="x", pady=(2, 0))
    ram_lbl = ttk.Label(head, text="RAM: —")
    ram_lbl.pack(fill="x", pady=(6, 2))
    ram_bar = ttk.Progressbar(head, maximum=100, length=100)
    ram_bar.pack(fill="x")

    body = ttk.Frame(root, padding=(12, 0))
    body.pack(fill="both", expand=True)

    ttk.Label(body, text="Amenazas (suplantación · inyección de DLL · integridad):",
              font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(10, 2))
    threats = ttk.Treeview(body, columns=("sev", "estado", "name", "pid", "why"),
                           show="headings", height=7)
    for col, txt, w in (("sev", "Sev", 70), ("estado", "Estado", 85),
                        ("name", "Proceso", 150), ("pid", "PID", 60),
                        ("why", "Motivo", 520)):
        threats.heading(col, text=txt)
        threats.column(col, width=w, anchor="w")
    threats.pack(fill="both", expand=True)

    ttk.Label(body, text="Top consumidores de RAM:",
              font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(10, 2))
    ram_tv = ttk.Treeview(body, columns=("name", "count", "mb"),
                          show="headings", height=8)
    for col, txt, w in (("name", "Proceso", 320), ("count", "Instancias", 110),
                        ("mb", "RAM (MB)", 120)):
        ram_tv.heading(col, text=txt)
        ram_tv.column(col, width=w, anchor="w")
    ram_tv.pack(fill="both", expand=True)

    foot = ttk.Frame(root, padding=12)
    foot.pack(fill="x")
    status = ttk.Label(foot, text="")
    status.pack(side="left")
    rescan_btn = ttk.Button(foot, text="Reescanear")
    rescan_btn.pack(side="right")
    export_btn = ttk.Button(foot, text="Exportar informe", state="disabled")
    export_btn.pack(side="right", padx=(0, 8))
    ttk.Button(foot, text="Cerrar", command=root.destroy).pack(
        side="right", padx=(0, 8))

    def do_export() -> None:
        data = estado_ultimo["data"]
        if not data:
            return
        ext = {"html": ".html", "json": ".json", "csv": ".csv"}[cfg.report_format]
        destino = filedialog.asksaveasfilename(
            title="Guardar informe", defaultextension=ext,
            initialdir=cfg.report_dir or ".",
            filetypes=[(cfg.report_format.upper(), "*" + ext)])
        if not destino:
            return
        try:
            from .storage.export import render
            with open(destino, "w", encoding="utf-8", newline="") as f:
                f.write(render(cfg.report_format, data["snapshot"], data["diff"],
                               host=platform.node()))
        except OSError as exc:
            messagebox.showerror("CENTINEL", f"No se pudo guardar: {exc}")
            return
        status.config(text=f"Informe guardado en {destino}")

    def render_gui(data: dict) -> None:
        events = data["events"]
        mem = data["mem"]
        d = data.get("diff")
        threats.delete(*threats.get_children())
        for ev in sorted(events, key=lambda e: e.severity, reverse=True):
            sev = Severity(ev.severity)
            estado = _estado_de(finding_from_event(ev).key, d)
            threats.insert("", "end", tags=(sev.name,), values=(
                sev.name, _ESTADO.get(estado, estado.upper()),
                ev.enrichment.get("name", ""), ev.enrichment.get("pid", ""),
                "; ".join(ev.enrichment.get("reasons", []))))
            threats.tag_configure(sev.name,
                                  foreground=_SEV_COLOR.get(sev, "#000"))
        if events:
            verdict.config(text=f"⚠  {len(events)} amenaza(s) detectada(s)",
                           fg="#c0392b")
        else:
            verdict.config(text="✓  LIMPIO — sin suplantación ni inyección de DLL",
                           fg="#27ae60")
        cambios.config(text=d.resumen() if d is not None else "")
        total = mem.get("total_mb", 0) or 0
        free = mem.get("free_mb", 0) or 0
        used = max(total - free, 0)
        pct = round(used / total * 100, 1) if total else 0
        ram_lbl.config(text=f"RAM: {used/1024:.1f} / {total/1024:.1f} GB "
                            f"({pct}% usado) — {data['n_procs']} procesos")
        ram_bar["value"] = pct
        ram_tv.delete(*ram_tv.get_children())
        for r in mem.get("top", []):
            ram_tv.insert("", "end", values=(
                r.get("name", ""), r.get("count", ""), r.get("mb", "")))
        estado_ultimo["data"] = data
        status.config(text="Listo.")
        rescan_btn.config(state="normal")
        export_btn.config(state="normal")

    def do_scan() -> None:
        rescan_btn.config(state="disabled")
        export_btn.config(state="disabled")
        status.config(text="Escaneando procesos y firmas…")
        verdict.config(text="Escaneando…", fg="#333")

        def worker() -> None:
            try:
                data, _d, _snap = run_scan(cfg)
            except Exception as e:   # noqa: BLE001
                root.after(0, lambda: status.config(text=f"Error: {e}"))
                root.after(0, lambda: rescan_btn.config(state="normal"))
                return
            root.after(0, lambda: render_gui(data))

        threading.Thread(target=worker, daemon=True).start()

    rescan_btn.config(command=do_scan)
    export_btn.config(command=do_export)
    if cfg.auto_scan_seconds:
        def reloj() -> None:
            do_scan()
            root.after(cfg.auto_scan_seconds * 1000, reloj)
        root.after(cfg.auto_scan_seconds * 1000, reloj)
    root.after(200, do_scan)
    root.mainloop()
    return 0


# --- consola --------------------------------------------------------------

def _imprimible(texto: str) -> bool:
    """¿La consola actual puede escribir estos caracteres?

    La consola de Windows sigue siendo cp1252 en muchas máquinas y no sabe
    escribir '⚠' ni '✓': imprimirlos revienta con UnicodeEncodeError y se
    pierde el resultado del escaneo. Preguntamos antes en vez de confiar.
    """
    enc = getattr(sys.stdout, "encoding", None) or "ascii"
    try:
        texto.encode(enc)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def print_scan(data: dict, d) -> None:
    """Resumen por consola del modo `--once`."""
    events = data["events"]
    bonito = _imprimible("⚠✓—")
    aviso, limpio, guion = (("⚠", "✓", "—") if bonito else ("!!", "OK", "-"))
    print(d.resumen() if d is not None else "")
    if not events:
        print(f"{limpio} LIMPIO {guion} sin suplantación ni inyección de DLL.")
        return
    print(f"{aviso} {len(events)} hallazgo(s):")
    for ev in sorted(events, key=lambda e: e.severity, reverse=True):
        sev = Severity(ev.severity).name
        enr = ev.enrichment
        marca = _estado_de(finding_from_event(ev).key, d)
        print("  [{}]{} {} (pid {}) — {}".format(
            sev, " " + marca.upper() if marca else "", enr.get("name", "?"),
            enr.get("pid", "?"), "; ".join(enr.get("reasons", []))))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="centinel-desktop",
        description="CENTINEL Escritorio: suplantación de procesos, inyección "
                    "de DLL e integridad en disco (Windows).")
    p.add_argument("--once", action="store_true",
                   help="un escaneo por consola y salir (sin ventana)")
    p.add_argument("--export", choices=FORMATOS, metavar="FORMATO",
                   help="con --once, guarda el informe ({})".format(
                       "|".join(FORMATOS)))
    p.add_argument("--outdir", default=None,
                   help="carpeta del informe (por defecto, la del config)")
    p.add_argument("--config", default=None, help="ruta de un centinel.toml")
    p.add_argument("--write-config", metavar="RUTA", nargs="?", const="centinel.toml",
                   help="escribe un centinel.toml de ejemplo y sale")
    return p


def main(argv: list[str] | None = None) -> int:
    try:  # consola de Windows: que no reviente con acentos ni con '⚠'
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError, ValueError):
        pass
    args = build_parser().parse_args(argv)

    if args.write_config:
        print("Configuración de ejemplo escrita en:",
              write_example(args.write_config))
        return 0

    cfg = load_config(args.config)
    for aviso in cfg.errors:
        print("config:", aviso)

    if os.name != "nt":
        print("CENTINEL Escritorio es para Windows. En Linux usa el demonio: "
              "python -m centinel.app --help")
        return 1

    if not args.once:
        return _gui(cfg)

    data, d, snap = run_scan(cfg)
    print_scan(data, d)
    if args.export:
        path = write_report(snap, d, fmt=args.export,
                            outdir=args.outdir or cfg.report_dir,
                            host=platform.node())
        print("Informe:", path)
    return 2 if data["events"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
