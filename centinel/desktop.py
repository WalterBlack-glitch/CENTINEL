"""CENTINEL Escritorio: ventana ligera de vigilancia para Windows.

CENTINEL como demonio es un IDS de Linux. Esta es su cara de escritorio para
Windows: una ventana que en un vistazo dice **si algún proceso se hace pasar por
Windows** (vía `procwatch`) y **qué se está comiendo la RAM**. Usa solo `tkinter`
(viene con Python) — 0 dependencias, fiel a la filosofía del proyecto.

Ejecutar:  `python -m centinel.desktop`   o   `centinel-desktop`
"""
from __future__ import annotations

import json
import os
import subprocess
import threading

from .collectors.procwatch import (
    enumerate_windows_procs, scan, default_win_dir, default_writable_dirs,
)
from .core import Severity


# --- I/O de memoria (Windows, vía PowerShell; no puro) --------------------
_PS_MEM = r"""
$ErrorActionPreference='SilentlyContinue'
$os=Get-CimInstance Win32_OperatingSystem
$top=Get-Process|Group-Object ProcessName|%{[PSCustomObject]@{name=$_.Name;count=$_.Count;mb=[math]::Round((($_.Group|Measure-Object WorkingSet64 -Sum).Sum/1MB),1)}}|Sort-Object mb -Descending|Select-Object -First 15
[PSCustomObject]@{total_mb=[math]::Round($os.TotalVisibleMemorySize/1KB,0);free_mb=[math]::Round($os.FreePhysicalMemory/1KB,0);top=$top}|ConvertTo-Json -Compress -Depth 4
"""


def windows_memory_summary(timeout: float = 30.0) -> dict:
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_MEM],
            capture_output=True, text=True, timeout=timeout)
        data = json.loads((res.stdout or "").strip() or "{}")
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return {"total_mb": 0, "free_mb": 0, "top": []}
    if isinstance(data.get("top"), dict):
        data["top"] = [data["top"]]
    return data


def collect() -> dict:
    """Escaneo completo (bloqueante): amenazas de suplantación + RAM."""
    procs = enumerate_windows_procs()
    events = scan(procs, win_dir=default_win_dir(),
                  writable_dirs=default_writable_dirs())
    mem = windows_memory_summary()
    return {"n_procs": len(procs), "events": events, "mem": mem}


# --- GUI ------------------------------------------------------------------

_SEV_COLOR = {
    Severity.CRITICAL: "#c0392b", Severity.HIGH: "#e67e22",
    Severity.MEDIUM: "#f1c40f", Severity.LOW: "#3498db",
}


def main() -> int:
    if os.name != "nt":
        print("CENTINEL Escritorio es para Windows. En Linux usa el demonio: "
              "python -m centinel.app --help")
        return 1
    try:
        import tkinter as tk
        from tkinter import ttk
    except Exception:   # noqa: BLE001
        print("tkinter no disponible en esta instalación de Python.")
        return 1

    root = tk.Tk()
    root.title("CENTINEL — Escritorio (Windows)")
    root.geometry("880x620")
    root.minsize(720, 520)

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    # Cabecera: veredicto + barra de RAM.
    head = ttk.Frame(root, padding=12)
    head.pack(fill="x")
    verdict = tk.Label(head, text="Escaneando…", font=("Segoe UI", 16, "bold"),
                       anchor="w")
    verdict.pack(fill="x")
    ram_lbl = ttk.Label(head, text="RAM: —")
    ram_lbl.pack(fill="x", pady=(6, 2))
    ram_bar = ttk.Progressbar(head, maximum=100, length=100)
    ram_bar.pack(fill="x")

    body = ttk.Frame(root, padding=(12, 0))
    body.pack(fill="both", expand=True)

    ttk.Label(body, text="Amenazas (procesos que suplantan al sistema):",
              font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(10, 2))
    threats = ttk.Treeview(body, columns=("sev", "name", "pid", "why"),
                           show="headings", height=7)
    for col, txt, w in (("sev", "Sev", 70), ("name", "Proceso", 150),
                        ("pid", "PID", 70), ("why", "Motivo", 560)):
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
    ttk.Button(foot, text="Cerrar", command=root.destroy).pack(
        side="right", padx=(0, 8))

    def render(data: dict) -> None:
        events = data["events"]
        mem = data["mem"]
        threats.delete(*threats.get_children())
        for ev in sorted(events, key=lambda e: e.severity, reverse=True):
            sev = Severity(ev.severity)
            tag = sev.name
            threats.insert("", "end", tags=(tag,), values=(
                sev.name, ev.enrichment.get("name", ""),
                ev.enrichment.get("pid", ""),
                "; ".join(ev.enrichment.get("reasons", []))))
            threats.tag_configure(tag, foreground=_SEV_COLOR.get(sev, "#000"))
        if events:
            verdict.config(text=f"⚠  {len(events)} amenaza(s) detectada(s)",
                           fg="#c0392b")
        else:
            verdict.config(text="✓  LIMPIO — ningún proceso suplanta a Windows",
                           fg="#27ae60")
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
        status.config(text="Listo.")
        rescan_btn.config(state="normal")

    def do_scan() -> None:
        rescan_btn.config(state="disabled")
        status.config(text="Escaneando procesos y firmas…")
        verdict.config(text="Escaneando…", fg="#333")

        def worker() -> None:
            try:
                data = collect()
            except Exception as e:   # noqa: BLE001
                root.after(0, lambda: status.config(text=f"Error: {e}"))
                root.after(0, lambda: rescan_btn.config(state="normal"))
                return
            root.after(0, lambda: render(data))

        threading.Thread(target=worker, daemon=True).start()

    rescan_btn.config(command=do_scan)
    root.after(200, do_scan)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
