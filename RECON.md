# CENTINEL — Modo RECON

Complemento **ofensivo/de reconocimiento** del CENTINEL defensivo. Mientras el
IDS vigila TU host, el recon **inventaría un objetivo autorizado**: TUI que
orquesta `nmap`, `ffuf` y un sniffer pasivo (`tcpdump`) con sesiones, temas,
reporte e historial. **Solo para pentesting/CTF autorizados.**

Nació inspirado en una pantalla de referencia ("PARANOID"); NO es un proyecto
aparte — vive dentro de CENTINEL como el subpaquete `centinel/recon/`.

Arranque:
- `python -m centinel --recon`
- `python -m centinel.recon`

Datos bajo `~/.local/share/centinel/recon/` (Linux) o `%LOCALAPPDATA%\centinel\recon`
(Windows), separado de las baselines del IDS.

## Filosofía (heredada del resto de CENTINEL)
0 dependencias pip. Las herramientas son binarios externos vía subprocess; la
lógica de decisión/parseo es **pura y testeable**, separada del I/O. Si una
herramienta falta, la función degrada con un mensaje claro (lo reporta `verify`).

## Arquitectura (centinel/recon/)
- **model.py** — `Finding` (puerto/ruta/subdominio) y `ScanResult`. Puro.
- **paths.py** — rutas XDG (Linux) / %APPDATA% (Windows) bajo `centinel/recon`.
- **parse.py** — `parse_nmap` (tabla de puertos) y `parse_ffuf` (JSON) → Findings. **Puro.**
- **scanner.py** — `build_nmap_cmd`/`build_ffuf_cmd` (puras) + `run_nmap`/`run_ffuf` (I/O). Modos nmap: quick/full/service/stealth. ffuf: dir/subdomain.
- **telemetry.py** — `build_sniff_cmd` + `capture` (tcpdump) + `summarize_capture` (protocolos, top hablantes, DNS). **summarize es puro.**
- **theme.py** — 6 temas ANSI (matrix/amber/ice/blood/violet/mono). Puro.
- **config.py** — config JSON persistente (tema, interfaz, wordlists, última sesión).
- **session.py** — `Session` en `results/<slug>/session.json`. `slugify` puro; dedup de hallazgos.
- **report.py** — `render_txt`/`render_md` (puros) + `export` al PWD (txt + md con tablas).
- **history.py** — `RunLog` en memoria (`logs`) + historial JSONL persistente (`history`).
- **verify.py** — `preflight` (puro) + `run_preflight`: herramientas, root, wordlists, interfaz.
- **context.py** — **menú declarativo** (1:1 con la pantalla) + `availability(item, Ctx)` puro: qué ítem está activo y **por qué no**.
- **state.py** — `AppState`; sesión implícita `global` (a la que vuelve `session close`); construye el `Ctx`.
- **keys.py** — lectura de tecla sin Enter multiplataforma (msvcrt / termios). Sin TTY → modo línea.
- **tui.py** — banner + menú navegable con flechas (fila resaltada, ítems bloqueados atenuados con su motivo) + dispatcher.
- **__main__.py** — habilita ANSI + fuerza UTF-8 en Windows; también lo llama `--recon`.

## Estado (2026-08-23)
✅ Menú completo, context-aware real. nmap 4 modos + ffuf dir/sub con parseo y persistencia. Sniffer pasivo + telemetría. Sesiones (new/use/close/list/info) con dedup e historial. Reporte view + export txt/md. Temas en vivo. Preflight.
✅ **37 tests** (`tests/test_recon_*.py`) de núcleos puros. Suite total de CENTINEL: **322 pasan**.
✅ Integrado en el CLI: `--recon`. Sin tocar el pipeline async del IDS.
⚠️ Sin herramientas en el host Windows del usuario: las corridas reales degradan; probar de verdad en Kali/Linux.

## Pendiente
1. Parseo nmap **XML** (`-oX`) además de la tabla de texto.
2. Empaquetar/autodetectar **wordlists** (SecLists).
3. Sniffer: IPv6 y captura a `.pcap`.
4. Export **HTML** (reusar patrón del IDS). Diff entre sesiones ("nuevo desde la última corrida").
5. Puente con el IDS: alimentar hallazgos del recon al event store como contexto.

## Seguridad
Recon para objetivos **autorizados**. El scan sigiloso (-sS) exige root y se
deshabilita si no lo hay. Sin exploits ni evasión de detección.
