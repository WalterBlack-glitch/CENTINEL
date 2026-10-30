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

## Estado (2026-10-30)
✅ Menú completo, context-aware real. nmap 4 modos + ffuf dir/sub con parseo y persistencia. Sniffer pasivo + telemetría. Sesiones (new/use/close/list/info) con dedup e historial. Reporte view + export txt/md/**html**. Temas en vivo. Preflight.
✅ **nmap XML** (`-oX`): `run_nmap` ahora emite XML además del texto y lo prefiere al parsear (estable entre versiones, trae producto/versión/extrainfo del servicio por separado); cae al parseo de texto si el XML falta o no parsea. Sin cambios de menú: el upgrade es transparente.
✅ **Diff** (`diff.py`, puro): compara dos conjuntos de hallazgos por clave natural (`tipo|puerto|proto|url|fuzz`, nunca el PID) → nuevos / desaparecidos / comunes, con titular al estilo del historial del IDS. El TUI muestra «Desde la corrida anterior: N nuevo(s)» tras cada scan; `diff_findings(a.findings, b.findings)` sirve también para diff entre sesiones.
✅ **Sniffer IPv6 + captura `.pcap`**: `summarize_capture` ahora parsea también líneas IPv6 de tcpdump (protocolos, hablantes y DNS AAAA); `build_sniff_cmd`/`capture` aceptan `pcap=` para grabar la captura cruda a fichero y abrirla en Wireshark. tcpdump captura v4 y v6 sin flag extra.
✅ **Informe HTML** autocontenido, tema claro/oscuro, reusando el cuidado del IDS: todo valor pasa por `html.escape` porque parte del contenido (versiones de servicio, URLs) lo escribe el objetivo escaneado.
✅ **64 tests** de recon (`tests/test_recon_*.py`) de núcleos puros + I/O simulado de `run_nmap`. Suite total de CENTINEL: **711 pasan** (1 skip).
✅ Integrado en el CLI: `--recon`. Sin tocar el pipeline async del IDS.
⚠️ Sin herramientas en el host Windows del usuario: las corridas reales degradan; probar de verdad en Kali/Linux.

## Pendiente
1. Empaquetar/autodetectar **wordlists** (SecLists).
2. Exponer en el TUI lo que ya existe en lógica pura y se verifica con ojos delante: diff entre sesiones como **comando del menú** (`diff.diff_findings`) y el prompt de `.pcap` en el flujo del sniffer (`capture(pcap=…)`).
3. Puente con el IDS: alimentar hallazgos del recon al event store como contexto.

## Seguridad
Recon para objetivos **autorizados**. El scan sigiloso (-sS) exige root y se
deshabilita si no lo hay. Sin exploits ni evasión de detección.
