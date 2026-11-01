# Arquitectura de CENTINEL

Mapa único del proyecto: cómo encajan las piezas, qué hace cada módulo y qué
convenciones se repiten en todo el repo. Para el *qué hace el producto* está el
[README](README.md); esto es el *cómo está construido*.

## Las tres caras

CENTINEL es **un solo paquete** (`centinel/`) con tres puntos de entrada que
comparten núcleo, almacenamiento y filosofía:

| Cara | Entrada | Para qué | SO |
|------|---------|----------|----|
| **IDS / daemon** | `centinel` · `python -m centinel` · `centinel/app.py` | Vigila TU host en vivo: colectores → bus → correlación → respuesta | Linux (servidor) |
| **Escritorio** | `centinel-desktop` · `python -m centinel.desktop` | Ventana tkinter que caza procesos que suplantan al sistema, con historial/diff | Windows |
| **RECON** | `python -m centinel --recon` · `python -m centinel.recon` | TUI de reconocimiento de un objetivo **autorizado** (nmap/ffuf/sniffer) | Linux/Kali |

Las tres comparten: el modelo de datos, la separación lógica-pura/IO, las 0
dependencias obligatorias y el principio de *degradar sin tumbar*.

## El pipeline del IDS

Todo el flujo del daemon gira en torno a un único tipo de evento,
`ThreatEvent` (ver [`centinel/core.py`](centinel/core.py)):

```
Colectores ─┐
            ├─► EventBus ─► Enriquecimiento ─► Correlación ─► Persistencia
Sniffer  ───┘      (async, sin deps)                │
                                                    └─► alertas ─► EventBus ─► Presentación
```

1. **Colectores** emiten `ThreatEvent` desde fuentes heterogéneas (journald,
   sniffer, honeypot, /proc, DNS…). Cada uno hereda de `Collector`
   ([`collectors/base.py`](centinel/collectors/base.py)) y es una capa
   enchufable: añadir una fuente = un archivo nuevo en `collectors/`.
2. **EventBus** (`core.py`): bus asíncrono con *backpressure*, sin dependencias.
3. **Enrichment** (`enrichment/`): IP→MAC→fabricante, rDNS, LAN/WAN, geo, KEV.
4. **Correlation** (`correlation/`): puntúa por actor en ventana deslizante,
   detecta beaconing, agrupa IPs en un mismo adversario, cruza firmas de exploit.
5. **Storage** (`storage/db.py`): event store SQLite con cadena HMAC
   tamper-evident.
6. **Presentation** (`presentation/`) y **Response** (`response/`): dashboard
   (terminal/web) y respuesta activa en firewall + webhooks.

## Convenciones transversales (valen para todo el repo)

- **Lógica pura separada del I/O.** Cada módulo parte su cerebro (parsear,
  clasificar, decidir — puro, determinista, testeable sin mocks) de sus manos
  (leer disco, lanzar subprocess, abrir sockets). Ejemplos: `recon/parse.py`
  (puro) vs `recon/scanner.py` (I/O); `build_nmap_cmd` (pura) vs `run_nmap`
  (I/O). Los tests atacan la parte pura directamente.
- **0 dependencias pip obligatorias.** `rich`, `scapy`, `fastapi`, `geoip2`,
  `yara-python` son *extras* opcionales; sin ninguno instalado el núcleo
  funciona. Las herramientas externas (nmap, ffuf, tcpdump, nft) son binarios
  vía subprocess, nunca librerías.
- **Degradar, no tumbar.** Una capa que no puede arrancar (falta una tool, un
  TOML roto, sin permisos) se desactiva con un mensaje claro; el resto sigue
  protegiendo. Un IDS que no arranca por una coma de más no protege.
- **Subprocess seguro.** Rutas absolutas, `PATH` controlado, args como lista,
  nunca `shell=True`.
- **Identidad sin PID.** Para historial/diff la identidad de un hallazgo es
  `tipo|nombre|ruta` (IDS) o `tipo|puerto|proto|url|fuzz` (recon), **nunca** el
  PID, que cambia en cada reinicio y haría que todo pareciese nuevo siempre.
- **El contenido hostil se trata como hostil.** El atacante controla parte de
  lo que se muestra (username SSH, rDNS, nombre de proceso, versión de servicio):
  todo se escapa (HTML `html.escape`, anti CSV-injection, saneado de ANSI/markup)
  antes de pintarlo.

## Referencia de módulos

### Núcleo

| Módulo | Responsabilidad |
|--------|-----------------|
| [`core.py`](centinel/core.py) | Modelo `ThreatEvent` unificado + `EventBus` asíncrono. |
| [`app.py`](centinel/app.py) | Orquestador: parsea la CLI, arranca todas las capas y conecta el pipeline. |
| [`__main__.py`](centinel/__main__.py) | `python -m centinel`; enruta a `app.main` o al modo `--recon`. |
| [`config.py`](centinel/config.py) | `centinel.toml` opcional (`tomllib`, 0 deps). Un TOML roto deja defaults + avisos, nunca tumba el arranque. |
| [`security.py`](centinel/security.py) | Drop de privilegios (`setuid`/`setgid` a `nobody`) y validación de rutas. |
| [`keyring.py`](centinel/keyring.py) | Carga/crea claves HMAC con `O_NOFOLLOW`+`O_EXCL` (anti symlink/TOCTOU). |
| [`watchdog.py`](centinel/watchdog.py) | Revive CENTINEL si un atacante lo mata, deshabilita o enmascara. |
| [`service.py`](centinel/service.py) | Instalación como servicio systemd endurecido (`--early-boot`). |
| [`doctor.py`](centinel/doctor.py) | Diagnostica (y arregla lo seguro) antes de arrancar; imprime el comando exacto para lo que no. |
| [`maintenance.py`](centinel/maintenance.py) | Ventanas de mantenimiento: distingue cambios legítimos de hostiles tras arranque. |
| [`baseline_store.py`](centinel/baseline_store.py) | Baselines persistentes y firmadas (HMAC-SHA256). |
| [`advisor.py`](centinel/advisor.py) | Remediación guiada: traduce cada amenaza a pasos concretos de arreglo. |
| [`feedback.py`](centinel/feedback.py) | Informe de lo que la app NO pudo arreglar sola, listo para pegar. |
| [`alerter.py`](centinel/alerter.py) | Empuja alertas a webhook externo (Slack/Discord/Telegram) con anti-SSRF. |
| [`digest.py`](centinel/digest.py) | Resumen periódico al webhook (lo que no cruza el umbral inmediato). |
| [`snapshots.py`](centinel/snapshots.py) | Historial de escaneos + diff «nuevo desde ayer» (JSONL firmado HMAC). |

### `collectors/` — las fuentes

| Módulo | Qué caza | Plataforma |
|--------|----------|-----------|
| [`base.py`](centinel/collectors/base.py) | Contrato base de un colector (capa pluggable). | — |
| [`journald.py`](centinel/collectors/journald.py) | Autenticación SSH/PAM con **procedencia confiable** (fuente por defecto). | Linux |
| [`authlog.py`](centinel/collectors/authlog.py) | Fallback a `auth.log`/`secure` con regex anclados. | Linux |
| [`sniffer.py`](centinel/collectors/sniffer.py) | Captura de paquetes capa 2/3 (scapy) → MAC real en LAN. | Linux |
| [`_proc_net.py`](centinel/collectors/_proc_net.py) | Lectura de `/proc/net/tcp(6)`: conexiones salientes. | Linux |
| [`netwatch.py`](centinel/collectors/netwatch.py) | Empareja proceso↔archivo↔conexión↔IP vía `/proc`. | Linux |
| [`dnswatch.py`](centinel/collectors/dnswatch.py) | Exfiltración por DNS (T1048.003). | Linux |
| [`beacon.py`](centinel/collectors/beacon.py) | Muestrea conexiones salientes → delega en `BeaconAnalyzer`. | Linux |
| [`execwatch.py`](centinel/collectors/execwatch.py) | Exec sospechoso / reverse shells por polling de `/proc` (T1059). | Linux |
| [`ebpf_exec.py`](centinel/collectors/ebpf_exec.py) | Captura de `execve` por tracepoint de kernel (sin ventana ciega). | Linux |
| [`persistence.py`](centinel/collectors/persistence.py) | Persistencia / rootkits (SUID, cron, systemd, ld.so.preload, dotfiles…). | Linux |
| [`hijackwatch.py`](centinel/collectors/hijackwatch.py) | Vectores de hijacking en host. | Linux |
| [`honeypot.py`](centinel/collectors/honeypot.py) | Puerto-trampa SSH de baja interacción (cualquier toque = malicioso). | multi |
| [`yarawatch.py`](centinel/collectors/yarawatch.py) | Escaneo de firmas YARA (cierra el hueco «sin firmas»). | multi |
| [`procwatch.py`](centinel/collectors/procwatch.py) | **Suplantación de procesos del sistema**: firma + linaje + ruta canónica. | Windows |
| [`injectwatch.py`](centinel/collectors/injectwatch.py) | Inyección de DLL / side-loading (T1055 / T1574). | Windows |
| [`winpersist.py`](centinel/collectors/winpersist.py) | Vectores de arranque (Run/RunOnce, Startup, servicios, tareas). Read-only. | Windows |
| [`hashwatch.py`](centinel/collectors/hashwatch.py) | Integridad en disco de binarios del sistema (SHA-256 + firma). | Windows |
| [`edgewatch.py`](centinel/collectors/edgewatch.py) | Anti-malware «edge» (Microsoft Edge + edge/IoT). | multi |
| [`simulator.py`](centinel/collectors/simulator.py) | Ataques sintéticos para demo/tests (`--simulate`). | — |

### `enrichment/` — contexto accionable

| Módulo | Responsabilidad |
|--------|-----------------|
| [`resolver.py`](centinel/enrichment/resolver.py) | IP/MAC → contexto: ARP, OUI→fabricante, rDNS, LAN/WAN. |
| [`geo.py`](centinel/enrichment/geo.py) | Geolocalización opcional con GeoLite2-City. |

### `correlation/` — el cerebro

| Módulo | Responsabilidad |
|--------|-----------------|
| [`engine.py`](centinel/correlation/engine.py) | Score por actor en ventana deslizante: fuerza bruta, spraying, scan, compromiso. |
| [`beacon.py`](centinel/correlation/beacon.py) | Detecta callbacks C2 por la **regularidad** temporal (baja varianza). |
| [`cluster.py`](centinel/correlation/cluster.py) | Atribución de actor: agrupa IPs distintas en un mismo adversario (Jaccard + índice invertido). |
| [`signatures.py`](centinel/correlation/signatures.py) | Firmas de exploit en logs sshd (Metasploit, masscan, CVE-2024-6387…). |
| [`ai_defense.py`](centinel/correlation/ai_defense.py) | Defensa contra ataques dirigidos por IA (low-and-slow distribuido, timing robótico, canary). |

### `intel/` — inteligencia externa

| Módulo | Responsabilidad |
|--------|-----------------|
| [`blocklist.py`](centinel/intel/blocklist.py) | Blocklist de IPs C2/botnet desde feeds gratuitos (abuse.ch). |
| [`kev.py`](centinel/intel/kev.py) | Catálogo KEV de CISA (offline-first); sube a HIGH/CRITICAL los CVE con explotación confirmada. |

### `ml/` — segunda opinión

| Módulo | Responsabilidad |
|--------|-----------------|
| [`scoring.py`](centinel/ml/scoring.py) | Regresión logística pura (sin deps) como segunda opinión al score por reglas. |

### `storage/` — persistencia y salida

| Módulo | Responsabilidad |
|--------|-----------------|
| [`db.py`](centinel/storage/db.py) | Event store SQLite con cadena HMAC encadenada (tamper-evident), parametrizado, `0600`, WAL. |
| [`report.py`](centinel/storage/report.py) | Informe forense + verificación de integridad desde la CLI (`--report`, `--verify-log`). |
| [`export.py`](centinel/storage/export.py) | Exporta un escaneo a JSON/CSV/HTML con fecha (HTML escapado, anti CSV-injection). |
| [`audit.py`](centinel/storage/audit.py) | Bitácora JSONL append-only con rotación (trazabilidad, no integridad). |

### `presentation/` — lo que ves

| Módulo | Responsabilidad |
|--------|-----------------|
| [`terminal.py`](centinel/presentation/terminal.py) | Dashboard en vivo en terminal con `rich`. |
| [`web.py`](centinel/presentation/web.py) | Dashboard SOC web (FastAPI + WebSocket + mapa geo); `/api/block` restringido a loopback. |
| [`assess.py`](centinel/presentation/assess.py) | Modo EXAMEN: cada ventana muestra lo más grave y dispara la corrección. |

### `response/` — respuesta activa

| Módulo | Responsabilidad |
|--------|-----------------|
| [`responder.py`](centinel/response/responder.py) | Decide a quién corregir por score + allowlist; dry-run por defecto. |
| [`firewall.py`](centinel/response/firewall.py) | Backend `nft`/`iptables`: bloqueo idempotente con timeout 24h; nunca corta redes privadas. |

### `desktop.py` — escritorio Windows

Ventana tkinter ligera ([`desktop.py`](centinel/desktop.py)) que orquesta
`procwatch`, `injectwatch`, `winpersist` y `hashwatch`; muestra historial/diff
(`snapshots.py`) y exporta informes (`storage/export.py`). Modo `--once`
headless: exit 0 limpio / 2 con hallazgos (apto para el Programador de tareas).

### `recon/` — reconocimiento ofensivo (objetivos autorizados)

Subpaquete autónomo con su propia TUI y almacenamiento separado. Detalle en
[RECON.md](RECON.md).

| Módulo | Responsabilidad | Pureza |
|--------|-----------------|--------|
| [`model.py`](centinel/recon/model.py) | `Finding` y `ScanResult`. | Puro |
| [`parse.py`](centinel/recon/parse.py) | `parse_nmap` / `parse_nmap_xml` / `parse_ffuf` → Findings. | Puro |
| [`scanner.py`](centinel/recon/scanner.py) | `build_*_cmd` (puras) + `run_nmap`/`run_ffuf` (I/O). nmap prefiere XML. | Mixto |
| [`telemetry.py`](centinel/recon/telemetry.py) | `build_sniff_cmd`/`capture` (tcpdump, con `.pcap`) + `summarize_capture` (v4/v6). | Mixto |
| [`diff.py`](centinel/recon/diff.py) | Diff entre dos conjuntos de hallazgos por clave natural. | Puro |
| [`report.py`](centinel/recon/report.py) | `render_txt`/`render_md`/`render_html` + export al PWD. | Mixto |
| [`session.py`](centinel/recon/session.py) | Sesiones en `results/<slug>/`; `slugify` puro; dedup. | Mixto |
| [`history.py`](centinel/recon/history.py) | `RunLog` en memoria + historial JSONL persistente. | Mixto |
| [`context.py`](centinel/recon/context.py) | Menú declarativo + `availability(item, Ctx)`: qué está activo y **por qué no**. | Puro |
| [`state.py`](centinel/recon/state.py) | `AppState`; sesión implícita `global`; construye el `Ctx`. | Mixto |
| [`config.py`](centinel/recon/config.py) | Config JSON (tema, interfaz, wordlists, última sesión). | I/O |
| [`paths.py`](centinel/recon/paths.py) | Rutas XDG / `%APPDATA%` bajo `centinel/recon`. | I/O |
| [`theme.py`](centinel/recon/theme.py) | 6 temas ANSI 256 (matrix/amber/ice/blood/violet/mono). | Puro |
| [`verify.py`](centinel/recon/verify.py) | `preflight` (puro) + `run_preflight`: tools, root, wordlists, interfaz. | Mixto |
| [`tools.py`](centinel/recon/tools.py) | Detección de herramientas externas y utilidades de privilegios. | I/O |
| [`keys.py`](centinel/recon/keys.py) | Tecla sin Enter multiplataforma (msvcrt/termios); sin TTY → modo línea. | I/O |
| [`tui.py`](centinel/recon/tui.py) | Banner + menú navegable con flechas + dispatcher. | I/O |
| [`__main__.py`](centinel/recon/__main__.py) | Habilita ANSI + UTF-8 en Windows; también lo llama `--recon`. | I/O |

## Tests

712 tests (`tests/test_*.py`, 43 ficheros), ~8 s, sin tocar sistema ni red.
Atacan la lógica pura directamente y simulan el I/O (subprocess, disco). CI en
GitHub Actions sobre Python 3.10–3.13, dos pasadas: sin extras (verifica las 0
deps) y con `[all]`. Ver [CONTRIBUTING.md](CONTRIBUTING.md).

> **Lección grabada a fuego:** los mocks de `subprocess` llegaron a ocultar que
> la verificación de firmas **nunca funcionó** en real (`powershell -Command` no
> pasa args tras `--`; `Valid` vale 0 en el enum; `text=True` decodifica cp1252).
> Probar siempre en real, no solo con mocks.
