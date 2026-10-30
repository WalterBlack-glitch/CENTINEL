# CENTINEL — Pulido profesional + estrategia frente a la IA

Estado: app de escritorio tkinter (0 deps) + `procwatch` (detección de suplantación de procesos de Windows) + resumen de RAM. Este doc es la fuente de verdad de hacia dónde llevarlo.

---

## 1. Pulido / profesionalización (por impacto, no por dificultad)

### Detección — subir la calidad de veredicto (lo que más vale)
1. ✅ **Verificación de firma Authenticode.** [HECHO] `procwatch` firma los candidatos vía `Get-AuthenticodeSignature`; binario del sistema sin firma válida de Microsoft = CRITICAL.
2. ✅ **Linaje de proceso (parent PID).** [HECHO 2026-08-15] Mapa `PARENT_LINEAGE`: `svchost`⟵`services`, `lsass`/`services`⟵`wininit`, `fontdrvhost`⟵`wininit`/`winlogon`. Padre conocido distinto = CRITICAL. Se omiten smss/csrss/winlogon (su padre smss ya salió → padre vacío, evita falsos positivos).
3. ✅ **Ruta canónica esperada.** [HECHO 2026-08-15] `_in_canonical_dir`: binario del sistema MS-firmado pero fuera de `System32`/`SysWOW64` (o `explorer` fuera de la raíz) = HIGH. Allowlist `_CANONICAL_CHECKED` excluye hosts UWP en SystemApps.
4. ✅ **Hash + allowlist con baseline.** [HECHO 2026-10-08] `hashwatch`: SHA-256 de los binarios de sistema que `procwatch` vigila + `explorer.exe`, con la línea base firmada en `BaselineStore`. La regla que lo hace usable es cruzar hash **y** firma: cambió y sigue MS-firmado válido = LOW «probable actualización»; cambió y la firma ya no vale = CRITICAL (reemplazo en disco). También avisa de binarios nuevos sin firma de confianza (MEDIUM) y de los que desaparecen (MEDIUM). Primera pasada = fija base sin alertar. Desactivado por defecto (`watch_hashes`), porque hashear cuesta. 48 tests.
5. ✅ **Persistencia (Windows).** [HECHO 2026-10-08] `winpersist`: lectura (nunca escritura) de `Run`/`RunOnce` de HKLM y HKCU, carpetas Startup, los 300+ servicios y las tareas programadas. Lo que delata no es estar ahí, sino **dónde vive el binario** y **cómo se invoca**: patrones *fuertes* de living-off-the-land (`-enc`, `iex`, `certutil -urlcache`, `mshta http…`, squiblydoo, pipe a intérprete) deciden solos = CRITICAL; los *débiles* (ventana oculta, `-nop`) solo acompañan, y en tareas programadas ni cuentan porque ahí es lo normal. Distingue «no firmado» de «no se pudo verificar» y no exige firma a un `.lnk` o un `.cmd`, que no se pueden firmar. Medido en esta máquina: de 13 avisos ruidosos a 3 reales. 94 tests.
   **Límite conocido:** no cubre los vectores exóticos (suscripciones WMI, COM hijacking, IFEO, AppInit_DLLs); están documentados, no silenciados.
4b. ✅ **Inyección de DLL / side-loading (Windows).** [HECHO 2026-09-01] `injectwatch` (compañero Windows de `hijackwatch`): mira las DLLs cargadas por cada proceso accesible. Dos huellas "invisibles" (no dejan .exe sospechoso): (a) DLL de sistema (`ntdll`, `version`, `kernel32`…) cargada FUERA de System32/SysWOW64/WinSxS = search-order hijacking (T1574.001/002) → CRITICAL; (b) DLL sin firma de confianza desde carpeta escribible = reflective/inyección desde disco → HIGH, y CRITICAL si el anfitrión está firmado por editor de confianza. Clasificador puro `classify_modules` + I/O PowerShell (`enumerate_module_candidates`, firma solo candidatos). Integrado en la ventana `desktop.py`. Respeta `CENTINEL_PROCWATCH_ALLOW`. 8 tests. **Límite honesto:** los procesos protegidos (lsass, PPL) no exponen su lista de módulos sin driver de kernel; ese flanco lo cubre procwatch por padre anómalo.

### Producto — que se sienta terminado
6. **Icono en bandeja + escaneo en segundo plano** con notificación toast si aparece algo CRITICAL (en vez de tener la ventana abierta).
7. ✅ **Exportar informe.** [HECHO 2026-10-08] `storage/export`: JSON (fiel, no pierde nada), CSV y HTML autocontenido con tema claro/oscuro, nombre con fecha (`centinel-2026-10-08_223319.html`). Dos cuidados que un informe de seguridad necesita porque su contenido lo escribe en parte el atacante: todo valor pasa por `html.escape` (un proceso llamado `<img onerror=…>` convertiría el informe en el segundo vector del ataque) y los campos que empiezan por `=`/`+`/`-`/`@` se neutralizan contra *CSV injection* en Excel. 46 tests.
8. ✅ **Historial / diff entre escaneos.** [HECHO 2026-10-08] `snapshots`: cada escaneo deja un retrato y se compara con el anterior → nuevos / agravados / resueltos / sin cambio, con la frase de cabecera («Desde el escaneo anterior: 1 nuevo [CRITICAL]»). El historial es **JSONL firmado con HMAC**: si fuera editable, un atacante podría colar su implante en el retrato de ayer para que hoy saliera como «ya conocido» y se perdiera entre el ruido. La identidad de un hallazgo es `tipo|nombre|ruta`, **nunca el PID**, que cambia en cada reinicio y haría que todo pareciese nuevo siempre. 48 tests.
9. **Empaquetado**: `.exe` con PyInstaller (que arranque sin Python instalado) y, a futuro, firma de código propia para no auto-alertar.
10. ✅ **Config.** [HECHO 2026-10-08] `centinel.toml` opcional (`tomllib`, 0 deps) con umbral de severidad, allowlist, qué capas activar, retención del historial, formato de informe e intervalo de auto-escaneo. Se busca en la ruta pedida, `CENTINEL_CONFIG`, el directorio actual y `%APPDATA%`/XDG. **La configuración nunca tumba el programa**: un TOML roto o un valor imposible deja los valores por defecto y una lista de avisos — un IDS que no arranca por una coma de más es un IDS que no te protege. `CENTINEL_PROCWATCH_ALLOW` se suma, no se pierde. `--write-config` deja un ejemplo comentado. 44 tests.

### Ingeniería
11. ✅ **CI** (GitHub Actions): tests en Python 3.10–3.13 + `compileall` + pasada con todos los extras.
12. **Cobertura de tests** para las nuevas reglas (firma/linaje/ruta) manteniendo el patrón clasificador-puro / I-O-separado.
13. ✅ **Logging estructurado.** [HECHO 2026-10-08] `storage/audit`: bitácora JSONL append-only (`%LOCALAPPDATA%\CENTINEL\audit.jsonl`) con una línea por hallazgo y una por escaneo, rotación por tamaño y degradado silencioso si no se puede escribir. Honestidad de capas: esto es trazabilidad legible con `grep`/jq, **no** integridad verificable — para eso están la cadena HMAC del event store y el historial firmado. 29 tests.

---

## 2. La IA como amenaza — y a nuestro favor

### Contra qué defiende CENTINEL en la era IA
- **Malware polimórfico generado por IA**: cambia de hash en cada build → las firmas hash tradicionales fallan. Nuestra ventaja: detectamos **comportamiento y contexto** (nombre que suplanta + sin firma + padre raro + ruta anómala), no un hash concreto. Ese enfoque envejece bien frente a IA.
- **Malware que se hace pasar por procesos del sistema** para esconderse a la vista: es exactamente el núcleo de `procwatch`. La firma + linaje + ruta lo hacen robusto aunque el binario esté generado por un LLM.
- **Living-off-the-land**: binarios legítimos (powershell, mshta, rundll32) usados con intención maliciosa. Futuro: reglas sobre líneas de comando sospechosas.

### La IA a nuestro favor (clave: **local y opcional**, fiel al 0-deps / privacidad)
1. **Explicador de hallazgos con LLM local (Ollama).** Botón "explicar" que traduce un evento técnico a lenguaje claro: "este proceso dice ser svchost pero corre desde tu carpeta de Descargas y no está firmado — típico de un troyano". Todo offline, sin mandar tus procesos a ninguna nube. Módulo enchufable; si no hay Ollama, CENTINEL funciona igual.
2. **Triaje / reducción de falsos positivos.** El LLM prioriza y agrupa: "3 de estas 5 alertas son la misma app portable legítima; céntrate en la primera".
3. **Consulta en lenguaje natural** sobre los eventos: "¿qué proceso nuevo apareció y toca la red?" en vez de leer tablas.
4. **Sugerencia de reglas.** A partir de un binario sospechoso, el LLM propone una regla YARA-like o un patrón de línea de comando que luego un humano revisa antes de activar (nunca auto-aplicar).

### Principio rector
La IA **asiste y explica**, nunca **decide sola** ni **auto-actúa**. Todo lo que la IA sugiere (reglas, veredictos) pasa por revisión. Y siempre local: la privacidad del usuario es parte del producto, no un extra.

---

## Orden recomendado
Firma Authenticode (#1) → linaje (#2) → ruta canónica (#3) → historial/diff (#8) → explicador LLM local opcional (IA #1). Cada uno es un incremento con tests y sin romper la filosofía 0-deps.

---

## Estado a 2026-10-08

**Hecho:** #1, #2, #3, #4, #4b, #5, #7, #8, #10, #11, #12, #13. Suite: **686 tests**
(333 antes de esta tanda), 8 s, sin tocar el sistema ni la red.

**Pendiente, por orden de valor:**
- **#6 Bandeja + escaneo en segundo plano con toast.** El config ya trae
  `auto_seconds` y la ventana ya reescanea sola; falta el icono en la bandeja y
  la notificación nativa. No se hizo aquí porque no hay forma de verificarlo sin
  ojos humanos delante.
- **IA #1 Explicador con LLM local (Ollama).** Los `reasons` de cada evento ya
  son el material de entrada; el módulo enchufable sigue sin escribir.
- **#9 Empaquetado `.exe` con PyInstaller.** Requiere ejecutar el empaquetador y
  probar el binario a mano.
- **Vectores de persistencia exóticos** (WMI, COM hijacking, IFEO, AppInit_DLLs),
  el límite conocido de #5.
- **Living-off-the-land en procesos vivos**: `winpersist` ya tiene los patrones
  de línea de comando; aplicarlos a procesos en ejecución (no solo a arranques)
  es la extensión natural.
