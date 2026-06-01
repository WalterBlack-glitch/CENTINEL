# Auditoría de seguridad — Honeypot SSH de Centinela

Alcance: `centinela/collectors/honeypot.py` y su integración en `centinela/app.py`.
Modelo de amenaza: servicio de red que escucha en `0.0.0.0`, puede arrancar como root,
y procesa datos 100% controlados por el atacante. No edito código; entrego hallazgos + fix.

Resumen de severidad: 1 ALTA, 4 MEDIA, 3 BAJA, 2 INFO.

---

## [ALTA] H-1 — TOCTOU en el guard del semáforo: backlog ilimitado de handlers bajo flood

**Archivo:** `honeypot.py:81-85`

```python
if self._sem.locked():
    writer.close()
    return
async with self._sem:
```

**Riesgo.** El chequeo `self._sem.locked()` solo devuelve `True` cuando el contador
llega a 0. Pero `asyncio.start_server` **acepta cada conexión y agenda un `_handle`
nuevo sin límite** antes de que el código mire el semáforo. Entre el `if not locked`
y el `async with self._sem` hay un punto de await (el `async with` puede bloquear si
otro handler tomó el último permiso en medio): N tareas pueden pasar el guard creyendo
que hay cupo y luego quedar **encoladas esperando el semáforo**, cada una reteniendo su
`StreamReader/StreamWriter` (=un FD y buffers). Bajo un flood o slowloris, el atacante
abre miles de conexiones: el SO las acepta, se crean miles de coroutines `_handle`
vivas esperando turno, y se agotan FD/RAM **aunque `max_conns=200`**. El semáforo acota
el trabajo *concurrente*, no el número de conexiones *aceptadas y pendientes*. No existe
límite al backlog ni a conexiones por IP.

**Fix.** Limitar conexiones aceptadas (no solo concurrentes) y rechazar rápido sin
encolar. Usar `acquire()` no bloqueante y cerrar de inmediato si no hay cupo:

```python
async def _handle(self, reader, writer):
    if self._sem.locked():               # heurística rápida
        writer.close(); return
    try:
        await asyncio.wait_for(self._sem.acquire(), timeout=0.0)
    except (asyncio.TimeoutError, Exception):
        writer.close(); return           # sin cupo -> no encolar
    try:
        ...                              # cuerpo actual
    finally:
        self._sem.release()
```

Además (defensa en profundidad) acotar el backlog del listener y conexiones por IP:

```python
srv = await asyncio.start_server(self._handle, self.host, port, backlog=64)
# y un contador {ip: n_conns_activas} con tope p.ej. 10, decrementado en finally.
```

---

## [MEDIA] H-2 — Sin límite de conexiones por IP: un solo origen monopoliza el honeypot

**Archivo:** `honeypot.py:39-51, 73-100`

**Riesgo.** No hay tope de conexiones simultáneas **por IP**. Una sola IP puede ocupar
los 200 permisos del semáforo (o todo el backlog de H-1), negando el servicio al resto
de orígenes: el honeypot deja de registrar otros atacantes (pérdida de visibilidad =
evasión). El rate-limit de `_emit_hit` (`emit_cooldown`) solo limita *eventos*, no
*conexiones*: las conexiones se siguen aceptando y consumiendo recursos.

**Fix.** Contador de conexiones activas por IP y rechazo por encima de un umbral:

```python
self._per_ip: dict[str, int] = {}
...
n = self._per_ip.get(ip, 0)
if n >= self.max_per_ip:           # p.ej. 10
    writer.close(); return
self._per_ip[ip] = n + 1
try:
    ...
finally:
    self._per_ip[ip] = self._per_ip.get(ip, 1) - 1
    if self._per_ip[ip] <= 0:
        self._per_ip.pop(ip, None)
```

---

## [MEDIA] H-3 — Race de binding: el honeypot abre el socket *como root* y mantiene el FD tras el drop

**Archivo:** `app.py:113-129` + `honeypot.py:56-71`

**Riesgo.** `app.py` agenda `c.run()` de cada colector y luego espera `asyncio.sleep(0.5)`
antes de `drop_privileges()`. El binding del honeypot es asíncrono: `start_server` corre
*dentro* de la tarea `run()`. El drop depende de una **carrera temporal de 0.5 s** para
que el `bind()` (que requiere root para puertos <1024) ya haya ocurrido. Si el event loop
está cargado (flood entrante, otros colectores), el `await start_server` puede no haberse
completado al disparar el drop -> el `bind()` a `:22` falla con `EACCES` tras el drop y el
honeypot **queda sin escuchar silenciosamente** (solo imprime un warning en `honeypot.py:64`
y, si ningún puerto abrió, `return` mata el colector sin alertar). Es un fallo de
disponibilidad inducible por el propio atacante saturando el arranque.

**Fix.** No depender de un sleep. Abrir *todos* los listeners de forma determinista y
señalizar su apertura antes de soltar privilegios:

```python
# en HoneypotCollector: separar bind() de serve_forever()
async def open(self):   # llamado y AWAITED antes del drop
    self._servers = []
    for port in self.ports:
        self._servers.append(await asyncio.start_server(self._handle, self.host, port))
# en app.run(): await c.open() para todos, LUEGO drop_privileges(), LUEGO serve_forever()
```

---

## [MEDIA] H-4 — Bind a `0.0.0.0` por defecto: exposición en interfaces no deseadas

**Archivo:** `honeypot.py:39` (`host: str = "0.0.0.0"`)

**Riesgo.** El default escucha en **todas** las interfaces. En un host con interfaz de
management, VPN o red interna, el honeypot queda expuesto donde no se pretende, y como
emite eventos `Severity.HIGH` por cada conexión, cualquier scanner interno legítimo
(inventario, monitoreo) genera ruido/falsos positivos y puede usarse para envenenar el
pipeline. Combinado con que puede correr como root en puertos privilegiados, amplía la
superficie. No hay validación de que `host` sea una interfaz/IP esperada
(`valid_iface`/`safe_path` existen en `security.py` pero no se aplican aquí).

**Fix.** Default explícito y documentado, idealmente la IP de la interfaz-trampa; validar:

```python
def __init__(self, bus, ports, host: str = "0.0.0.0", ...):
    # forzar configuración consciente; rechazar si no es IP válida
    ipaddress.ip_address(host)   # ValueError si basura
# y en la doc/CLI: recomendar fijar la IP de la interfaz expuesta, no 0.0.0.0.
```

---

## [MEDIA] H-5 — `raw` persiste el banner del atacante con escapes ANSI/OSC sin sanear (hasta 1000 bytes)

**Archivo:** `honeypot.py:133` (`raw=_clean(data, 1000)`) + `honeypot.py:28,32`

**Riesgo.** `_clean` usa el regex `_CTRL = [\x00-\x08\x0b-\x1f\x7f-\x9f]`, que **deja
pasar `\x1b` (ESC, 0x1B)** porque está fuera de los rangos eliminados (el rango llega a
`\x1f` pero excluye explícitamente `\x09`/`\x0a`/... y nota que `\x1b` SÍ está en
`\x0b-\x1f`... **corrección:** `\x1b` está dentro de `\x0b-\x1f`, luego ESC sí se elimina).
El problema real: `_clean` elimina controles C0/C1 **pero no escapa markup de `rich`**.
El campo `client_banner`/`raw` derivado del atacante viaja por enrichment al store y al
dashboard. La protección anti-markup vive en `presentation/terminal.py:38`
(`_rich_escape`) y se aplica a `message`/`user`, pero hay que verificar que **todo** valor
de `enrichment` (`client_banner`, `signature`, `cve`) y `raw` pase por `_safe`/escape en
*todas* las vistas (terminal y `presentation/web.py`). Si el dashboard web inserta
`raw`/`client_banner` en HTML sin escapar, el atacante inyecta `<script>`/markup (XSS en
el panel del operador). El banner controla además los `tags` (`tags.add(sig.cve)`): un
CVE proviene de la firma (controlado), ok, pero conviene confirmar.

**Fix.** Sanear en origen para defensa en profundidad y verificar el render web:

```python
# en _clean, además de strip de C0/C1, neutralizar markup rich y < > para HTML:
def _clean(b, limit=200):
    s = _CTRL.sub("", b.decode("utf-8", "replace"))[:limit]
    return s.replace("[", "［").replace("<", "&lt;").replace(">", "&gt;")  # según vista
```

Acción concreta: auditar `presentation/web.py` para confirmar que `raw` y todo
`enrichment` se escapan con `html.escape()` antes de inyectarse en el DOM.

---

## [BAJA] H-6 — Posible ReDoS / coste CPU al cruzar el banner con `signatures.scan`

**Archivo:** `honeypot.py:120` + `correlation/signatures.py:105-118`

**Riesgo.** El banner saneado (≤200 chars por `_clean`) se concatena en una cadena y se
pasa a `signatures.scan`, que itera ~10 regex con `.search()`. El input está acotado a
200 chars, lo que limita el daño, pero `scan` recorre **todas** las firmas en cada hit y
algunas usan `.*` (p.ej. `Connection (?:from|closed by).*libssh`, `Unable to negotiate
with .* no matching`). Con 200 chars el backtracking es despreciable, pero el patrón se
ejecuta por *cada* conexión que supere el cooldown; bajo flood distribuido (muchas IPs,
cada una pasa el rate-limit por-IP) es CPU desperdiciada en el path caliente.

**Fix.** El límite de 200 chars ya mitiga ReDoS. Reforzar: anclar regex donde se pueda,
y mover `scan` fuera del path de aceptación si el volumen crece (cola/batch). Confirmar
que `_clean(data)` (200) es lo que va a `scan`, no `raw` (1000) — actualmente sí usa el
de 200, correcto.

---

## [BAJA] H-7 — `_handle` no captura excepciones genéricas: una no prevista puede escalar

**Archivo:** `honeypot.py:87-100`

**Riesgo.** El `try/except` solo atrapa `(asyncio.TimeoutError, OSError, ConnectionError)`.
`reader.read()`/`writer.drain()` pueden lanzar otras (p.ej. `MemoryError`,
`asyncio.LimitOverrunError`, errores de decodificación no esperados aguas abajo en
`_emit_hit`/`signatures.scan`). Una excepción no capturada en `_handle` la registra el
loop como "Task exception was never retrieved" pero **deja el `StreamWriter` sin cerrar**
(el `finally` cierra el writer solo en el bloque interno; si `_emit_hit` en la línea 100
lanza, queda fuera de cualquier try) -> **fuga de FD**. La tarea muere pero
`serve_forever` sigue; aun así es una fuga inducible.

**Fix.** Envolver todo el cuerpo de `_handle` y garantizar cierre del writer:

```python
async def _handle(self, reader, writer):
    try:
        ... # cuerpo completo, incluyendo _emit_hit
    except Exception:
        pass
    finally:
        if not writer.is_closing():
            writer.close()
```

---

## [BAJA] H-8 — `serve_forever()` agrupado en un solo `gather`: un fallo tumba todos los listeners

**Archivo:** `honeypot.py:67-71`

**Riesgo.** `await asyncio.gather(*(s.serve_forever() for s in servers))` sin
`return_exceptions=True`: si **uno** de los `serve_forever` lanza (error de socket en un
puerto), `gather` propaga y el `finally` cierra **todos** los servidores -> se pierde la
visibilidad de todos los puertos-trampa, no solo del que falló. Auto-DoS parcial del
colector.

**Fix.**

```python
await asyncio.gather(*(s.serve_forever() for s in servers),
                     return_exceptions=True)
```

(y loguear las excepciones individuales para no enmascarar fallos).

---

## [INFO] H-9 — El banner fijo filtra una versión de SO concreta (huella estática)

**Archivo:** `honeypot.py:29`

`_DEFAULT_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"`. Es un banner
honeypot deliberado, no filtra el host real, lo cual es correcto. Riesgo menor: es
**estático y reconocible**; herramientas de fingerprinting de honeypots pueden marcarlo
si la versión no concuerda con el comportamiento (no completa el handshake). No es
vulnerabilidad, es detectabilidad. Sugerencia: banner configurable/rotativo por puerto.

---

## [INFO] H-10 — No hay riesgo de amplificador/reflector ni SSRF/conexiones salientes

**Archivo:** `honeypot.py` (global)

Confirmado positivo: el honeypot **solo escribe un banner fijo y cierra**; la respuesta
(≤41 bytes) es menor que cualquier request, así que **no sirve como amplificador UDP/TCP**.
No realiza conexiones salientes, ni resuelve nombres, ni reenvía el input a ningún
destino controlable por el atacante -> **sin SSRF ni pivot**. El banner no incluye datos
del host. Buen diseño en este eje. (La resolución rDNS ocurre en el *enricher*, fuera de
este archivo; no la dispara directamente el honeypot con datos del atacante salvo la IP
de origen, que es legítima.)

---

## Apéndice — priorización

| ID  | Sev   | Eje                         | Acción mínima                                  |
|-----|-------|-----------------------------|------------------------------------------------|
| H-1 | ALTA  | Agotamiento (TOCTOU sem)    | `acquire()` no bloqueante + `backlog` + tope IP|
| H-2 | MEDIA | Agotamiento (per-IP)        | contador conexiones/IP                          |
| H-3 | MEDIA | Privilegios (race binding)  | `open()` awaited antes del drop                 |
| H-4 | MEDIA | Exposición de red           | no `0.0.0.0` por defecto; validar host          |
| H-5 | MEDIA | Inyección dashboard         | escapar `raw`/`enrichment` en vista web         |
| H-6 | BAJA  | CPU/ReDoS                   | mantener tope 200; anclar regex                 |
| H-7 | BAJA  | asyncio (fuga FD)           | `except Exception` + cierre garantizado         |
| H-8 | BAJA  | asyncio (resiliencia)       | `return_exceptions=True`                        |
