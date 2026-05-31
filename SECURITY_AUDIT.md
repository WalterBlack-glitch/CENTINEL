# Auditoría de Seguridad — Centinela

Herramienta defensiva de detección de intrusiones. Corre como **root** en Linux, parsea `auth.log` no confiable, captura paquetes con scapy, ejecuta `subprocess` y escribe en SQLite. El modelo de amenaza clave: **un atacante remoto controla parcialmente el contenido de `auth.log`** (vía su username SSH, rDNS, etc.) y puede generar millones de eventos. Todo input que llega del atacante debe tratarse como hostil.

Hallazgos ordenados por severidad.

---

## CRÍTICA

### C-1. DoS de memoria: el dict de actores nunca se purga
**Archivo:** `centinela/correlation/engine.py:47, 56`

`CorrelationEngine.actors` crece sin límite: `self.actors.setdefault(ev.src_ip, ...)` crea una entrada por cada IP de origen y **jamás se elimina**, ni siquiera cuando un actor lleva horas inactivo. `Actor.prune()` vacía las deques/dicts internos pero la entrada del actor permanece. Un atacante que rota IPs (botnet, IP spoofing en SYN floods del sniffer, o líneas falsas inyectadas en auth.log — ver C-2) crea entradas ilimitadas hasta agotar la RAM y matar el proceso (auto-DoS de la herramienta defensiva). Cada `Actor` retiene además sets/deques. Con scapy capturando SYN con IP de origen falsificable, el agotamiento es trivial.

**FIX:** purgar actores inactivos y poner un tope duro al número de actores.
```python
MAX_ACTORS = 50_000

async def process(self, ev: ThreatEvent) -> ThreatEvent:
    if not ev.src_ip:
        return ev
    now = ev.ts
    self._evict(now)
    actor = self.actors.get(ev.src_ip)
    if actor is None:
        if len(self.actors) >= MAX_ACTORS:
            self._evict(now, force=True)   # bota el más viejo
            if len(self.actors) >= MAX_ACTORS:
                return ev                  # backpressure: descarta
        actor = self.actors[ev.src_ip] = Actor(ip=ev.src_ip)
    actor.last_seen = now
    ...

def _evict(self, now: float, force: bool = False) -> None:
    # elimina actores sin actividad en > WINDOW*2 y score 0
    dead = [ip for ip, a in self.actors.items()
            if now - getattr(a, "last_seen", 0) > WINDOW * 2 and a.score == 0]
    for ip in dead:
        del self.actors[ip]
    if force and self.actors:
        oldest = min(self.actors, key=lambda ip: getattr(self.actors[ip], "last_seen", 0))
        del self.actors[oldest]
```
Añade `last_seen: float = 0.0` al dataclass `Actor`.

### C-2. Inyección / spoofing de logs vía username SSH (IP y usuario falsificables)
**Archivo:** `centinela/collectors/authlog.py:16-26, 56-81`

Los regex **buscan el patrón en cualquier parte de la línea** (`.search`, no anclado con `^`/`$`). Un atacante controla su propio nombre de usuario SSH, que sshd escribe literalmente en `auth.log`. Conectándose con un username como:

```
ssh 'pwn from 1.2.3.4 port 22 ; Failed password for root from 9.9.9.9 port 22'@victima
```

sshd registra una línea de `Invalid user` que contiene esa subcadena. Como `_FAILED.search()` no está anclado, **el atacante inyecta IPs y usuarios arbitrarios** en el pipeline: puede atribuir ataques a IPs inocentes (envenenar la correlación / forense), falsificar un `login_success` (no, ese viene de Accepted, pero sí `Failed`/`Invalid`), o disparar alertas contra terceros. También puede inflar `actors` (alimenta C-1). El campo `user=\S+` permite que el username absorba tokens hasta el primer espacio, pero combinando varias líneas/saltos el atacante moldea el resto.

**FIX:** anclar los patrones al formato real de la línea de syslog (prefijo `sshd[pid]:` + mensaje) y validar que la IP extraída es la que sshd reporta, no una incrustada en el username. Anclar el final del mensaje y rechazar usernames con caracteres no shell-safe.
```python
# Exigir el prefijo de proceso sshd y anclar el mensaje completo.
_PREFIX = r"sshd\[\d+\]:\s"
_USER = r"(?P<user>[A-Za-z0-9._@-]{1,64})"   # whitelist, longitud acotada
_IP   = r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
_FAILED = re.compile(
    rf"{_PREFIX}Failed password for (?:invalid user )?{_USER} "
    rf"from {_IP} port (?P<port>\d{{1,5}})\s*$")
```
Además, validar la IP con `ipaddress.ip_address()` tras el match y descartar octetos > 255 (el regex actual acepta `999.999.999.999`). El username **nunca** debe poder contener espacios; con la whitelist `[A-Za-z0-9._@-]` la inyección de ` from <ip> port ` se vuelve imposible. Idealmente, leer de **journald** (`sd_journal`) que entrega campos estructurados en vez de texto.

---

## ALTA

### A-1. ReDoS — y backtracking + ancla faltante amplifican el coste por línea
**Archivo:** `centinela/collectors/authlog.py:16-26`

Los patrones se aplican con `.search()` (no anclado) a líneas controladas por el atacante. Aunque los regex actuales no son catastróficos clásicos (no hay anidamiento `(a+)+`), la combinación `\S+` para `user` + `.search()` sin ancla obliga al motor a reintentar el match desde **cada posición** de una línea larga. Un atacante puede mandar un username de decenas de KB (sshd no limita agresivamente) sin que haya `from <ip> port`, forzando que los tres regex recorran toda la línea repetidamente. Con `_INVALID` aplicado a líneas largas, el coste es O(n) por regex × 3 regex × millones de líneas = degradación seria del pipeline (el `readline` corre en executor, pero el parse satura el thread y la cola).

**FIX:** (1) acotar la longitud de línea antes de parsear; (2) anclar los patrones (ver C-2), lo que ancla el motor y elimina el reintento posicional.
```python
_MAX_LINE = 4096
def _parse(self, line: str) -> ThreatEvent | None:
    if len(line) > _MAX_LINE:
        line = line[:_MAX_LINE]
    ...
```
Y compilar con patrones anclados (`^...sshd\[\d+\]:`) como en C-2. Considera `re2`/`regex` con timeout si se quiere defensa en profundidad.

### A-2. No hay drop de privilegios — todo el pipeline corre como root
**Archivo:** `centinela/app.py:25-69`; `centinela/collectors/sniffer.py:44`

La herramienta necesita root **solo** para abrir el socket de captura (scapy) y leer `auth.log`. Sin embargo, el proceso completo —parser de input hostil, motor de correlación, escritura SQLite, render con rich, resolución DNS— sigue como root indefinidamente. Cualquier RCE o memory-corruption en scapy/parser se ejecuta con privilegios totales. No se hace `setuid`/`setgid` ni se usan capabilities.

**FIX:** abrir los recursos privilegiados al inicio y soltar privilegios a un usuario sin privilegios (o usar capabilities en vez de root). Patrón:
```python
import os, pwd, grp
def drop_privileges(user: str = "nobody", group: str = "nogroup") -> None:
    if os.getuid() != 0:
        return
    pw, gr = pwd.getpwnam(user), grp.getgrnam(group)
    os.setgroups([])
    os.setgid(gr.gr_gid)
    os.setuid(pw.pw_uid)
    os.umask(0o077)
```
Mejor aún, en producción no correr como root: otorgar `cap_net_raw,cap_net_admin` al binario/python (`setcap`) y abrir `auth.log` por grupo `adm`. Llamar `drop_privileges()` **después** de `AsyncSniffer.start()` y de abrir el fd de auth.log, antes de procesar el primer paquete/línea.

### A-3. Inyección de secuencias de escape ANSI en el dashboard
**Archivo:** `centinela/presentation/terminal.py:66-93, 96-106`; alimentado por `enrichment/resolver.py:115` (rDNS) y username de `authlog.py`

`username`, `rDNS` (`socket.gethostbyaddr` devuelve un PTR **controlado por el atacante** que opera el DNS reverso de su IP) y `vendor` se renderizan en la terminal. En el fallback de **texto plano** (`_run_plain`, líneas 96-106) se hace `print()` directo del `ev.message`/`origin` **sin sanitizar**: un PTR o username con bytes `\x1b[...` inyecta secuencias de escape ANSI → puede mover el cursor, borrar pantalla, falsificar otras líneas del log, o (en terminales vulnerables) abusar de secuencias de título/OSC. Con `rich`, `Table.add_row` interpreta además **markup** `[...]`: un username como `[red]FAKE[/]` o `[link=file:///etc/passwd]` se interpreta como markup de rich. El message ya incluye el user sin escapar (`authlog.py:62`).

**FIX:** sanitizar todo string derivado del atacante antes de imprimir/renderizar.
```python
import re as _re
_CTRL = _re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
def _safe(s: str | None) -> str:
    if not s:
        return "—"
    return _CTRL.sub("", str(s))[:200]
```
- En `_run_plain`: aplicar `_safe()` a `origin` y `ev.message`.
- Con rich: pasar los valores por `rich.markup.escape()` (o `Text(..., style=...)` que no interpreta markup) para `ip`, `mac`, `vendor`, `rdns`, `kind`, `message`, `user`. Ej.: `t.add_row(Text(_safe(a.ip)), ...)`.

---

## MEDIA

### M-1. Caches de rDNS y ARP sin límite de tamaño
**Archivo:** `centinela/enrichment/resolver.py:33, 118`

`self._rdns_cache` crece sin cota: una entrada por cada IP distinta vista (incluye IPs spoofeadas inyectadas vía C-2 o SYN floods). No hay expiración ni `maxsize`. Junto con C-1 da un segundo vector de agotamiento de RAM. El `_arp_cache` se **reemplaza** por completo en cada refresh (acotado a las entradas reales de `ip neigh`), así que ese está OK, pero `_rdns_cache`/`_rdns_pending` no.

**FIX:** usar una cache LRU acotada con TTL.
```python
from collections import OrderedDict
_RDNS_MAX = 10_000
# en __init__:
self._rdns_cache: OrderedDict[str, tuple[str | None, float]] = OrderedDict()

def _cache_put(self, ip, name):
    self._rdns_cache[ip] = (name, time.time())
    self._rdns_cache.move_to_end(ip)
    while len(self._rdns_cache) > _RDNS_MAX:
        self._rdns_cache.popitem(last=False)
```
Aplicar TTL al leer y limpiar `_rdns_pending` siempre (incluso si la task muere).

### M-2. `asyncio.create_task` sin retener referencia (rDNS) — tasks recolectadas
**Archivo:** `centinela/enrichment/resolver.py:102`

`asyncio.create_task(self._rdns(ip))` no guarda la referencia al `Task`. El GC de Python puede recolectar la task antes de que termine (el event loop solo guarda `weakref`), provocando que la resolución se cancele silenciosamente y, peor, que `_rdns_pending` quede con la IP marcada para siempre (línea 101 la añade, pero la línea 119 que la quita puede no ejecutarse si la task muere), bloqueando futuras resoluciones de esa IP. También oculta excepciones.

**FIX:** retener las tasks y limpiar en el callback.
```python
# en __init__:
self._tasks: set[asyncio.Task] = set()

def _schedule_rdns(self, ip: str) -> None:
    if ip in self._rdns_pending:
        return
    self._rdns_pending.add(ip)
    t = asyncio.create_task(self._rdns(ip))
    self._tasks.add(t)
    t.add_done_callback(lambda fut: (self._tasks.discard(fut),
                                     self._rdns_pending.discard(ip)))
```
Quitar el `discard` de `_rdns_pending` de dentro de `_rdns` o dejarlo en `finally`.

### M-3. PATH hijacking en subprocess (`ip neigh`, `arp -an`)
**Archivo:** `centinela/enrichment/resolver.py:76-82`

`subprocess.run(["ip", "neigh"], ...)` resuelve `ip` y `arp` vía `$PATH`. Como el proceso corre **como root**, si `$PATH` está envenenado (heredado de un entorno comprometido, o un directorio escribible por no-root antes que `/usr/sbin`) se ejecuta un binario atacante con privilegios root cada 10 s. No hay inyección de comandos clásica (no usa `shell=True`, los args son lista fija — eso está bien), pero el PATH hijacking sí aplica.

**FIX:** usar rutas absolutas y un entorno mínimo controlado.
```python
import shutil
_IP_BIN = "/usr/sbin/ip" if os.path.exists("/usr/sbin/ip") else (shutil.which("ip") or "ip")
_ARP_BIN = "/usr/sbin/arp"
subprocess.run([_IP_BIN, "neigh"], capture_output=True, text=True, timeout=2,
               env={"PATH": "/usr/sbin:/sbin:/usr/bin:/bin", "LC_ALL": "C"})
```
Resolver las rutas absolutas una vez al arranque (antes de drop de privilegios).

### M-4. Validación de paths: `--oui`, `--authlog-path`, `--db` (path traversal / lectura arbitraria)
**Archivo:** `centinela/app.py:37, 72-84, 90, 98, 101`

`--authlog-path`, `--oui` y `--db` se usan tal cual. Aunque son flags del operador (no del atacante remoto directamente), corren como root y abren/leen/escriben rutas arbitrarias sin validación. `_load_oui` abre cualquier path. `EventStore` crea la DB en cualquier ruta. Si Centinela se lanza desde un wrapper/servicio que pasa argumentos desde una fuente menos confiable (config, entorno multiusuario), hay lectura/escritura arbitraria como root. Riesgo menor pero conviene endurecer.

**FIX:** validar/normalizar y, si aplica, restringir a un directorio base.
```python
from pathlib import Path
def _safe_path(p: str, *, must_exist=False, base: str | None = None) -> Path:
    rp = Path(p).resolve()
    if base and not str(rp).startswith(str(Path(base).resolve()) + os.sep):
        raise SystemExit(f"ruta fuera de {base}: {p}")
    if must_exist and not rp.is_file():
        raise SystemExit(f"no existe: {p}")
    return rp
```
Aplicar a `--authlog-path` (`must_exist=True`) y `--oui`. Para `--iface` (sniffer): validar contra la lista real de interfaces (`scapy.all.get_if_list()` o `/sys/class/net`) antes de pasarla a `AsyncSniffer`, en vez de aceptar cualquier string.

### M-5. SQLite: sin parametrización dinámica peligrosa, pero `commit` por inserción y sin `top_actors` cota razonable
**Archivo:** `centinela/storage/db.py:52-71`

**No hay SQL injection**: todos los valores van por placeholders `?` (incluido `LIMIT ?`), correcto. Sin embargo: (1) `check_same_thread=False` + escrituras desde el executor sin el `asyncio.Lock` cubriendo la lectura `top_actors` (que corre en el thread del loop) puede producir lecturas concurrentes con escrituras del executor; sqlite lo tolera en modo serializado por defecto, pero conviene WAL. (2) `commit()` por cada inserción bajo flood de eventos (C-1/C-2) genera presión de I/O = vector de DoS de disco. (3) la DB se crea con permisos por defecto (legible por otros si umask lo permite) conteniendo IPs/usuarios/logs sensibles.

**FIX:** lote/transacción y endurecer.
```python
self._conn.execute("PRAGMA journal_mode=WAL")
self._conn.execute("PRAGMA synchronous=NORMAL")
os.umask(0o077)  # antes de connect, para que el archivo .db no sea world-readable
# Agrupar commits: acumular N inserts o flush cada T segundos en vez de commit por evento.
```
Confirmar `top_actors`/`save` ambos dentro del mismo lock o usar una conexión por hilo.

---

## BAJA

### B-1. Regex de IP acepta octetos inválidos (`999.999.999.999`)
**Archivo:** `centinela/collectors/authlog.py:18,21,25`; `enrichment/resolver.py:24`

`\d{1,3}` acepta `999`, permitiendo IPs sintácticamente inválidas que luego se almacenan/correlacionan como actores reales (ayuda al spoofing de C-2). 

**FIX:** validar tras el match con `ipaddress.ip_address(m["ip"])` y descartar el evento si lanza `ValueError` (el `_classify_ip` ya lo intenta pero no descarta el evento, solo no lo clasifica).

### B-2. `_tail` no maneja truncamiento (no-rotación) ni límite de reapertura
**Archivo:** `centinela/collectors/authlog.py:83-105`

Solo detecta rotación por cambio de inode; si el log se trunca en sitio (mismo inode, tamaño menor) el offset queda más allá del EOF y se pierden eventos silenciosamente — un atacante podría truncar el log (si tiene acceso) para evadir detección. Riesgo bajo (requiere acceso local de escritura al log).

**FIX:** comparar `os.stat(path).st_size` con la posición actual; si el archivo encogió, `f.seek(0)`.

### B-3. Bus descarta eventos silenciosamente bajo presión
**Archivo:** `centinela/core.py:62-72`

Bajo flood, `publish` descarta el evento más viejo de cada cola sin contador ni alerta. Un atacante que genere ruido puede empujar fuera de la ventana los eventos de su ataque real (evasión por saturación). 

**FIX:** incrementar una métrica `dropped` y, si supera un umbral, emitir un meta-evento de "pérdida de visibilidad" (señal de posible evasión).

### B-4. `_detect_path` / `available` TOCTOU menor
**Archivo:** `centinela/collectors/authlog.py:38-46`

`os.path.exists` seguido de `open` más tarde: ventana TOCTOU para symlink swap del log. Como corre como root, un symlink colocado por un local hacia un archivo sensible podría hacer que Centinela lo lea/tail. Riesgo bajo (requiere control del directorio del log).

**FIX:** abrir con `os.open(path, os.O_RDONLY | os.O_NOFOLLOW)` para los componentes finales, o validar que el path es un archivo regular y no symlink antes de abrir.

---

## Resumen de prioridades

| # | Sev | Archivo | Riesgo |
|---|-----|---------|--------|
| C-1 | CRÍTICA | correlation/engine.py:47 | Agotamiento de RAM (actores sin purga) |
| C-2 | CRÍTICA | collectors/authlog.py:16 | Inyección/spoofing de IP y usuario en logs |
| A-1 | ALTA | collectors/authlog.py:16 | ReDoS/coste O(n) por línea hostil sin ancla |
| A-2 | ALTA | app.py / sniffer.py | Sin drop de privilegios (todo como root) |
| A-3 | ALTA | presentation/terminal.py | Inyección de escapes ANSI/markup vía rDNS/user |
| M-1 | MEDIA | enrichment/resolver.py:33 | Cache rDNS sin límite (DoS RAM) |
| M-2 | MEDIA | enrichment/resolver.py:102 | create_task sin referencia (tasks perdidas) |
| M-3 | MEDIA | enrichment/resolver.py:76 | PATH hijacking en subprocess como root |
| M-4 | MEDIA | app.py:37,72 | Sin validación de --oui/--authlog/--iface/--db |
| M-5 | MEDIA | storage/db.py:52 | commit por evento + permisos DB + WAL |
| B-1..B-4 | BAJA | varios | IP inválida, truncado de log, drop silencioso, TOCTOU |

**Acción inmediata recomendada:** C-1 y C-2 (la herramienta defensiva se auto-DoSea y su forense es falsificable por cualquier atacante SSH remoto), seguidas de A-2 (radio de impacto de cualquier otra vuln, dado que corre como root).
