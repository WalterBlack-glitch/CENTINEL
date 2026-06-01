# Auditoría de seguridad — Defensas anti-IA de Centinel

Alcance: `centinel/correlation/ai_defense.py` (CampaignTracker, timing_cv) y la
integración en `centinel/correlation/engine.py` (`_ai_defenses`, `_score`, dataclass `Actor`).
Modelo de amenaza: IDS corriendo como root; el atacante controla su username SSH y rota IPs.

Hallazgos ordenados por severidad.

---

## [CRÍTICO] Envenenamiento de correlación: el atacante atribuye "campañas" a IPs de terceros

**Archivo:** `engine.py:150-158`, `ai_defense.py:81-96`

**Riesgo.** `observe()` agrupa por `user` controlado por el atacante. El atacante puede
fijar un mismo username (p.ej. `root`) y enviar intentos *desde su botnet rotando IPs*.
Esto es el caso de uso legítimo. Pero también puede **falsificar el campo `src_ip`** si
la fuente del evento no es de confianza (logs que el atacante puede inducir, X-Forwarded-For,
spoofing de logs syslog remotos), y entonces las `sample_ips` de la alerta de campaña
contienen IPs de víctimas inocentes. Si aguas abajo existe respuesta activa (firewall) que
consuma `sample_ips` o `src_ip` de `alert_*`, el atacante dirige bloqueos contra terceros
(reflected blocklisting / auto-DoS de terceros).

Incluso sin spoofing de IP: el atacante puede **inflar el contador `by_user` de un usuario
real** (p.ej. el admin) hasta `DISTINCT_IPS_PER_USER` usando su propia botnet, generando una
alerta de "credential stuffing" perpetua contra ese username y ahogando al operador en ruido
(degradación de la señal).

**Fix.** Nunca derivar acción de bloqueo de las `sample_ips` de una alerta de correlación;
tratar la correlación como señal de *priorización*, no de *respuesta*. Validar que `src_ip`
provenga de una fuente de confianza (kernel/conntrack), no de un campo de log parseado.
Marcar el origen:

```python
# engine.py _ai_defenses, al publicar:
enrichment={"sample_ips": c["sample_ips"], "ip_trust": ev.ip_trust},
# y en la capa de respuesta activa: bloquear SOLO si ip_trust == "kernel"
```

---

## [ALTO] DoS de memoria/ceguera: `by_user` se satura con usernames basura y nunca purga hasta el prune de 30 s

**Archivo:** `ai_defense.py:82-87`, `100-105`, `124-137`

**Riesgo.** La cota `MAX_TRACKED_USERS` **solo deja de añadir** entradas nuevas (rama
`else: ips = None`), no expulsa las viejas. El atacante (que controla su username SSH) rota
20.000 usernames distintos en una ráfaga y satura `by_user`. A partir de ahí, **durante los
siguientes 30 s ningún usuario nuevo se rastrea** → ceguera total del detector de campañas
por-usuario hasta el próximo `_prune`. Es un bypass barato: inundar de usernames aleatorios
para cegar la correlación antes de lanzar el credential stuffing real.

Además el prune es **O(n·m)**: recorre las 20.000 claves × las IPs de cada una (`list(ips.items())`)
cada 30 s. Con `by_user` y `by_subnet` saturados son cientos de miles de operaciones bajo flood,
ejecutadas *de forma síncrona dentro de `observe()`* en la ruta caliente — pico de CPU explotable.

**Fix.** Usar una estructura LRU con expulsión del más antiguo cuando se alcanza la cota, en
vez de dejar de admitir; y limitar el coste del prune por iteración. Mínimo viable:

```python
from collections import OrderedDict
by_user: "OrderedDict[str, dict[str, float]]" = field(default_factory=OrderedDict)

def _touch(self, table, key, cap):
    ips = table.get(key)
    if ips is None:
        if len(table) >= cap:
            table.popitem(last=False)   # expulsa el más antiguo (LRU), nunca ciega
        ips = table[key] = {}
    table.move_to_end(key)
    return ips
```

Y acotar el coste del prune (amortizar / cota por ciclo) y/o sacarlo de la ruta caliente
(`await asyncio.sleep`-driven task).

---

## [ALTO] Falso positivo / auto-DoS sobre CGNAT, NAT corporativo y operadores móviles

**Archivo:** `ai_defense.py:43-50`, `98-113`; umbral `DISTINCT_IPS_PER_SUBNET = 12`

**Riesgo.** `_subnet24` agrupa por /24. Un operador móvil o CGNAT pone a **miles de usuarios
legítimos detrás de la misma /24**; 12 clientes distintos del mismo carrier que hacen un
login fallido (contraseña caducada tras un cambio de política) disparan `botnet_subred`. Si
hay respuesta activa por subred, **se bloquea la /24 entera de un carrier** → se deja sin
servicio a usuarios legítimos (auto-DoS). Lo mismo aplica a `DISTINCT_IPS_PER_USER` con un
proxy/NAT corporativo saliente: muchos empleados tras una IP comparten user de servicio.

Para IPv6 (`ai_defense.py:47`) el problema es inverso: se usa la IP /128 tal cual, así que la
botnet IPv6 (que tiene /64 o /48 enteros) **nunca** correlaciona por subred → evasión trivial
del detector en redes IPv6.

**Fix.**
- Allowlist de subredes de carriers/NAT conocidos exenta de respuesta activa por subred.
- Que `botnet_subred` sea solo señal de score, jamás disparador de bloqueo de /24.
- IPv6: agrupar por /64 (o /48), no por /128.

```python
def _subnet(ip):
    a = ipaddress.ip_address(ip)
    net = 24 if a.version == 4 else 64
    return str(ipaddress.ip_network(f"{ip}/{net}", strict=False).network_address)
```

---

## [MEDIO] `actor.intervals` mezcla intervalos antiguos: timing_cv evaluado sobre ventana no acotada en tiempo

**Archivo:** `engine.py:39, 96-98, 137`

**Riesgo.** `intervals` es un `deque(maxlen=64)` acotado por *cantidad* pero no por *tiempo*.
En un ataque low-and-slow (que es el caso que este módulo dice combatir, WINDOW=600 s en
ai_defense), los 64 intervalos pueden abarcar horas, incluyendo huecos enormes. Un atacante
que mantiene cadencia robótica (CV bajo) pero intercala un par de eventos legítimos espaciados
puede **mantener un CV alto y evadir** `ROBOTIC_CV`. Inversamente, intervalos viejos irrelevantes
contaminan la media y pueden producir falsos negativos. El deque tampoco se purga en `prune()`,
a diferencia de `users`/`ports`.

**Fix.** Guardar timestamps y filtrar por ventana antes de calcular el CV:

```python
# almacenar now en un deque de timestamps y derivar intervalos recientes:
recent = [t for t in actor.event_ts if now - t <= WINDOW]
intervals = [b - a for a, b in zip(recent, recent[1:])]
cv = timing_cv(intervals)
```

---

## [MEDIO] Fuga / crecimiento no acotado en estado por-actor: `users`, `ports`, `last_alert`, `flags`

**Archivo:** `engine.py:103, 106, 42, 49-50`

**Riesgo.** Igual patrón que el hallazgo ALTO: al alcanzar `MAX_USERS`/`MAX_PORTS` el código
**deja de añadir** (`len(actor.users) < MAX_USERS`) pero `prune()` solo elimina por tiempo, no
por cota; bajo ráfaga el actor queda "congelado" con 256 usernames basura y ciego a usuarios
nuevos hasta que caduquen. `actor.last_alert` **nunca se purga** (no aparece en `prune()`): con
muchos tipos de alerta distintos crece, aunque el conjunto de `kind` es finito, por lo que el
riesgo real es bajo aquí. `flags` es acotado (conjunto fijo de strings), sin riesgo.

El detector "robotico" se añade/quita (`flags.discard`) pero **una vez puesto, sube el score
+20 de forma pegajosa** hasta que un CV alto lo retire; un atacante puede limpiar su propio
flag intercalando eventos irregulares (ver hallazgo de intervals).

**Fix.** Expulsión LRU al alcanzar la cota en `users`/`ports` (mismo patrón OrderedDict que
arriba) y purgar `last_alert` por tiempo en `prune()`:

```python
self.last_alert = {k: t for k, t in self.last_alert.items() if now - t <= WINDOW}
```

---

## [BAJO] Correctitud de `timing_cv` — robusto, una observación menor

**Archivo:** `ai_defense.py:53-64`

**Análisis.** El código es correcto frente a los casos límite habituales:
- Lista vacía / pocas muestras → `len(vals) < MIN_INTERVALS` devuelve `None`. OK.
- `vals = [x for x in intervals if x > 0]` excluye negativos y ceros → sin división por cero,
  sin stddev sobre basura. OK.
- `mean <= 0` redundante tras el filtro `x > 0` pero defensivo. OK.
- `pstdev` (poblacional) no lanza con ≥1 elemento. OK.

**Observación menor.** El filtro `x > 0` descarta silenciosamente intervalos no positivos. Si
dos eventos llegan con el mismo `ts` (resolución de reloj) el intervalo 0 se descarta y puede
hacer caer la muestra por debajo de `MIN_INTERVALS`, retrasando la detección. Un atacante con
control fino del timing podría inyectar pares de eventos simultáneos para mantener la muestra
siempre justo por debajo del mínimo. Riesgo bajo.

**Fix (opcional).** Tratar reloj no monotónico explícitamente y usar `time.monotonic()` como
fuente de `ts` para intervalos (evita saltos negativos por NTP) en vez de descartarlos en silencio.

---

## Resumen de prioridades

1. **No derivar respuesta activa (bloqueo) de señales de correlación por-user/por-subnet**
   sin validar la confianza del `src_ip`. Es el riesgo más grave (bloqueo de terceros / carriers).
2. **Cambiar la política de cota de "dejar de admitir" a "LRU/expulsar"** en `by_user`, `by_subnet`,
   `actor.users`, `actor.ports`. La cota actual es cegable por el atacante.
3. **Acotar `intervals` por tiempo** y agrupar IPv6 por /64.
4. Acotar el coste del prune y sacarlo de la ruta caliente.
