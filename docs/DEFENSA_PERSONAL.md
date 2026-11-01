# CENTINEL — Defensa personal contra lo que no sabemos que está ahí

> Hipótesis de amenaza: un **unknown-unknown** —no una amenaza que aún no
> identifiqué, sino una categoría que ni sé que existe—. Una entidad **ya
> residente** en tu máquina: implante durmiente, troyano a medida, algo que pasó
> los antivirus porque no tiene firma conocida. No sabemos qué es, ni que está,
> ni qué forma tiene. Contra eso, reconocer al enemigo (firmas, hashes, IoCs)
> **es ciego por diseño**: solo encuentra lo que ya sabías nombrar. El arma es
> reconocer **tu propia normalidad** y delatar lo que se desvía de *ti*, no de
> una lista.
>
> Las defensas que atrapan un unknown-unknown son las que **no necesitan
> nombrarlo**: #1 (lo que no eres tú salta solo), #2 (algo te miente aunque no
> sepas qué), #4 (certeza sin saber quién tocó el cebo) y #8 (la *ausencia* de
> latido es la señal). Las demás suben la confianza una vez que algo ya saltó.

Las 8 ideas, de más a menos "ya casi lo tienes". Cada una se apoya en módulos
existentes; ninguna rompe la filosofía 0-deps / lógica pura separada del I/O.

---

## 1. Baseline de "mi propia normalidad" (el núcleo)
Aprende TU equipo en reposo durante unos días: qué procesos corren, qué puertos
escuchan, a qué dominios resuelves, qué binarios de sistema hay, qué autostarts
existen. Luego alerta de **lo que se desvía de ti**, no de una firma. Lo
desconocido se delata por ser *nuevo o raro respecto a tu patrón*.
- **Apoyo:** `baseline_store.py` (baselines firmadas HMAC), `snapshots.py` (diff),
  `winpersist`/`procwatch`/`hashwatch` ya fijan primera-pasada-sin-alertar.
- **Qué falta:** un "perfil de reposo" transversal (proceso+puerto+DNS+autostart)
  en vez de un baseline por capa aislada. El veredicto pasa a ser "esto no es tú".

## 2. Cazar lo que se esconde del propio sistema operativo (cross-view)
Un rootkit se oculta mintiéndole a la API del SO. La contra: enumerar lo mismo
por **dos vías** y comparar. PIDs por API vs. por recorrido de handles; puertos
por `netstat`/API vs. lectura cruda de `/proc/net` o tablas del kernel. Toda
discrepancia = algo oculto, aunque no sepas qué.
- **Apoyo:** `hashwatch` ya cierra "binario del sistema troyanizado"; `_proc_net`
  ya lee crudo. Esto añade el "ocultarse a sí mismo" que la integridad no ve.
- **Honestidad:** el cross-view fuerte (lsass/PPL, kernel) necesita driver; en
  user-land cubre bastante y se documenta el límite.

## 3. La red como delator inevitable
Toda entidad durmiente acaba **llamando a casa**. No busques malware; busca el
hecho anómalo: "este binario nunca había abierto una conexión saliente y ahora
sí", "este proceso late a intervalos regulares", "DNS a subdominios de alta
entropía". El contenido puede ir cifrado; el *patrón* no se puede ocultar.
- **Apoyo:** `beacon` (latido C2), `dnswatch` (exfil/entropía), `netwatch`
  (proceso↔IP). Falta el disparador **"primera vez que ESTE binario toca la red"**
  cruzado contra el baseline de #1.

## 4. Trampas personales (canarios): certeza, no sospecha
Siembra cebos que ningún uso legítimo tocaría y vigila el acceso: un fichero
`contraseñas.txt` / `wallet.dat` falso en Documentos, una clave de registro
señuelo, un puerto honeypot local. **Cualquier** lectura o conexión = intruso con
relación señal/ruido perfecta (no hay falsos positivos por definición).
- **Apoyo:** el honeypot SSH ya existe en el lado Linux y los canary users en
  `ai_defense`. Extensión natural al host personal: canarios de **fichero y
  registro** en Windows, vía los relojes de acceso que ya se pueden leer.

## 5. Ritmo: lo humano es irregular, lo automatizado late
Una entidad dormida que despierta para actuar casi siempre lo hace por reloj
(tarea, temporizador, polling). Mide el coeficiente de variación de intervalos de
ejecución/red local; una cadencia demasiado regular delata automatización aunque
cada acción individual parezca inocente.
- **Apoyo:** `ai_defense` ya calcula timing robótico para ataques de red;
  reusar el mismo cálculo sobre actividad **local** (exec, conexiones salientes).

## 6. "¿Qué cambió mientras no miraba?"
Dispara diffs en los momentos en que una entidad aprovecha para moverse:
arranque, apagado, tras conectar un USB, tras una actualización, tras volver de
suspensión. Lo desconocido aparece como un **delta inexplicable** entre dos
fotos, aunque en estado estable pase desapercibido.
- **Apoyo:** `snapshots` ya hace el diff; falta engancharlo a esos **eventos del
  sistema** en vez de solo a "cuando pulsas Reescanear".

## 7. Correlación entre capas = confianza frente a indicio débil
Una entidad real deja huella en **varias capas a la vez**: un autostart nuevo +
un binario sin firma + una conexión saliente, en la misma ventana de tiempo. Cada
indicio por separado es débil (ruido); correlacionados son una historia. Una
**línea de tiempo del incidente** que una esos puntos sube la confianza y reduce
el griterío (el enemigo nº1 de un IDS personal: que lo aprendas a ignorar).
- **Apoyo:** el `engine` de correlación ya existe para el lado Linux; llevar esa
  idea de "score por actor en ventana" al **host personal** (actor = cadena de
  cambios), no solo a IPs.

## 8. Dead-man / anti-silenciamiento
Lo primero que hace un intruso competente es cegar al vigilante. Un "si CENTINEL
deja de reportar, algo lo silenció" con **ancla externa** (igual que anclas el
`head` de la cadena HMAC fuera de la máquina): si el latido no llega al móvil/
webhook/otro equipo, la ausencia *es* la alerta.
- **Apoyo:** `watchdog.py` ya revive el proceso si lo matan; falta el pulso
  externo cuya **falta** se note desde fuera.

---

## El marco mental (para no perderse)
Tres preguntas, en este orden, son toda la doctrina:
1. **¿Esto es *tú*?** (baseline de normalidad — #1, #6)
2. **¿Algo me está mintiendo sobre lo que veo?** (cross-view, anti-silenciamiento — #2, #8)
3. **¿Algo se delató solo?** (red, canarios, ritmo — #3, #4, #5)

Y una regla de oro heredada del resto del proyecto: **asistir y explicar, nunca
decidir solo**. Contra lo desconocido se sube la señal y se baja el ruido; la
acción destructiva (bloquear, matar, aislar) sigue pasando por un humano.

> Pendiente de aterrizar: priorizar cuál de las 8 es el primer incremento. La #1
> (perfil de reposo transversal) habilita a casi todas las demás, así que es el
> candidato natural a cabeza de serie.
