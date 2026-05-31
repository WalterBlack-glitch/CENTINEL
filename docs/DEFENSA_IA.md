# Defensa contra hacking asistido por IA

Los ataques que usan IA/LLM rompen las defensas clásicas de detección de
intrusiones por tres razones, y Centinela está diseñado para contrarrestar cada
una. Este documento separa lo **implementado** (✅) de las **ideas de roadmap**
(◻️) para no vender humo.

## Por qué la IA rompe la detección clásica

| Táctica del atacante con IA | Por qué evade lo clásico |
|---|---|
| **Low-and-slow distribuido** (botnet) | Cada IP queda bajo el umbral por-IP; el contador por actor nunca dispara |
| **Credential stuffing dirigido** | Usa filtraciones reales: pocos intentos, alta tasa de acierto, parece tráfico legítimo |
| **Temporización adaptativa** | Imita el ritmo humano o lo aleatoriza para no parecer un script |
| **Polimorfismo** | Rota user-agents, banners, orden de cifrados; las firmas estáticas no sirven |
| **Reconocimiento dirigido por LLM** | Prioriza objetivos y se detiene antes de hacer ruido |

La idea central de la defensa: **dejar de depender de umbrales por-IP** y pasar
a señales que la IA no puede esconder fácilmente — correlación global,
estructura temporal y trampas.

## Defensas implementadas

### ✅ 1. Correlación global de campañas (`correlation/ai_defense.py`)
En vez de contar por IP, se agrega **entre actores**:
- **Por usuario objetivo:** si ≥8 IPs distintas atacan al mismo usuario en la
  ventana → `alert_credential_stuffing_distribuido`. Atrapa la botnet aunque
  cada nodo haga 1 solo intento.
- **Por subred /24:** si ≥12 IPs de la misma /24 atacan → `alert_botnet_subred`.

Esto convierte el "low-and-slow distribuido" —el evasor número uno— en una señal
fuerte. El estado está acotado y se purga por ventana (no es un vector de DoS).

### ✅ 2. Análisis de temporización robótica
Se mide el **coeficiente de variación** (CV = desviación/media) de los intervalos
entre intentos de cada actor. Un proceso humano/Poisson tiene CV ≈ 1; un script
con cadencia fija tiene CV ≈ 0. CV < 0.06 sobre ≥8 muestras → `alert_robotic_timing`.
Detecta automatización aunque el volumen sea bajo.

### ✅ 3. Credenciales-cebo (canary)
Usuarios que **no existen** y que solo un proceso automatizado probaría
(`--canary svc_backup,deploy_old`). Cualquier intento contra ellos es malicioso
por definición → CRÍTICO inmediato, sin esperar acumulación. Es la trampa más
barata y de mayor señal/ruido contra scrapers y credential-stuffers.

### ✅ 4. Procedencia confiable de logs (journald)
Un atacante con IA podría intentar **envenenar el propio detector** inyectando
eventos falsos. El colector journald valida `_COMM=sshd`/`_UID=0`, así que el
modelo de amenazas no se puede contaminar desde el contenido del log.

### ✅ 5. Scoring que premia las señales anti-IA
Los flags `robotico` (+20), `campaign` (+30) y `canary` (+60) elevan el score
aunque el volumen por-IP sea bajo, de modo que la respuesta activa (bloqueo)
puede actuar sobre ataques sigilosos, no solo sobre fuerza bruta ruidosa.

## Ideas de roadmap (aún no implementadas)

- ◻️ **Tarpitting / pegado de conexión:** en vez de solo `drop`, retrasar al
  atacante (nft `delay`, o un endpoint SSH señuelo lento) para encarecer la
  iteración de un agente automatizado.
- ◻️ **Baseline adaptativo (EWMA):** aprender el ritmo normal de fallos por
  hora/usuario y alertar por desviación estadística, en vez de umbrales fijos
  que la IA aprende a esquivar.
- ◻️ **Grafo de campaña:** enlazar actores que comparten usuarios objetivo,
  contraseñas (si se observan), o huella temporal → identificar la botnet como
  un único adversario y bloquearla en bloque por ASN.
- ◻️ **Fingerprint de cliente SSH (algoritmos/banner):** agrupar herramientas
  aunque roten IP; muchos kits de IA comparten librería y delatan un patrón.
- ◻️ **Entropía de selección de usuarios:** distinguir enumeración de
  diccionario (alta entropía) de credential stuffing dirigido (baja entropía,
  usuarios reales).
- ◻️ **Enriquecimiento con listas de reputación / Tor exit / cloud ASN:** la IA
  suele operar desde VPS y exit-nodes; ponderar el score por reputación de ASN.
- ◻️ **Honeytokens en la app:** credenciales-cebo plantadas en repos, pastebins
  o robots.txt que, si se usan, prueban scraping automatizado previo.

## Defensa del propio Centinela frente a IA ofensiva

Un punto a menudo ignorado: si en el futuro se añade un "analista LLM" que
resuma alertas, **el log es input no confiable** (un atacante controla su
username/rDNS). Reglas de diseño ya adoptadas y a mantener:

- **Nunca** ejecutar como comando la salida de un LLM ni de un campo del log.
- Sanitizar todo string derivado del atacante antes de mostrarlo (ya se hace:
  strip de escapes ANSI + escape de markup en la UI) — también aplica antes de
  meterlo en un prompt, para evitar **inyección de prompt** vía username/rDNS.
- Tratar al LLM como asesor, no como autoridad: la respuesta activa se decide
  por reglas auditables (score + allowlist), no por texto generado.
