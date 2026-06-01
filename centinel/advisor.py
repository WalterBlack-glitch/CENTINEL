"""Asesor de remediación: traduce cada amenaza en pasos concretos de arreglo.

Detectar no basta. Cuando un actor compromete (o intenta comprometer) el host,
Centinel acompaña la alerta con un PLAYBOOK accionable: qué comprobar, qué
ejecutar y cómo cerrar el agujero. Los pasos son plantillas estáticas (no
incrustan entrada del atacante en comandos) y van marcados como copiables.

`advise(kind, ctx)` devuelve un dict con:
  - title:   resumen humano de la amenaza
  - urgency: "alta" | "media" | "critica"
  - steps:   lista de acciones (cada una: texto + comando opcional)
  - refs:    referencias (CVE, hardening) opcionales

Nada aquí ejecuta comandos: solo recomienda. La ejecución la decide el usuario.
"""
from __future__ import annotations

import re

# Solo estos caracteres se permiten en un valor interpolado dentro de un comando
# sugerido. Así, aunque el usuario/IP venga de una fuente no fiable, NUNCA puede
# introducir metacaracteres de shell ($ ` ; | & espacios comillas paréntesis) en
# un comando que el operador podría copiar y pegar. Defensa anti-inyección.
_SAFE = re.compile(r"[^A-Za-z0-9._:@/-]")


def _clean(v: str) -> str:
    return _SAFE.sub("", str(v))[:64]


# Cada playbook: kind (sin prefijo "alert_") -> dict de remediación. Los {ip}/
# {user} se rellenan con .format desde ctx, escapando a cadena vacía si faltan.
_PLAYBOOKS: dict[str, dict] = {
    "compromise": {
        "title": "Posible cuenta comprometida (login exitoso tras fuerza bruta)",
        "urgency": "critica",
        "steps": [
            ("Bloquea la IP atacante en el firewall ahora mismo (o pulsa "
             "«Bloquear» arriba para que lo haga Centinel).",
             "sudo nft add rule inet filter input ip saddr {ip} drop"),
            ("Aísla la sesión: revisa logins activos y cierra los sospechosos.",
             "who; w; last -a | head; pkill -KILL -u {user}"),
            ("Rota la contraseña de la cuenta y fuerza su caducidad.",
             "sudo passwd {user}; sudo passwd -e {user}"),
            ("Revisa claves SSH y autorizadas no reconocidas.",
             "sudo cat /home/{user}/.ssh/authorized_keys /root/.ssh/authorized_keys"),
            ("Busca persistencia: cron, servicios y binarios recientes.",
             "sudo crontab -l -u {user}; systemctl --type=service --state=running; "
             "find / -mtime -2 -type f -perm -4000 2>/dev/null"),
            ("Desactiva login por contraseña: solo clave + MFA.", None),
        ],
        "refs": ["CIS SSH hardening", "Deshabilita PasswordAuthentication"],
    },
    "bruteforce": {
        "title": "Fuerza bruta SSH en curso",
        "urgency": "alta",
        "steps": [
            ("Bloquea la IP de origen.",
             "sudo nft add rule inet filter input ip saddr {ip} drop"),
            ("Instala/activa fail2ban para baneo automático.",
             "sudo apt install -y fail2ban && sudo systemctl enable --now fail2ban"),
            ("Cambia SSH a solo-clave y desactiva root por SSH.",
             "sudo sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/;"
             "s/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' "
             "/etc/ssh/sshd_config && sudo systemctl reload sshd"),
        ],
        "refs": ["fail2ban", "SSH key-only auth"],
    },
    "spray": {
        "title": "Password spraying (muchos usuarios, pocas claves)",
        "urgency": "alta",
        "steps": [
            ("Bloquea la IP y revisa qué usuarios se probaron.",
             "sudo nft add rule inet filter input ip saddr {ip} drop"),
            ("Verifica que no existan cuentas débiles/por defecto.",
             "sudo awk -F: '($3>=1000)&&($3<65534){print $1}' /etc/passwd"),
            ("Exige contraseñas fuertes y bloqueo tras N fallos (pam_faillock).",
             None),
        ],
        "refs": ["pam_faillock", "Política de contraseñas"],
    },
    "scan": {
        "title": "Escaneo de puertos / reconocimiento",
        "urgency": "media",
        "steps": [
            ("Revisa qué servicios expones realmente.",
             "sudo ss -tulpn"),
            ("Cierra todo lo no imprescindible con el firewall (deny por defecto).",
             "sudo ufw default deny incoming && sudo ufw allow 22/tcp && sudo ufw enable"),
            ("Considera bloquear al escáner reincidente.",
             "sudo nft add rule inet filter input ip saddr {ip} drop"),
        ],
        "refs": ["Principio de mínima exposición"],
    },
    "canary": {
        "title": "Credencial-cebo usada: atacante confirmado dentro del perímetro",
        "urgency": "critica",
        "steps": [
            ("El uso del cebo no tiene falsos positivos: bloquea la IP ya.",
             "sudo nft add rule inet filter input ip saddr {ip} drop"),
            ("Investiga cómo obtuvo el cebo (filtración de credenciales/config).",
             None),
            ("Audita accesos recientes y rota secretos potencialmente expuestos.",
             "sudo last -a | head -30"),
        ],
        "refs": ["Rotación de secretos", "Detección de filtraciones"],
    },
    "robotic_timing": {
        "title": "Cadencia robótica: bot/script automatizado (no humano)",
        "urgency": "alta",
        "steps": [
            ("Aplica rate-limiting de conexiones por IP en el firewall.",
             "sudo nft add rule inet filter input ip saddr {ip} "
             "ct state new limit rate over 10/minute drop"),
            ("Pon SSH tras un puerto no estándar + clave (reduce ruido de bots).",
             None),
        ],
        "refs": ["nftables rate limiting"],
    },
    "credential_stuffing_distribuido": {
        "title": "Credential stuffing distribuido contra un usuario (botnet)",
        "urgency": "alta",
        "steps": [
            ("NO bloquees por usuario (el atacante quiere que bloquees a víctimas). "
             "Protege la cuenta: rota su clave y exige MFA.", None),
            ("Activa MFA/2FA en SSH (pam_google_authenticator).",
             "sudo apt install -y libpam-google-authenticator"),
            ("Revisa si la credencial aparece en filtraciones conocidas.", None),
        ],
        "refs": ["MFA en SSH", "Have I Been Pwned"],
    },
    "botnet_subred": {
        "title": "Botnet coordinada desde una subred",
        "urgency": "alta",
        "steps": [
            ("Bloquea la subred completa (no IPs sueltas) si el origen es hostil.",
             "sudo nft add rule inet filter input ip saddr {subnet} drop"),
            ("Si es tráfico extranjero no esperado, considera geo-bloqueo.", None),
        ],
        "refs": ["Bloqueo por CIDR"],
    },
    "actor_atribuido": {
        "title": "Múltiples IPs son el mismo adversario (campaña atribuida)",
        "urgency": "alta",
        "steps": [
            ("Bloquea TODAS las IPs del cluster, no solo la última vista.", None),
            ("Trátalo como un único adversario persistente: sube la vigilancia "
             "y conserva evidencia para denuncia/forense.", None),
            ("Refuerza el servicio objetivo (clave+MFA, mínima exposición).", None),
        ],
        "refs": ["Respuesta a campañas persistentes"],
    },
    "exploit_attempt": {
        "title": "Intento de explotación (exploit/CVE) detectado",
        "urgency": "critica",
        "steps": [
            ("Bloquea la IP e identifica el CVE en el detalle de la alerta.",
             "sudo nft add rule inet filter input ip saddr {ip} drop"),
            ("Actualiza el paquete vulnerable de inmediato.",
             "sudo apt update && sudo apt upgrade -y"),
            ("Si es regreSSHion (CVE-2024-6387), parchea OpenSSH y revisa "
             "LoginGraceTime.", None),
            ("Revisa si el exploit tuvo éxito (procesos/conexiones anómalas).",
             "sudo ss -tnp; ps aux --sort=-%cpu | head"),
        ],
        "refs": ["CVE-2024-6387", "CVE-2018-10933", "Parcheo urgente"],
    },
    "honeypot_hit": {
        "title": "Conexión al señuelo (honeypot): origen malicioso confirmado",
        "urgency": "alta",
        "steps": [
            ("Toda conexión al honeypot es maliciosa: bloquea la IP.",
             "sudo nft add rule inet filter input ip saddr {ip} drop"),
            ("Usa el banner capturado para identificar la herramienta del atacante.",
             None),
            ("Verifica que el servicio REAL no esté expuesto en el puerto estándar.",
             "sudo ss -tulpn | grep -E ':22|:23|:3389'"),
        ],
        "refs": ["Análisis de honeypot"],
    },
}

_MAX_STEPS = 8


# Valor neutro cuando falta el dato (evita comandos a medio rellenar).
_DEFAULTS = {"ip": "<IP>", "user": "<usuario>", "subnet": "<subred>"}


def _fmt(s: str, ctx: dict) -> str:
    # Sustitución EXPLÍCITA de marcadores conocidos (no str.format): así las
    # llaves literales de los comandos (awk '{print $1}', find -printf) quedan
    # intactas y nunca se interpreta entrada del atacante como campo de formato.
    for key, default in _DEFAULTS.items():
        token = "{" + key + "}"
        if token in s:
            raw = ctx.get(key)
            val = _clean(raw) if raw else default
            val = val or default            # si el saneo lo deja vacío, neutro
            s = s.replace(token, val)
    return s


def advise(kind: str, ctx: dict | None = None) -> dict | None:
    """Devuelve el playbook de remediación para un tipo de alerta, o None."""
    kind = (kind or "").removeprefix("alert_")
    pb = _PLAYBOOKS.get(kind)
    if not pb:
        return None
    ctx = ctx or {}
    steps = []
    for text, cmd in pb["steps"][:_MAX_STEPS]:
        steps.append({"text": _fmt(text, ctx),
                      "cmd": _fmt(cmd, ctx) if cmd else None})
    return {
        "title": pb["title"],
        "urgency": pb["urgency"],
        "steps": steps,
        "refs": list(pb.get("refs", [])),
    }


def known_kinds() -> set[str]:
    return set(_PLAYBOOKS)
