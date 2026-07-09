/*
  CENTINEL — reglas YARA por defecto.

  Firmas genéricas de ALTA SEÑAL para ficheros que caen en directorios
  efímeros (/tmp, /dev/shm, ...). No pretenden ser un antivirus completo:
  son las huellas más comunes de una intrusión de Linux. Sustituye o
  amplía con --yara-rules <tus_reglas>.

  Cada regla declara meta.severity para que CENTINEL priorice el match.
*/

rule Reverse_Shell_OneLiner
{
    meta:
        description = "One-liner de reverse shell (bash/dev/tcp, python pty, nc -e)"
        severity = "critical"
        mitre = "T1059"
    strings:
        $bash_devtcp = /bash\s+-i\s+>&\s*\/dev\/tcp\//
        $devtcp      = /\/dev\/tcp\/[0-9]{1,3}(\.[0-9]{1,3}){3}\/[0-9]+/
        $py_pty      = "pty.spawn(" ascii
        $py_sock     = "socket.socket(socket.AF_INET" ascii
        $nc_e        = /\bnc\s+-e\s+\/bin\/(ba)?sh/
        $mkfifo      = /mkfifo\s+\/tmp\/[a-z]+;\s*(cat|sh)/
    condition:
        any of them
}

rule Download_And_Execute
{
    meta:
        description = "Descarga-y-ejecuta (curl|sh, wget|bash, base64 -d|sh)"
        severity = "high"
        mitre = "T1105"
    strings:
        $curl_sh = /curl\s+[^\n|]*\|\s*(ba)?sh/
        $wget_sh = /wget\s+[^\n|]*\|\s*(ba)?sh/
        $b64_sh  = /base64\s+-d[^\n|]*\|\s*(ba)?sh/
    condition:
        any of them
}

rule PHP_Webshell
{
    meta:
        description = "Webshell PHP (eval de entrada del cliente / system de GET)"
        severity = "critical"
        mitre = "T1505.003"
    strings:
        $eval_post = /eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/
        $assert    = /assert\s*\(\s*\$_(POST|GET|REQUEST)/
        $sys_get   = /(system|shell_exec|passthru|popen)\s*\(\s*\$_(GET|POST|REQUEST)/
        $b64_eval  = /eval\s*\(\s*base64_decode\s*\(/
    condition:
        any of them
}

rule Crypto_Miner_Config
{
    meta:
        description = "Config/binario de minero (stratum, xmrig, pools conocidos)"
        severity = "high"
        mitre = "T1496"
    strings:
        $stratum = "stratum+tcp://" ascii
        $xmrig   = "xmrig" nocase ascii
        $donate  = "\"donate-level\"" ascii
        $rand_x  = "randomx" nocase ascii
    condition:
        2 of them
}

rule Suspicious_ELF_In_Tmp
{
    meta:
        description = "ELF con marcadores de packer/anti-análisis en directorio temporal"
        severity = "medium"
        mitre = "T1027"
    strings:
        $elf   = { 7F 45 4C 46 }        // \x7fELF al inicio
        $upx   = "UPX!" ascii
        $ptrace= "ptrace" ascii
    condition:
        $elf at 0 and ($upx or $ptrace)
}

rule Linux_Persistence_Snippet
{
    meta:
        description = "Snippet de persistencia (crontab con curl, authorized_keys inyectado)"
        severity = "high"
        mitre = "T1053.003"
    strings:
        $cron_curl = /\*\s+\*\s+\*\s+\*\s+\*\s+[^\n]*(curl|wget)[^\n]*\|\s*(ba)?sh/
        $authkeys  = /echo\s+["']?ssh-(rsa|ed25519)[^\n]*>>\s*[^\n]*authorized_keys/
    condition:
        any of them
}
