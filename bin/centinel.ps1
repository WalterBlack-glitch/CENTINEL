$Host.UI.RawUI.WindowTitle = 'Centinel'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$e   = [char]27
$R   = "$e[0m"
$B   = "$e[1m"
$DIM = "$e[2m"
$RED = "$e[38;5;196m"   # Sentinel rojo
$GLD = "$e[38;5;220m"   # plata/dorado
$CYN = "$e[38;5;51m"
$GRN = "$e[38;5;46m"

$banner = @"

$RED$B    ╔══════════════════════════════════════════════════════════════════╗$R
$RED$B    ║$R   $GLD ██████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗    $R $RED$B║$R
$RED$B    ║$R   $GLD██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║    $R $RED$B║$R
$RED$B    ║$R   $GLD██║     █████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║    $R $RED$B║$R
$RED$B    ║$R   $GLD██║     ██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║    $R $RED$B║$R
$RED$B    ║$R   $GLD╚██████╗███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗$R $RED$B║$R
$RED$B    ║$R   $GLD ╚═════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝$R $RED$B║$R
$RED$B    ║$R                                                                  $RED$B║$R
$RED$B    ║$R       $CYN rastreo multicapa de amenazas · sentinel-class IDS    $R     $RED$B║$R
$RED$B    ╚══════════════════════════════════════════════════════════════════╝$R

"@
Write-Host $banner

# 1) WSL.
$null = wsl.exe -l -q 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "    $RED>>$R WSL no instalado. PowerShell admin: $B`wsl --install -d Ubuntu`$R"
    Read-Host '    pulsa Enter'; exit 1
}

# 2) Bootstrap idempotente dentro de WSL.
$boot = @'
set -e
cd ~
if [ ! -d CENTINEL ]; then
  echo '[boot] clonando CENTINEL...'
  git clone --depth 1 https://github.com/WalterBlack-glitch/CENTINEL.git
fi
cd CENTINEL
if [ ! -d .venv ]; then
  echo '[boot] venv + extras [ui,web]...'
  python3 -m venv .venv
  .venv/bin/pip install -q -U pip
  .venv/bin/pip install -q -e '.[ui,web]'
fi
echo
echo '[run] dashboard http://127.0.0.1:8787  (Ctrl+C para detener)'
echo
exec .venv/bin/python -m centinel --simulate --web
'@

# 3) Abre el navegador cuando el dashboard responda (segundo plano).
Start-Job -ScriptBlock {
    for ($i = 0; $i -lt 40; $i++) {
        try {
            Invoke-WebRequest 'http://127.0.0.1:8787' -UseBasicParsing -TimeoutSec 1 | Out-Null
            Start-Process 'http://127.0.0.1:8787'; break
        } catch { Start-Sleep 1 }
    }
} | Out-Null

Write-Host "    $GRN>>$R lanzando dashboard en $B http://127.0.0.1:8787 $R"
Write-Host ''
wsl.exe -d Ubuntu -- bash -lc $boot

Write-Host ''
Write-Host "    $DIM Centinel detenido. $R"
Read-Host '    pulsa Enter para cerrar'
