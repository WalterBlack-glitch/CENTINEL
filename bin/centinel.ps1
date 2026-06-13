$Host.UI.RawUI.WindowTitle = 'Centinel'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
try { [Console]::CursorVisible = $false } catch {}

# Fuerza fuente Cascadia Mono (renderiza bien box-drawing y emoji).
$src = @'
using System;
using System.Runtime.InteropServices;
public static class ConFont {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct CONSOLE_FONT_INFO_EX {
        public uint cbSize; public uint nFont;
        public short dwFontSizeX; public short dwFontSizeY;
        public uint FontFamily; public uint FontWeight;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=32)] public string FaceName;
    }
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr GetStdHandle(int n);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetCurrentConsoleFontEx(IntPtr h, bool max, ref CONSOLE_FONT_INFO_EX i);
    public static void Set(string face, short h) {
        var f = new CONSOLE_FONT_INFO_EX();
        f.cbSize = (uint)Marshal.SizeOf(f);
        f.dwFontSizeX = 0; f.dwFontSizeY = h;
        f.FontFamily = 54; f.FontWeight = 400; f.FaceName = face;
        SetCurrentConsoleFontEx(GetStdHandle(-11), false, ref f);
    }
}
'@
try { Add-Type -TypeDefinition $src -ErrorAction Stop; [ConFont]::Set('Cascadia Mono', 18) } catch {}

$e   = [char]27
$R   = "$e[0m"; $B = "$e[1m"; $DIM = "$e[2m"
$RED = "$e[38;5;196m"; $RD2 = "$e[38;5;160m"; $RD3 = "$e[38;5;124m"
$GLD = "$e[38;5;220m"; $SLV = "$e[38;5;250m"; $CYN = "$e[38;5;51m"; $GRN = "$e[38;5;46m"

# Letras del banner (ANSI Shadow, 8 columnas x 6 filas por letra).
$letters = @{
'C' = @('  ██████╗',
        ' ██╔════╝',
        ' ██║     ',
        ' ██║     ',
        ' ╚██████╗',
        '  ╚═════╝')
'E' = @(' ███████╗',
        ' ██╔════╝',
        ' █████╗  ',
        ' ██╔══╝  ',
        ' ███████╗',
        ' ╚══════╝')
'N' = @(' ███╗   ██╗',
        ' ████╗  ██║',
        ' ██╔██╗ ██║',
        ' ██║╚██╗██║',
        ' ██║ ╚████║',
        ' ╚═╝  ╚═══╝')
'T' = @(' ████████╗',
        ' ╚══██╔══╝',
        '    ██║   ',
        '    ██║   ',
        '    ██║   ',
        '    ╚═╝   ')
'I' = @(' ██╗',
        ' ██║',
        ' ██║',
        ' ██║',
        ' ██║',
        ' ╚═╝')
'L' = @(' ██╗     ',
        ' ██║     ',
        ' ██║     ',
        ' ██║     ',
        ' ███████╗',
        ' ╚══════╝')
}

$word = 'CENTINEL'
$lines = @('','','','','','')
foreach ($ch in $word.ToCharArray()) {
    $glyph = $letters["$ch"]
    for ($i = 0; $i -lt 6; $i++) { $lines[$i] += $glyph[$i] }
}
$bannerWidth = $lines[0].Length

Clear-Host
$top = 2
# --- Animación 1: letras aparecen una a una (typewriter por columnas) ---
$colWidth = @(9,9,11,10,4,9,10,9)  # ancho real de cada letra
$xCursor  = 4
$startCols = @()
$acc = 0
foreach ($w in $colWidth) { $startCols += $acc; $acc += $w }

for ($k = 0; $k -lt $word.Length; $k++) {
    $sx = $startCols[$k]; $w = $colWidth[$k]
    for ($i = 0; $i -lt 6; $i++) {
        [Console]::SetCursorPosition($xCursor + $sx, $top + $i)
        $slice = $lines[$i].Substring($sx, $w)
        Write-Host "$RED$B$slice$R" -NoNewline
    }
    Start-Sleep -Milliseconds 70
}

# --- Animación 2: barra de escaneo horizontal sobre el banner ---
$scanRow = $top + 7
for ($pass = 0; $pass -lt 2; $pass++) {
    for ($x = 0; $x -lt ($bannerWidth + 8); $x += 2) {
        [Console]::SetCursorPosition($xCursor, $scanRow)
        $bar = ''
        for ($j = 0; $j -lt $bannerWidth; $j++) {
            if ([math]::Abs($j - $x) -lt 3) { $bar += "█" }
            elseif ([math]::Abs($j - $x) -lt 6) { $bar += "▓" }
            elseif ([math]::Abs($j - $x) -lt 9) { $bar += "░" }
            else { $bar += ' ' }
        }
        Write-Host "$CYN$bar$R" -NoNewline
        Start-Sleep -Milliseconds 8
    }
}
# limpia la barra
[Console]::SetCursorPosition($xCursor, $scanRow)
Write-Host (' ' * $bannerWidth)

# --- Tagline con pulso ---
$tag = 'rastreo multicapa de amenazas · sentinel-class IDS'
$padX = $xCursor + [int](($bannerWidth - $tag.Length) / 2)
[Console]::SetCursorPosition($padX, $top + 8)
Write-Host "$GLD$tag$R"
[Console]::SetCursorPosition(0, $top + 10)

try { [Console]::CursorVisible = $true } catch {}

# 1) WSL.
$null = wsl.exe -l -q 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "    $RED>>$R WSL no instalado: $B`wsl --install -d Ubuntu`$R"
    Read-Host '    Enter para salir'; exit 1
}

# 2) Bootstrap idempotente (clona repo + venv una sola vez).
$boot = @'
set -e
cd ~
if [ ! -d CENTINEL ]; then
  echo '[boot] clonando CENTINEL...'
  git clone --depth 1 https://github.com/WalterBlack-glitch/CENTINEL.git
fi
cd CENTINEL
if [ ! -d .venv ]; then
  echo '[boot] venv + extras [ui]...'
  python3 -m venv .venv
  .venv/bin/pip install -q -U pip
  .venv/bin/pip install -q -e '.[ui]'
fi
echo '[boot] listo.'
'@
Write-Host "    $GRN>>$R preparando WSL..."
wsl.exe -d Ubuntu -- bash -lc $boot | Out-Host
Write-Host ''

# 3) Lanza un panel en una ventana cmd separada.
function Start-Panel($title, $color, $flags) {
    $args_b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($flags))
    $bash = "cd ~/CENTINEL && flags=`$(echo $args_b64 | base64 -d) && echo && echo `"  >> centinel $flags`" && echo && .venv/bin/python -m centinel `$flags ; echo ; echo '[panel detenido — Enter para cerrar]' ; read"
    $wslCmd = "wsl.exe -d Ubuntu -- bash -lc `"$bash`""
    Start-Process cmd.exe -ArgumentList @('/c', "title Centinel - $title && color $color && $wslCmd")
}

# 4) Menú persistente.
$opts = @(
  @{ key='1'; name='Red (sniff + netwatch)';        color='0B'; flags='--simulate' },
  @{ key='2'; name='C2 beaconing (T1071)';          color='0C'; flags='--simulate --beacon' },
  @{ key='3'; name='Exec / reverse shells (T1059)'; color='0E'; flags='--simulate --execwatch' },
  @{ key='4'; name='DNS exfil (T1048.003)';         color='0D'; flags='--simulate --dnswatch' },
  @{ key='5'; name='Persistencia / rootkits';       color='0A'; flags='--simulate --rootcheck' },
  @{ key='6'; name='Honeypot 2222';                 color='09'; flags='--simulate --honeypot 2222' },
  @{ key='7'; name='Forense (informe + cadena)';    color='07'; flags='--report --verify-log' },
  @{ key='8'; name='Anti-hijacking (LD_PRELOAD/PATH/ptrace)'; color='05'; flags='--simulate --hijackwatch' },
  @{ key='A'; name='AUTO-DEFENSA (todas las capas)';color='4F'; flags='--simulate --beacon --execwatch --dnswatch --rootcheck --hijackwatch --assess --block-threshold 70' }
)

function Show-Menu {
    Clear-Host
    Write-Host ''
    Write-Host "    $RED$B  ┌─────────────────────────────────────────────────────────┐$R"
    Write-Host "    $RED$B  │$R   $GLD$B C E N T I N E L $R  $DIM·  panel de control$R              $RED$B│$R"
    Write-Host "    $RED$B  └─────────────────────────────────────────────────────────┘$R"
    Write-Host ''
    foreach ($o in $opts) {
        $key = $o.key.PadLeft(2)
        $name = $o.name.PadRight(38)
        if ($o.key -eq 'A') {
            Write-Host "      $RED$B[ $key ]$R  $RED$B$name$R $DIM— modo automatizado$R"
        } else {
            Write-Host "      $CYN[ $key ]$R  $name $DIM"
        }
    }
    Write-Host ''
    Write-Host "      $DIM[ Q ]$R  salir"
    Write-Host ''
    Write-Host "    $DIM   Cada selección abre una ventana propia. El menú persiste.$R"
    Write-Host ''
}

while ($true) {
    Show-Menu
    $sel = (Read-Host "    > opción").Trim().ToUpper()
    if ($sel -eq 'Q' -or $sel -eq '') { break }
    $opt = $opts | Where-Object { $_.key -eq $sel } | Select-Object -First 1
    if (-not $opt) {
        Write-Host "    $RED>>$R opción no válida"; Start-Sleep 1; continue
    }
    Start-Panel $opt.name $opt.color $opt.flags
    Start-Sleep -Milliseconds 400
}

try { [Console]::CursorVisible = $true } catch {}
Write-Host "    $DIM Centinel cerrado. $R"
