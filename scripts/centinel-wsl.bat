@echo off
setlocal enabledelayedexpansion
title CENTINEL :: rastreo multicapa de amenazas
mode con: cols=110 lines=34
chcp 65001 >nul

REM Truco estandar para obtener el byte ESC (0x1B) real en cmd:
for /f %%E in ('echo prompt $E ^| cmd') do set "ESC=%%E"
set "C1=%ESC%[38;5;51m"
set "C2=%ESC%[38;5;208m"
set "OK=%ESC%[38;5;46m"
set "DIM=%ESC%[38;5;244m"
set "B=%ESC%[1m"
set "R=%ESC%[0m"

cls
echo.
echo    %C1%%B%   ____ _____ _   _ _____ ___ _   _ _____ _      %R%
echo    %C1%%B%  / ___^| ____^| ^| ^| ^|_   _^|_ _^| ^| ^| ^| ____^| ^|     %R%
echo    %C1%%B% ^| ^|   ^|  _^| ^| ^|^| ^|   ^|  ^| ^|^| ^|^| ^| ^|  _^| ^| ^|     %R%
echo    %C1%%B% ^| ^|___^| ^|___^| ^|^|^| ^|   ^|  ^| ^|^| ^|^|^| ^| ^|___^| ^|___  %R%
echo    %C1%%B%  \____^|_____^|_^| \_^|   ^|_^| ^|___^|_^| \_^|_____^|_____^| %R%
echo.
echo    %DIM%   rastreo multicapa de amenazas  ·  arrancando en WSL...%R%
echo.

REM 1) Comprueba WSL.
wsl.exe -l -q >nul 2>&1
if errorlevel 1 (
  echo    %C2%^>^>%R% WSL no esta instalado. Ejecuta en PowerShell admin:
  echo       %B%wsl --install -d Ubuntu%R%
  echo.
  pause
  exit /b 1
)

REM 2) Bootstrap dentro de WSL: clona y crea venv con extras web si no estan.
set "BOOT=set -e; cd ~ ; if [ ! -d CENTINEL ]; then echo '[boot] clonando CENTINEL...'; git clone --depth 1 https://github.com/WalterBlack-glitch/CENTINEL.git ; fi ; cd CENTINEL ; if [ ! -d .venv ]; then echo '[boot] creando venv + instalando extras [ui,web]...'; python3 -m venv .venv ; .venv/bin/pip install -q -U pip ; .venv/bin/pip install -q -e '.[ui,web]' ; fi ; echo ; echo '[run] dashboard en http://127.0.0.1:8787  (Ctrl+C para detener)'; echo ; exec .venv/bin/python -m centinel --simulate --web"

REM 3) Abre el navegador cuando el dashboard responda (timeout 30 s).
start "" /b powershell -nop -windowstyle hidden -c ^
  "for($i=0;$i -lt 30;$i++){try{Invoke-WebRequest http://127.0.0.1:8787 -UseBasicParsing -TimeoutSec 1 ^| Out-Null;Start-Process 'http://127.0.0.1:8787';break}catch{Start-Sleep 1}}"

echo    %OK%^>^>%R% lanzando CENTINEL en %B%http://127.0.0.1:8787%R%
echo.
wsl.exe -d Ubuntu -- bash -lc "%BOOT%"

echo.
echo    %DIM%CENTINEL detenido. Pulsa una tecla para cerrar.%R%
pause >nul
