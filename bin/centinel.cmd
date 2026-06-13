@echo off
mode con: cols=78 lines=30
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0centinel.ps1"
