@echo off
rem Removes Sysmon. Asks for administrator rights and for confirmation.
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\remove_sysmon.ps1"
pause
