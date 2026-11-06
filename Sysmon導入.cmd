@echo off
rem Sets up Sysmon for GuardianMascot. Asks for administrator rights and for your agreement to the license.
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\install_sysmon.ps1"
pause
