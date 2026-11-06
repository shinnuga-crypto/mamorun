@echo off
rem Runs the WFP and disconnect check as administrator. Only a test port on this PC is blocked, and the filter is removed when the check ends.
rem Uses the latest build so that a running GuardianMascot does not have to be closed.
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
cd /d "%~dp0"
if not exist "work\check" mkdir "work\check"
start "" /wait "work\build\dist\GuardianMascot\GuardianMascot.exe" --trap-check "%~dp0work\check\trap-check.json"
if errorlevel 1 echo Trap check finished with a problem.
start "" /wait "work\build\dist\GuardianMascot\GuardianMascot.exe" --sysmon-check "%~dp0work\check\sysmon-check.json"
if errorlevel 1 echo Sysmon check finished with a problem.
start "" /wait "work\build\dist\GuardianMascot\GuardianMascot.exe" --startup-check "%~dp0work\check\startup-check.json"
if errorlevel 1 echo Startup check finished with a problem.
start "" /wait "work\build\dist\GuardianMascot\GuardianMascot.exe" --gate-check "%~dp0work\check\gate-check.json"
if errorlevel 1 (
  echo Check finished with a problem. Tell Claude it is done.
) else (
  echo Check finished. Tell Claude it is done.
)
pause
