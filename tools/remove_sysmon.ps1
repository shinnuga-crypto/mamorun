# Removes Sysmon. Run it from the remove .cmd file (needs administrator).
$ErrorActionPreference = 'Stop'
$service = Get-Service 'sysmon*' -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike 'SysmonDrv*' } | Select-Object -First 1
if (-not $service) {
    Write-Host 'Sysmon is not installed.'
    exit 0
}
$answer = Read-Host "Remove Sysmon ($($service.Name))? Other tools may also use it. (Y/N)"
if ($answer -notmatch '^[Yy]') {
    Write-Host 'Cancelled. Nothing was changed.'
    exit 2
}
$exe = $null
foreach ($name in 'Sysmon64.exe', 'Sysmon64a.exe', 'Sysmon.exe') {
    foreach ($folder in $env:SystemRoot, (Join-Path $env:SystemRoot 'System32')) {
        $path = Join-Path $folder $name
        if (-not $exe -and (Test-Path $path)) { $exe = $path }
    }
}
if (-not $exe) { throw 'The Sysmon program was not found.' }
& $exe -u
if ($LASTEXITCODE -ne 0) { throw "Sysmon returned exit code $LASTEXITCODE" }
Write-Host 'Done.'
