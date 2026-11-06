# Sets up Sysmon for GuardianMascot. Run it from the install .cmd file (needs administrator).
# Order: already installed -> update settings / built-in Windows feature -> official download.
$ErrorActionPreference = 'Stop'
$config = Join-Path $PSScriptRoot 'mamorun-sysmon.xml'
$zipUrl = 'https://download.sysinternals.com/files/Sysmon.zip'
$licenseUrl = 'https://learn.microsoft.com/en-us/sysinternals/license-terms'

function Confirm-License {
    Write-Host 'Sysmon is a Microsoft Sysinternals tool. Its license applies to you:'
    Write-Host "  $licenseUrl"
    $answer = Read-Host 'Do you accept the license and want to continue? (Y/N)'
    if ($answer -notmatch '^[Yy]') {
        Write-Host 'Cancelled. Nothing was changed.'
        exit 2
    }
}

function Invoke-Sysmon($exe, [string[]]$arguments) {
    & $exe @arguments
    if ($LASTEXITCODE -ne 0) { throw "Sysmon returned exit code $LASTEXITCODE" }
}

function Find-InstalledSysmon {
    foreach ($name in 'Sysmon64.exe', 'Sysmon64a.exe', 'Sysmon.exe') {
        $path = Join-Path $env:SystemRoot $name
        if (Test-Path $path) { return $path }
        $path = Join-Path $env:SystemRoot "System32\$name"
        if (Test-Path $path) { return $path }
    }
    $command = Get-Command sysmon -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    return $null
}

# 1. Already installed: only replace the settings.
$service = Get-Service 'sysmon*' -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike 'SysmonDrv*' } | Select-Object -First 1
if ($service) {
    $exe = Find-InstalledSysmon
    if (-not $exe) { throw 'Sysmon service exists, but its program was not found.' }
    Write-Host "Sysmon is already installed ($($service.Name)). Updating settings."
    Invoke-Sysmon $exe @('-c', $config)
    Write-Host 'Done. Restart GuardianMascot as administrator.'
    exit 0
}

Confirm-License

# 2. Windows 11 built-in feature: no download needed. The two versions cannot coexist.
$feature = Get-WindowsOptionalFeature -Online -FeatureName 'Sysmon' -ErrorAction SilentlyContinue
if ($feature) {
    Write-Host 'Using the Sysmon feature built into Windows.'
    Enable-WindowsOptionalFeature -Online -FeatureName 'Sysmon' -NoRestart | Out-Null
    $exe = Find-InstalledSysmon
    if (-not $exe) { throw 'The feature was enabled, but the sysmon command was not found. Restart Windows and run this again.' }
    Invoke-Sysmon $exe @('-accepteula', '-i', $config)
    Write-Host 'Done. Restart Windows once: the Sysmon log may not be readable until then.'
    exit 0
}

# 3. Official download. The signature is verified before anything runs.
$folder = Join-Path $env:TEMP ('GuardianMascot-Sysmon-' + [guid]::NewGuid())
New-Item -ItemType Directory $folder | Out-Null
try {
    Write-Host "Downloading $zipUrl"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $zip = Join-Path $folder 'Sysmon.zip'
    Invoke-WebRequest -Uri $zipUrl -OutFile $zip -UseBasicParsing
    Expand-Archive -Path $zip -DestinationPath $folder
    $name = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'Sysmon64a.exe' } else { 'Sysmon64.exe' }
    $exe = Join-Path $folder $name
    if (-not (Test-Path $exe)) { throw "$name was not found in the download." }
    $signature = Get-AuthenticodeSignature $exe
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        throw "The signature is not a valid Microsoft signature: $($signature.Status) $($signature.SignerCertificate.Subject)"
    }
    Write-Host "Signature OK: $($signature.SignerCertificate.Subject)"
    Invoke-Sysmon $exe @('-accepteula', '-i', $config)
    Write-Host 'Done. Restart GuardianMascot as administrator.'
} finally {
    Remove-Item -LiteralPath $folder -Recurse -Force -ErrorAction SilentlyContinue
}
