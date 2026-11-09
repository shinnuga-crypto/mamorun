# テスト → 自己検査 → EXE作成 → EXEの自己検査 → 配布ZIP の順に実行する。
# 使い方: powershell -ExecutionPolicy Bypass -File build.ps1
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$env:PYTHONDONTWRITEBYTECODE = '1'
$version = (python -c "from guardian import VERSION; print(VERSION)").Trim()
$name = "GuardianMascot-$version-win64"
$work = Join-Path $PSScriptRoot 'work\build'
$release = Join-Path $PSScriptRoot 'release'
$stage = Join-Path $release $name

# 使用中のフォルダを消さないよう、最初に確かめる。起動中のEXEは排他で開けないので、
# 誰の権限で起動していても見分けられる。開くだけで、ファイルは変更しない。
$stageExe = Join-Path $stage 'GuardianMascot.exe'
if (Test-Path $stageExe) {
    try {
        [IO.File]::Open($stageExe, 'Open', 'ReadWrite', 'None').Close()
    } catch {
        throw 'This version in release is in use. Close GuardianMascot, then build again.'
    }
}

python tests.py
if ($LASTEXITCODE -ne 0) { throw 'tests failed' }

python main.py --self-check work\check\source-check.json --shots-dir work\check\shots
if ($LASTEXITCODE -ne 0) { throw 'source self-check failed' }

# 絵はEXEの中に入れる。raw は納品時の原本なので入れない
$common = @(
    '--noconfirm', '--clean', '--windowed', '--name', 'GuardianMascot', '--specpath', "$work\spec",
    '--add-data', "$PSScriptRoot\assets\mascot\luce;assets\mascot\luce",
    '--add-data', "$PSScriptRoot\assets\mascot\ansel;assets\mascot\ansel",
    '--add-data', "$PSScriptRoot\assets\mascot\silva;assets\mascot\silva",
    '--exclude-module', 'PyQt6.QtWebEngineWidgets', '--exclude-module', 'PyQt6.QtWebEngineCore',
    '--exclude-module', 'PyQt6.QtNetwork', '--exclude-module', 'PyQt6.QtQml', '--exclude-module', 'PyQt6.QtQuick',
    '--exclude-module', 'tkinter', '--exclude-module', 'PIL', '--exclude-module', 'numpy'
)

# 詳しい検査はフォルダ形式で行う。1ファイル形式は起動役と本体でプロセスが分かれ、検査用プロセスの特定ができない
python -m PyInstaller main.py @common --onedir --distpath "$work\dist" --workpath "$work\pyi"
if ($LASTEXITCODE -ne 0) { throw 'PyInstaller failed' }
$check = Join-Path $PSScriptRoot 'work\check\packaged-check.json'
$process = Start-Process "$work\dist\GuardianMascot\GuardianMascot.exe" -ArgumentList '--self-check', $check -Wait -PassThru
if ($process.ExitCode -ne 0) { throw "packaged self-check failed: $($process.ExitCode)" }

# 配布するのはEXE 1つ
python -m PyInstaller main.py @common --onefile --distpath "$work\onefile" --workpath "$work\pyi-onefile"
if ($LASTEXITCODE -ne 0) { throw 'PyInstaller (onefile) failed' }

if (Test-Path $stage) { [IO.Directory]::Delete($stage, $true) }
New-Item -ItemType Directory -Force $stage | Out-Null
Copy-Item "$work\onefile\GuardianMascot.exe" $stage
Copy-Item 'LICENSE' $stage
# Windows PowerShell 5.1 はBOMなしUTF-8を誤読するので、「説明書」を文字コードで指定する
$manual = -join ([char[]](0x8AAC, 0x660E, 0x66F8)) + '.md'
Copy-Item 'README.md' (Join-Path $stage $manual)
# Sysmon は任意で、再配布できないので同梱しない。導入用のファイルと設定だけを入れる
New-Item -ItemType Directory -Force "$stage\Sysmon\tools" | Out-Null
Copy-Item 'tools\mamorun-sysmon.xml', 'tools\install_sysmon.ps1', 'tools\remove_sysmon.ps1' "$stage\Sysmon\tools\"
Copy-Item 'Sysmon*.cmd' "$stage\Sysmon\"

# 配布用EXE 自体の確認。管理者権限は求めず、ほかのプログラムも止めない
$bundle = Join-Path $PSScriptRoot 'work\check\bundle-check.json'
$process = Start-Process "$stage\GuardianMascot.exe" -ArgumentList '--bundle-check', $bundle -Wait -PassThru
if ($process.ExitCode -ne 0) { throw "bundle check failed: $($process.ExitCode)" }
$smoke = Join-Path $PSScriptRoot 'work\check\smoke-data'
$process = Start-Process "$stage\GuardianMascot.exe" -ArgumentList '--no-elevate', '--observe', '--run-seconds', '6', '--data-dir', $smoke -Wait -PassThru
if ($process.ExitCode -ne 0) { throw "smoke run failed: $($process.ExitCode)" }

$zip = Join-Path $release "$name.zip"
if (Test-Path $zip) { [IO.File]::Delete($zip) }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($stage, $zip, 'Optimal', $true, [Text.Encoding]::UTF8)
$hash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
"$hash  $name.zip" | Out-File "$zip.sha256" -Encoding ascii
"OK: $zip"
"SHA256: $hash"
