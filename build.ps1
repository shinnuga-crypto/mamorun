# テスト → 自己検査 → EXE作成 → EXEの自己検査 → 配布ZIP の順に実行する。
# 使い方: powershell -ExecutionPolicy Bypass -File build.ps1
# 出力: release\最新版\GuardianMascot.exe（いつもここが最新）、release\1つ前\（1つ前の版）、
#       release\GuardianMascot-<版>-win64.zip（最新と1つ前の分だけ残す）
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$env:PYTHONDONTWRITEBYTECODE = '1'
$version = (python -c "from guardian import VERSION; print(VERSION)").Trim()
$name = "GuardianMascot-$version-win64"
$work = Join-Path $PSScriptRoot 'work\build'
$release = Join-Path $PSScriptRoot 'release'
$stage = Join-Path $work "stage\$name"
# Windows PowerShell 5.1 はBOMなしUTF-8を誤読するので、日本語の名前は文字コードで指定する
$latest = Join-Path $release (-join ([char[]](0x6700, 0x65B0, 0x7248)))          # 最新版
$previous = Join-Path $release ('1' + (-join ([char[]](0x3064, 0x524D))))         # 1つ前
$manual = -join ([char[]](0x8AAC, 0x660E, 0x66F8)) + '.md'                         # 説明書.md

function Test-InUse([string]$folder) {
    # 起動中のEXEは排他で開けないので、誰の権限で起動していても見分けられる。開くだけで変更しない
    $exe = Join-Path $folder 'GuardianMascot.exe'
    if (-not (Test-Path $exe)) { return $false }
    try { [IO.File]::Open($exe, 'Open', 'ReadWrite', 'None').Close(); return $false } catch { return $true }
}

function Read-Version([string]$folder) {
    $file = Join-Path $folder 'version.txt'
    if (Test-Path $file) { return (Get-Content $file -Raw).Trim() }
    return $null
}

# 使用中のフォルダを消さないよう、何も変える前に確かめる
foreach ($folder in @($latest, $previous)) {
    if (Test-InUse $folder) { throw "GuardianMascot in $folder is running. Close it, then build again." }
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

# 配布するのはEXE 1つ。まず作業フォルダで組み立てて確かめる
python -m PyInstaller main.py @common --onefile --distpath "$work\onefile" --workpath "$work\pyi-onefile"
if ($LASTEXITCODE -ne 0) { throw 'PyInstaller (onefile) failed' }

if (Test-Path $stage) { [IO.Directory]::Delete($stage, $true) }
New-Item -ItemType Directory -Force $stage | Out-Null
Copy-Item "$work\onefile\GuardianMascot.exe" $stage
Copy-Item 'LICENSE' $stage
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

New-Item -ItemType Directory -Force $release | Out-Null
$zip = Join-Path $release "$name.zip"
if (Test-Path $zip) { [IO.File]::Delete($zip) }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($stage, $zip, 'Optimal', $true, [Text.Encoding]::UTF8)
$hash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
"$hash  $name.zip" | Out-File "$zip.sha256" -Encoding ascii

# 最新版を入れ替える。版が変わったときだけ、今の最新版を「1つ前」へ回す
$oldVersion = Read-Version $latest
if (Test-Path $latest) {
    if ($oldVersion -and $oldVersion -ne $version) {
        if (Test-Path $previous) { [IO.Directory]::Delete($previous, $true) }
        Move-Item $latest $previous
    } else {
        [IO.Directory]::Delete($latest, $true)
    }
}
Copy-Item $stage $latest -Recurse
$version | Out-File (Join-Path $latest 'version.txt') -Encoding ascii

# 最新と1つ前以外の版を消す（ZIPと、以前の版ごとのフォルダ）。使用中のものは残して知らせる
$keep = @($version, (Read-Version $previous)) | Where-Object { $_ }
Get-ChildItem $release -Filter 'GuardianMascot-*-win64*' | ForEach-Object {
    if ($_.Name -match '^GuardianMascot-(.+)-win64(\.zip(\.sha256)?)?$' -and $keep -notcontains $Matches[1]) {
        if ($_.PSIsContainer) {
            if (Test-InUse $_.FullName) { Write-Warning "$($_.Name) is in use. Left as is." }
            else { [IO.Directory]::Delete($_.FullName, $true) }
        } else {
            [IO.File]::Delete($_.FullName)
        }
    } elseif ($_.PSIsContainer) {
        # 版ごとのフォルダは作らなくなった。中身は最新版か1つ前にある
        if (Test-InUse $_.FullName) { Write-Warning "$($_.Name) is in use. Left as is." }
        else { [IO.Directory]::Delete($_.FullName, $true) }
    }
}
"OK: $latest\GuardianMascot.exe ($version)"
"ZIP: $zip"
"SHA256: $hash"
