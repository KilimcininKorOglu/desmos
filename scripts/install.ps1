# Desmos installer for Windows — downloads the latest MSI and runs it.
#
# Usage (PowerShell, run as Administrator):
#   irm https://raw.githubusercontent.com/KilimcininKorOglu/desmos/main/scripts/install.ps1 | iex
#
# Options:
#   $env:DESMOS_VERSION = "1.1.0"   Pin a specific version

$ErrorActionPreference = "Stop"
$Repo = "KilimcininKorOglu/desmos"

function Log($label, $msg) {
    Write-Host "  $label" -ForegroundColor Green -NoNewline
    Write-Host " $msg"
}

function Die($msg) {
    Write-Host "  error:" -ForegroundColor Red -NoNewline
    Write-Host " $msg"
    exit 1
}

# --- Resolve version --------------------------------------------------------

if ($env:DESMOS_VERSION) {
    $Version = $env:DESMOS_VERSION
    Log "version" "$Version (pinned)"
} else {
    try {
        $release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest"
        $Version = $release.tag_name -replace '^v', ''
        Log "version" "$Version (latest)"
    } catch {
        Die "could not resolve latest version: $_"
    }
}

# --- Download MSI -----------------------------------------------------------

$MsiName = "desmos-${Version}-x64.msi"
$Url = "https://github.com/$Repo/releases/download/v${Version}/$MsiName"
$SumsUrl = "https://github.com/$Repo/releases/download/v${Version}/SHA256SUMS.txt"
$TmpDir = Join-Path $env:TEMP "desmos-install"

if (Test-Path $TmpDir) { Remove-Item -Recurse -Force $TmpDir }
New-Item -ItemType Directory -Path $TmpDir | Out-Null

$MsiPath = Join-Path $TmpDir $MsiName

Log "download" $Url
try {
    Invoke-WebRequest -Uri $Url -OutFile $MsiPath -UseBasicParsing
} catch {
    Die "download failed: $_"
}

# --- Verify checksum --------------------------------------------------------

Log "verify" "downloading SHA256SUMS.txt"
try {
    $sums = Invoke-WebRequest -Uri $SumsUrl -UseBasicParsing
    $lines = $sums.Content -split "`n"
    $expected = ($lines | Where-Object { $_ -match $MsiName } | ForEach-Object { ($_ -split '\s+')[0] })[0]

    if (-not $expected) {
        Die "MSI not found in SHA256SUMS.txt"
    }

    $actual = (Get-FileHash -Path $MsiPath -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $expected) {
        Die "checksum mismatch: expected $expected, got $actual"
    }
    Log "verify" "SHA256 OK"
} catch {
    Write-Host "  warn: checksum verification failed, continuing anyway" -ForegroundColor Yellow
}

# --- Install ----------------------------------------------------------------

Log "install" "running MSI installer"
$proc = Start-Process msiexec.exe -ArgumentList "/i `"$MsiPath`" /quiet /norestart" -Wait -PassThru

if ($proc.ExitCode -ne 0) {
    Die "MSI installer failed with exit code $($proc.ExitCode)"
}

# --- Wintun -----------------------------------------------------------------

$DesmosBin = "C:\Program Files\Desmos"
$WintunPath = Join-Path $DesmosBin "wintun.dll"

if (-not (Test-Path $WintunPath)) {
    Log "wintun" "downloading wintun.dll"
    try {
        $wintunZip = Join-Path $TmpDir "wintun.zip"
        Invoke-WebRequest -Uri "https://www.wintun.net/builds/wintun-0.14.1.zip" -OutFile $wintunZip -UseBasicParsing
        Expand-Archive -Path $wintunZip -DestinationPath (Join-Path $TmpDir "wintun")
        Copy-Item (Join-Path $TmpDir "wintun\wintun\bin\amd64\wintun.dll") $WintunPath
        Log "wintun" "installed to $WintunPath"
    } catch {
        Write-Host "  warn: could not download wintun.dll — download manually from https://www.wintun.net/" -ForegroundColor Yellow
    }
}

# --- Cleanup and finish -----------------------------------------------------

Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue

$desmos = Join-Path $DesmosBin "desmos.exe"
if (Test-Path $desmos) {
    $ver = & $desmos version 2>&1
    Log "installed" $ver
} else {
    Log "installed" "desmos (version check skipped)"
}

Write-Host ""
Write-Host "  Desmos installed successfully."
Write-Host ""
Write-Host "  Next steps:"
Write-Host "    1. Generate a config:   desmos config generate > C:\ProgramData\Desmos\config.toml"
Write-Host "    2. Edit the config"
Write-Host "    3. Start the tunnel:    desmos up --config C:\ProgramData\Desmos\config.toml"
Write-Host ""
Write-Host "  Full guide: https://github.com/$Repo/blob/main/docs/getting-started.md"
Write-Host ""
