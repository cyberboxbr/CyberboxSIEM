# build-msi.ps1 — Build the Cyberbox Agent MSI installer
#
# Prerequisites:
#   1. Rust toolchain: cargo build --release -p cyberbox-agent
#   2. WiX Toolset v4: winget install WixToolset.WiX
#
# Usage:
#   .\packaging\windows\build-msi.ps1 [-Version "0.1.0"]

param(
    [string]$Version = "0.1.0"
)

$ErrorActionPreference = "Stop"
$Root = (Get-Item "$PSScriptRoot\..\..").FullName

Write-Host "=== Building Cyberbox Agent MSI v$Version ===" -ForegroundColor Cyan

# Step 1: Build release binary
Write-Host "Building release binary..." -ForegroundColor Yellow
Push-Location $Root
cargo build --release -p cyberbox-agent
if ($LASTEXITCODE -ne 0) { throw "Cargo build failed" }
Pop-Location

$BinaryPath   = "$Root\target\release\cyberbox-agent.exe"
$ConfigPath   = "$Root\apps\cyberbox-agent\agent.example.toml"
$IconPath     = "$Root\web\cyberbox-ui\public\cyberboxlogo.png"
$WxsPath      = "$Root\packaging\windows\cyberbox-agent.wxs"
$OutputMsi    = "$Root\packaging\windows\cyberbox-agent-$Version.msi"

# Verify files exist
foreach ($f in @($BinaryPath, $ConfigPath, $IconPath, $WxsPath)) {
    if (-not (Test-Path $f)) { throw "Required file not found: $f" }
}

# Step 2: Build MSI
Write-Host "Running WiX build..." -ForegroundColor Yellow
wix build $WxsPath `
    -d Version=$Version `
    -d BinaryPath=$BinaryPath `
    -d ConfigPath=$ConfigPath `
    -d IconPath=$IconPath `
    -o $OutputMsi

if ($LASTEXITCODE -ne 0) { throw "WiX build failed" }

$Size = [math]::Round((Get-Item $OutputMsi).Length / 1MB, 2)
Write-Host ""
Write-Host "=== MSI built successfully ===" -ForegroundColor Green
Write-Host "  Output: $OutputMsi"
Write-Host "  Size:   $Size MB"
Write-Host ""
Write-Host "Install:   msiexec /i `"$OutputMsi`" /qn" -ForegroundColor Gray
Write-Host "Uninstall: msiexec /x `"$OutputMsi`" /qn" -ForegroundColor Gray
