# build-msi.ps1 - Build the Cyberbox Agent MSI installer
#
# Prerequisites:
#   1. Rust toolchain: cargo build --release -p cyberbox-agent
#   2. WiX Toolset v4: winget install WixToolset.WiX
#
# Usage:
#   .\packaging\windows\build-msi.ps1 [-Version "0.1.0"]
#   .\packaging\windows\build-msi.ps1 [-Version "0.1.0"] -Sign
#   .\packaging\windows\build-msi.ps1 [-Version "0.1.0"] -Sign -PfxPath "path\to\cert.pfx" -PfxPassword "pass"

param(
    [string]$Version     = "0.1.0",
    [switch]$Sign,
    [string]$PfxPath     = "",
    [string]$PfxPassword = ""
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

# Step 2: Sign the EXE (before packaging into MSI)
if ($Sign) {
    Write-Host "Signing binary..." -ForegroundColor Yellow

    $signingCert = $null

    if ($PfxPath) {
        # Use provided PFX file
        if (-not (Test-Path $PfxPath)) { throw "PFX file not found: $PfxPath" }
        if ($PfxPassword) {
            $secPwd = ConvertTo-SecureString $PfxPassword -AsPlainText -Force
        } else {
            $secPwd = Read-Host "Enter PFX password" -AsSecureString
        }
        $signingCert = Get-PfxCertificate -FilePath $PfxPath -Password $secPwd
    } else {
        # Find code signing cert in CurrentUser store
        $signingCert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
            Where-Object { $_.Subject -like "*Cyberbox*" } |
            Sort-Object NotAfter -Descending |
            Select-Object -First 1

        if (-not $signingCert) {
            throw "No Cyberbox code signing certificate found. Run generate-signing-cert.ps1 first, or pass -PfxPath."
        }
    }

    Write-Host "  Using cert: $($signingCert.Subject) [$($signingCert.Thumbprint.Substring(0,8))...]" -ForegroundColor Gray

    $sig = Set-AuthenticodeSignature `
        -FilePath $BinaryPath `
        -Certificate $signingCert `
        -TimestampServer "http://timestamp.digicert.com" `
        -HashAlgorithm SHA256

    if ($sig.Status -eq "Valid" -or $sig.Status -eq "UnknownError") {
        # UnknownError = signed but self-signed cert not in local trust store (expected)
        Write-Host "[+] Binary signed ($($sig.Status))" -ForegroundColor Green
    } else {
        throw "EXE signing failed: $($sig.Status) - $($sig.StatusMessage)"
    }
}

# Step 3: Build MSI
Write-Host "Running WiX build..." -ForegroundColor Yellow
wix build $WxsPath `
    -d Version=$Version `
    -d BinaryPath=$BinaryPath `
    -d ConfigPath=$ConfigPath `
    -d IconPath=$IconPath `
    -o $OutputMsi

if ($LASTEXITCODE -ne 0) { throw "WiX build failed" }

# Step 4: Sign the MSI
if ($Sign) {
    Write-Host "Signing MSI..." -ForegroundColor Yellow

    $sig = Set-AuthenticodeSignature `
        -FilePath $OutputMsi `
        -Certificate $signingCert `
        -TimestampServer "http://timestamp.digicert.com" `
        -HashAlgorithm SHA256

    if ($sig.Status -eq "Valid" -or $sig.Status -eq "UnknownError") {
        Write-Host "[+] MSI signed ($($sig.Status))" -ForegroundColor Green
    } else {
        Write-Host "[!] MSI signing returned: $($sig.Status) - $($sig.StatusMessage)" -ForegroundColor Yellow
    }
}

$Size = [math]::Round((Get-Item $OutputMsi).Length / 1MB, 2)
Write-Host ""
Write-Host "=== MSI built successfully ===" -ForegroundColor Green
Write-Host "  Output: $OutputMsi"
Write-Host "  Size:   $Size MB"
if ($Sign) {
    Write-Host "  Signed: Yes (Authenticode SHA256)" -ForegroundColor Green
}
Write-Host ""
Write-Host "Install:   msiexec /i `"$OutputMsi`" /qn" -ForegroundColor Gray
Write-Host "Uninstall: msiexec /x `"$OutputMsi`" /qn" -ForegroundColor Gray
