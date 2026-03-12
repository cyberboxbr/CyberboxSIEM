# generate-signing-cert.ps1 — Create a self-signed code signing certificate
#
# Run ONCE on the build machine. The cert is stored in the Windows cert store
# and exported as:
#   - cyberbox-signing.pfx  (private key — keep secret, use in CI)
#   - cyberbox-signing.cer  (public cert — distribute to clients)
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts/generate-signing-cert.ps1

param(
    [string]$Subject     = "CN=Cyberbox Security, O=Cyberbox Security, L=Sao Paulo, S=SP, C=BR",
    [string]$OutDir      = "$PSScriptRoot\..\packaging\windows",
    [int]$ValidYears     = 3,
    [string]$PfxPassword = ""
)

$ErrorActionPreference = "Stop"

Write-Host "=== Generating Code Signing Certificate ===" -ForegroundColor Cyan

# Prompt for PFX password if not provided
if (-not $PfxPassword) {
    $secPwd = Read-Host "Enter PFX export password" -AsSecureString
} else {
    $secPwd = ConvertTo-SecureString $PfxPassword -AsPlainText -Force
}

# Create a self-signed code signing certificate (valid for $ValidYears years)
$cert = New-SelfSignedCertificate `
    -Subject $Subject `
    -Type CodeSigningCert `
    -CertStoreLocation Cert:\CurrentUser\My `
    -NotAfter (Get-Date).AddYears($ValidYears) `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -HashAlgorithm SHA256 `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3")

Write-Host "[+] Certificate created: $($cert.Thumbprint)" -ForegroundColor Green

# Export PFX (private key — for signing)
$pfxPath = Join-Path $OutDir "cyberbox-signing.pfx"
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $secPwd | Out-Null
Write-Host "[+] PFX exported to: $pfxPath" -ForegroundColor Green
Write-Host "    KEEP THIS FILE SECRET — add to CI as a secret, do NOT commit." -ForegroundColor Yellow

# Export public certificate (for client trust)
$cerPath = Join-Path $OutDir "cyberbox-signing.cer"
Export-Certificate -Cert $cert -FilePath $cerPath -Type CERT | Out-Null
Write-Host "[+] Public cert exported to: $cerPath" -ForegroundColor Green
Write-Host "    This file is safe to distribute and commit." -ForegroundColor Gray

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Cyan
Write-Host "Thumbprint: $($cert.Thumbprint)"
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Run build-msi.ps1 -Sign to build and sign the MSI"
Write-Host "  2. Upload cyberbox-signing.pfx to GitHub Secrets as SIGNING_PFX_BASE64"
Write-Host "     (base64 encode: [Convert]::ToBase64String([IO.File]::ReadAllBytes('$pfxPath')))"
Write-Host "  3. Commit cyberbox-signing.cer (public cert) to the repo"
