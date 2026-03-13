# CyberboxSIEM Agent Setup Script
# Run as Administrator: powershell -ExecutionPolicy Bypass -File setup-agent.ps1

#Requires -RunAsAdministrator

$ConfigDir = "$env:ProgramData\Cyberbox"
$ConfigFile = "$ConfigDir\agent.toml"

# --- Configuration ---
$CollectorHost = "192.168.26.128"
$CollectorPort = 601
$TenantId = "safebox"
# ---------------------

Write-Host "=== CyberboxSIEM Agent Setup ===" -ForegroundColor Cyan

# Import Cyberbox code signing certificate to Trusted Publishers
$CertFile = "$PSScriptRoot\cyberbox-signing.cer"
if (-not (Test-Path $CertFile)) {
    $CertFile = "C:\Program Files\Cyberbox\Agent\cyberbox-signing.cer"
}
if (Test-Path $CertFile) {
    Write-Host "[*] Importing code signing certificate..." -ForegroundColor Yellow
    try {
        Import-Certificate -FilePath $CertFile -CertStoreLocation Cert:\LocalMachine\TrustedPublisher -ErrorAction Stop | Out-Null
        Import-Certificate -FilePath $CertFile -CertStoreLocation Cert:\LocalMachine\Root -ErrorAction Stop | Out-Null
        Write-Host "[+] Signing certificate trusted" -ForegroundColor Green
    } catch {
        Write-Host "[!] Could not import certificate: $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "[!] Signing certificate not found — skipping trust import" -ForegroundColor Yellow
}

# Add Windows Defender exclusions (prevents binary quarantine)
Write-Host "[*] Adding Defender exclusions..." -ForegroundColor Yellow
try {
    Add-MpPreference -ExclusionPath "C:\Program Files\Cyberbox" -ErrorAction Stop
    Add-MpPreference -ExclusionPath $ConfigDir -ErrorAction Stop
    Write-Host "[+] Defender exclusions added" -ForegroundColor Green
} catch {
    Write-Host "[!] Could not add Defender exclusions: $_" -ForegroundColor Yellow
    Write-Host "    The agent .exe may be quarantined. Add exclusions manually if needed." -ForegroundColor Yellow
}

# Verify the binary exists (may have been quarantined)
$AgentExe = "C:\Program Files\Cyberbox\Agent\cyberbox-agent.exe"
if (-not (Test-Path $AgentExe)) {
    Write-Host "[-] Agent binary not found at $AgentExe" -ForegroundColor Red
    Write-Host "    Windows Defender may have quarantined it. Check:" -ForegroundColor Yellow
    Write-Host "    Get-MpThreatDetection | Select-Object -First 5 | Format-List" -ForegroundColor Yellow
    Write-Host "    Then reinstall: msiexec /i cyberbox-agent-windows.msi /qn" -ForegroundColor Yellow
    exit 1
}

# Create config directory
if (-not (Test-Path $ConfigDir)) {
    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
    Write-Host "[+] Created $ConfigDir" -ForegroundColor Green
}

# Write config file
$Config = @"
[collector]
host = "$CollectorHost"
port = $CollectorPort
protocol = "syslog"

[agent]
tenant_id = "$TenantId"

[[source]]
type = "wineventlog"
channels = ["Security", "System", "Application"]

[api]
url = "https://siem.cyberboxsecurity.com.br"
heartbeat_secs = 30
"@

Set-Content -Path $ConfigFile -Value $Config -Encoding UTF8
Write-Host "[+] Config written to $ConfigFile" -ForegroundColor Green

# Start the service
$svc = Get-Service -Name CyberboxAgent -ErrorAction SilentlyContinue
if ($null -eq $svc) {
    Write-Host "[-] CyberboxAgent service not found. Install the MSI first." -ForegroundColor Red
    exit 1
}

if ($svc.Status -eq "Running") {
    Write-Host "[*] Restarting service..." -ForegroundColor Yellow
    Restart-Service CyberboxAgent
} else {
    Write-Host "[*] Starting service..." -ForegroundColor Yellow
    Start-Service CyberboxAgent
}

Start-Sleep -Seconds 3
$svc = Get-Service CyberboxAgent
if ($svc.Status -eq "Running") {
    Write-Host "[+] CyberboxAgent is RUNNING" -ForegroundColor Green
} else {
    Write-Host "[-] Service status: $($svc.Status)" -ForegroundColor Red
    Write-Host "    Check logs: Get-WinEvent -LogName Application -MaxEvents 20 | Where-Object { `$_.ProviderName -like '*Cyberbox*' }" -ForegroundColor Yellow
}
