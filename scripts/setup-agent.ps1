# CyberboxSIEM Agent Setup Script
# Run as Administrator: powershell -ExecutionPolicy Bypass -File setup-agent.ps1

#Requires -RunAsAdministrator

$ConfigDir = "$env:ProgramData\Cyberbox"
$ConfigFile = "$ConfigDir\agent.toml"

# --- Configuration ---
$CollectorHost = "10.10.0.1"
$CollectorPort = 601
$TenantId = "safebox"
# ---------------------

Write-Host "=== CyberboxSIEM Agent Setup ===" -ForegroundColor Cyan

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
