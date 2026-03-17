$config = @"
[collector]
host = "192.168.26.128"
port = 601
protocol = "syslog"

[agent]
tenant_id = "safebox"

[[source]]
type = "wineventlog"
channels = ["Security", "System", "Application"]

[api]
url = "https://siem.cyberboxsecurity.com.br"
heartbeat_secs = 30
"@

Set-Content -Path "C:\ProgramData\Cyberbox\agent.toml" -Value $config -Encoding UTF8
Write-Host "Config updated with API registration"
Restart-Service CyberboxAgent
Start-Sleep 3
Get-Service CyberboxAgent | Format-List Name,Status
