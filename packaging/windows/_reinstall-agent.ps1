Stop-Service CyberboxAgent -Force -ErrorAction SilentlyContinue
Start-Sleep 3
Copy-Item "C:\Code\CyberboxSIEM\target\release\cyberbox-agent.exe" "C:\Program Files\Cyberbox\Agent\cyberbox-agent.exe" -Force
Start-Service CyberboxAgent
Start-Sleep 2
Get-Service CyberboxAgent | Format-List Name,Status
