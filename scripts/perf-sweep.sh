#!/usr/bin/env bash
# perf-sweep.sh — Build release binaries, start the API server with unlimited EPS,
# then run cyberbox-loadgen across a matrix of concurrency × batch-size configs.
#
# Usage:
#   bash scripts/perf-sweep.sh [--duration 15] [--api-base http://127.0.0.1:8080]
#
# Env overrides:
#   SWEEP_DURATION   seconds per scenario (default: 15)
#   SKIP_BUILD       set to 1 to skip cargo build --release
#   API_BASE         loadgen target (default: http://127.0.0.1:8080)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="$REPO_ROOT/target/release"
LOG_DIR="$REPO_ROOT/logs/perf-sweep"
DURATION="${SWEEP_DURATION:-15}"
API_BASE="${API_BASE:-http://127.0.0.1:8080}"
SKIP_BUILD="${SKIP_BUILD:-0}"

mkdir -p "$LOG_DIR"

# ── 1. Build ──────────────────────────────────────────────────────────────────
if [[ "$SKIP_BUILD" != "1" ]]; then
  echo "==> Building release binaries…"
  cargo build --release -p cyberbox-api -p cyberbox-loadgen 2>&1 | tail -5
  echo "    done."
fi

# ── 2. Start API server ───────────────────────────────────────────────────────
SERVER_LOG="$LOG_DIR/server.log"
echo "==> Starting cyberbox-api (EPS limit=10 000 000, auth disabled)…"

# Raise EPS limit well above what any single-machine test can saturate.
# Keep auth disabled (default) so the loadgen's plain headers work.
CYBERBOX__EPS_LIMIT_PER_TENANT=10000000 \
CYBERBOX__EPS_BURST_SECONDS=5 \
CYBERBOX__KAFKA_PUBLISH_RAW_ENABLED=false \
CYBERBOX__CLICKHOUSE_SEARCH_ENABLED=false \
"$BIN_DIR/cyberbox-api" > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!

# Ensure the server is killed on exit, even on error.
cleanup() {
  if kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "==> Stopping server (PID $SERVER_PID)…"
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# Wait for the server to become healthy (up to 15 s).
echo "    waiting for health check…"
for i in $(seq 1 30); do
  if curl -sf "$API_BASE/healthz" > /dev/null 2>&1; then
    echo "    server ready after ${i}×0.5s"
    break
  fi
  if [[ $i -eq 30 ]]; then
    echo "ERROR: server did not become healthy in 15s. Check $SERVER_LOG"
    exit 1
  fi
  sleep 0.5
done

# ── 3. Helper ─────────────────────────────────────────────────────────────────
run_scenario() {
  local label="$1"
  local concurrency="$2"
  local batch_size="$3"
  local target_eps="${4:-}"          # empty = max-throughput mode
  local report_path="$LOG_DIR/${label}.json"

  echo ""
  echo "── $label ──"
  printf "   concurrency=%-4s  batch=%-5s  " "$concurrency" "$batch_size"
  if [[ -n "$target_eps" ]]; then
    printf "mode=fixed-rate  target_eps=%s\n" "$target_eps"
  else
    printf "mode=max-throughput\n"
  fi

  local args=(
    --api-base "$API_BASE"
    --duration-seconds "$DURATION"
    --concurrency "$concurrency"
    --batch-size "$batch_size"
    --tenant-id "bench-tenant"
    --user-id "soc-admin"
    --skip-persist-check
    --report-path "$report_path"
  )
  if [[ -n "$target_eps" ]]; then
    args+=(--target-eps "$target_eps")
  fi

  "$BIN_DIR/cyberbox-loadgen" "${args[@]}" 2>/dev/null
  # Print key fields from the JSON report using awk (no python required).
  awk -F': ' '
    /"accepted_eps_target_window"/ { gsub(/,/,"",$2); accepted=$2 }
    /"attempted_eps"/              { gsub(/,/,"",$2); attempted=$2 }
    /"api_rejection_loss_pct"/     { gsub(/,/,"",$2); loss=$2 }
    /"request_latency_p95_ms"/     { gsub(/,/,"",$2); p95=$2 }
    /"request_latency_p99_ms"/     { gsub(/,/,"",$2); p99=$2 }
    /"target_achieved_pct"/        { gsub(/,/,"",$2); if($2!="null") target=$2 }
    END {
      printf "   accepted_eps   : %10s  (attempted: %s)\n", accepted, attempted
      printf "   rejection_loss : %9s%%\n", loss
      printf "   p95_latency_ms : %10s\n", p95
      printf "   p99_latency_ms : %10s\n", p99
      if (target != "") printf "   target_achieved: %8s%%\n", target
    }
  ' "$report_path" || echo "   (parse error — see $report_path)"
}

# ── 4. Max-throughput matrix ──────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
echo "  MAX-THROUGHPUT SWEEP  (${DURATION}s per scenario)"
echo "════════════════════════════════════════════════════════"

#         label                    conc  batch
run_scenario "max_c1_b100"           1    100
run_scenario "max_c4_b100"           4    100
run_scenario "max_c8_b100"           8    100
run_scenario "max_c16_b100"         16    100
run_scenario "max_c8_b50"            8     50
run_scenario "max_c8_b500"           8    500
run_scenario "max_c8_b1000"          8   1000
run_scenario "max_c16_b500"         16    500

# ── 5. Fixed-rate scenarios ───────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
echo "  FIXED-RATE SWEEP  (${DURATION}s per scenario)"
echo "════════════════════════════════════════════════════════"

#         label                    conc  batch  target_eps
run_scenario "rate_1k_c4_b100"       4    100    1000
run_scenario "rate_5k_c8_b100"       8    100    5000
run_scenario "rate_10k_c8_b100"      8    100   10000
run_scenario "rate_20k_c16_b100"    16    100   20000
run_scenario "rate_50k_c16_b500"    16    500   50000

echo ""
echo "════════════════════════════════════════════════════════"
echo "  Reports written to: $LOG_DIR/"
echo "════════════════════════════════════════════════════════"
