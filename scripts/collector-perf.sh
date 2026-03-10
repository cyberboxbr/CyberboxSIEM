#!/usr/bin/env bash
# =============================================================================
#  CyberboxSIEM — Collector Performance Sweep
# =============================================================================
#
#  What it measures
#  ----------------
#  Four sweeps, each varying one variable while holding the others fixed:
#
#    1. Batch size          (UDP, fwd_concurrency=4)
#    2. Forwarder concurrency (UDP, batch_size=1000)
#    3. API response delay  (UDP, batch=1000, concurrency=4)  — backpressure
#    4. Source protocol     (batch=1000, concurrency=4)        — UDP vs TCP
#
#  For each run the script:
#    • Starts the mock API (collector-bench mock-api)
#    • Starts the collector (cyberbox-collector)
#    • Starts the sender   (collector-bench send)
#    • Waits WARMUP_SECS for the pipeline to stabilise
#    • Takes a /healthz snapshot (collector-bench snapshot)
#    • Waits MEASURE_SECS
#    • Takes a second /healthz snapshot
#    • Computes delta counters → EPS/drops/latency
#    • Kills everything and prints the result row
#
#  Output columns
#  --------------
#  Test case | rx EPS | fwd EPS | drops | ok batches | err batches | channel depth
#
#  Environment overrides
#  ---------------------
#  SKIP_BUILD=1        skip cargo build --release
#  WARMUP_SECS=N       warmup period (default 3)
#  MEASURE_SECS=N      measurement window (default 15)
#  SENDER_TASKS=N      concurrent sender goroutines (default 8)
# =============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO_ROOT/target/release"
HEALTHZ_URL="http://127.0.0.1:9999"
MOCK_API_PORT=8888
COLLECTOR_UDP_PORT=5514
COLLECTOR_TCP_PORT=5515
WARMUP_SECS="${WARMUP_SECS:-3}"
MEASURE_SECS="${MEASURE_SECS:-15}"
SENDER_TASKS="${SENDER_TASKS:-8}"

# ── Build ─────────────────────────────────────────────────────────────────────

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
    echo "Building release binaries…"
    cd "$REPO_ROOT"
    cargo build --release -p cyberbox-collector -p collector-bench 2>&1 | tail -5
    echo "Build complete."
    echo ""
fi

# ── Helpers ───────────────────────────────────────────────────────────────────

snap() {
    # Returns: udp_rx  tcp_rx  forwarded  channel_full  batches_ok  batches_err  channel_depth
    "$BIN/collector-bench" snapshot --url "$HEALTHZ_URL" 2>/dev/null || echo "0	0	0	0	0	0	0"
}

cleanup() {
    local pids=("$@")
    for p in "${pids[@]}"; do
        kill "$p" 2>/dev/null || true
    done
    for p in "${pids[@]}"; do
        wait "$p" 2>/dev/null || true
    done
    rm -f /tmp/collector-bench-queue.jsonl
    sleep 0.5
}

# Run one test case.
# Args:
#   $1  label
#   $2  protocol (udp|tcp)
#   $3  mock API delay ms
#   $4+ COLLECTOR env var overrides  (KEY=VALUE …)
run_test() {
    local label="$1"
    local protocol="$2"
    local api_delay="$3"
    shift 3

    # ── Start mock API ────────────────────────────────────────────────────────
    "$BIN/collector-bench" mock-api \
        --bind "127.0.0.1:$MOCK_API_PORT" \
        --delay-ms "$api_delay" \
        >/dev/null 2>&1 &
    local mock_pid=$!

    sleep 0.3  # let the socket bind

    # ── Start collector ───────────────────────────────────────────────────────
    local col_target_port
    col_target_port="$( [[ "$protocol" == "tcp" ]] && echo "$COLLECTOR_TCP_PORT" || echo "$COLLECTOR_UDP_PORT" )"

    env \
        COLLECTOR_UDP_BIND="127.0.0.1:$COLLECTOR_UDP_PORT" \
        COLLECTOR_TCP_BIND="127.0.0.1:$COLLECTOR_TCP_PORT" \
        COLLECTOR_API_URL="http://127.0.0.1:$MOCK_API_PORT" \
        COLLECTOR_TENANT_ID="perf-test" \
        COLLECTOR_HEALTHZ_BIND="127.0.0.1:9999" \
        COLLECTOR_QUEUE_PATH="/tmp/collector-bench-queue.jsonl" \
        COLLECTOR_QUEUE_MAX_MB="10" \
        COLLECTOR_HEARTBEAT_SECS="0" \
        COLLECTOR_WEL_CHANNELS="" \
        RUST_LOG="error" \
        "$@" \
        "$BIN/cyberbox-collector" \
        >/dev/null 2>&1 &
    local col_pid=$!

    sleep 1  # let sources start listening

    # ── Start sender ──────────────────────────────────────────────────────────
    "$BIN/collector-bench" send \
        --target "127.0.0.1:$col_target_port" \
        --protocol "$protocol" \
        --concurrency "$SENDER_TASKS" \
        --rate 0 \
        --duration $(( WARMUP_SECS + MEASURE_SECS + 2 )) \
        >/dev/null 2>&1 &
    local send_pid=$!

    # ── Warmup ────────────────────────────────────────────────────────────────
    sleep "$WARMUP_SECS"

    # ── Snapshot t0 ───────────────────────────────────────────────────────────
    read -r udp0 tcp0 fwd0 drop0 ok0 err0 depth0 < <(snap)
    local t0=$SECONDS

    # ── Measurement window ────────────────────────────────────────────────────
    sleep "$MEASURE_SECS"

    # ── Snapshot t1 ───────────────────────────────────────────────────────────
    read -r udp1 tcp1 fwd1 drop1 ok1 err1 depth1 < <(snap)
    local elapsed=$(( SECONDS - t0 ))
    [[ $elapsed -eq 0 ]] && elapsed=1

    # ── Compute deltas ────────────────────────────────────────────────────────
    local rx_eps fwd_eps drop_total ok_total err_total

    if [[ "$protocol" == "udp" ]]; then
        rx_eps=$(( (udp1 - udp0) / elapsed ))
    else
        rx_eps=$(( (tcp1 - tcp0) / elapsed ))
    fi
    fwd_eps=$(( (fwd1 - fwd0) / elapsed ))
    drop_total=$(( drop1 - drop0 ))
    ok_total=$(( ok1 - ok0 ))
    err_total=$(( err1 - err0 ))

    # ── Print row ─────────────────────────────────────────────────────────────
    printf "| %-42s | %9d | %9d | %9d | %7d | %7d |\n" \
        "$label" "$rx_eps" "$fwd_eps" "$drop_total" "$ok_total" "$err_total"

    # ── Cleanup ───────────────────────────────────────────────────────────────
    cleanup "$send_pid" "$col_pid" "$mock_pid"
}

# ── Header ────────────────────────────────────────────────────────────────────

echo "======================================================================"
echo " CyberboxSIEM — Collector Performance Sweep  $(date)"
echo " warmup=${WARMUP_SECS}s  measure=${MEASURE_SECS}s  sender_tasks=${SENDER_TASKS}"
echo "======================================================================"
echo ""

print_header() {
    local title="$1"
    echo ""
    echo "### $title"
    printf "| %-42s | %9s | %9s | %9s | %7s | %7s |\n" \
        "Test case" "rx EPS" "fwd EPS" "drops" "ok" "err"
    printf "|%s|%s|%s|%s|%s|%s|\n" \
        "$(printf '%.0s-' {1..44})" \
        "$(printf '%.0s-' {1..11})" \
        "$(printf '%.0s-' {1..11})" \
        "$(printf '%.0s-' {1..11})" \
        "$(printf '%.0s-' {1..9})" \
        "$(printf '%.0s-' {1..9})"
}

# =============================================================================
#  Sweep 1 — Batch size
# =============================================================================
print_header "Batch size sweep  (UDP, fwd_concurrency=4, flush=100ms)"
for bs in 100 500 1000 2500 5000; do
    run_test "batch_size=$bs" udp 0 \
        COLLECTOR_BATCH_SIZE="$bs" \
        COLLECTOR_FWD_CONCURRENCY=4 \
        COLLECTOR_FLUSH_MS=100
done

# =============================================================================
#  Sweep 2 — Forwarder concurrency
# =============================================================================
print_header "Forwarder concurrency sweep  (UDP, batch_size=1000, flush=100ms)"
for c in 1 2 4 8 16; do
    run_test "fwd_concurrency=$c" udp 0 \
        COLLECTOR_BATCH_SIZE=1000 \
        COLLECTOR_FWD_CONCURRENCY="$c" \
        COLLECTOR_FLUSH_MS=100
done

# =============================================================================
#  Sweep 3 — API response latency (backpressure)
# =============================================================================
print_header "API response delay  (UDP, batch_size=1000, concurrency=4)"
for delay in 0 5 20 50 100; do
    run_test "api_delay=${delay}ms" udp "$delay" \
        COLLECTOR_BATCH_SIZE=1000 \
        COLLECTOR_FWD_CONCURRENCY=4 \
        COLLECTOR_FLUSH_MS=100
done

# =============================================================================
#  Sweep 4 — Source protocol
# =============================================================================
print_header "Source protocol  (batch_size=1000, concurrency=4)"
run_test "protocol=udp" udp 0 \
    COLLECTOR_BATCH_SIZE=1000 \
    COLLECTOR_FWD_CONCURRENCY=4 \
    COLLECTOR_FLUSH_MS=100

run_test "protocol=tcp" tcp 0 \
    COLLECTOR_BATCH_SIZE=1000 \
    COLLECTOR_FWD_CONCURRENCY=4 \
    COLLECTOR_FLUSH_MS=100

# =============================================================================
#  Sweep 5 — Flush interval
# =============================================================================
print_header "Flush interval  (UDP, batch_size=1000, concurrency=4)"
for ms in 10 50 100 500 1000; do
    run_test "flush_interval=${ms}ms" udp 0 \
        COLLECTOR_BATCH_SIZE=1000 \
        COLLECTOR_FWD_CONCURRENCY=4 \
        COLLECTOR_FLUSH_MS="$ms"
done

echo ""
echo "======================================================================"
echo " Sweep complete."
echo "======================================================================"
