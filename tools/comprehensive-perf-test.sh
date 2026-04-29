#!/usr/bin/env bash
# tools/comprehensive-perf-test.sh
#
# Comprehensive stability and performance test for the private-key-agent.
# Combines memory tracking, concurrency stress testing, and segfault detection
# across four distinct load phases.
#
# Phases:
#   1. Baseline        6c  ×  30s per endpoint   (~120s)
#   2. Sustained load  20c × 120s per endpoint   (~480s)
#   3. Stress burst    50c ×  60s per endpoint   (~240s)
#   4. Recovery check   6c ×  30s per endpoint   (~120s)
#
# Total wall-clock duration: ~15-16 minutes
#
# Usage:
#   ./tools/comprehensive-perf-test.sh
#   ./tools/comprehensive-perf-test.sh -v          # verbose: show raw hey output
#   ./tools/comprehensive-perf-test.sh --no-debug   # skip debug-logging activation
#   BASE_URL=http://agent.example.com ./tools/comprehensive-perf-test.sh
#
# Requires: hey, curl, openssl, docker

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_FILE="$PROJECT_ROOT/config/private-key-agent.yaml"
COMPOSE_FILE="$PROJECT_ROOT/compose.yaml"
BASE_URL="${BASE_URL:-http://localhost}"
VERBOSE=false
ENABLE_DEBUG_LOGGING=true  # Enable debug logging by default for this comprehensive test

while [[ $# -gt 0 ]]; do
    case "$1" in
        -v|--verbose) VERBOSE=true; shift ;;
        --no-debug)   ENABLE_DEBUG_LOGGING=false; shift ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; GRAY='\033[0;90m'; NC='\033[0m'

RESULTS_DIR=$(mktemp -d "/tmp/pka-comprehensive-XXXXXX")
STATS_FILE="$RESULTS_DIR/docker-stats.csv"
BENCH_FILE="$RESULTS_DIR/bench-results.txt"

log()   { echo -e "$*"; }
info()  { log "  ${BLUE}▸${NC} $*"; }
ok()    { log "  ${GREEN}✓${NC} $*"; }
warn()  { log "  ${YELLOW}⚠${NC} $*"; }
die()   { log "  ${RED}✗ ERROR:${NC} $*" >&2; exit 1; }
hdr()   { log "\n${BOLD}$*${NC}"; }

# ── Prerequisites ──────────────────────────────────────────────────────────────

[[ -f "$CONFIG_FILE" ]] || die "Config not found — run: ./tools/setup-dev.sh"
BEARER_TOKEN=$(awk -F'"' '/token:/ {print $2; exit}' "$CONFIG_FILE")
[[ -n "$BEARER_TOKEN" ]] || die "Could not read token from $CONFIG_FILE"
command -v curl    >/dev/null 2>&1 || die "curl required"
command -v openssl >/dev/null 2>&1 || die "openssl required"
command -v hey     >/dev/null 2>&1 || die "hey required (brew install hey)"
command -v docker  >/dev/null 2>&1 || die "docker required"

CONTAINER=$(docker compose -f "$COMPOSE_FILE" ps -q app 2>/dev/null | head -1)
CONTAINER_NAME=$(docker compose -f "$COMPOSE_FILE" ps app 2>/dev/null | awk 'NR==2 {print $1}')
[[ -n "$CONTAINER" ]] || die "App container not running — run: docker compose up -d"

# ── Debug logging setup ──────────────────────────────────────────────────────

ENV_FILE="$PROJECT_ROOT/.env"
ORIG_LOG_LEVEL=$(grep '^LOG_LEVEL=' "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2 || echo "info")
DEBUG_LOGGING_CHANGED=false

if $ENABLE_DEBUG_LOGGING && [[ "$ORIG_LOG_LEVEL" != "debug" ]]; then
    hdr "Enabling debug logging"
    # macOS-compatible in-place sed (portable: write to temp then move)
    sed "s/^LOG_LEVEL=.*/LOG_LEVEL=debug/" "$ENV_FILE" > "$ENV_FILE.tmp" && mv "$ENV_FILE.tmp" "$ENV_FILE"
    docker compose -f "$COMPOSE_FILE" up -d --force-recreate app >/dev/null 2>&1
    # Wait for the container to be ready
    _wait=0
    until curl -sk "${BASE_URL}/health" -o /dev/null -w "%{http_code}" 2>/dev/null | grep -q '200\|503'; do
        sleep 1; _wait=$((_wait + 1))
        [[ $_wait -lt 30 ]] || die "Container did not become ready after restart"
    done
    CONTAINER=$(docker compose -f "$COMPOSE_FILE" ps -q app 2>/dev/null | head -1)
    CONTAINER_NAME=$(docker compose -f "$COMPOSE_FILE" ps app 2>/dev/null | awk 'NR==2 {print $1}')
    DEBUG_LOGGING_CHANGED=true
    ok "Debug logging enabled (was: $ORIG_LOG_LEVEL)"
elif $ENABLE_DEBUG_LOGGING; then
    ok "Debug logging already enabled (LOG_LEVEL=debug)"
else
    info "Running with LOG_LEVEL=$ORIG_LOG_LEVEL (use --no-debug to suppress this step)"
fi

restore_log_level() {
    if $DEBUG_LOGGING_CHANGED; then
        sed "s/^LOG_LEVEL=.*/LOG_LEVEL=$ORIG_LOG_LEVEL/" "$ENV_FILE" > "$ENV_FILE.tmp" \
            && mv "$ENV_FILE.tmp" "$ENV_FILE"
        docker compose -f "$COMPOSE_FILE" up -d --force-recreate app >/dev/null 2>&1 || true
        info "Log level restored to $ORIG_LOG_LEVEL"
    fi
}

# ── Helper: prepare ciphertexts ────────────────────────────────────────────────

prepare_openssl_ciphertext() {
    local pem_file="$1"
    local tmp_pub; tmp_pub=$(mktemp /tmp/pka-XXXXXX.pem)
    local tmp_enc; tmp_enc=$(mktemp /tmp/pka-XXXXXX)
    local plaintext="dev-session-key-12345678"
    local ok=true

    openssl rsa -in "$pem_file" -pubout -out "$tmp_pub" 2>/dev/null || ok=false
    if $ok; then
        printf '%s' "$plaintext" | openssl pkeyutl -encrypt \
            -pubin -inkey "$tmp_pub" -pkeyopt rsa_padding_mode:oaep \
            -pkeyopt rsa_oaep_md:sha256 -out "$tmp_enc" 2>/dev/null || ok=false
    fi
    $ok && base64 < "$tmp_enc"
    rm -f "$tmp_pub" "$tmp_enc"
    $ok
}

# ── Helper: run a single benchmark and capture output ─────────────────────────

run_bench() {
    local phase="$1" label="$2" url="$3" concurrency="$4" duration="$5"
    shift 5
    # remaining args are hey -H / -d options

    local out; out=$(mktemp /tmp/pka-bench-XXXXXX)
    local status=0

    hey -c "$concurrency" -z "$duration" \
        -m POST \
        -H "Authorization: Bearer $BEARER_TOKEN" \
        -H "Content-Type: application/json" \
        "$@" "$url" > "$out" 2>&1 || status=$?

    # Extract summary line from hey output
    # NOTE: hey outputs percentile lines as "  50%% in 0.xxxx secs" (double %)
    local reqs_s avg p50 p95 p99 slowest total_reqs http200 errors
    reqs_s=$(grep  'Requests/sec' "$out"      | awk '{print $2}')
    avg=$(grep     'Average:' "$out"           | awk '{printf "%.1fms", $2*1000}' | head -1)
    p50=$(grep     '50%% in' "$out"            | awk '{printf "%.1fms", $3*1000}' | head -1)
    p95=$(grep     '95%% in' "$out"            | awk '{printf "%.1fms", $3*1000}' | head -1)
    p99=$(grep     '99%% in' "$out"            | awk '{printf "%.1fms", $3*1000}' | head -1)
    slowest=$(grep 'Slowest:' "$out"           | awk '{printf "%.1fms", $2*1000}' | head -1)
    # Total requests = sum of all status code response counts
    total_reqs=$(grep -E '^\s+\[[0-9]+\]' "$out" | awk '{s+=$2} END{print s+0}')
    http200=$(grep '\[200\]' "$out"            | awk '{print $2}' | head -1)
    errors=$(grep -E '^\s+\[([^2][0-9]{2}|2[^0][0-9]|20[^0])\]' "$out" \
                | awk 'BEGIN{s=0} {s+=$2} END{print s}')
    [[ -z "$errors" ]] && errors=0

    # Include non-HTTP transport errors
    local eof_count reset_count
    eof_count=$(grep -c '\[.*\] EOF' "$out" || true)
    reset_count=$(grep -c '\[.*\] connection reset' "$out" || true)

    if $VERBOSE; then
        cat "$out"
    fi

    # Append to bench results file
    printf "PHASE=%s|LABEL=%s|CONCURRENCY=%s|DURATION=%s|REQS_S=%s|AVG=%s|P50=%s|P95=%s|P99=%s|SLOWEST=%s|TOTAL=%s|HTTP200=%s|ERRORS=%s|EOF=%s|RESET=%s\n" \
        "$phase" "$label" "$concurrency" "$duration" \
        "${reqs_s:-?}" "${avg:-?}" "${p50:-?}" "${p95:-?}" "${p99:-?}" "${slowest:-?}" \
        "${total_reqs:-?}" "${http200:-?}" "${errors}" "${eof_count}" "${reset_count}" \
        >> "$BENCH_FILE"

    rm -f "$out"
    return $status
}

# ── Helper: run all 4 endpoints for a given phase ─────────────────────────────

run_phase() {
    local phase_label="$1" concurrency="$2" duration="$3"

    info "Phase: ${BOLD}$phase_label${NC}  (concurrency=$concurrency, duration=$duration)"

    # --- Sign OpenSSL ---
    local HASH SIGN_BODY
    HASH=$(printf '%s' 'perf-test-payload' | openssl dgst -sha256 -binary | base64)
    SIGN_BODY="{\"algorithm\":\"rsa-pkcs1-v1_5-sha256\",\"hash\":\"$HASH\"}"

    run_bench "$phase_label" "sign/dev-signing-key" \
        "${BASE_URL}/sign/dev-signing-key" \
        "$concurrency" "$duration" \
        -d "$SIGN_BODY" || warn "sign/dev-signing-key phase had errors"

    # --- Decrypt OpenSSL ---
    if [[ -n "${OPENSSL_DECRYPT_BODY:-}" ]]; then
        run_bench "$phase_label" "decrypt/dev-decryption-key" \
            "${BASE_URL}/decrypt/dev-decryption-key" \
            "$concurrency" "$duration" \
            -d "$OPENSSL_DECRYPT_BODY" || warn "decrypt/dev-decryption-key phase had errors"
    else
        warn "decrypt/dev-decryption-key skipped (ciphertext not available)"
    fi
}

# ── Prepare payloads ──────────────────────────────────────────────────────────

hdr "Preparing test payloads"

OPENSSL_DECRYPT_BODY=""

OPENSSL_DEC_PEM="$PROJECT_ROOT/config/keys/dev-decryption.pem"
if [[ -f "$OPENSSL_DEC_PEM" ]]; then
    if CT=$(prepare_openssl_ciphertext "$OPENSSL_DEC_PEM" 2>/dev/null); then
        OPENSSL_DECRYPT_BODY="{\"algorithm\":\"rsa-pkcs1-oaep-mgf1-sha256\",\"encrypted_data\":\"$CT\"}"
        ok "OpenSSL ciphertext prepared"
    else
        warn "Could not prepare OpenSSL ciphertext"
    fi
else
    warn "dev-decryption.pem not found — decrypt/dev-decryption-key will be skipped"
fi

# ── Sanity checks ─────────────────────────────────────────────────────────────

hdr "Sanity checks"

HASH=$(printf '%s' 'perf-test-payload' | openssl dgst -sha256 -binary | base64)
SIGN_BODY="{\"algorithm\":\"rsa-pkcs1-v1_5-sha256\",\"hash\":\"$HASH\"}"

for ep in sign/dev-signing-key; do
    status=$(curl -sk -X POST -H "Authorization: Bearer $BEARER_TOKEN" \
        -H "Content-Type: application/json" \
        -d "$SIGN_BODY" -o /dev/null -w "%{http_code}" "${BASE_URL}/$ep")
    if [[ "$status" == "200" ]]; then
        ok "$ep → HTTP 200"
    else
        die "$ep returned HTTP $status — abort"
    fi
done

# ── Record baseline container state ───────────────────────────────────────────

hdr "Recording baseline state"

RESTART_COUNT_BEFORE=$(docker inspect --format='{{.RestartCount}}' "$CONTAINER" 2>/dev/null || echo "?")
START_TIME=$(date +%s)

info "Container: $CONTAINER_NAME"
info "RestartCount before test: $RESTART_COUNT_BEFORE"

# Drain logs before test starts (mark start)
LOG_START_MARKER="COMPREHENSIVE_TEST_START_$(date +%s)"
docker compose -f "$COMPOSE_FILE" exec -T app sh -c \
    "logger -t pka-test '$LOG_START_MARKER'" 2>/dev/null || true

# ── Start background docker stats collection ──────────────────────────────────

printf "timestamp,mem_usage,mem_limit,cpu_pct\n" > "$STATS_FILE"

collect_stats() {
    while true; do
        local ts; ts=$(date +%s)
        local stats
        stats=$(docker stats --no-stream --format \
            "{{.MemUsage}}|{{.CPUPerc}}" "$CONTAINER_NAME" 2>/dev/null || echo "?|?")
        local mem cpu
        mem=$(echo "$stats" | cut -d'|' -f1)
        cpu=$(echo "$stats" | cut -d'|' -f2)
        printf "%s,%s,%s\n" "$ts" "$mem" "$cpu" >> "$STATS_FILE"
        sleep 10
    done
}

collect_stats &
STATS_PID=$!
trap 'kill "$STATS_PID" 2>/dev/null || true; restore_log_level' EXIT

ok "Docker stats collector started (PID $STATS_PID, sampling every 10s)"

# ── Run test phases ────────────────────────────────────────────────────────────

hdr "Running load phases"

log ""
log "  ${BOLD}Phase 1 — Baseline${NC}  (6 concurrent, 30s per endpoint, ~2 min)"
run_phase "Phase1-Baseline" 6 30s

log ""
log "  ${BOLD}Phase 2 — Sustained load${NC}  (20 concurrent, 120s per endpoint, ~8 min)"
run_phase "Phase2-Sustained" 20 120s

log ""
log "  ${BOLD}Phase 3 — Stress burst${NC}  (50 concurrent, 60s per endpoint, ~4 min)"
run_phase "Phase3-Stress" 50 60s

log ""
log "  ${BOLD}Phase 4 — Recovery check${NC}  (6 concurrent, 30s per endpoint, ~2 min)"
run_phase "Phase4-Recovery" 6 30s

END_TIME=$(date +%s)
TOTAL_SECONDS=$((END_TIME - START_TIME))

# ── Stop stats collector ──────────────────────────────────────────────────────

kill "$STATS_PID" 2>/dev/null || true
restore_log_level
trap - EXIT

# ── Collect post-run container state ─────────────────────────────────────────

hdr "Post-run analysis"

RESTART_COUNT_AFTER=$(docker inspect --format='{{.RestartCount}}' "$CONTAINER" 2>/dev/null || echo "?")
EXIT_CODE=$(docker inspect --format='{{.State.ExitCode}}' "$CONTAINER" 2>/dev/null || echo "?")
OOM_KILLED=$(docker inspect --format='{{.State.OOMKilled}}' "$CONTAINER" 2>/dev/null || echo "?")

info "RestartCount after test: $RESTART_COUNT_AFTER (was: $RESTART_COUNT_BEFORE)"
info "Last ExitCode: $EXIT_CODE"
info "OOMKilled: $OOM_KILLED"

# ── Collect and analyze container logs ────────────────────────────────────────

LOG_FILE="$RESULTS_DIR/container-logs.txt"
# Use a relative --since to limit to this test run only (Docker doesn't accept Unix timestamps)
ELAPSED_SECS=$(( $(date +%s) - START_TIME ))
SINCE_MINUTES=$(( (ELAPSED_SECS / 60) + 5 ))
docker logs --since "${SINCE_MINUTES}m" "$CONTAINER" > "$LOG_FILE" 2>&1 || true

# Disable errexit for log analysis: grep -c exits 1 on zero matches
set +e

# Count sign/decrypt operations — matches the debug-level log emitted by the controllers
# (requires LOG_LEVEL=debug; falls back to info-level messages if debug not available)
SIGN_OPS=$(grep -c '"sign completed"' "$LOG_FILE" 2>/dev/null); SIGN_OPS=${SIGN_OPS:-0}
[[ "$SIGN_OPS" -eq 0 ]] && { SIGN_OPS=$(grep -c 'Signing request processed' "$LOG_FILE" 2>/dev/null); SIGN_OPS=${SIGN_OPS:-0}; }
DECRYPT_OPS=$(grep -c '"decrypt completed"' "$LOG_FILE" 2>/dev/null); DECRYPT_OPS=${DECRYPT_OPS:-0}
[[ "$DECRYPT_OPS" -eq 0 ]] && { DECRYPT_OPS=$(grep -c 'Decryption request processed' "$LOG_FILE" 2>/dev/null); DECRYPT_OPS=${DECRYPT_OPS:-0}; }

# Segfault / fatal error detection
SEGFAULTS=$(grep -ciE 'segfault|sigsegv|signal 11|fatal error' "$LOG_FILE" 2>/dev/null); SEGFAULTS=${SEGFAULTS:-0}
# Backend errors: look for ERROR/CRITICAL level log entries (Symfony logs unhandled 5xx as CRITICAL)
BACKEND_ERRORS=$(grep -cE '"level_name":"(ERROR|CRITICAL)"' "$LOG_FILE" 2>/dev/null); BACKEND_ERRORS=${BACKEND_ERRORS:-0}

set -e

# Sign operation timing (from debug logs) — extracts durationMs logged at debug level
SIGN_TIMING_FILE="$RESULTS_DIR/sign-timing.txt"
grep '"sign completed"' "$LOG_FILE" 2>/dev/null \
    | grep -oE '"durationMs":[0-9]+' | cut -d: -f2 > "$SIGN_TIMING_FILE" || true

# Decrypt operation timing
DECRYPT_TIMING_FILE="$RESULTS_DIR/decrypt-timing.txt"
grep '"decrypt completed"' "$LOG_FILE" 2>/dev/null \
    | grep -oE '"durationMs":[0-9]+' | cut -d: -f2 > "$DECRYPT_TIMING_FILE" || true

compute_stats() {
    local file="$1"
    local count
    count=$(wc -l < "$file" 2>/dev/null | tr -d ' ')
    if [[ "${count:-0}" -gt 0 ]]; then
        sort -n "$file" | awk -v n="$count" '
            BEGIN { i=0 }
            {
                a[i++] = $1
                s += $1
            }
            END {
                min = a[0]
                max = a[n-1]
                avg = s/n
                p95 = a[int(n*0.95)]
                p99 = a[int(n*0.99)]
                printf "n=%d min=%dms avg=%.1fms p95=%dms p99=%dms max=%dms\n", \
                    n, min, avg, p95, p99, max
            }
        '
    else
        echo "no data"
    fi
}

SIGN_TIMING_SUMMARY=$(compute_stats "$SIGN_TIMING_FILE")
DECRYPT_TIMING_SUMMARY=$(compute_stats "$DECRYPT_TIMING_FILE")

# Memory stats from docker stats CSV
MEM_FILE="$RESULTS_DIR/mem-parsed.txt"
# Extract numeric MiB values from "X.XXXGiB / Y.YYGiB" or "XXXMiB / YYYMiB" format
grep -v '^timestamp' "$STATS_FILE" 2>/dev/null | awk -F',' '
{
    # The mem field is "36MiB / 15.6GiB" — only consider the used portion (before " / ")
    mem=$2
    sub(/ \/.*/, "", mem)   # strip " / <limit>" — POSIX-compatible
    val=0
    # Handle GiB — 2-arg match (POSIX-compatible, works on macOS nawk and gawk)
    if (match(mem, /[0-9.]+GiB/)) {
        n=substr(mem, RSTART, RLENGTH-3)+0; val=n*1024
    }
    # Handle MiB
    else if (match(mem, /[0-9.]+MiB/)) {
        val=substr(mem, RSTART, RLENGTH-3)+0
    }
    # Handle kB
    else if (match(mem, /[0-9.]+kB/)) {
        n=substr(mem, RSTART, RLENGTH-2)+0; val=n/1024
    }
    else next
    print val
}
' > "$MEM_FILE" || true

MEM_STATS=""
if [[ -s "$MEM_FILE" ]]; then
    MEM_STATS=$(awk '
        NR==1{min=$1; max=$1; sum=$1; c=1; next}
        {if($1<min)min=$1; if($1>max)max=$1; sum+=$1; c++}
        END{if(c>0) printf "min=%.1fMiB avg=%.1fMiB max=%.1fMiB (n=%d samples)", min, sum/c, max, c}
    ' "$MEM_FILE")
fi

# Sum totals from bench file
TOTAL_200=$(awk -F'|' '
{
    for(i=1;i<=NF;i++){
        if($i ~ /^HTTP200=/){
            sub(/HTTP200=/,"",$i)
            sum+=$i
        }
    }
}
END{print sum+0}
' "$BENCH_FILE" 2>/dev/null || echo 0)

TOTAL_ERRORS=$(awk -F'|' '
{
    for(i=1;i<=NF;i++){
        if($i ~ /^ERRORS=/){sub(/ERRORS=/,"",$i); e+=$i}
        if($i ~ /^EOF=/){sub(/EOF=/,"",$i); eof+=$i}
        if($i ~ /^RESET=/){sub(/RESET=/,"",$i); rst+=$i}
    }
}
END{print (e+eof+rst)+0}
' "$BENCH_FILE" 2>/dev/null || echo 0)

# ── Print summary ─────────────────────────────────────────────────────────────

hdr "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "  ${BOLD}Comprehensive Test Summary${NC}"
log "  Total wall-clock time : ${TOTAL_SECONDS}s"
log ""

log "  ${BOLD}Stability${NC}"
log "  Container restarts    : $((RESTART_COUNT_AFTER - RESTART_COUNT_BEFORE))"
log "  OOM killed            : $OOM_KILLED"
log "  Last exit code        : $EXIT_CODE"
log "  Segfaults detected    : $SEGFAULTS"
log "  Backend errors        : $BACKEND_ERRORS"
log "  Sign ops logged       : $SIGN_OPS"
log "  Decrypt ops logged    : $DECRYPT_OPS"
log ""

log "  ${BOLD}Operation Timing (from debug logs)${NC}"
log "  Sign    : $SIGN_TIMING_SUMMARY"
log "  Decrypt : $DECRYPT_TIMING_SUMMARY"
log ""

log "  ${BOLD}Container Memory (Docker stats, 10s samples)${NC}"
log "  ${MEM_STATS:-no data collected}"
log ""

log "  ${BOLD}Throughput totals${NC}"
log "  Total HTTP 200s       : $TOTAL_200"
log "  Total errors          : $TOTAL_ERRORS"
log ""

log "  ${BOLD}Per-phase breakdown${NC}"
printf "  %-26s %-20s %-8s %-10s %-8s %-8s %-8s %-8s %-10s\n" \
    "Phase/Endpoint" "Key" "Reqs/s" "Avg" "p50" "p95" "p99" "Slowest" "HTTP200"
printf "  %s\n" "$(printf '─%.0s' {1..100})"

awk -F'|' '
{
    # Parse key=value fields from pipe-delimited line (bash 3.x compatible, no declare -A)
    for(i=1;i<=NF;i++){
        n=index($i,"="); k=substr($i,1,n-1); v=substr($i,n+1)
        f[k]=v
    }
    phase=f["PHASE"]; label=f["LABEL"]
    # Strip leading path prefix for endpoint column (e.g. "sign/dev-signing-key" → "signing-key")
    key=label; sub(/.*dev-/, "dev-", key); sub(/-key$/, "-key", key)
    # Endpoint: phase + "/" + short label (strip "dev-signing-key" prefix)
    ep=phase"/"label; sub(/.*\//,"",ep)
    printf "  %-26s %-20s %-8s %-10s %-8s %-8s %-8s %-8s %-10s\n",
        ep, key, f["REQS_S"], f["AVG"], f["P50"], f["P95"], f["P99"], f["SLOWEST"], f["HTTP200"]
}
' "$BENCH_FILE" 2>/dev/null || true

log ""
log "  Raw data saved to: ${GRAY}$RESULTS_DIR${NC}"
hdr "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Export results dir for the calling script if needed
echo "$RESULTS_DIR" > /tmp/pka-last-results-dir
