#!/usr/bin/env bash
# tools/perf-test.sh
#
# Performance-tests the private-key-agent sign and decrypt endpoints using hey.
# Reads the bearer token from config/private-key-agent.yaml automatically.
#
# Usage:
#   ./tools/perf-test.sh                        # run all benchmarks (defaults: -c 10 -d 10s)
#   ./tools/perf-test.sh sign                   # benchmark signing endpoints only
#   ./tools/perf-test.sh decrypt                # benchmark decryption endpoints only
#   ./tools/perf-test.sh -c 20                  # 20 concurrent workers
#   ./tools/perf-test.sh -d 30s                 # 30-second duration per endpoint
#   ./tools/perf-test.sh -c 10 -d 15s sign      # combined
#   BASE_URL=https://agent.example.com ./tools/perf-test.sh
#
# Requires: hey (https://github.com/rakyll/hey)
#   Install: go install github.com/rakyll/hey@latest
#        or: brew install hey
#
# Available groups: sign  decrypt

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_FILE="$PROJECT_ROOT/config/private-key-agent.yaml"
COMPOSE_FILE="$PROJECT_ROOT/compose.yaml"
BASE_URL="${BASE_URL:-https://localhost}"
CONCURRENCY=10
DURATION="10s"
FILTER=""

# ── parse args ────────────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        -c) [[ $# -ge 2 ]] || { echo "ERROR: -c requires a value" >&2; exit 1; }
            CONCURRENCY="$2"; shift 2 ;;
        -d) [[ $# -ge 2 ]] || { echo "ERROR: -d requires a value" >&2; exit 1; }
            DURATION="$2"; shift 2 ;;
        sign|decrypt) FILTER="$1"; shift ;;
        -h|--help)
            sed -n '2,21p' "$0" | sed -E 's/^# ?//'
            exit 0
            ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

# ── colours ───────────────────────────────────────────────────────────────────

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; GRAY='\033[0;90m'; NC='\033[0m'

# ── helpers ───────────────────────────────────────────────────────────────────

die() { echo -e "${RED}✗ ERROR:${NC} $*" >&2; exit 1; }

mktemp_compat() {
    local ext="${1:-}"
    mktemp "/tmp/pka-perf-XXXXXX${ext}"
}

sanity_check() {
    local label="$1" url="$2"; shift 2
    local status
    status=$(curl -sk -X POST \
        -H "Authorization: Bearer $BEARER_TOKEN" \
        -o /dev/null -w "%{http_code}" "$@" "$url")
    if [[ "$status" == "200" ]]; then
        echo -e "  ${GREEN}✓${NC} Sanity check passed ${GRAY}(HTTP $status)${NC}"
    else
        echo -e "  ${RED}✗${NC} Sanity check failed ${GRAY}(HTTP $status)${NC} — skipping benchmark"
        return 1
    fi
}

run_bench() {
    local label="$1" url="$2"; shift 2
    echo -e "\n  ${BLUE}▸${NC} ${BOLD}$label${NC}"
    echo -e "  ${GRAY}Concurrency: $CONCURRENCY | Duration: $DURATION${NC}"
    echo ""
    hey -c "$CONCURRENCY" -z "$DURATION" \
        -m POST \
        -H "Authorization: Bearer $BEARER_TOKEN" \
        -H "Content-Type: application/json" \
        "$@" "$url"
}

# Encrypt plaintext with an OpenSSL PEM key (OAEP-SHA256).
# Prints base64-encoded ciphertext on success, returns 1 on failure.
prepare_openssl_ciphertext() {
    local pem_file="$1"
    local tmp_pub; tmp_pub=$(mktemp_compat .pem)
    local tmp_enc; tmp_enc=$(mktemp_compat)
    local plaintext="dev-session-key-12345678"
    local ok=true

    openssl rsa -in "$pem_file" -pubout -out "$tmp_pub" 2>/dev/null || ok=false
    if $ok; then
        printf '%s' "$plaintext" | openssl pkeyutl -encrypt \
            -pubin -inkey "$tmp_pub" \
            -pkeyopt rsa_padding_mode:oaep \
            -pkeyopt rsa_oaep_md:sha256 \
            -out "$tmp_enc" 2>/dev/null || ok=false
    fi

    if $ok; then
        base64 < "$tmp_enc"
    fi
    rm -f "$tmp_pub" "$tmp_enc"
    $ok
}

# Encrypt plaintext with the SoftHSM public key (OAEP-SHA1).
# Prints base64-encoded ciphertext on success, returns 1 on failure.
prepare_hsm_ciphertext() {
    local tmp_der; tmp_der=$(mktemp_compat .der)
    local tmp_pub; tmp_pub=$(mktemp_compat .pem)
    local tmp_enc; tmp_enc=$(mktemp_compat)
    local plaintext="dev-session-key-12345678"
    local ok=true

    docker compose -f "$COMPOSE_FILE" exec -T app sh -c "
        pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
            --login --pin 1234 \
            --read-object --type pubkey \
            --label test-signing-key \
            --output-file /tmp/hsm-pubkey.der 2>/dev/null
        cat /tmp/hsm-pubkey.der
    " > "$tmp_der" 2>/dev/null || ok=false

    if $ok; then
        openssl pkey -pubin -inform DER -in "$tmp_der" -out "$tmp_pub" 2>/dev/null \
            || openssl rsa -pubin -inform DER -in "$tmp_der" -out "$tmp_pub" 2>/dev/null \
            || ok=false
    fi

    if $ok && [[ -s "$tmp_pub" ]]; then
        # SoftHSM 2.6.1 on Alpine only supports OAEP with SHA-1.
        printf '%s' "$plaintext" | openssl pkeyutl -encrypt \
            -pubin -inkey "$tmp_pub" \
            -pkeyopt rsa_padding_mode:oaep \
            -pkeyopt rsa_oaep_md:sha1 \
            -pkeyopt rsa_mgf1_md:sha1 \
            -out "$tmp_enc" 2>/dev/null || ok=false
    else
        ok=false
    fi

    if $ok; then
        base64 < "$tmp_enc"
    fi
    rm -f "$tmp_der" "$tmp_pub" "$tmp_enc"
    $ok
}

# ── prerequisites ─────────────────────────────────────────────────────────────

[[ -f "$CONFIG_FILE" ]] || die "Config not found. Run: ./tools/setup-dev.sh"
BEARER_TOKEN=$(awk -F'"' '/token:/ {print $2; exit}' "$CONFIG_FILE")
[[ -n "$BEARER_TOKEN" ]] || die "Could not read token from $CONFIG_FILE"
command -v curl    >/dev/null 2>&1 || die "curl is required"
command -v openssl >/dev/null 2>&1 || die "openssl is required"
command -v hey     >/dev/null 2>&1 || die "hey is required — install with: brew install hey  (or: go install github.com/rakyll/hey@latest)"

# ── test groups ───────────────────────────────────────────────────────────────

group_sign() {
    echo -e "${BOLD}Signing benchmarks${NC}"

    HASH=$(printf '%s' 'perf-test-payload' | openssl dgst -sha256 -binary | base64)
    SIGN_BODY="{\"algorithm\":\"rsa-pkcs1-v1_5-sha256\",\"hash\":\"$HASH\"}"

    # OpenSSL backend
    echo -e "\n  ${BOLD}OpenSSL backend (dev-signing-key)${NC}"
    if sanity_check "sign/dev-signing-key" "${BASE_URL}/sign/dev-signing-key" \
        -H "Content-Type: application/json" \
        -d "$SIGN_BODY"; then
        run_bench "POST /sign/dev-signing-key (OpenSSL, RSA-PKCS1-v1.5-SHA256)" \
            "${BASE_URL}/sign/dev-signing-key" \
            -d "$SIGN_BODY"
    fi

    # SoftHSM backend
    echo -e "\n  ${BOLD}SoftHSM backend (hsm-key)${NC}"
    if sanity_check "sign/hsm-key" "${BASE_URL}/sign/hsm-key" \
        -H "Content-Type: application/json" \
        -d "$SIGN_BODY"; then
        run_bench "POST /sign/hsm-key (SoftHSM, RSA-PKCS1-v1.5-SHA256)" \
            "${BASE_URL}/sign/hsm-key" \
            -d "$SIGN_BODY"
    fi

    echo ""
}

group_decrypt() {
    echo -e "${BOLD}Decryption benchmarks${NC}"

    # ── OpenSSL backend ───────────────────────────────────────────────────────

    echo -e "\n  ${BOLD}OpenSSL backend (dev-decryption-key)${NC}"
    OPENSSL_DEC_PEM="$PROJECT_ROOT/config/keys/dev-decryption.pem"
    if [[ ! -f "$OPENSSL_DEC_PEM" ]]; then
        echo -e "  ${YELLOW}⚠${NC} Skipped — dev-decryption.pem not found. Run ./tools/setup-dev.sh"
    elif OPENSSL_CIPHERTEXT=$(prepare_openssl_ciphertext "$OPENSSL_DEC_PEM"); then
        DECRYPT_BODY="{\"algorithm\":\"rsa-pkcs1-oaep-mgf1-sha256\",\"encrypted_data\":\"$OPENSSL_CIPHERTEXT\"}"

        if sanity_check "decrypt/dev-decryption-key" "${BASE_URL}/decrypt/dev-decryption-key" \
            -H "Content-Type: application/json" \
            -d "$DECRYPT_BODY"; then
            run_bench "POST /decrypt/dev-decryption-key (OpenSSL, OAEP-SHA256)" \
                "${BASE_URL}/decrypt/dev-decryption-key" \
                -d "$DECRYPT_BODY"
        fi
    else
        echo -e "  ${YELLOW}⚠${NC} Skipped — failed to prepare ciphertext"
    fi

    # ── SoftHSM backend ──────────────────────────────────────────────────────

    echo -e "\n  ${BOLD}SoftHSM backend (hsm-key)${NC}"
    if ! docker compose -f "$COMPOSE_FILE" ps --services --filter status=running 2>/dev/null | grep -q '^app$'; then
        echo -e "  ${YELLOW}⚠${NC} Skipped — app container not running"
    elif HSM_CIPHERTEXT=$(prepare_hsm_ciphertext); then
        HSM_DECRYPT_BODY="{\"algorithm\":\"rsa-pkcs1-oaep-mgf1-sha1\",\"encrypted_data\":\"$HSM_CIPHERTEXT\"}"

        if sanity_check "decrypt/hsm-key" "${BASE_URL}/decrypt/hsm-key" \
            -H "Content-Type: application/json" \
            -d "$HSM_DECRYPT_BODY"; then
            run_bench "POST /decrypt/hsm-key (SoftHSM, OAEP-SHA1)" \
                "${BASE_URL}/decrypt/hsm-key" \
                -d "$HSM_DECRYPT_BODY"
        fi
    else
        echo -e "  ${YELLOW}⚠${NC} Skipped — could not prepare HSM ciphertext (export or encrypt failed)"
    fi

    echo ""
}

# ── run ───────────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}Private Key Agent — performance benchmarks${NC}"
echo -e "Base URL:     ${BLUE}${BASE_URL}${NC}"
echo -e "Concurrency:  ${BLUE}${CONCURRENCY}${NC}"
echo -e "Duration:     ${BLUE}${DURATION}${NC}"
[[ -n "$FILTER" ]] && echo -e "Group:        ${BLUE}${FILTER}${NC}"
echo ""

case "${FILTER}" in
    sign)    group_sign    ;;
    decrypt) group_decrypt ;;
    "")
        group_sign
        group_decrypt
        ;;
esac

echo -e "${GREEN}${BOLD}Benchmarks complete.${NC}"
echo ""
