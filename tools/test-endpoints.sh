#!/usr/bin/env bash
# tools/test-endpoints.sh
#
# Smoke-tests all private-key-agent API endpoints using curl.
# Reads the bearer token from config/private-key-agent.yaml automatically.
#
# Usage:
#   ./tools/test-endpoints.sh                    # run all test groups
#   ./tools/test-endpoints.sh -v                 # verbose: show every response body
#   ./tools/test-endpoints.sh health             # run only the health group
#   ./tools/test-endpoints.sh auth               # run only the auth group
#   ./tools/test-endpoints.sh sign               # run only the signing group
#   ./tools/test-endpoints.sh decrypt            # run only the decryption group
#   ./tools/test-endpoints.sh -v sign            # verbose + single group
#   BASE_URL=http://agent.example.com ./tools/test-endpoints.sh
#
# Available groups: health  auth  sign  decrypt

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_FILE="$PROJECT_ROOT/config/private-key-agent.yaml"
COMPOSE_FILE="$PROJECT_ROOT/compose.yaml"
BASE_URL="${BASE_URL:-http://localhost}"
VERBOSE=false
FILTER=""
RESP_BODY_FILE=$(mktemp)
trap 'rm -f "$RESP_BODY_FILE"' EXIT

# Parse args: optional -v flag, optional group name
for arg in "$@"; do
    case "$arg" in
        -v|--verbose) VERBOSE=true ;;
        health|auth|sign|decrypt) FILTER="$arg" ;;
        --help|-h)
            sed -n '2,14p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "Unknown argument: $arg" >&2; exit 1 ;;
    esac
done

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; BOLD='\033[1m'; GRAY='\033[0;90m'; NC='\033[0m'

PASS=0; FAIL=0

# ── helpers ───────────────────────────────────────────────────────────────────

die() { echo -e "${RED}✗ ERROR:${NC} $*" >&2; exit 1; }

mktemp_compat() {
    # macOS mktemp does not support --suffix; use a template instead.
    local ext="${1:-}"
    mktemp "/tmp/pka-test-XXXXXX${ext}"
}

pretty() {
    if command -v python3 >/dev/null 2>&1; then
        echo "$1" | python3 -m json.tool 2>/dev/null || echo "$1"
    else
        echo "$1"
    fi
}

check() {
    local name="$1" got="$2" want="$3"
    local body; body=$(cat "$RESP_BODY_FILE" 2>/dev/null)
    if [[ "$got" == "$want" ]]; then
        echo -e "  ${GREEN}✓${NC} ${BOLD}$name${NC}  ${GRAY}HTTP $got${NC}"
        $VERBOSE && [[ -n "$body" ]] && \
            echo -e "${GRAY}$(pretty "$body" | sed 's/^/    /')${NC}"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗${NC} ${BOLD}$name${NC}  ${YELLOW}expected HTTP $want, got HTTP $got${NC}"
        [[ -n "$body" ]] && \
            echo -e "${GRAY}$(pretty "$body" | sed 's/^/    /')${NC}"
        FAIL=$((FAIL + 1))
    fi
}

api() {
    local method="${1:-GET}"; shift
    local url="${BASE_URL}${1}"; shift
    curl -sk -X "$method" \
        -H "Authorization: Bearer $BEARER_TOKEN" \
        -o "$RESP_BODY_FILE" -w "%{http_code}" "$@" "$url"
}

api_noauth() {
    local method="${1:-GET}"; shift
    local url="${BASE_URL}${1}"; shift
    curl -sk -X "$method" -o "$RESP_BODY_FILE" -w "%{http_code}" "$@" "$url"
}

# ── prerequisites ─────────────────────────────────────────────────────────────

[[ -f "$CONFIG_FILE" ]] || die "Config not found. Run: ./tools/setup-dev.sh"
BEARER_TOKEN=$(awk -F'"' '/token:/ {print $2; exit}' "$CONFIG_FILE")
[[ -n "$BEARER_TOKEN" ]] || die "Could not read token from $CONFIG_FILE"
command -v curl    >/dev/null 2>&1 || die "curl is required"
command -v openssl >/dev/null 2>&1 || die "openssl is required"

# ── test groups ───────────────────────────────────────────────────────────────

group_health() {
    echo -e "${BOLD}Health${NC}"

    status=$(api GET /health)
    check "GET /health" "$status" "200"

    status=$(api GET /health/key/dev-signing-key)
    check "GET /health/key/dev-signing-key" "$status" "200"

    status=$(api GET /health/key/dev-decryption-key)
    check "GET /health/key/dev-decryption-key" "$status" "200"

    status=$(api GET /health/key/no-such-key)
    check "GET /health/key/no-such-key → 404" "$status" "404"

    echo ""
}

group_auth() {
    echo -e "${BOLD}Authentication${NC}"

    # The /health endpoint is unauthenticated by design.
    # Use /sign to verify bearer token enforcement.
    HASH=$(printf '%s' 'hello' | openssl dgst -sha256 -binary | base64)

    status=$(api_noauth POST /sign/dev-signing-key \
        -H "Content-Type: application/json" \
        -d "{\"algorithm\":\"rsa-pkcs1-v1_5-sha256\",\"hash\":\"$HASH\"}")
    check "POST /sign (no token) → 401" "$status" "401"

    status=$(api_noauth POST /sign/dev-signing-key \
        -H "Authorization: Bearer wrong-token" \
        -H "Content-Type: application/json" \
        -d "{\"algorithm\":\"rsa-pkcs1-v1_5-sha256\",\"hash\":\"$HASH\"}")
    check "POST /sign (wrong token) → 401" "$status" "401"

    echo ""
}

group_sign() {
    echo -e "${BOLD}Signing${NC}"

    HASH=$(printf '%s' 'hello private-key-agent' | openssl dgst -sha256 -binary | base64)

    status=$(api POST /sign/dev-signing-key \
        -H "Content-Type: application/json" \
        -d "{\"algorithm\":\"rsa-pkcs1-v1_5-sha256\",\"hash\":\"$HASH\"}")
    check "POST /sign/dev-signing-key  (OpenSSL, sha256)" "$status" "200"

    # Key not in client's allowed list → 403
    status=$(api POST /sign/unknown-key \
        -H "Content-Type: application/json" \
        -d "{\"algorithm\":\"rsa-pkcs1-v1_5-sha256\",\"hash\":\"$HASH\"}")
    check "POST /sign/unknown-key      (unknown key) → 403" "$status" "403"

    # Wrong hash length for algorithm → 400
    SHORT_HASH=$(printf '%s' 'x' | base64)
    status=$(api POST /sign/dev-signing-key \
        -H "Content-Type: application/json" \
        -d "{\"algorithm\":\"rsa-pkcs1-v1_5-sha256\",\"hash\":\"$SHORT_HASH\"}")
    check "POST /sign/dev-signing-key  (wrong hash length) → 400" "$status" "400"

    # Missing algorithm field → 400
    status=$(api POST /sign/dev-signing-key \
        -H "Content-Type: application/json" \
        -d "{\"hash\":\"$HASH\"}")
    check "POST /sign/dev-signing-key  (missing algorithm) → 400" "$status" "400"

    echo ""
}

group_decrypt() {
    echo -e "${BOLD}Decryption${NC}"

    encrypt_with_pem() {
        local pem_file="$1" plaintext="dev-session-key-12345678"
        local tmp_pub; tmp_pub=$(mktemp_compat .pem)
        local tmp_enc; tmp_enc=$(mktemp_compat)
        openssl rsa -in "$pem_file" -pubout -out "$tmp_pub" 2>/dev/null
        printf '%s' "$plaintext" | openssl pkeyutl -encrypt \
            -pubin -inkey "$tmp_pub" \
            -pkeyopt rsa_padding_mode:oaep \
            -pkeyopt rsa_oaep_md:sha256 \
            -out "$tmp_enc" 2>/dev/null
        base64 < "$tmp_enc"
        rm -f "$tmp_pub" "$tmp_enc"
    }

    OPENSSL_DEC_PEM="$PROJECT_ROOT/config/keys/dev-decryption.pem"
    if [[ -f "$OPENSSL_DEC_PEM" ]]; then
        CIPHERTEXT=$(encrypt_with_pem "$OPENSSL_DEC_PEM")
        status=$(api POST /decrypt/dev-decryption-key \
            -H "Content-Type: application/json" \
            -d "{\"algorithm\":\"rsa-pkcs1-oaep-mgf1-sha256\",\"encrypted_data\":\"$CIPHERTEXT\"}")
        check "POST /decrypt/dev-decryption-key  (OpenSSL, OAEP-SHA256)" "$status" "200"
    else
        echo -e "  ${YELLOW}⚠${NC} Skipped OpenSSL decrypt — run ./tools/setup-dev.sh first"
    fi

    # Missing ciphertext field → 400
    status=$(api POST /decrypt/dev-decryption-key \
        -H "Content-Type: application/json" \
        -d '{"algorithm":"rsa-pkcs1-oaep-mgf1-sha256"}')
    check "POST /decrypt/dev-decryption-key  (missing ciphertext) → 400" "$status" "400"

    # Key not in client's allowed list → 403
    DUMMY=$(dd if=/dev/urandom bs=256 count=1 2>/dev/null | base64)
    status=$(api POST /decrypt/unknown-key \
        -H "Content-Type: application/json" \
        -d "{\"algorithm\":\"rsa-pkcs1-oaep-mgf1-sha256\",\"encrypted_data\":\"$DUMMY\"}")
    check "POST /decrypt/unknown-key          (unknown key) → 403" "$status" "403"

    echo ""
}

# ── run ───────────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}Private Key Agent — endpoint tests${NC}"
echo -e "Base URL: ${BLUE}${BASE_URL}${NC}"
[[ -n "$FILTER" ]] && echo -e "Group:    ${BLUE}${FILTER}${NC}"
echo ""

case "${FILTER}" in
    health)  group_health  ;;
    auth)    group_auth    ;;
    sign)    group_sign    ;;
    decrypt) group_decrypt ;;
    "")
        group_health
        group_auth
        group_sign
        group_decrypt
        ;;
esac

TOTAL=$((PASS + FAIL))
if [[ "$FAIL" -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}All $TOTAL tests passed.${NC}"
else
    echo -e "${RED}${BOLD}$FAIL/$TOTAL tests failed.${NC}"
    exit 1
fi
echo ""
