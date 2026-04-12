#!/usr/bin/env bash
# tools/setup-dev.sh
#
# Provisions the local dev environment:
#   - Generates RSA-2048 PEM keys for the OpenSSL backend
#   - Detects the SoftHSM slot from the running app container
#   - Writes config/private-key-agent.yaml with a fresh bearer token
#
# Usage:
#   ./tools/setup-dev.sh          # idempotent — skips if already set up
#   ./tools/setup-dev.sh --force  # regenerate everything

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
KEYS_DIR="$PROJECT_ROOT/config/keys"
CONFIG_FILE="$PROJECT_ROOT/config/private-key-agent.yaml"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${BLUE}▸${NC} $*"; }
success() { echo -e "${GREEN}✓${NC} $*"; }
warn()    { echo -e "${YELLOW}⚠${NC} $*"; }
die()     { echo -e "${RED}✗ ERROR:${NC} $*" >&2; exit 1; }

# ── prerequisites ────────────────────────────────────────────────────────────

command -v openssl >/dev/null 2>&1 || die "openssl is required but not found"
command -v docker  >/dev/null 2>&1 || die "docker is required but not found"

# ── idempotency check ────────────────────────────────────────────────────────

if [[ -f "$CONFIG_FILE" && -f "$KEYS_DIR/dev-signing.pem" && -f "$KEYS_DIR/dev-decryption.pem" ]]; then
    if [[ "${1:-}" != "--force" ]]; then
        warn "Dev environment already set up. Run with --force to regenerate."
        TOKEN=$(awk -F'"' '/token:/ {print $2; exit}' "$CONFIG_FILE")
        echo ""
        echo -e "  Bearer token: ${BOLD}$TOKEN${NC}"
        echo "  Test the API:  ./tools/test-endpoints.sh"
        echo ""
        exit 0
    fi
    warn "--force specified — regenerating all keys and config."
fi

# ── detect container ─────────────────────────────────────────────────────────

COMPOSE_FILE="$PROJECT_ROOT/compose.yaml"

if docker compose -f "$COMPOSE_FILE" ps --services --filter status=running 2>/dev/null | grep -q '^app$'; then
    CONTAINER_RUNNING=true
else
    CONTAINER_RUNNING=false
    warn "App container is not running. Start it first with: docker compose up -d"
    warn "Using fallback SoftHSM slot number (may not match a rebuilt image)."
fi

# ── generate OpenSSL keys ────────────────────────────────────────────────────

info "Generating OpenSSL RSA-2048 key pair for signing..."
mkdir -p "$KEYS_DIR"
openssl genrsa -out "$KEYS_DIR/dev-signing.pem" 2048 2>/dev/null
openssl rsa -in "$KEYS_DIR/dev-signing.pem" -pubout -out "$KEYS_DIR/dev-signing.pub.pem" 2>/dev/null
success "config/keys/dev-signing.pem + dev-signing.pub.pem"

info "Generating OpenSSL RSA-2048 key pair for decryption..."
openssl genrsa -out "$KEYS_DIR/dev-decryption.pem" 2048 2>/dev/null
openssl rsa -in "$KEYS_DIR/dev-decryption.pem" -pubout -out "$KEYS_DIR/dev-decryption.pub.pem" 2>/dev/null
success "config/keys/dev-decryption.pem + dev-decryption.pub.pem"

# ── SoftHSM slot index ──────────────────────────────────────────────────────
# pkcs11_slot is the 0-based index into the slot list returned by the PKCS#11
# library (i.e. position in the array returned by C_GetSlotList). The dev
# Dockerfile initialises exactly one token, so it is always at index 0.
SOFTHSM_SLOT=0

# ── generate bearer token ────────────────────────────────────────────────────

BEARER_TOKEN=$(openssl rand -hex 32)

# ── write config ─────────────────────────────────────────────────────────────

info "Writing config/private-key-agent.yaml..."

cat > "$CONFIG_FILE" <<YAML
agent_name: private-key-agent-dev

backend_groups:
  # OpenSSL backend — signing key (unencrypted PEM, dev only)
  - name: openssl-signing
    type: openssl
    key_path: /app/config/keys/dev-signing.pem

  # OpenSSL backend — decryption key (unencrypted PEM, dev only)
  - name: openssl-decryption
    type: openssl
    key_path: /app/config/keys/dev-decryption.pem

  # SoftHSM backend — PKCS#11 token baked into the dev Docker image
  # Token:  test-token
  # Key:    test-signing-key  (label=test-signing-key, id=01)
  # PIN:    1234
  # pkcs11_slot is the slot list index (0 = first slot).
  - name: softhsm
    type: pkcs11
    pkcs11_lib: /usr/lib/softhsm/libsofthsm2.so
    pkcs11_slot: ${SOFTHSM_SLOT}
    pkcs11_pin: "1234"
    pkcs11_key_label: test-signing-key

keys:
  - name: dev-signing-key
    signing_backends:
      - openssl-signing

  - name: dev-decryption-key
    decryption_backends:
      - openssl-decryption

  - name: hsm-key
    signing_backends:
      - softhsm
    decryption_backends:
      - softhsm

clients:
  - name: dev-client
    # Bearer token for development — never reuse in production
    token: "${BEARER_TOKEN}"
    allowed_keys:
      - dev-signing-key
      - dev-decryption-key
      - hsm-key
YAML

success "config/private-key-agent.yaml written"

# ── restart app to pick up new config ────────────────────────────────────────

if [[ "$CONTAINER_RUNNING" == "true" ]]; then
    info "Restarting app container to load the new config..."
    docker compose -f "$COMPOSE_FILE" restart app >/dev/null 2>&1
    # Wait until PHP-FPM is ready (health check via caddy, or just a short wait)
    sleep 2
    success "App container restarted"

    # Export HSM public key so clients can encrypt data / verify signatures
    info "Exporting SoftHSM public key..."
    if docker compose -f "$COMPOSE_FILE" exec -T app \
        pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
            --slot-index "${SOFTHSM_SLOT}" --pin 1234 \
            --read-object --type pubkey --label test-signing-key \
            --output-file /tmp/hsm-pubkey.der 2>/dev/null; then
        docker compose -f "$COMPOSE_FILE" exec -T app \
            openssl pkey -pubin -inform DER -in /tmp/hsm-pubkey.der \
                -out /tmp/hsm-pubkey.pem 2>/dev/null \
            || docker compose -f "$COMPOSE_FILE" exec -T app \
                openssl rsa -pubin -inform DER -in /tmp/hsm-pubkey.der \
                    -out /tmp/hsm-pubkey.pem 2>/dev/null
        docker compose -f "$COMPOSE_FILE" cp app:/tmp/hsm-pubkey.pem \
            "$KEYS_DIR/hsm-signing.pub.pem"
        success "config/keys/hsm-signing.pub.pem"
    else
        warn "Could not export HSM public key — run again after the container starts"
    fi
fi

# ── summary ──────────────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}  Dev environment ready!${NC}"
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  Bearer token:  ${BOLD}${BEARER_TOKEN}${NC}"
echo ""
echo "  OpenSSL keys (private key + public key for clients):"
echo "    Signing:    config/keys/dev-signing.pem  /  dev-signing.pub.pem"
echo "    Decryption: config/keys/dev-decryption.pem  /  dev-decryption.pub.pem"
echo ""
echo "  SoftHSM:"
echo "    Token:      test-token"
echo "    Slot:       ${SOFTHSM_SLOT}"
echo "    Key:        test-signing-key (label) / 01 (id)"
echo "    PIN:        1234"
echo "    Public key: config/keys/hsm-signing.pub.pem (if exported above)"
echo ""
echo "  Note: public keys are for client use only — distribute them to any"
echo "  service that needs to encrypt data or verify signatures."
echo ""
echo "  Run API tests:"
echo "    ./tools/test-endpoints.sh"
echo ""
