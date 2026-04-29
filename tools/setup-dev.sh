#!/usr/bin/env bash
# tools/setup-dev.sh
#
# Provisions the local dev environment:
#   - Generates RSA-2048 PEM keys for the OpenSSL backend
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

# ── generate bearer token ────────────────────────────────────────────────────

BEARER_TOKEN=$(openssl rand -hex 32)

# ── write config ─────────────────────────────────────────────────────────────

info "Writing config/private-key-agent.yaml..."

cat > "$CONFIG_FILE" <<YAML
agent_name: private-key-agent-dev

keys:
  # Signing key — unencrypted PEM (dev only)
  - name: dev-signing-key
    key_path: /var/www/html/config/keys/dev-signing.pem
    operations: [sign]

  # Decryption key — unencrypted PEM (dev only)
  - name: dev-decryption-key
    key_path: /var/www/html/config/keys/dev-decryption.pem
    operations: [decrypt]

clients:
  - name: dev-client
    # Bearer token for development — never reuse in production
    token: "${BEARER_TOKEN}"
    allowed_keys:
      - dev-signing-key
      - dev-decryption-key
YAML

success "config/private-key-agent.yaml written"

# ── restart app to pick up new config ────────────────────────────────────────

if [[ "$CONTAINER_RUNNING" == "true" ]]; then
    info "Restarting app container to load the new config..."
    docker compose -f "$COMPOSE_FILE" restart app >/dev/null 2>&1
    # Wait until PHP-FPM is ready (health check via caddy, or just a short wait)
    sleep 2
    success "App container restarted"
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
echo "  Note: public keys are for client use only — distribute them to any"
echo "  service that needs to encrypt data or verify signatures."
echo ""
echo "  Run API tests:"
echo "    ./tools/test-endpoints.sh"
echo ""
