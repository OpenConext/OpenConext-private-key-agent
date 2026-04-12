#!/usr/bin/env bash
# tests/fixtures/setup-softhsm.sh
# Sets up a SoftHSM2 token for integration testing.
set -euo pipefail

export SOFTHSM2_CONF=$(mktemp)
TOKENDIR=$(mktemp -d)

cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $TOKENDIR
objectstore.backend = file
log.level = ERROR
EOF

# Initialize token
softhsm2-util --init-token --slot 0 --label "test-token" --pin 1234 --so-pin 5678

# Generate RSA 2048 key pair
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --keypairgen --key-type rsa:2048 \
  --label "test-signing-key" \
  --id 01

echo "SOFTHSM2_CONF=$SOFTHSM2_CONF"
echo "TOKENDIR=$TOKENDIR"
