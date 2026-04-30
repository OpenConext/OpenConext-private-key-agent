# OpenConext Private Key Agent

A REST API service that performs RSA signing and decryption operations using protected private keys — without ever exposing the keys to callers. The agent runs in a separate process and user context, optionally on a separate host, from the services that consume it.

> **Design specifications:** See [DESIGN-SPECIFICATION.md](docs/DESIGN-SPECIFICATION.md) for the full architecture, API contract, configuration reference, and implementation details.

---

## Overview

### Why this exists

Services like SimpleSAMLphp need to sign SAML assertions and decrypt RSA-encrypted session keys. The standard approach loads the private key into the PHP process — meaning the key is accessible to every piece of code in that process. The Private Key Agent moves the key material into an isolated service: clients send only hashes (for signing) or ciphertext (for decryption) and receive back only the result.

### What it does

| Operation | Client sends | Agent returns |
|---|---|---|
| `POST /sign/{key_name}` | Base64-encoded hash + algorithm | Base64-encoded RSA signature |
| `POST /decrypt/{key_name}` | Base64-encoded `encrypted_data` + algorithm | Base64-encoded `decrypted_data` (symmetric key) |
| `GET /health` | — | Overall health status |
| `GET /health/key/{key_name}` | — | Per-key health status |

**The private key never leaves the agent.** Only cryptographic inputs and outputs cross the network boundary.

### Supported algorithms

**Signing:**
- `rsa-pkcs1-v1_5-sha1`
- `rsa-pkcs1-v1_5-sha256`
- `rsa-pkcs1-v1_5-sha384`
- `rsa-pkcs1-v1_5-sha512`

**Decryption:**
- `rsa-pkcs1-v1_5`
- `rsa-pkcs1-oaep-mgf1-sha1`
- `rsa-pkcs1-oaep-mgf1-sha224`
- `rsa-pkcs1-oaep-mgf1-sha256`
- `rsa-pkcs1-oaep-mgf1-sha384`
- `rsa-pkcs1-oaep-mgf1-sha512`

### Key features

- **OpenSSL backend:** software PEM keys protected by the agent process.
- **Static bearer-token authentication** (RFC 6750): each client has a pre-shared token; tokens are compared with `hash_equals()` to prevent timing attacks.
- **Brute-force rate limiting:** sliding-window limiter (5 failures / 60 s per IP); only failed authentication attempts are counted — the success path has zero overhead.
- **Per-client key authorisation:** each client declares the key names it may use.
- **Fail-fast configuration:** invalid or missing config prevents the application container from starting.
- **Health endpoints:** `/health` and `/health/key/{key_name}` for liveness probes and monitoring.

### Technology stack

| Component | Choice |
|---|---|
| Language | PHP **8.5** (required — see note below) |
| Framework | Symfony 7.4 |
| Logging | Monolog → JSON → stdout |
| HTTP server | Apache 2.4 (`ghcr.io/openconext/openconext-basecontainers/php85-apache2`) |
| Deployment | Docker Compose |

> **PHP 8.5 is a hard requirement.** PHP 8.5 adds the `digest_algo` parameter to `openssl_private_decrypt()`, which is the only way to select non-SHA-1 OAEP hash algorithms. Earlier PHP versions cannot implement `rsa-pkcs1-oaep-mgf1-sha256/384/512` via OpenSSL.

---

## Developer setup

### Prerequisites

- Docker with Compose v2
- `openssl` CLI (for key generation)
- `bash` (for helper scripts)

### 1 — Clone and start the stack

```bash
git clone <repo-url> openconext-private-key-agent
cd openconext-private-key-agent
docker compose up -d
```

This builds the `dev` Docker image and starts the Apache container.

### 2 — Provision the development environment

Run the setup script **from the project root** (not inside the container):

```bash
./tools/setup-dev.sh
```

The script:
1. Generates RSA-2048 PEM keys in `config/keys/` for the OpenSSL backend.
2. Writes a fresh `config/private-key-agent.yaml` with a randomly generated bearer token.

The setup is **idempotent** — running it again is safe. Use `--force` to regenerate keys and token:

```bash
./tools/setup-dev.sh --force
```

### 3 — Install PHP dependencies

```bash
docker compose exec app composer install
```

### 4 — Verify the setup

Smoke-test all endpoints (reads the bearer token from the config file automatically):

```bash
./tools/test-endpoints.sh
```

Verbose mode shows every response body:

```bash
./tools/test-endpoints.sh -v
```

Run a single group:

```bash
./tools/test-endpoints.sh sign
./tools/test-endpoints.sh decrypt
./tools/test-endpoints.sh health
./tools/test-endpoints.sh auth
```

### Development keys

After running `setup-dev.sh` the project has two logical keys.

#### Key inventory

| Logical key name | Type | Allowed operations |
|---|---|---|
| `dev-signing-key` | Software PEM (OpenSSL) | signing |
| `dev-decryption-key` | Software PEM (OpenSSL) | decryption |

#### OpenSSL (software) keys

`setup-dev.sh` generates two unencrypted RSA-2048 PEM key pairs under `config/keys/`:

```
config/keys/
├── dev-signing.pem          ← private key (loaded by the agent)
├── dev-signing.pub.pem      ← public key (for clients: verify signatures)
├── dev-decryption.pem       ← private key (loaded by the agent)
└── dev-decryption.pub.pem   ← public key (for clients: encrypt session keys)
```

The private key files are **unencrypted and ephemeral** — suitable only for local development. They are listed in `.gitignore` and must never be committed.

> **Production equivalent:** replace the PEM file with a properly protected key (file permissions restricted to the service account, or a key stored in a secrets manager and written to a tmpfs mount at deploy time). The agent config just needs `key_path` updated to point to the production key file.

#### Bearer token

`setup-dev.sh` generates a random 256-bit hex token per run and writes it into `config/private-key-agent.yaml`. It is printed to the terminal on completion.

> **Production equivalent:** generate a cryptographically random token of at least 256 bits and inject it into the config file via your secrets management solution (Docker secrets, Kubernetes secret, Vault, etc.). Each client should have its own token. **Never reuse the development token in production.**

#### Summary: dev → production mapping

| Dev resource | Production replacement |
|---|---|
| Unencrypted PEM key in `config/keys/` | PEM key with restricted filesystem permissions, or secrets-manager-mounted key |
| Hardcoded token in `config/private-key-agent.yaml` | Randomly generated token injected at deploy time via secrets management |
| Single `dev-client` with access to all keys | One client entry per consuming service, with `allowed_keys` scoped to only the keys that service needs |

---

## Development

All `composer` and PHP commands run **inside the `app` container**. Start the stack first if it is not already running:

```bash
docker compose up -d
```

### Composer scripts

| Script | Command | What it runs |
|--------|---------|--------------|
| `lint` | `composer lint` | phplint → PHPStan → PHP_CodeSniffer |
| `test` | `composer test` | PHPUnit (Unit + Integration suites) |
| `check` | `composer check` | phplint + PHPStan + `composer audit` + PHPUnit |
| `phpstan` | `composer phpstan` | Static analysis only |
| `phpcs` | `composer phpcs` | Code style check only |
| `phpcbf` | `composer phpcbf` | Auto-fix code style violations |
| `phplint` | `composer phplint` | PHP syntax check on `src/` and `tests/` |

### Static analysis — PHPStan

PHPStan runs at **level 8** and covers `src/` and `tests/`:

```bash
docker compose exec app composer phpstan
```

The configuration is in `phpstan.neon`. A `phpstan-baseline.neon` file tracks any accepted false positives. To regenerate the baseline after deliberate changes:

```bash
docker compose exec app vendor/bin/phpstan analyse --generate-baseline
```

> PHPStan runs inside the container.

### Code style — PHP_CodeSniffer (Doctrine standard)

The project follows the [Doctrine Coding Standard](https://github.com/doctrine/coding-standard). Configuration is in `phpcs.xml`.

Check for violations:

```bash
docker compose exec app composer phpcs
```

Auto-fix what can be fixed automatically:

```bash
docker compose exec app composer phpcbf
```

### Unit and integration tests — PHPUnit

```bash
# Run all tests (Unit + Integration)
docker compose exec app composer test

# Run the Unit suite only
docker compose exec app vendor/bin/phpunit --testsuite Unit

# Run the Integration suite only
docker compose exec app vendor/bin/phpunit --testsuite Integration

# Run a single test file
docker compose exec app vendor/bin/phpunit tests/Unit/Controller/SignControllerTest.php

# Run a single test method
docker compose exec app vendor/bin/phpunit --filter testSignReturnsSignature

# Show test progress (dots → verbose)
docker compose exec app vendor/bin/phpunit --testdox
```

**Test suites:**

- `tests/Unit/` — fast, isolated tests with mocked dependencies. No network or filesystem access.
- `tests/Integration/Backend/` — backend tests that use real OpenSSL keys. These require the Docker container (key files must be present).

PHPUnit configuration is in `phpunit.xml.dist`. The `APP_ENV=test` environment is set automatically.

### Full CI check

Runs everything the CI pipeline checks, in order:

```bash
docker compose exec app composer check
```

This executes: `phplint` → `phpstan` → `phpcs` → `composer audit` → `phpunit`.

### Smoke tests — test-endpoints.sh

End-to-end HTTP tests against the running stack (run from the host, not inside the container):

```bash
# Run all test groups
./tools/test-endpoints.sh

# Verbose — print every response body
./tools/test-endpoints.sh -v

# Run a single group
./tools/test-endpoints.sh health
./tools/test-endpoints.sh auth
./tools/test-endpoints.sh sign
./tools/test-endpoints.sh decrypt

# Verbose + single group
./tools/test-endpoints.sh -v sign

# Target a different host
BASE_URL=http://agent.example.com ./tools/test-endpoints.sh
```

The script reads the bearer token from `config/private-key-agent.yaml` automatically. Docker Compose must be running.

### Performance benchmarks — perf-test.sh

Load-tests the sign and decrypt endpoints using [`hey`](https://github.com/rakyll/hey):

```bash
# Install hey (macOS)
brew install hey

# Run all benchmarks (default: 10 concurrent workers, 10s per endpoint)
./tools/perf-test.sh

# Tune concurrency and duration
./tools/perf-test.sh -c 20 -d 30s

# Benchmark a single group
./tools/perf-test.sh sign
./tools/perf-test.sh decrypt

# Combined options
./tools/perf-test.sh -c 10 -d 15s sign

# Target a different host
BASE_URL=http://agent.example.com ./tools/perf-test.sh
```

The script runs a sanity check (HTTP 200) before each benchmark and skips the endpoint if the check fails.

### Validate config — console command

Parse and validate a config file without starting the server:

```bash
docker compose exec app bin/console app:validate-config /path/to/config.yaml
```

Exit code `0` means the config is structurally valid. Errors are printed to stderr. This does **not** open key files — it validates the YAML structure and cross-references only.

### Dependency security audit

```bash
docker compose exec app composer audit
```

Reports known vulnerabilities in installed packages via the Packagist Security Advisories database.

---

## Configuration

The agent is configured from a single YAML file. The path is set via the `PRIVATE_KEY_AGENT_CONFIG` environment variable (default in Docker Compose: `/etc/private-key-agent/config.yaml`).

### Minimal example

```yaml
agent_name: my-private-key-agent

keys:
  - name: my-signing-key
    key_path: /etc/private-key-agent/keys/signing.pem
    operations: [sign]

clients:
  - name: simplesamlphp
    token: "your-secret-bearer-token"
    allowed_keys:
      - my-signing-key
```

For the full configuration reference (all fields, validation rules, secrets handling) see [DESIGN-SPECIFICATION.md — Configuration](docs/DESIGN-SPECIFICATION.md#configuration).

### Validate a config file without starting the server

```bash
docker compose exec app bin/console app:validate-config /path/to/config.yaml
```

---

## SimpleSAML integration

The agent is designed to be used with the [`simplesamlphp/xml-security`](https://github.com/simplesamlphp/xml-security) library via two adapter classes — one implementing `SignatureBackend`, one implementing `EncryptionBackend`.

### How signing works (IdP)

When SimpleSAMLphp signs a SAML Response:

1. `xml-security` C14N-transforms the element, computes a SHA digest of the result, builds `ds:SignedInfo`, and calls `SignatureBackend::sign($key, $plaintext)` with the canonicalized `ds:SignedInfo` bytes.
2. The adapter **hashes the plaintext locally** (e.g. SHA-256) and calls `POST /sign/{key_name}` with the Base64-encoded hash and algorithm.
3. The agent constructs the DigestInfo ASN.1 structure internally and returns the RSA signature.
4. The adapter returns the raw signature bytes; `xml-security` embeds them in `ds:SignatureValue`.

### How decryption works (SP)

When SimpleSAMLphp decrypts an encrypted SAML Assertion:

1. `xml-security` extracts the RSA-encrypted session key from `xenc:CipherValue` and calls `EncryptionBackend::decrypt($key, $ciphertext)` with those bytes.
2. The adapter calls `POST /decrypt/{key_name}` with the Base64-encoded `encrypted_data` and `algorithm`.
3. The agent RSA-decrypts the session key and returns it.
4. `xml-security` uses the session key to AES-decrypt the assertion content.

The symmetric session key and the assertion content are **never sent to the agent**.

### Adapter skeleton (PHP)

```php
use SimpleSAML\XMLSecurity\Backend\SignatureBackend;

class PrivateKeyAgentSignatureBackend implements SignatureBackend
{
    public function __construct(
        private readonly string $baseUrl,
        private readonly string $bearerToken,
        private readonly string $keyName,
    ) {}

    public function sign(PrivateKey $key, string $plaintext): string
    {
        // Determine algorithm from $key (e.g. RSA + SHA-256 → rsa-pkcs1-v1_5-sha256)
        $algorithm = 'rsa-pkcs1-v1_5-sha256';
        $hash = base64_encode(hash('sha256', $plaintext, true));

        $response = $this->post("/sign/{$this->keyName}", [
            'algorithm' => $algorithm,
            'hash'      => $hash,
        ]);

        return base64_decode($response['signature']);
    }

    // … HTTP helper; EncryptionBackend adapter follows the same pattern:
    // send { "algorithm": $algorithm, "encrypted_data": $base64Ciphertext }
    // and decode $response['decrypted_data'] to recover the symmetric key.
}
```

For the full sequence diagrams and integration notes see [DESIGN-SPECIFICATION.md — SimpleSAML integration](docs/DESIGN-SPECIFICATION.md#simplesam-integration).

---

## API reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/sign/{key_name}` | Bearer token | Sign a hash |
| `POST` | `/decrypt/{key_name}` | Bearer token | Decrypt ciphertext |
| `GET` | `/health` | None | Overall health |
| `GET` | `/health/key/{key_name}` | None | Per-key health |

Error responses follow RFC 6750 and always include `status`, `error`, and an optional `message` field. On `401` a `WWW-Authenticate` header is also returned. On `429` a `Retry-After` header is returned indicating the number of seconds until the rate-limit window resets.

### Rate limiting

The `POST /sign` and `POST /decrypt` endpoints apply a **failure-only sliding-window rate limit** per caller IP to protect against bearer-token brute-force attacks.

| Parameter | Value |
|---|---|
| Window | 60 seconds (sliding) |
| Maximum failures per IP | 5 |
| Response when exceeded | `429 Too Many Requests` + `Retry-After` header |

**Only failed authentication attempts are counted.** Requests with a valid bearer token never touch the rate limiter, so there is no performance impact on normal high-frequency usage. The IP key is taken from `REMOTE_ADDR` (not `X-Forwarded-For`) to prevent clients from spoofing a shared proxy IP.

Rate limit state is stored on disk using the filesystem cache adapter, shared across all Apache worker processes within the same container. In the test environment the in-memory array adapter is used instead.

> **Load-balanced deployments.** With multiple replicas behind a load balancer, each replica maintains its own failure counter on local disk. For cross-replica enforcement, replace the `cache.rate_limiter` pool adapter in `config/packages/cache.yaml` with a network-shared backend (Redis or Memcached).

### Interactive API documentation (Swagger UI)

The application serves an interactive OpenAPI/Swagger UI powered by [NelmioApiDocBundle](https://github.com/nelmio/NelmioApiDocBundle). It is available in all environments (no authentication required).

| URL | What it serves |
|-----|---------------|
| `http://localhost/api/doc` | Swagger UI — interactive browser for all endpoints |
| `http://localhost/api/doc.json` | Raw OpenAPI 3 JSON — import into Postman, Insomnia, etc. |

**Using the Swagger UI:**

1. Start the stack: `docker compose up -d`
2. Open `http://localhost/api/doc` in your browser.
3. Each endpoint lists its request schema, required fields, and example values. Click **Try it out** to send a live request.
4. To authenticate, click the **Authorize** button (lock icon at the top) and enter your bearer token. The token is written to `config/private-key-agent.yaml` by `setup-dev.sh`.

**Importing the OpenAPI spec:**

```bash
# Download the spec to a local file
curl http://localhost/api/doc.json -o openapi.json
```

Import `openapi.json` into any OpenAPI-compatible tool (Postman, Insomnia, Bruno, etc.) to generate a pre-configured collection with all request schemas.

---

## Project structure

```
src/
├── Backend/        # OpenSSL backend implementations
├── Command/        # CLI commands (validate-config)
├── Config/         # Config loading and validation
├── Controller/     # Sign, Decrypt, Health endpoints
├── Crypto/         # DigestInfo ASN.1 builder
├── Dto/            # Request DTOs
├── EventSubscriber/# Exception → JSON error response mapping
├── Exception/      # Domain exceptions
├── Security/       # Bearer-token authenticator and access control
├── Service/        # KeyRegistry (runtime key → backend mapping)
└── Validator/      # Custom Symfony validators (Base64)
```

---

## License

Apache-2.0 — see [LICENSE](LICENSE).
