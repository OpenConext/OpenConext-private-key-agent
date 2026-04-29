---
description: General instructions for the OpenConext Private-key agent workspace
---

# OpenConext Private-Key Agent Guidelines

## Code Style

- **Language**: PHP 8.5+. Always use strict typing (`declare(strict_types=1);`).
- **Standard**: Follow the Doctrine Coding Standard (enforced via `phpcs`).
- **Static Analysis**: Code must pass PHPStan analysis (`docker compose exec app composer phpstan`).
- **Framework**: Use Symfony 7.4 structural conventions (e.g., controllers in `src/Controller`, configuration in `config/`).

## Architecture

- **Purpose**: A REST API service that strictly executes cryptographic operations (signing, decrypting) using protected private keys (OpenSSL), without exposing the keys themselves.
- **Separation of Concerns**: The agent *only* performs private key operations. It does not process or hash the actual message/data (e.g., it expects the client to handle the DigestInfo structure).
- **Authentication**: Clients authenticate using static pre-shared bearer tokens (RFC 6750). Tokens are compared with `hash_equals()` to prevent timing attacks. There is no OAuth 2.0 authorisation server involved.

## Build and Test

**Important:** The project development environment relies on a Docker setup. All `composer`, PHP, or Symfony CLI commands MUST be run inside the `app` container.

- **Install dependencies**: `docker compose exec app composer install`
- **Run all linting and static analysis**: `docker compose exec app composer lint` (runs phplint, phpstan, and phpcs)
- **Run test suite**: `docker compose exec app composer test` (executes PHPUnit)
- **Run full CI check**: `docker compose exec app composer check` (runs lint, tests, and composer audit)

## Validation

After implementing or modifying API endpoints, controllers, or cryptographic operations, validate end-to-end behaviour by running the smoke tests **from the host** (not inside the container):

```bash
./tools/test-endpoints.sh        # run all groups
./tools/test-endpoints.sh -v     # verbose: show every response body
```

Ensure Docker Compose is running (`docker compose up -d`) before running the script. The script reads credentials from `config/private-key-agent.yaml` automatically.

## Conventions

- **Security First**: The service design aims to protect private keys; keep the REST API surface small and exchange only necessary cryptographic data (no full documents or certificates).
- **Error Handling**: Use the errors defined in RFC 6750 for client authentication and invalid requests.
