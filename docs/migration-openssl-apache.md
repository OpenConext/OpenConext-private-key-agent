# Migration Plan: Drop HSM/FrankenPHP, adopt OpenConext Apache base

**Status:** Pending implementation  
**Scope:** Drop PKCS#11 (HSM) support, remove FrankenPHP runtime, adopt the OpenConext standard
`ghcr.io/openconext/openconext-basecontainers/php85-apache2:latest` base image, and address
outstanding Symfony 7.4 best-practice gaps.

---

## Background and motivation

The project originally supported two backend types — software keys (OpenSSL) and hardware security
modules via PKCS#11. PKCS#11 required persistent HSM sessions across PHP requests, which drove the
choice of FrankenPHP (ZTS worker mode with static session cache). Now that HSM support is being
dropped, the entire FrankenPHP runtime justification disappears.

The project is joining OpenConext and must align with the project ecosystem:
- Base image: `ghcr.io/openconext/openconext-basecontainers/php85-apache2:latest`
- Apache HTTP on port 80 (TLS terminated upstream by the ingress layer)
- Working directory: `/var/www/html`

---

## Decisions

| Decision | Choice |
|----------|--------|
| App root in container | `/var/www/html` (OpenConext convention) |
| TLS | Terminated upstream; container runs HTTP-only on port 80 |
| Obsolete docs | Deleted |
| GitHub Actions CI | Included in scope |
| Symfony Flex | Add to `require` (was only in `allow-plugins`) |
| Symfony best practices | `session: false`, `router.utf8: true`, `http_method_override: false` |
| `security.yaml` | Unchanged intentionally (`stateless: true`, `security: false` — existing firewall config remains as-is) |

---

## Acceptance criteria

All three of the following must pass after the migration:

**1. No legacy references remain** — the following grep must return zero results
(excluding this plan file and git history):

```bash
grep -rn --include='*.php' --include='*.yaml' --include='*.yml' --include='*.neon' \
     --include='*.sh' --include='*.md' --include='*.json' --include='*.ini' \
     --include='*.xml' --include='Dockerfile' --include='.env' \
     -iE 'pkcs11|softhsm|frankenphp|worker\.php|FRANKENPHP_LOOP_MAX|Caddyfile' \
     --exclude-dir=vendor --exclude-dir=var \
     --exclude='migration-openssl-apache.md' .
```

**2. Full CI check passes** (run inside the container):

```bash
docker compose run --rm app composer check
```

**3. Smoke tests pass** (run from the host, requires `docker compose up -d` first):

```bash
./tools/test-endpoints.sh
```

---

## Phase 1 — Remove PKCS#11 backend

### Delete
- `src/Backend/Pkcs11BackendTypeFactory.php`
- `src/Backend/Pkcs11DecryptionBackend.php`
- `src/Backend/Pkcs11ModuleCache.php`
- `src/Backend/Pkcs11SessionCache.php`
- `src/Backend/Pkcs11SessionManager.php`
- `src/Backend/Pkcs11SigningBackend.php`
- `tests/Integration/Backend/Pkcs11DecryptionBackendTest.php`
- `tests/Integration/Backend/Pkcs11SigningBackendTest.php`
- `tests/Unit/Backend/Pkcs11BackendTypeFactoryTest.php`
- `tests/Unit/Backend/Pkcs11ModuleCacheTest.php`
- `tests/Unit/Backend/Pkcs11SessionCacheTest.php`
- `tests/fixtures/setup-softhsm.sh`

### Modify

**`src/Config/BackendGroupConfig.php`**  
Remove all `pkcs11_*` constructor parameters: `pkcs11Lib`, `pkcs11Slot`, `pkcs11Pin`,
`pkcs11KeyLabel`, `pkcs11KeyId`. Also remove the `$environment` parameter — it was only used
for PKCS#11 (`SOFTHSM2_CONF`).

**`src/Config/ConfigLoader.php`**  
Remove `pkcs11` from the allowed types list. Remove all PKCS#11 validation and parsing branches.
Accept `openssl` as the only valid backend type. Remove the `$environment` parsing block.

**`tests/Unit/Config/ConfigLoaderTest.php`**  
Remove PKCS#11 fixture test cases. Add a test asserting that a backend with `type: pkcs11`
is rejected with an appropriate `InvalidConfigurationException`.

**`tests/Unit/Backend/BackendFactoryTest.php`**  
Remove any test cases that reference the `pkcs11` backend type.

**`tests/Unit/Backend/OpenSslBackendTypeFactoryTest.php`**  
The `testDoesNotSupportOtherTypes()` method asserts both `supports('pkcs11')` and
`supports('unknown')`. Remove only the `pkcs11` assertion; keep (or rename `'unknown'` to
`'unsupported'`) the remaining generic assertion. No method rename needed.

**`tests/Unit/Service/KeyRegistryBootstrapperTest.php`**  
Remove the `Pkcs11BackendTypeFactory` import and its usage in `BackendFactory` constructor calls.
Pass only `OpenSslBackendTypeFactory` to the `BackendFactory`.

**`tests/Unit/Service/KeyRegistryTest.php`**  
Rename mock backend names from `softhsm` / `hsm-key` to generic names (e.g., `backend-a` /
`key-a`) to avoid stale HSM references.

**`tests/Unit/Controller/HealthControllerTest.php`**  
Rename mock backend names from `softhsm` / `hsm-key` to generic names (e.g., `backend-a` /
`key-a`).

**`tests/Unit/EventSubscriber/ExceptionSubscriberTest.php`**  
Change the `'HSM unreachable'` test message to a generic message (e.g.,
`'Backend unreachable'`).

**`src/Backend/BackendInterface.php`**  
Update the `isHealthy()` docblock — remove the PKCS#11 reference
(`"For PKCS#11: checks session via C_GetSessionInfo"`). Replace with a generic description
(e.g., `"Returns true if the backend can perform operations."`).

**`phpstan-baseline.neon`**  
Both existing entries point at deleted PKCS#11 files. Reset to an empty baseline:
```neon
parameters:
    ignoreErrors:
```

**`phpstan.neon`**  
Remove the PKCS#11-specific ignore rules that are no longer needed:
```neon
# remove these:
- '#^Class \\\\?Pkcs11\\\\#'
- '#^Constant \\\\?Pkcs11\\\\#'
- identifier: deadCode.unreachable
```
Also remove the `reportUnmatchedIgnoredErrors: false` setting (no longer needed without
PKCS#11 ignore rules) and the comment about the Pkcs11 extension.

**`config/private-key-agent.yaml`**  
Remove the `softhsm` PKCS#11 backend group and the `hsm-key`. Also remove `hsm-key` from the
`clients[].allowed_keys` list. Update `key_path` values from `/app/...` to `/var/www/html/...`.

> Note: `BackendFactory` itself needs no changes — it uses a tagged-iterator factory pattern;
> removing `Pkcs11BackendTypeFactory` is sufficient.

---

## Phase 2 — Remove FrankenPHP

### Delete
- `public/worker.php`
- `docker/Caddyfile`

### Modify

**`composer.json` + `composer.lock`**

> ⚠️ **MUST DO BEFORE PHASE 3:** Run the commands below inside the *existing running container*
> before making any Dockerfile changes. The FrankenPHP container must be up
> (`docker compose up -d`) when you do this. If you change the Dockerfile first, you will have
> no working container to run composer in.

```bash
# docker compose exec app bash
composer remove runtime/frankenphp-symfony   # removes from require, regenerates lock
composer require symfony/flex:^2.0           # adds to require, regenerates lock
```

Then manually update the `description` field in `composer.json`:
- Change `"OpenSSL or PKCS#11 backends"` → `"REST API service for RSA signing and decryption using OpenSSL backends"`

Also add `@phpcs` to the `check` script so CI covers code style:
```json
"check": ["@phplint", "@phpstan", "@phpcs", "@composer audit", "@test"]
```

> **Note:** `phpcs` currently runs as part of `lint` but not `check`. Adding it to `check`
> (and therefore to CI) for the first time means any pre-existing code-style violations will
> become blocking failures immediately. Run `composer phpcs` in the current codebase before
> wiring this into CI and fix any violations first.

Commit both `composer.json` and `composer.lock`.

**`config/services.yaml`**  
Remove the two `public: true` aliases that were required only by `worker.php`:
```yaml
# remove these:
App\Service\KeyRegistryInterface:
    alias: App\Service\KeyRegistry
    public: true

Psr\Log\LoggerInterface:
    alias: logger
    public: true
```
Also remove the comments referencing `worker.php` and `frankenphp_handle_request()`.

**`.env`**  
Remove `FRANKENPHP_LOOP_MAX=10000`.

---

## Phase 3 — New Dockerfile and Apache configuration

### Rewrite `docker/Dockerfile`

Base image: `ghcr.io/openconext/openconext-basecontainers/php85-apache2:<pinned-tag>`

> **Pin the base image** to a specific tag or digest (not `:latest`) before implementation.
> Using `:latest` produces non-reproducible builds — two builds a week apart may silently use
> different PHP patch versions or OS packages. Check the available tags at the
> [openconext-basecontainers registry](https://github.com/orgs/OpenConext/packages) and pin
> to the current stable tag (e.g. `:1.2.3` or `@sha256:…`).
Working directory: `/var/www/html`

Key differences from current:
- No PKCS#11 PHP extension build
- No FrankenPHP-specific configuration
- Apache serves the Symfony app
- Two stages: `prod` (default), `dev` (extends prod, adds composer dev deps)
- Dev stage no longer installs softhsm2 / opensc
- Cache warm-up uses `/var/www/html` paths

### Create `docker/apache-app.conf`

Apache VirtualHost config for the Symfony front controller pattern:
```apache
<VirtualHost *:80>
    DocumentRoot /var/www/html/public

    <Directory /var/www/html/public>
        AllowOverride None
        Require all granted
        FallbackResource /index.php
    </Directory>

    ErrorLog /dev/stderr
    CustomLog /dev/stdout combined
</VirtualHost>
```
Copied into `/etc/apache2/sites-enabled/000-default.conf` in the Dockerfile.

> **Note:** `FallbackResource` requires `mod_dir` to be enabled. Verify it is present in the
> base image (`apache2ctl -M | grep dir`) when writing the Dockerfile.

### Update `docker/app.ini`

Change `opcache.preload` path:
```ini
; before:
opcache.preload = /app/var/cache/prod/App_KernelProdContainer.preload.php
; after:
opcache.preload = /var/www/html/var/cache/prod/App_KernelProdContainer.preload.php
```

### Update `docker/app.dev.ini`

Add explicit preload disable so the dev INI fully overrides the prod preload setting
(the preload cache file does not exist when the app directory is bind-mounted):
```ini
opcache.preload=
opcache.preload_user=
```

### Update `compose.yaml`

```yaml
services:
  app:
    build:
      context: .
      dockerfile: docker/Dockerfile
      target: dev
    volumes:
      - .:/var/www/html
      - ./config/private-key-agent.yaml:/etc/private-key-agent/config.yaml:ro
      - ./docker/app.dev.ini:/usr/local/etc/php/conf.d/zz-app-local.ini:ro
    ports:
      - "80:80"
    restart: unless-stopped
```
Remove: Caddyfile volume mount, port 443.

> Note: The dev INI override is mounted as `zz-app-local.ini` to guarantee it loads after the
> production `app.ini` (PHP scans `conf.d/` in alphabetical order). Because the prod `app.ini`
> sets `opcache.preload`, the dev INI must explicitly clear it — the preloaded cache file does
> not exist when the source tree is bind-mounted.

---

## Phase 4 — Symfony best practices

### `config/packages/framework.yaml`

Add three settings recommended by Symfony 7.4 docs for an API service:
```yaml
framework:
    secret: '%env(APP_SECRET)%'
    handle_all_throwables: true
    http_method_override: false   # API does not need X-HTTP-Method-Override
    session: false                # stateless API — disable sessions entirely
    router:
        utf8: true                # recommended default since Symfony 4.3
    php_errors:
        log: true
    serializer:
        enabled: true
    validation:
        enabled: true
```

> Note: `session: false` complements the existing `stateless: true` in `security.yaml` — the
> security setting prevents the firewall from creating sessions; the framework setting disables
> the session service entirely.

> Note: `config/packages/validator.yaml` remains unchanged — it provides
> `email_validation_mode: html5` which is orthogonal to the `validation.enabled` setting here.

---

## Phase 5 — Update tooling

**`tools/test-endpoints.sh`**  
- Change the default `BASE_URL` from `https://localhost` to `http://localhost`.
- Remove all `hsm-key` / SoftHSM test sections (sign and decrypt test groups that hit
  `/sign/hsm-key` and `/decrypt/hsm-key`).
- Remove the `encrypt_with_hsm_key()` helper function and `pkcs11-tool` usage.

**`tools/perf-test.sh`**  
- Change the default `BASE_URL` from `https://localhost` to `http://localhost`.
- Remove all SoftHSM benchmark sections (`sign/hsm-key`, `decrypt/hsm-key`).
- Remove the `prepare_hsm_ciphertext()` function and `pkcs11-tool` usage.

**`tools/comprehensive-perf-test.sh`**  
- Change the default `BASE_URL` from `https://localhost` to `http://localhost`.
- Remove all SoftHSM benchmark sections (`sign/hsm-key`, `decrypt/hsm-key`).
- Remove the `prepare_hsm_ciphertext()` function.
- Remove `PKCS11_ERRORS` log-grep and PKCS#11 timing report sections.

**`tools/setup-dev.sh`**  
- Remove the SoftHSM slot detection logic.
- Remove the `softhsm` backend group from the generated YAML template.
- Remove the `hsm-key` from the generated keys and clients sections.
- Remove the HSM public key export (`pkcs11-tool` / `hsm-signing.pub.pem`).
- Remove the SoftHSM summary from the final output.
- Update `key_path` values in the generated YAML from `/app/...` to `/var/www/html/...`.

---

## Phase 6 — Documentation

### Delete
- `docs/pkcs11-session-reuse-report.md`
- `docs/zts-benchmark-report.md`
- `docs/comprehensive-stability-report.md`
- `docs/DRAFT-SPEC.md`
- `docs/crypto-audit-report.md`
- `docs/openconext-private-key-agent-ASVS-L1-audit-2026-04-19.md`

### Rewrite `docs/DESIGN-SPECIFICATION.md`

Sections to update:
- **Introduction**: remove "hardware keys / PKCS#11 HSM" sentence; OpenSSL-only
- **Architecture / runtime**: replace FrankenPHP worker-loop model with standard Apache/PHP
  request lifecycle
- **PKCS#11 HSM sections**: remove entirely (session management, ZTS, worker lifecycle, SoftHSM)
- **Deployment / Docker**: reflect new base image, Apache, port 80, `/var/www/html`
- **Configuration reference**: remove all `pkcs11_*` fields and example PKCS#11 `backend_group`
  blocks
- **Sequence diagrams**: update "OpenSSL / PKCS#11 HSM" labels to just "OpenSSL"

### Rewrite `README.md`

Sections to update:
- **Key features**: remove "Two cryptographic backends" bullet; describe OpenSSL-only. Remove
  "PKCS#11 (hardware security modules, tested with SoftHSM2)" reference.
- **Technology stack table**: replace FrankenPHP / `gamringer/php-pkcs11` rows with Apache.
- **Developer setup**: remove SoftHSM references. Update "builds the FrankenPHP server" to
  "starts the Apache container". Remove step about `setup-dev.sh` detecting SoftHSM slots.
- **Development keys and SoftHSM section**: remove the entire SoftHSM subsection (`hsm-key`,
  token details table, `pkcs11-tool` commands, HSM public key export).
- **Dev → production mapping table**: remove SoftHSM row.
- **Configuration examples**: remove the "Full example with PKCS#11 and multiple backends"
  block. Keep only the OpenSSL minimal example.
- **Project structure comment**: change `# OpenSSL and PKCS#11 backend implementations` to
  `# OpenSSL backend implementations`.
- **PHPStan section**: remove note about running inside container for PKCS#11 extension. Remove
  `phpstan-baseline.neon` tracking "PKCS#11 extension classes" note.
- **Performance benchmarks**: remove SoftHSM references in `perf-test.sh` usage.

### Update `AGENTS.md`

- **Architecture**: change `"OpenSSL or PKCS#11"` to `"OpenSSL"`.
- Remove any remaining PKCS#11 / HSM references.

---

## Phase 7 — GitHub Actions CI

### Create `.github/workflows/ci.yml`

One job, **`lint-and-test`** (all branches and PRs):
1. Checkout
2. Set up Docker Buildx and enable GitHub Actions layer cache (`cache-from: type=gha`, `cache-to: type=gha,mode=max`) to avoid rebuilding unchanged layers on every run
3. Build the `dev` Docker image: `docker compose build`
4. Run checks: `docker compose run --rm app composer check`

> Note: `docker compose run --rm` creates a one-off container without needing a prior `up -d`,
> which is simpler and idempotent in CI.

---

## File change summary

| File | Action |
|------|--------|
| `config/keys/hsm-signing.pub.pem` | Delete |
| `src/Backend/Pkcs11*.php` (×6) | Delete |
| `src/Config/BackendGroupConfig.php` | Simplify (remove `pkcs11_*` + `$environment` params) |
| `src/Config/ConfigLoader.php` | Simplify (openssl-only, remove `$environment` parsing) |
| `src/Backend/BackendInterface.php` | Remove PKCS#11 reference from `isHealthy()` docblock |
| `public/worker.php` | Delete |
| `docker/Caddyfile` | Delete |
| `docker/Dockerfile` | Rewrite |
| `docker/apache-app.conf` | **New** |
| `docker/app.dev.ini` | Add preload disable for dev |
| `docker/app.ini` | Update opcache path |
| `composer.json` | Remove frankenphp, add flex to `require`, add `@phpcs` to `check` script, update description |
| `composer.lock` | Regenerate |
| `config/packages/framework.yaml` | Add 3 settings |
| `config/services.yaml` | Remove 2 worker-only public aliases + comments |
| `config/private-key-agent.yaml` | Remove pkcs11 backend + hsm-key from clients + fix paths |
| `.env` | Remove `FRANKENPHP_LOOP_MAX` |
| `compose.yaml` | Port 80, remove Caddyfile volume, update paths + INI mount |
| `phpstan-baseline.neon` | Reset to empty |
| `phpstan.neon` | Remove PKCS#11 ignore rules |
| `tests/Integration/Backend/Pkcs11*.php` (×2) | Delete |
| `tests/Unit/Backend/Pkcs11*.php` (×3) | Delete |
| `tests/Unit/Backend/BackendFactoryTest.php` | Remove pkcs11 cases |
| `tests/Unit/Backend/OpenSslBackendTypeFactoryTest.php` | Replace pkcs11 assertion |
| `tests/Unit/Config/ConfigLoaderTest.php` | Remove pkcs11 cases, add rejection test |
| `tests/Unit/Service/KeyRegistryBootstrapperTest.php` | Remove Pkcs11BackendTypeFactory usage |
| `tests/Unit/Service/KeyRegistryTest.php` | Rename HSM mock names to generic |
| `tests/Unit/Controller/HealthControllerTest.php` | Rename HSM mock names to generic |
| `tests/Unit/EventSubscriber/ExceptionSubscriberTest.php` | Rename HSM test message |
| `tests/fixtures/setup-softhsm.sh` | Delete |
| `tools/test-endpoints.sh` | Remove HSM tests + update `BASE_URL` |
| `tools/perf-test.sh` | Remove HSM benchmarks + update `BASE_URL` |
| `tools/comprehensive-perf-test.sh` | Remove HSM benchmarks + update `BASE_URL` |
| `tools/setup-dev.sh` | Remove HSM setup + update paths |
| `docs/pkcs11-session-reuse-report.md` | Delete |
| `docs/zts-benchmark-report.md` | Delete |
| `docs/comprehensive-stability-report.md` | Delete |
| `docs/DRAFT-SPEC.md` | Delete |
| `docs/crypto-audit-report.md` | Delete |
| `docs/openconext-private-key-agent-ASVS-L1-audit-2026-04-19.md` | Delete |
| `docs/DESIGN-SPECIFICATION.md` | Major rewrite |
| `README.md` | Major rewrite (remove HSM/FrankenPHP content) |
| `AGENTS.md` | Remove PKCS#11 references |
| `.github/workflows/ci.yml` | **New** (lint-and-test only) |
