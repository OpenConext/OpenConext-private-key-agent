# Plan: Simplify Backend Configuration (Drop Load Balancing)

## Problem

The config has a 3-tier indirection: **clients → keys → backend_groups → PEM file**.  
`backend_groups` was designed for round-robin load balancing across multiple HSM slots. HSM support has been dropped; only `openssl` exists and there is never more than one backend per key. The entire abstraction is dead weight.

## Decisions

| Decision | Choice |
|---|---|
| Key supports sign AND decrypt from single key_path | Yes — one key, one PEM |
| Per-key operations restriction | `operations: [sign, decrypt]` field; defaults to both when omitted |
| `/health/backend/{name}` → | `/health/key/{key_name}`; response fields renamed `unhealthy_keys` / `key_name` |
| Merge OpenSslSigningBackend + OpenSslDecryptionBackend | Yes → `OpenSslBackend` |
| Drop BackendFactory + plugin architecture | Yes |
| Backward compat for old backend_groups format | No — greenfield, clean break |
| Update docs, tests, tooling | Yes — all included (README, DESIGN-SPECIFICATION, fixtures, smoke tests) |

## New Config Shape

```yaml
agent_name: my-private-key-agent

keys:
  - name: my-signing-key
    key_path: /etc/agent/keys/signing.pem
    operations: [sign]            # optional; defaults to [sign, decrypt]

  - name: my-decryption-key
    key_path: /etc/agent/keys/decryption.pem
    operations: [decrypt]

  - name: my-dual-key
    key_path: /etc/agent/keys/dual.pem
    # operations omitted → both sign and decrypt are allowed

clients:
  - name: simplesamlphp
    token: "bearer-token-value"
    allowed_keys:
      - my-signing-key
      - my-decryption-key
      - my-dual-key
```

`operations` is an optional list that may contain `sign`, `decrypt`, or both. Omitting it is equivalent to `[sign, decrypt]`. The config loader must reject an empty list and unknown values.

When a client requests an operation that the key does not support (e.g. decrypt with a sign-only key), controllers must return **404** — identical to the response for a key that doesn't exist at all. This is intentional: returning a distinct status would reveal which keys support which operations, leaking capability information to clients whose `allowed_keys` list includes the key. A client that is correctly configured should never hit this path.

To achieve HTTP 404, `getSigningBackend` and `getDecryptionBackend` must throw a new `KeyNotFoundException` (not `InvalidRequestException`, which maps to 400). `ExceptionSubscriber` must be updated to map `KeyNotFoundException → 404`. The same exception is used for both "key name unknown" and "operation not permitted" so the two cases are indistinguishable to callers.

## What Gets Removed

**Source files deleted:**
- `src/Config/BackendGroupConfig.php`
- `src/Backend/BackendFactory.php`
- `src/Backend/BackendTypeFactoryInterface.php`
- `src/Backend/OpenSslBackendTypeFactory.php`
- `src/Backend/OpenSslSigningBackend.php`
- `src/Backend/OpenSslDecryptionBackend.php`

**Source files updated (interface/method cleanup):**
- `src/Backend/BackendInterface.php`: remove `getPublicKeyFingerprint()` (only used for multi-backend equivalence checks, which are being removed); update `getName()` docblock ("backend group name" → "key name")

**Test files deleted:**
- `tests/Unit/Backend/BackendFactoryTest.php`
- `tests/Unit/Backend/OpenSslBackendTypeFactoryTest.php`
- `tests/Integration/Backend/OpenSslSigningBackendTest.php`
- `tests/Integration/Backend/OpenSslDecryptionBackendTest.php`
- `tests/fixtures/invalid-orphan-backend.yaml`

**Logic removed:**
- Round-robin counters in `KeyRegistry`
- Fingerprint equivalence checks in `KeyRegistry`
- `getSigningKeyNames`, `getDecryptionKeyNames`, `getAllSigningBackends`, `getAllDecryptionBackends`, `getBackendsByName` from `KeyRegistryInterface`
- `registerSigningBackend()` / `registerDecryptionBackend()` from `KeyRegistry` (replaced by a single `register(string $keyName, OpenSslBackend $backend): void`)
- `getPublicKeyFingerprint()` implementation from `OpenSslSigningBackend` and `OpenSslDecryptionBackend` (removed with those classes)

## Implementation Phases

> **Note on ordering:** Phases 1–4 must be worked as a unit — deleting files in Phase 1 leaves the codebase
> uncompilable until Phase 4 wires up the replacements. Do not run `composer check` between individual phases;
> run it only after Phase 4 is complete.

### Phase 1 — New merged backend (create before deleting)
Create `src/Backend/OpenSslBackend.php` implementing both `SigningBackendInterface` and
`DecryptionBackendInterface`. Constructor takes `name: string` and `keyPath: string` directly
(no `BackendGroupConfig`). The class may keep `getPublicKeyFingerprint()` as a private method if
convenient, but it must **not** appear on `BackendInterface`.
Create `tests/Integration/Backend/OpenSslBackendTest.php` merging the two existing integration tests.

Create `src/Exception/KeyNotFoundException.php` (extends `RuntimeException`, HTTP 404 semantic).
Update `ExceptionSubscriber` to map `KeyNotFoundException → [404, 'not_found', ...]`.

### Phase 2 — Config layer
- `KeyConfig.php`: replace `signingBackends[]` + `decryptionBackends[]` with `keyPath: string` and
  `operations: list<'sign'|'decrypt'>` (validated to non-empty subset of `['sign', 'decrypt']`; defaults to
  both when omitted)
- `AgentConfig.php`: remove `$backends` array
- `ConfigLoader.php`: remove `backend_groups` parsing; parse `key_path` and `operations` directly on each
  key; remove orphan-backend check

### Phase 3 — Service layer
- `KeyRegistryInterface.php`: slim down to `getSigningBackend`, `getDecryptionBackend`, `getAllBackends`,
  and new `findBackend(keyName): ?BackendInterface`.
  **Do not add `register()` to the interface** — the bootstrapper always operates on `KeyRegistry`
  directly (not through the interface), matching the existing pattern for `registerSigningBackend`/
  `registerDecryptionBackend`. `SigningBackendInterface` and `DecryptionBackendInterface` are kept as
  return types for `getSigningBackend`/`getDecryptionBackend` respectively; they are not dead code.
- `KeyRegistry.php`: one map (`array<string, OpenSslBackend>`); gate `getSigningBackend` /
  `getDecryptionBackend` on the key's `operations` list — throw `KeyNotFoundException` (not
  `InvalidRequestException`) when the key is unknown **or** when the operation is not allowed, so both
  cases produce HTTP 404; no round-robin; no fingerprint check; remove `registerSigningBackend` /
  `registerDecryptionBackend`; add `register(string $keyName, OpenSslBackend $backend): void` (concrete
  class only — not on the interface)
- `KeyRegistryBootstrapper.php`: directly instantiate `OpenSslBackend` per key via `register()`; no
  `BackendFactory`; check DI config (`config/services.yaml`) and remove any explicit wiring for deleted
  classes (`BackendFactory`, `OpenSslBackendTypeFactory`)
- `ValidateConfigCommand.php`: remove any output that references backend groups or backend names; print
  key names and their allowed operations instead

### Phase 4 — Delete dead code
Remove all files listed in *What Gets Removed* above.
Update `src/Backend/BackendInterface.php`: remove `getPublicKeyFingerprint()` from the interface and update the `getName()` docblock to say "key name" instead of "backend group name".

### Phase 5 — Health controller
- Rename route `/health/backend/{backendName}` → `/health/key/{keyName}`.
  Use `findBackend(keyName)` from registry (returns `null` → 404).
  Update JSON field names: `backend_name` → `key_name`.
- Aggregate `/health` 503 response: rename `unhealthy_backends` → `unhealthy_keys`
  (because `OpenSslBackend::getName()` now returns the key name, not a separate backend group name).

### Phase 6 — Config files & fixtures
- `config/private-key-agent.yaml`: remove `backend_groups`, add `key_path` to each key;
  preserve existing key names (`dev-signing-key`, `dev-decryption-key`) so the smoke test script
  continues to work without further changes
- `tests/fixtures/valid-config.yaml`: same migration
- Add `tests/fixtures/invalid-empty-operations.yaml`: key with `operations: []`
- Add `tests/fixtures/invalid-unknown-operation.yaml`: key with `operations: [encrypt]`
- `ValidateConfigCommand.php`: remove any output that references backend groups or backend names; print key
  names and their allowed operations instead. (`operations: []` is caught at config-load time, so operators
  see a clear boot-time error rather than a silent runtime 404.)

### Phase 7 — Tests
Update `ConfigLoaderTest.php` (including new negative cases for `operations` validation),
`KeyRegistryTest.php`, `KeyRegistryBootstrapperTest.php`, `HealthControllerTest.php`,
`ValidateConfigCommandTest.php`.

### Phase 8 — README + design spec
Update `README.md`:
- **Key features** section: remove "Multiple backends per key" bullet; update health endpoint path to
  `/health/key/{name}`; add note about per-key `operations` field.
- **Configuration minimal example**: replace `backend_groups` / `signing_backends` / `decryption_backends`
  YAML with the new `key_path` + optional `operations` format.
- **API reference table**: `/health/backend/{name}` → `/health/key/{name}`; note `unhealthy_keys` field.
- **Development keys / Key inventory table**: update "Allowed operations" column to reflect `operations`
  field.

Update `docs/DESIGN-SPECIFICATION.md`: config section, field reference, example config,
health endpoint docs, class overview diagram.

Update `tools/test-endpoints.sh`:
- In `group_health()`: add a test for the new `GET /health/key/{keyName}` endpoint (200 for a valid key,
  404 for an unknown key name).

### Phase 9 — Verify
```bash
docker compose exec app composer check
./tools/test-endpoints.sh
```
