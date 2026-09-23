# Security Policy

The Private Key Agent keeps private keys out of the applications that use them. To stay small, it
deliberately leaves transport encryption, secret lifecycle and abuse protection to the environment it
runs in. On its own, the agent is not safe to expose to an untrusted network. This document lists
what your environment must provide, the design decisions behind that, and how to report a
vulnerability.

A bearer token is as powerful as the private keys it unlocks: whoever holds a client's token can sign
and decrypt with every key that client may use, for as long as the token is configured. Most of the
requirements below exist to keep tokens from leaking.

## Reporting a vulnerability

> **TODO:** Placeholder section for rules when reporting security issues.

Behaviour described under [Design decisions and known limitations](#design-decisions-and-known-limitations)
is intended and is not treated as a vulnerability. A way to break one of the guarantees under
[What the agent protects](#what-the-agent-protects), in an environment that meets the
[requirements](#required-deployment-environment), is.

## Required deployment environment

Do not run the agent outside local development until your environment provides all of the following.

1. **A private network path.** Only the services that consume the agent can reach its port: the same
   host (loopback), a private network, or a network policy that allows nothing else.
2. **TLS whenever traffic leaves the host.** Terminate TLS in a reverse proxy, ingress or service-mesh
   sidecar in front of the agent, and keep the hop from proxy to agent on the same host or a private
   network. Mutual TLS between consumer and proxy adds a second factor on top of the bearer token.
3. **Strong, separate tokens.** At least 256 bits of randomness (for example `openssl rand -hex 32`),
   one token per consuming service, never reused across environments.
4. **Protected configuration and key files.** The configuration file holds tokens in plaintext and the
   key files hold unencrypted private keys. Make both readable only by the agent's service user, and
   deliver them through a secrets manager (Docker or Kubernetes secrets, Vault) rather than baking them
   into images or committing them.
5. **A token rotation procedure.** Rotate on a fixed schedule, and immediately when a token may have
   leaked or a consuming service is retired. See [Rotating a token](#rotating-a-token).
6. **Rate limiting and request size limits** in the proxy, WAF or ingress in front of the agent.
7. **Restricted health endpoints.** Expose `/v1/health` and `/v1/health/key/{key_name}` only to your
   monitoring and orchestration.
8. **Up-to-date dependencies.** Rebuild the image regularly so Symfony and base-image security fixes
   are picked up. `composer audit` lists known advisories.
9. **Log monitoring.** Alert on repeated invalid-token and access-denied warnings; they point to token
   guessing or a misconfigured consumer.

## Design decisions and known limitations

These are deliberate choices to keep the agent small. Each one moves a responsibility to the
environment described above.

### Plain HTTP, no TLS

The Docker image serves the API over plain HTTP on port 80, and `compose.yaml` publishes that port on
all host interfaces for local development. Bearer tokens travel in the `Authorization` header and
decrypted session keys travel in the response body. Anyone who can observe this traffic can steal a
token, and can read the session keys that protect encrypted SAML assertions.

TLS is left out of the agent because the proxy, ingress or mesh in front of a service already manages
certificates, renewal and cipher policy, and does it better than a per-application setup would.

The Private Key Agent backends for `simplesamlphp/xml-security` require `https://` and allow plain
HTTP only to a loopback address, and only when explicitly enabled. Other clients, including `curl`,
the scripts in `tools/` and custom integrations, have no such guard.

Covered by requirements 1 and 2.

### Static bearer tokens

Clients authenticate with a pre-shared token from the configuration file. Tokens:

- never expire and are not rotated automatically;
- stay valid until they are removed from the configuration and the agent is restarted;
- are stored in plaintext in the configuration file;
- are checked for a minimum length of 32 characters, not for randomness.

A leaked token therefore lets an attacker sign and decrypt with that client's keys until an operator
replaces it. The agent has no token endpoint, expiry or revocation list, because each would add state,
dependencies and attack surface to a service whose only job is to guard keys. Tokens are compared in
constant time and are never logged.

Covered by requirements 3, 4, 5 and 9.

#### Rotating a token

Each client entry has exactly one token, so rotate by running the old and new token side by side:

1. Add a second client entry with a new `name`, a new `token` and the same `allowed_keys`.
2. Restart the agent so it loads the new configuration.
3. Switch the consuming service to the new token.
4. Remove the old client entry and restart the agent again.

To revoke a token immediately, remove its client entry and restart the agent.

### No rate limiting or request size limits in the application

The agent answers every request: an invalid token always gets `401`, never `429`. With 256-bit tokens,
brute force is infeasible at any request rate, and throttling belongs in the layer that already sees
all traffic. The bundled Apache configuration limits request bodies to 64 KB.

Covered by requirement 6.

### Unauthenticated health endpoints

`/v1/health` and `/v1/health/key/{key_name}` need no token, so orchestrators and load balancers can
probe them. They reveal which key names exist and whether each key is healthy.

Covered by requirement 7.

### Descriptive validation errors

When an authenticated request is malformed, the `400` response says what is wrong, for example that
the hash length does not match the algorithm or that the ciphertext length does not match the key
size. This helps integrators, and none of it is secret: expected hash lengths are public, and the key
size follows from the public key. Only callers with a valid token see these messages.

Decryption failures are the exception: every failure of the RSA operation returns the same generic
`400`, so error messages cannot be used as a padding oracle. Backend and internal errors return a
generic `500`; the details go to the log only.

### Legacy algorithms for SAML interoperability

The agent accepts `rsa-pkcs1-v1_5` decryption and `rsa-pkcs1-v1_5-sha1` signing because existing SAML
partners still use them. PKCS#1 v1.5 encryption is inherently exposed to Bleichenbacher-style
padding-oracle attacks. Configure consumers to use OAEP (`rsa-pkcs1-oaep-mgf1-sha256` or stronger) and
SHA-256 or stronger signatures wherever partners allow it.

### Unencrypted key files

The agent loads private keys from PEM files without a passphrase. Their protection comes from file
permissions and from the secrets manager that delivers them.

Covered by requirement 4.

## What the agent protects

In an environment that meets the requirements above, the agent guarantees that:

- private keys never leave the agent process: only hashes and ciphertext go in, only signatures and
  decrypted session keys come out;
- a client can use only the keys in its `allowed_keys`, and a key only for the operations in its
  `operations`;
- tokens are compared in constant time;
- tokens, key material, hashes and decrypted values are never logged;
- an invalid or incomplete configuration stops the agent from starting.

## Related documents

- [README](README.md): setup and the development-to-production mapping
- [Design specification](docs/DESIGN-SPECIFICATION.md): architecture and configuration reference
- [API reference](docs/api.md): endpoints and error responses
- [OWASP ASVS Level 1 audit (2026-05-15)](docs/openconext-private-key-agent-ASVS-L1-audit-2026-05-15.md)
