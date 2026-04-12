# Cryptographic Security Audit Report

**Project:** OpenConext Private-Key Agent  
**Audit Date:** 2026-04-10  
**Scope:** Full codebase — cryptographic operations, key management, authentication  
**Standard:** OWASP Cryptographic Storage Cheat Sheet, OWASP ASVS v4.0 (V6), NIST SP 800-131A Rev.2, RFC 8017  

---

## Executive Summary

The OpenConext Private-Key Agent exposes a REST API for private-key operations (RSA signing and RSA decryption) on behalf of clients. The codebase is well-structured, uses strict PHP typing, and applies timing-safe token comparison (`hash_equals`). Input validation is thorough (algorithm allowlisting, hash-length checks, base64 strictness).

However, two remaining findings warrant attention: a critical Bleichenbacher padding-oracle exposure from the `rsa-pkcs1-v1_5` decryption support, and SHA-1 appearing in both signing and OAEP algorithm lists contrary to NIST's deprecation guidance.

### Specification Alignment

Cross-referencing audit findings against `README.md` reveals two distinct categories:

| Category | Findings | Meaning |
|---|---|---|
| **Spec-mandated security gap** | Finding 1, Finding 2 | The README explicitly requires these insecure algorithms for SAML compatibility. The security risk is real but the behaviour is intentional. |

Findings 1 and 2 represent a **design-level decision** where backward compatibility with SAML was chosen over strict cryptographic hygiene. This trade-off should be consciously owned, documented, and mitigated (see recommendations per finding).

---

## Findings

### Finding 1 — PKCS#1 v1.5 Decryption Oracle (Bleichenbacher Attack Surface)

| | |
|---|---|
| **Severity** | Critical |
| **Files** | `src/Backend/OpenSslDecryptionBackend.php` (line 28, 93–98), `src/Backend/Pkcs11DecryptionBackend.php` (line 50), `src/Dto/DecryptRequest.php` (line 20) |

**Description**  
The service accepts `rsa-pkcs1-v1_5` as a valid decryption algorithm and exposes it over a network-accessible REST endpoint. PKCS#1 v1.5 RSA decryption is vulnerable to Bleichenbacher's adaptive chosen-ciphertext attack (CCA2). An attacker who can submit arbitrary ciphertexts and observe whether the response is a backend error (padding failure) versus a successful decryption can iteratively recover the plaintext.

The `OpenSslDecryptionBackend` propagates `openssl_error_string()` in its exception message, which may leak distinguishable error strings between a padding failure and a non-padding OpenSSL error. Even a binary success/failure distinction is sufficient for a Bleichenbacher oracle.

```php
// OpenSslDecryptionBackend.php — algorithm map explicitly includes PKCS1 v1.5
private const array ALGORITHM_MAP = [
    'rsa-pkcs1-v1_5' => ['padding' => OPENSSL_PKCS1_PADDING, 'digest' => null],
    ...
];

// Error message includes OpenSSL detail, potentially distinguishable
throw new BackendException(sprintf(
    'OpenSSL decryption failed for backend "%s": %s',
    $this->config->name,
    openssl_error_string() ?: 'unknown error',  // ← leaks padding failure reason
));
```

**Context:** The README acknowledges `rsa-pkcs1-v1_5` decryption is required for SAML `http://www.w3.org/2001/04/xmlenc#rsa-1_5` compatibility. However, that XML Encryption specification is itself deprecated. The exposure is compounded because the agent is designed to be called repeatedly by automated clients, making timing/oracle attacks practical.

> **⚠️ Specification Conflict — Spec-Mandated Security Gap**  
> `README.md` (line 58) explicitly lists *"RSA PKCS#1 v1.5 decryption (CKM_RSA_PKCS)"* as a required operation for SAML support. The implementation is therefore intentional and spec-compliant, but the spec itself mandates a cryptographically insecure operation. This is not merely an implementation defect — **the specification must be updated** to acknowledge the risk, define an explicit deprecation/removal timeline, and require the mitigations described below. Keeping this algorithm active indefinitely is not acceptable from a security standpoint.

**Recommendations**
1. **Deprecate and remove `rsa-pkcs1-v1_5` decryption support** if at all possible. Prefer `rsa-pkcs1-oaep-mgf1-sha256` exclusively.
2. If PKCS#1 v1.5 decryption must be retained for legacy compatibility, **return a constant-time, generic error response** for *all* decryption failures regardless of root cause — never propagate the OpenSSL error string to the caller for decryption operations:

```php
// Replace fine-grained error propagation with a generic message for ALL decryption failures:
if ($result === false) {
    throw new BackendException(sprintf(
        'Decryption failed for backend "%s"',
        $this->config->name,
        // Do NOT include openssl_error_string() here
    ));
}
```

3. Apply **rate limiting** on the `/decrypt/{keyName}` endpoint to raise the cost of oracle attacks.
4. Consult NIST SP 800-131A Rev.2 and consider logging a deprecation warning when `rsa-pkcs1-v1_5` decryption is invoked.

---

### Finding 2 — SHA-1 Supported for RSA Signing and OAEP

| | |
|---|---|
| **Severity** | High |
| **Files** | `src/Crypto/DigestInfoBuilder.php` (line 20), `src/Dto/SignRequest.php` (line 19), `src/Dto/DecryptRequest.php` (line 21) |

**Description**  
SHA-1 appears in the supported algorithm lists for both signing (`rsa-pkcs1-v1_5-sha1`) and OAEP decryption (`rsa-pkcs1-oaep-mgf1-sha1`). NIST formally deprecated SHA-1 for digital signature generation after 31 December 2013 (NIST SP 800-131A Rev.2, Table 9) and disallowed it for new signatures. The OWASP Cryptographic Storage Cheat Sheet explicitly recommends SHA-256 or higher.

For **signing**, SHA-1 collision attacks (SHAttered, 2017) allow two different documents to share the same SHA-1 hash, enabling signature forging against systems that still verify SHA-1. Allowing clients to send a SHA-1 hash for signing means the agent may produce valid signatures over colliding documents without any indication.

For **OAEP decryption**, SHA-1 is theoretically weaker for the OAEP hash than SHA-2 alternatives, though practical attacks against OAEP-SHA1 are not currently known.

```php
// DigestInfoBuilder.php
private const array PREFIXES = [
    'rsa-pkcs1-v1_5-sha1'   => '3021300906052b0e03021a05000414',  // ← SHA-1
    'rsa-pkcs1-v1_5-sha256' => '3031300d060960864801650304020105000420',
    ...
];

// SignRequest.php
public const array ALGORITHMS = [
    'rsa-pkcs1-v1_5-sha1',    // ← SHA-1 allowed
    'rsa-pkcs1-v1_5-sha256',
    ...
];
```

> **⚠️ Specification Conflict — Spec-Mandated Security Gap**  
> `README.md` (line 76) explicitly lists `sha1` as a valid MGF1/hash algorithm for OAEP, and the API documentation example (line 140) includes `"rsa-pkcs1-v1_5-sha1"` as a valid signing algorithm identifier. Both usages are therefore intentional per the specification. However, **the specification itself is in conflict with NIST SP 800-131A Rev.2 and OWASP guidance**, both of which forbid SHA-1 for new digital signature generation. Accepting a client-supplied SHA-1 hash for signing means the agent can be made to produce valid RSA signatures over SHA-1-colliding inputs, a threat made practical by the SHAttered attack (2017). The spec must be updated to mark `rsa-pkcs1-v1_5-sha1` as deprecated with a removal date, and to discourage `rsa-pkcs1-oaep-mgf1-sha1` for new deployments.

**Recommendations**
1. **Remove `rsa-pkcs1-v1_5-sha1`** from `SignRequest::ALGORITHMS` and `DigestInfoBuilder::PREFIXES` unless SHA-1 signing is strictly required for a legacy integration that cannot be migrated.
2. **Remove `rsa-pkcs1-oaep-mgf1-sha1`** from `DecryptRequest::ALGORITHMS` for the same reason where feasible.
3. If SHA-1 support cannot be immediately removed, add a configuration flag to **explicitly opt-in** to SHA-1 usage and log a deprecation warning on each invocation.

---

## Positive Findings

The following security controls are correctly implemented and worth acknowledging:

| Control | Location | Assessment |
|---|---|---|
| Timing-safe token comparison | `TokenAuthenticator.php` | `hash_equals()` prevents timing attacks on bearer-token comparison ✅ |
| Algorithm allowlisting | `SignRequest`, `DecryptRequest` | Strict `Choice` constraint; unknown algorithms are rejected before reaching backends ✅ |
| Hash length validation | `SignRequest::validateHashLength()` | Prevents oversized or undersized hash blobs from reaching the signing operation ✅ |
| Strict base64 validation | `Base64Validator.php` | No whitespace, strict regex + `base64_decode(..., true)` double check ✅ |
| Ciphertext size bounds | `DecryptRequest::validateRequest()` | Rejects ciphertext outside 128–1024 bytes before decryption is attempted ✅ |
| OAEP SHA-2 for OpenSSL | `OpenSslDecryptionBackend.php` | Uses `digest_algo` named parameter (PHP 8.5+) for OAEP with SHA-2 hashes ✅ |
| Separation of concerns | Architecture | Agent never hashes the message itself; only operates on pre-computed hashes. Attack surface minimised ✅ |
| RFC 6750 error codes | `ExceptionSubscriber.php` | Correct `WWW-Authenticate` header with `Bearer realm=` on 401 responses ✅ |
| PKCS#11 session retry | Both PKCS#11 backends | Transparent session reconnect on `CKR_SESSION_CLOSED` / `CKR_SESSION_HANDLE_INVALID` ✅ |

---

## Summary Table

| # | Finding | Severity | Spec Alignment | File(s) |
|---|---|---|---|---|
| 1 | PKCS#1 v1.5 decryption Bleichenbacher oracle | **Critical** | ⚠️ Spec-mandated gap — spec must be updated | `OpenSslDecryptionBackend.php`, `Pkcs11DecryptionBackend.php`, `DecryptRequest.php` |
| 2 | SHA-1 accepted for signing and OAEP | **High** | ⚠️ Spec-mandated gap — spec must be updated | `DigestInfoBuilder.php`, `SignRequest.php`, `DecryptRequest.php` |
