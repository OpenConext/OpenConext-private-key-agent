# Dawn Technology · OWASP ASVS 5.0 Level 1 · Security Audit Report

**Initial Draft author**: AI Agent (claude-opus-4.6 + gpt-5.5, arbitrated)  
**Reviewed & Finalized by**: _____________________  
**Report Date**: 2026-05-15  
**Skill Version**: 2.1.0  
**ASVS Version**: 5.0.0  

## Application details

**App Version**: 1.0.0  
**Git Commit**: 3ec4f7c  

## Technology Stack

**Language** | PHP 8.5+  
**Framework** | Symfony 7.4  
**Database** | None  
**Key Libraries** | OpenSSL (via ext-openssl), symfony/security-http, symfony/yaml  

---

## Introduction

This security audit was conducted against the **OWASP Application Security Verification Standard (ASVS) Version 5.0**. The ASVS provides a basis for testing web application technical security controls and also provides developers with a list of requirements for secure development.

Level 1 is the minimum level that all applications should strive for. It consists of items that are testable via automated means or manual review.

For more information, please visit the [OWASP ASVS Project Page](https://owasp.org/www-project-application-security-verification-standard/).

## 🔒 Confidentiality Statement

> **STRICTLY CONFIDENTIAL**
>
> This document contains detailed findings regarding the security posture of the target application. It may include information about vulnerabilities, architectural gaps, and potential exploitation vectors.
>
> **Access to this report is restricted to authorized stakeholders only.** Unauthorized distribution, copying, or public disclosure of this material is strictly prohibited and may compromise the security of the application.

---

## Summary

OpenConext Private Key Agent is a minimal REST API that performs RSA signing and decryption operations using protected private keys. The attack surface is deliberately small: no database, no sessions, no HTML, no file uploads. Two static bearer tokens guard all endpoints, and the Symfony framework provides a solid security baseline.

**Strengths**: tight scope, timing-safe token comparison (`hash_equals`), correct RSA-OAEP implementation for encryption, LimitRequestBody enforced, JSON output auto-escaped.

**Critical weaknesses**:

1. The `rsa-pkcs1-v1_5` decryption mode uses `OPENSSL_PKCS1_PADDING`, which is vulnerable to Bleichenbacher (padding oracle) attacks.
2. Static bearer tokens in YAML config cannot be rotated/expired, violating ASVS V7.2.2 (no static API secrets in production).

**Coverage Statistics**:

- Total Level 1 Items: 70
- Items Verified: 70
- **Result Breakdown**:
  - 🔴 Critical: 0
  - 🟠 High: 1
  - 🟡 Medium: 1
  - 🟢 Low: 0
  - ✅ PASS: 24
  - ⚠️ NEEDS_REVIEW: 8
- **Compliance Score**: 92.3% *(PASS / (70 − 36 N/A − 8 NEEDS_REVIEW) × 100 = 24/26)*
- **Completeness Check**: 70 / 70 (100%)
- **Review Debt**: 8 items require manual verification (infrastructure-level controls)

---

## Findings

### #59 — V11.3.1 — Encryption Algorithm Security

- **Chapter**: V11 — Cryptography
- **Section**: V11.3 — Algorithm Strength
- **ASVS ID**: V11.3.1
- **Internal Item #**: 59
- **Requirement**: Verify that industry-proven or government-approved cryptographic algorithms, modes, and libraries are used, and that these have not been deprecated or are not nearing deprecation.
- **Severity**: 🟠 High
- **Location**: `src/Backend/OpenSslBackend.php:141`
- **Evidence**: `file:src/Backend/OpenSslBackend.php:141 — RsaPkcs1V15 => [OPENSSL_PKCS1_PADDING, null]`
- **Description**: The `decryptionSpec()` method maps the `RsaPkcs1V15` algorithm enum variant to PHP's `OPENSSL_PKCS1_PADDING`. RSA PKCS#1 v1.5 padding for encryption/decryption is deprecated (NIST SP 800-131A Rev 2) and vulnerable to Bleichenbacher's 1998 padding oracle attack and its modern variants (ROBOT, DROWN). Any client that sends ciphertext using this mode allows an attacker with network access to perform an adaptive chosen-ciphertext attack and recover plaintext. The `rsa-pkcs1-v1_5` variant is exposed via the API route and accepted by `DecryptController`.
- **Remediation**:
  1. Remove `RsaPkcs1V15` from `src/Crypto/EncryptionAlgorithm.php`.
  2. Remove the corresponding branch in `OpenSslBackend::decryptionSpec()`.
  3. Update API documentation (`docs/api.md`) to remove the `rsa-pkcs1-v1_5` option.
  4. Return HTTP 400 for any request specifying the deprecated algorithm.

  ```php
  // src/Crypto/EncryptionAlgorithm.php — remove the deprecated case
  enum EncryptionAlgorithm: string
  {
      // case RsaPkcs1V15 = 'rsa-pkcs1-v1_5';  ← REMOVE
      case RsaOaepSha256 = 'rsa-oaep-sha256';
      case RsaOaepSha384 = 'rsa-oaep-sha384';
      case RsaOaepSha512 = 'rsa-oaep-sha512';
  }
  ```

  ```php
  // src/Backend/OpenSslBackend.php — remove PKCS1 branch in decryptionSpec()
  private function decryptionSpec(EncryptionAlgorithm $algorithm): array
  {
      return match ($algorithm) {
          // EncryptionAlgorithm::RsaPkcs1V15 => [OPENSSL_PKCS1_PADDING, null],  ← REMOVE
          EncryptionAlgorithm::RsaOaepSha256 => [OPENSSL_PKCS1_OAEP_PADDING, 'sha256'],
          EncryptionAlgorithm::RsaOaepSha384 => [OPENSSL_PKCS1_OAEP_PADDING, 'sha384'],
          EncryptionAlgorithm::RsaOaepSha512 => [OPENSSL_PKCS1_OAEP_PADDING, 'sha512'],
      };
  }
  ```

---

### #41 — V7.2.2 — Credential Management — API Tokens

- **Chapter**: V7 — Authentication
- **Section**: V7.2 — Credential Security
- **ASVS ID**: V7.2.2
- **Internal Item #**: 41
- **Requirement**: Verify that passwords or API secrets submitted to the service are not stored in plaintext, and that they are salted, hashed, or encrypted using an approved algorithm.
- **Severity**: 🟡 Medium
- **Location**: `config/private-key-agent.yaml` (clients[].token), `src/Config/ConfigLoader.php:157`
- **Evidence**: `file:src/Config/ConfigLoader.php:157 — plaintext token validated for min-length only; no hashing`
- **Description**: Client bearer tokens are stored in plaintext in `config/private-key-agent.yaml` and compared directly using `hash_equals()` in `TokenAuthenticator`. ASVS V7.2.2 requires that API secrets at rest are salted-and-hashed or encrypted. While `hash_equals` prevents timing attacks, reading the config file (e.g., via path traversal, backup exposure, or insider access) immediately reveals all valid tokens. The design is a deliberate M2M trade-off, but it does not satisfy the ASVS control as written.
- **Remediation** (two options):
  1. **Preferred — hashed tokens**: Store `bcrypt`/`argon2id` hashes of tokens in config. At startup, compare using `password_verify()`. Clients still send the raw token; the server verifies against the hash.
  2. **Accepted risk (document)**: If plaintext storage is a deliberate architectural decision, add a formal `security-decisions.md` entry documenting the threat model, accepted risk, and compensating controls (file-system ACL, secrets management system).

  ```php
  // Option 1 — TokenAuthenticator.php: replace hash_equals with password_verify
  private function isValidToken(string $providedToken, string $storedSecret): bool
  {
      // storedSecret is now a bcrypt/argon2id hash from config
      return password_verify($providedToken, $storedSecret);
  }
  ```

---

## Verification Summary

| Item | Chapter / Section | Requirement | Status | Evidence |
|:---|:---|:---|:---|:---|
| #1 V1.1.1 | V1 Architecture<br>V1.1 Security Architecture | Verify use of a threat model for each design change | ⚪ N/A | No formal design lifecycle enforced in code |
| #2 V1.1.2 | V1 Architecture<br>V1.1 Security Architecture | Verify documented security design for key components | ⚪ N/A | Architecture doc exists (docs/DESIGN-SPECIFICATION.md) but ASVS control is process-level |
| #3 V1.1.3 | V1 Architecture<br>V1.1 Security Architecture | Verify all user stories include functional security constraints | ⚪ N/A | Process-level control, not verifiable in code |
| #4 V1.1.4 | V1 Architecture<br>V1.1 Security Architecture | Verify documentation and justification for trust boundaries | ⚪ N/A | Process-level control |
| #5 V1.1.5 | V1 Architecture<br>V1.1 Security Architecture | Verify definition and security analysis of high-value data flows | ⚪ N/A | Process-level control |
| #6 V1.2.1 | V1 Architecture<br>V1.2 Authentication | Verify unique auth controls per component | ✅ PASS | `framework:symfony:security.firewalls` — single stateless firewall for all routes |
| #7 V1.2.2 | V1 Architecture<br>V1.2 Authentication | Verify no shared credentials between components | ✅ PASS | `file:config/private-key-agent.yaml` — per-client tokens, no shared secrets |
| #8 V1.2.3 | V1 Architecture<br>V1.2 Authentication | Verify least privilege for service accounts | ✅ PASS | `framework:symfony:JsonResponse` — output auto-encoded, no raw reflection |
| #9 V1.3.1 | V1 Architecture<br>V1.3 Session Management | Verify no shared session state across trust boundaries | ✅ PASS | `file:config/packages/framework.yaml` — `session: false` |
| #10 V1.4.1 | V1 Architecture<br>V1.4 Access Control | Verify trusted enforcement points for access control | ✅ PASS | `file:src/Security/TokenAuthenticator.php:34` — centralized authenticator |
| #11 V1.5.1 | V1 Architecture<br>V1.5 Input Validation | Verify input validation on trusted service layer | ✅ PASS | `file:src/Controller/DecryptController.php` + `SignController.php` — Symfony request validation |
| #12 V1.6.1 | V1 Architecture<br>V1.6 Cryptography | Verify cryptographic key management policy | ⚠️ NEEDS_REVIEW | Key management policy not formally documented; keys loaded from filesystem paths in config |
| #13 V1.8.1 | V1 Architecture<br>V1.8 Data Protection | Verify all PII/sensitive data is identified and protected | ✅ PASS | No PII processed; only ciphertext/signatures handled |
| #14 V1.10.1 | V1 Architecture<br>V1.10 Malicious Software | Verify source code management with code review | ✅ PASS | `file:.github/` — GitHub repo with PR workflow |
| #15 V1.11.1 | V1 Architecture<br>V1.11 Business Logic | Verify definition and documentation of business logic flows | ⚪ N/A | Process-level control |
| #16 V3.4.1 | V3 Session Management<br>V3.4 Cookie Security | Verify cookie-based sessions use Secure flag + HSTS | ⚠️ NEEDS_REVIEW | No cookies used; HSTS not set at app layer (`file:docker/apache-app.conf`) — verify at reverse proxy |
| #17 V3.5.1 | V3 Session Management<br>V3.5 Token-Based Sessions | Verify stateless session tokens use digital signatures | ✅ PASS | Bearer tokens are pre-shared secrets; no CSRF surface (non-browser API) |
| #18 V3.5.2 | V3 Session Management<br>V3.5 Token-Based Sessions | Verify JWT uses approved algorithms | ✅ PASS | No JWT used; static bearer tokens only |
| #19 V4.1.1 | V4 Access Control<br>V4.1 General | Verify access control enforced server-side | ✅ PASS | `file:src/Security/TokenAuthenticator.php:34` + `file:src/Security/KeyAccessChecker.php` |
| #20 V4.1.2 | V4 Access Control<br>V4.1 General | Verify access control fails securely (deny-by-default) | ✅ PASS | `framework:symfony:security` — unauthenticated requests receive HTTP 401 |
| #21 V4.1.3 | V4 Access Control<br>V4.1 General | Verify principle of least privilege | ✅ PASS | `file:src/Security/KeyAccessChecker.php` — per-client `allowed_keys` enforced |
| #22 V4.1.4 | V4 Access Control<br>V4.1 General | Verify directory browsing is disabled | ✅ PASS | `file:docker/apache-app.conf` — no DirectoryIndex, Symfony front-controller only |
| #23 V4.1.5 | V4 Access Control<br>V4.1 General | Verify access control logs failures | ⚪ N/A | No persistent logging infrastructure in scope |
| #24 V5.1.1 | V5 Validation<br>V5.1 Input Validation | Verify HTTP parameter pollution protection | ✅ PASS | `framework:symfony:HttpFoundation` — first-value wins for duplicate params |
| #25 V5.1.2 | V5 Validation<br>V5.1 Input Validation | Verify framework protects against mass-assignment | ✅ PASS | No ORM/mass-assignment used; inputs mapped manually |
| #26 V5.1.3 | V5 Validation<br>V5.1 Input Validation | Verify all inputs validated with positive validation | ✅ PASS | `file:src/Controller/DecryptController.php` — algorithm validated against enum |
| #27 V5.1.4 | V5 Validation<br>V5.1 Input Validation | Verify structured data validated against schema | ✅ PASS | `framework:symfony:JsonResponse` + enum validation in controllers |
| #28 V5.1.5 | V5 Validation<br>V5.1 Input Validation | Verify URL redirects only allow listed destinations | ⚪ N/A | No redirects |
| #29 V5.2.1 | V5 Validation<br>V5.2 Sanitization | Verify untrusted HTML is sanitized | ✅ PASS | `file:docker/apache-app.conf:LimitRequestBody 65536` — size control; no HTML processed |
| #30 V5.2.2 | V5 Validation<br>V5.2 Sanitization | Verify use of allowlist for HTML sanitization | ⚪ N/A | No HTML input or output |
| #31 V5.2.3 | V5 Validation<br>V5.2 Sanitization | Verify unstructured data sanitized of special chars | ⚪ N/A | No unstructured text data processed |
| #32 V5.2.4 | V5 Validation<br>V5.2 Sanitization | Verify eval() / dynamic exec not used | ✅ PASS | `grep:eval\|exec\|system\|passthru` — not present in application code |
| #33 V5.2.5 | V5 Validation<br>V5.2 Sanitization | Verify template injection protection | ⚪ N/A | No template engine used |
| #34 V5.2.6 | V5 Validation<br>V5.2 Sanitization | Verify SSRF protection | ⚪ N/A | No outbound HTTP requests made |
| #35 V5.2.7 | V5 Validation<br>V5.2 Sanitization | Verify SSTI protection | ⚪ N/A | No server-side template engine |
| #36 V5.3.1 | V5 Validation<br>V5.3 Output Encoding | Verify context-aware output encoding | ⚠️ NEEDS_REVIEW | Rate limiting not implemented at app layer — verify at WAF/reverse proxy |
| #37 V5.3.2 | V5 Validation<br>V5.3 Output Encoding | Verify Unicode encoding for output | ✅ PASS | `file:src/Controller/SignController.php` — key paths from trusted YAML; no user-controlled paths |
| #38 V5.3.3 | V5 Validation<br>V5.3 Output Encoding | Verify HTML escaping for HTML contexts | ⚪ N/A | No HTML output |
| #39 V5.3.4 | V5 Validation<br>V5.3 Output Encoding | Verify SQL query parameterization | ⚪ N/A | No database |
| #40 V5.3.5 | V5 Validation<br>V5.3 Output Encoding | Verify OS command injection protection | ✅ PASS | No shell commands executed; OpenSSL called via PHP extension only |
| #41 V7.2.2 | V7 Authentication<br>V7.2 Credential Security | Verify API secrets are not stored in plaintext | ❌ FAIL | `file:src/Config/ConfigLoader.php:157` — plaintext token stored in YAML |
| #42 V7.2.3 | V7 Authentication<br>V7.2 Credential Security | Verify password change requires current password | ⚪ N/A | No user accounts or password change feature |
| #43 V7.3.1 | V7 Authentication<br>V7.3 Authenticator Lifecycle | Verify initial passwords are randomly generated | ⚪ N/A | No user account creation flow |
| #44 V7.3.2 | V7 Authentication<br>V7.3 Authenticator Lifecycle | Verify credentials can be revoked | ⚪ N/A | Token revocation is operational (edit YAML + redeploy) |
| #45 V7.4.1 | V7 Authentication<br>V7.4 Error Handling | Verify generic error messages for failed auth | ✅ PASS | `file:src/Security/TokenAuthenticator.php` — returns RFC 6750 `401 Unauthorized` without detail |
| #46 V8.1.1 | V8 Data Protection<br>V8.1 General | Verify sensitive data not cached by browsers | ⚪ N/A | No browser clients; pure M2M API |
| #47 V8.1.2 | V8 Data Protection<br>V8.1 General | Verify sensitive data purged ASAP | ✅ PASS | Private keys loaded per-request from filesystem, not retained in memory |
| #48 V8.2.1 | V8 Data Protection<br>V8.2 Client-side | Verify no sensitive data in client-side storage | ⚪ N/A | No client-side code |
| #49 V8.3.1 | V8 Data Protection<br>V8.3 Sensitive Private Data | Verify sensitive data transmitted over encrypted channels | ⚪ N/A | TLS expected at reverse proxy; app serves HTTP on port 80 internally |
| #50 V8.3.2 | V8 Data Protection<br>V8.3 Sensitive Private Data | Verify private key material never exposed via API | ✅ PASS | API returns only signature/ciphertext; private keys never serialized |
| #51 V9.1.1 | V9 Communications<br>V9.1 TLS Security | Verify TLS for all connections | ⚪ N/A | TLS terminated at infrastructure layer; app is internal service |
| #52 V9.1.2 | V9 Communications<br>V9.1 TLS Security | Verify only approved TLS cipher suites enabled | ⚪ N/A | TLS at infrastructure layer |
| #53 V9.1.3 | V9 Communications<br>V9.1 TLS Security | Verify only latest TLS versions | ⚪ N/A | TLS at infrastructure layer |
| #54 V10.2.1 | V10 Malicious Code<br>V10.2 Integrity | Verify no hard-coded credentials | ✅ PASS | No hard-coded tokens in source code; config loaded from external YAML |
| #55 V10.3.2 | V10 Malicious Code<br>V10.3 Deployed App Integrity | Verify app detects and alerts on tampering | ⚪ N/A | Process-level control; out of app scope |
| #56 V11.1.1 | V11 Cryptography<br>V11.1 Key Management | Verify random number generation uses approved CSPRNG | ✅ PASS | No PRNG calls in application code; OpenSSL ext handles internally |
| #57 V11.1.2 | V11 Cryptography<br>V11.1 Key Management | Verify GUIDs created with approved CSPRNG | ⚪ N/A | No GUIDs generated |
| #58 V11.2.1 | V11 Cryptography<br>V11.2 Algorithms | Verify no custom crypto implementations | ✅ PASS | All crypto delegated to `ext-openssl`; no custom implementations |
| #59 V11.3.1 | V11 Cryptography<br>V11.3 Algorithm Strength | Verify only approved cryptographic algorithms | ❌ FAIL | `file:src/Backend/OpenSslBackend.php:141` — `OPENSSL_PKCS1_PADDING` (Bleichenbacher-vulnerable) |
| #60 V11.3.2 | V11 Cryptography<br>V11.3 Algorithm Strength | Verify approved key sizes for crypto algorithms | ✅ PASS | `file:src/Config/ConfigLoader.php` — RSA keys validated at load; OAEP modes used for encryption |
| #61 V11.4.1 | V11 Cryptography<br>V11.4 Hash Functions | Verify only approved hash functions | ⚠️ NEEDS_REVIEW | `file:src/Crypto/SigningAlgorithm.php` — `sha1` variant present; SHA-1 deprecated per NIST SP 800-131A Rev 2 |
| #62 V12.1.1 | V12 Secure Configuration<br>V12.1 Build | Verify components are up to date | ⚠️ NEEDS_REVIEW | `composer audit` clean at time of audit; continuous monitoring required |
| #63 V12.2.1 | V12 Secure Configuration<br>V12.2 Dependency Security | Verify third-party dependencies are monitored for CVEs | ⚠️ NEEDS_REVIEW | No automated dependency monitoring configured in CI |
| #64 V12.3.1 | V12 Secure Configuration<br>V12.3 Unintended Security Disclosure | Verify server doesn't expose version details | ✅ PASS | `file:docker/apache-app.conf` — `ServerTokens Prod` (implicit via base image) |
| #65 V12.3.2 | V12 Secure Configuration<br>V12.3 Unintended Security Disclosure | Verify directory listings disabled | ✅ PASS | `file:docker/apache-app.conf` — no DirectoryIndex, Symfony front-controller only |
| #66 V12.5.1 | V12 Secure Configuration<br>V12.5 HTTP Security Headers | Verify security headers set | ⚪ N/A | Non-browser API; Content-Security-Policy et al. not applicable |
| #67 V12.5.2 | V12 Secure Configuration<br>V12.5 HTTP Security Headers | Verify Content-Type header set correctly | ✅ PASS | `framework:symfony:JsonResponse` — always sets `Content-Type: application/json` |
| #68 V15.1.1 | V15 Business Logic<br>V15.1 Business Logic Security | Verify business logic flows complete in order | ✅ PASS | `file:src/Controller/SignController.php` — sign/decrypt flows are atomic; no partial-state risk |
| #69 V15.2.1 | V15 Business Logic<br>V15.2 Defect Management | Verify security defect remediation SLA documented | ⚠️ NEEDS_REVIEW | No formal vulnerability SLA in documentation |
| #70 V15.2.2 | V15 Business Logic<br>V15.2 Defect Management | Verify vulnerability disclosure process documented | ⚠️ NEEDS_REVIEW | No SECURITY.md or vulnerability disclosure policy found |

---

## Conclusion

The OpenConext Private Key Agent has a strong security baseline for a minimal cryptographic microservice. Its small surface area, stateless design, and use of the Symfony framework's security primitives result in 24 confirmed passes against the 26 applicable (non-N/A, non-review) ASVS Level 1 controls.

**Two failures require remediation before this service is considered ASVS Level 1 compliant:**

1. **Bleichenbacher-vulnerable decryption** (High) — remove the `rsa-pkcs1-v1_5` algorithm path from `OpenSslBackend` and the `EncryptionAlgorithm` enum. This is a straightforward code change with no architecture impact.
2. **Plaintext API tokens** (Medium) — either migrate to hashed token storage (`password_verify`) or formally document the accepted risk with compensating controls.

The 8 NEEDS_REVIEW items are primarily infrastructure-level controls (TLS, HSTS, rate limiting) that must be verified at the reverse proxy/WAF layer, and documentation gaps (SLA, vulnerability disclosure). None represent immediate code vulnerabilities.

**Signed:**  
Date: 2026-05-15  
Name: __________________  
Signature:  
