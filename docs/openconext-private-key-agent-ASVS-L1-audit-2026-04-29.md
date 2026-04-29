# Dawn Technology · OWASP ASVS 5.0 Level 1 · Security Audit Report

**Initial Draft author**: AI Agent (Claude Sonnet 4.6 + GPT-5.4, merged by Claude Sonnet 4.6)  
**Reviewed & Finalized by**: _____________________  
**Report Date**: 2026-04-29  
**Skill Version**: 2.3.0  
**ASVS Version**: 5.0.0  

## Application details

**App Version**: 1.0  
**Git Commit**: `92fb50a`  

## Technology Stack

**Language** | PHP 8.5  
**Framework** | Symfony 7.4  
**Database** | None  
**Key Libraries** | Symfony RateLimiter, Monolog, APCu, OpenSSL extension  

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

The OpenConext Private-Key Agent is a narrow-scope REST API that performs RSA cryptographic operations (signing and decryption) using protected private keys, without exposing those keys to callers. Its small attack surface, stateless design, and absence of a browser client, database, session management, and file upload handling render the majority of ASVS L1 items not applicable.

**Strengths:** Timing-safe token comparison (`hash_equals()`), strict algorithm allowlists in input DTOs, rate limiting on authentication failures (5/min per IP backed by APCu shared memory under Apache mod_php), centralized exception handling that returns generic error messages, `expose_php = Off` and `display_errors = Off` in PHP ini, minimal response payloads, and well-structured architecture documentation.

**Critical weaknesses:** The service supports RSA PKCS#1 v1.5 padding for decryption — a mode known to be vulnerable to Bleichenbacher padding oracle attacks. Static pre-shared bearer tokens have no expiry or rotation mechanism. Security response headers are absent from the Apache configuration.

**Coverage Statistics**:

- Total Level 1 Items: 70
- Items Verified: 70
- **Result Breakdown**:
  - 🔴 Critical: 0
  - 🟠 High: 3
  - 🟡 Medium: 3
  - 🟢 Low: 0
  - ✅ PASS: 20
  - ⚠️ NEEDS_REVIEW: 4
- **Compliance Score**: 76.9% (PASS / (Total Items − N/A Items − NEEDS_REVIEW Items) = 20 / 26)
- **Completeness Check**: 70 / 70 (100%)
- **Review Debt**: 4 items require manual verification

---

## Findings

### #13 - V3.2.1 - Unintended Content Interpretation

- **Chapter**: V3 — Web Frontend Security
- **Section**: V3.2 — Unintended Content Interpretation
- **ASVS ID**: V3.2.1
- **Internal Item #**: 13
- **Requirement**: Verify that security controls are in place to prevent browsers from rendering content or functionality in HTTP responses in an incorrect context (e.g. API responses should never render as HTML or JavaScript).
- **Severity**: 🟡 Medium
- **Location**: `docker/apache-app.conf`
- **Evidence**: `missing:X-Content-Type-Options, Content-Security-Policy, X-Frame-Options in docker/apache-app.conf and Symfony response stack`
- **Description**: No security response headers are configured in the Apache VirtualHost or as Symfony middleware. While the risk is reduced because all responses are `application/json` (no HTML output) and the intended clients are backend services rather than browsers, the absence of `X-Content-Type-Options: nosniff`, `Content-Security-Policy`, and `X-Frame-Options` means any browser that directly accesses an endpoint has no nosniff protection. ASVS L1 requires these controls to be in place regardless.
- **Remediation**: Add the following `Header` directives to the `<VirtualHost>` block in `docker/apache-app.conf` (requires `mod_headers`):

  ```apacheconf
  Header always set X-Content-Type-Options "nosniff"
  Header always set X-Frame-Options "DENY"
  Header always set Content-Security-Policy "default-src 'none'"
  Header always set Referrer-Policy "no-referrer"
  ```

  Alternatively, add a global `after_send` event listener in Symfony to set these headers on every JsonResponse.

---

### #41 - V7.2.2 - Fundamental Session Management Security

- **Chapter**: V7 — Session Management
- **Section**: V7.2 — Fundamental Session Management Security
- **ASVS ID**: V7.2.2
- **Internal Item #**: 41
- **Requirement**: Verify that the application uses either secure session management (as described in V7) or uses dynamically generated cryptographically random signed, encrypted tokens (e.g., JWTs) for authentication instead of static API keys.
- **Severity**: 🟠 High
- **Location**: `config/private-key-agent.yaml`, `src/Security/TokenAuthenticator.php`
- **Evidence**: `config/private-key-agent.yaml#clients[].token` — static operator-defined secrets; `src/Security/TokenAuthenticator.php:14` — tokens compared directly; no token issuance endpoint exists
- **Description**: Authentication is implemented using long-lived, static pre-shared bearer tokens defined in `config/private-key-agent.yaml`. There is no token issuance endpoint, no expiry, no rotation mechanism, and no revocation mechanism short of modifying the configuration and redeploying. This violates the ASVS requirement for dynamically generated tokens or proper session management. **Note:** This is an intentional architectural decision documented in `docs/DESIGN-SPECIFICATION.md` ("This is a static pre-shared bearer token scheme, not OAuth 2.0 client credentials"). The finding is recorded faithfully against ASVS L1 standards.
- **Remediation**: At minimum, implement an operational procedure for periodic token rotation and document a rotation interval (e.g., every 90 days). For stronger compliance, consider:
  1. Adding a `created_at` field to each client config and enforcing a maximum token age at startup validation.
  2. Supporting zero-downtime rotation by accepting two tokens simultaneously during a transition window.
  3. Longer-term: replace static tokens with short-lived JWT/JWS access tokens issued by a trusted token service.

---

### #59 - V11.3.1 - Encryption Algorithms

- **Chapter**: V11 — Cryptography
- **Section**: V11.3 — Encryption Algorithms
- **ASVS ID**: V11.3.1
- **Internal Item #**: 59
- **Requirement**: Verify that insecure block modes (e.g., ECB) and weak padding schemes (e.g., PKCS#1 v1.5) are not used.
- **Severity**: 🟠 High
- **Location**: `src/Backend/OpenSslBackend.php:30`, `src/Dto/DecryptRequest.php:21`
- **Evidence**: `src/Backend/OpenSslBackend.php:30` — `'rsa-pkcs1-v1_5' => ['padding' => OPENSSL_PKCS1_PADDING, ...]`; `src/Dto/DecryptRequest.php:21` — `'rsa-pkcs1-v1_5'` in `ALLOWED_ALGORITHMS`
- **Description**: The `ALGORITHM_MAP` in `OpenSslBackend` exposes `rsa-pkcs1-v1_5` as a supported decryption algorithm, which maps to `OPENSSL_PKCS1_PADDING` in `openssl_private_decrypt()`. RSA PKCS#1 v1.5 encryption padding is known to be vulnerable to Bleichenbacher padding oracle attacks (ROBOT attack class, CVE-2017-17428). If an attacker can make repeated decryption queries and observe any timing or error differences, they can recover the plaintext (the symmetric session key). ASVS 5.0 explicitly lists PKCS#1 v1.5 padding as disallowed. **Note:** This algorithm exists for SAML legacy compatibility (XML Encryption with `xenc:EncryptedKey` using `rsa-1_5`). RSA PKCS#1 v1.5 used for **signing** (RSASSA-PKCS1-v1_5, separate construct) is a distinct and widely accepted standard — only the decryption case is the finding.
- **Remediation**:
  1. **Short term**: Add a per-client configuration flag `allow_weak_algorithms: false` (default) and deprecate `rsa-pkcs1-v1_5` with a logged warning when used. Document the accepted risk for deployments that require legacy SAML compatibility.
  2. **Medium term**: Migrate SAML consumers to use `rsa-pkcs1-oaep-mgf1-sha256` or stronger. SimpleSAMLphp supports OAEP since `simplesamlphp/xml-security` v1.6+.
  3. **Long term**: Remove `rsa-pkcs1-v1_5` from the supported algorithm set entirely.
  4. Regardless: Ensure the error responses for all decryption failures are constant-time and return identical error messages to eliminate oracle side-channels. Verify `ExceptionSubscriber` already does this (current implementation returns `'A backend operation failed'` for all 500 errors — this is correct and should be preserved).

---

### #61 - V11.4.1 - Hashing

- **Chapter**: V11 — Cryptography
- **Section**: V11.4 — Hashing
- **ASVS ID**: V11.4.1
- **Internal Item #**: 61
- **Requirement**: Verify that only approved hash functions are used for general cryptographic use cases, including digital signatures. Disallowed hash functions, such as MD5, must not be used for any cryptographic purpose.
- **Severity**: 🟠 High
- **Location**: `src/Dto/SignRequest.php:19`, `src/Crypto/DigestInfoBuilder.php`
- **Evidence**: `src/Dto/SignRequest.php:19` — `'rsa-pkcs1-v1_5-sha1'` in `ALLOWED_ALGORITHMS`; `src/Dto/SignRequest.php:26` — `'rsa-pkcs1-v1_5-sha1' => 20` (SHA-1 digest length); `src/Crypto/DigestInfoBuilder.php` — SHA-1 OID prefix `\x30\x21\x30\x09...` included in DigestInfo ASN.1 structure
- **Description**: SHA-1 is explicitly allowlisted as a signing algorithm (`rsa-pkcs1-v1_5-sha1`). NIST SP 800-131A Rev 2 disallows SHA-1 for digital signature generation from 2014 onwards and fully disallows it after 2030. The `DigestInfoBuilder` constructs the PKCS#1 v1.5 DigestInfo ASN.1 structure with the SHA-1 OID, meaning the agent participates in SHA-1-based signature schemes. While the hash itself is computed by the client, the agent validates, encodes, and signs with SHA-1. **Note:** This algorithm exists for SAML 1.1 / XML-DSig backward compatibility. Business justification does not satisfy the ASVS requirement.
- **Remediation**:
  1. **Short term**: Add a per-client config flag `allow_weak_algorithms: false` (default). When a client submits `rsa-pkcs1-v1_5-sha1`, log a deprecation warning. Document the accepted risk.
  2. **Medium term**: Migrate all SAML consumers to SHA-256 (`rsa-pkcs1-v1_5-sha256`). All modern SAML libraries support SHA-256 (SimpleSAMLphp since v1.6, Shibboleth since 3.x).
  3. **Long term**: Remove `rsa-pkcs1-v1_5-sha1` from `ALLOWED_ALGORITHMS` and `DigestInfoBuilder::PREFIXES`.

---

### #68 - V15.1.1 - Secure Coding and Architecture Documentation

- **Chapter**: V15 — Secure Coding and Architecture
- **Section**: V15.1 — Documentation
- **ASVS ID**: V15.1.1
- **Internal Item #**: 68
- **Requirement**: Verify that application documentation specifies how to handle security vulnerabilities in third-party components (e.g., update within X days of patch release), including a process for identifying, tracking, and remediating vulnerable components.
- **Severity**: 🟡 Medium
- **Location**: `README.md`, `docs/DESIGN-SPECIFICATION.md`
- **Evidence**: `missing:vulnerability remediation timeframe policy` — README references `composer audit` in the CI section but defines no SLA or response timeframe; no `SECURITY.md` exists
- **Description**: Neither `README.md`, `DESIGN-SPECIFICATION.md`, nor any other project document defines a vulnerability remediation SLA or response timeframe for third-party dependencies. While `composer audit` is referenced as a CI step, there is no policy specifying how quickly identified vulnerabilities must be addressed (e.g., Critical within 7 days, High within 30 days).
- **Remediation**: Add a `SECURITY.md` file at the repository root (or a section to `docs/DESIGN-SPECIFICATION.md`) defining:
  - Severity-to-deadline mapping (e.g., Critical: 7 days, High: 30 days, Medium: 90 days)
  - The process for triaging `composer audit` findings
  - How to report security vulnerabilities (responsible disclosure)
  
  Example skeleton:

  ```markdown
  ## Vulnerability Management Policy
  | Severity | Remediation Deadline |
  |----------|----------------------|
  | Critical | 7 days               |
  | High     | 30 days              |
  | Medium   | 90 days              |
  | Low      | Next release cycle   |
  ```

---

### #69 - V15.2.1 - Dependencies

- **Chapter**: V15 — Secure Coding and Architecture
- **Section**: V15.2 — Dependencies
- **ASVS ID**: V15.2.1
- **Internal Item #**: 69
- **Requirement**: Verify that all components are up to date, preferably using a dependency checker during build or compile time. This includes OS components, libraries, frameworks, and other components.
- **Severity**: 🟡 Medium
- **Location**: `composer.json`, CI pipeline
- **Evidence**: `missing:documented remediation timeframes` — `composer audit` is referenced as a CI step (README) and currently returns no advisories, but without a formal remediation policy (V15.1.1 FAIL) there is no timeframe against which to assess that components are "up to date" within acceptable bounds
- **Description**: The requirement cannot be formally satisfied without the policy defined in V15.1.1. While `composer audit` is clean at time of audit, no documented SLA exists to verify that components would be updated within acceptable timeframes if advisories were found. This is a procedural/documentation gap rather than a technical one, and is remediated by the same `SECURITY.md` that resolves V15.1.1.
- **Remediation**: Resolving V15.1.1 (adding a vulnerability remediation policy) also resolves this finding. Ensure the CI pipeline blocks on `composer audit` failures and that the policy SLA is enforced via issue/ticket creation for each advisory.

---

## Verification Summary

| Item | Chapter / Section | Requirement | Status | Evidence |
|:---|:---|:---|:---|:---|
| #1 V1.2.1 | V1 Encoding<br>V1.2 Injection Prevention | Output encoding for HTML/XML context | ⚪ N/A | No HTML or XML output; all responses are `application/json` |
| #2 V1.2.2 | V1 Encoding<br>V1.2 Injection Prevention | URL encoding for dynamically-built URLs | ⚪ N/A | No outbound HTTP calls; no dynamic URL construction |
| #3 V1.2.3 | V1 Encoding<br>V1.2 Injection Prevention | Output encoding for JavaScript/JSON | ✅ PASS | `framework:Symfony:JsonResponse` uses `json_encode()` with default escaping |
| #4 V1.2.4 | V1 Encoding<br>V1.2 Injection Prevention | SQL/database injection protection | ⚪ N/A | No database, SQL, HQL, NoSQL, or ORM |
| #5 V1.2.5 | V1 Encoding<br>V1.2 Injection Prevention | OS command injection protection | ✅ PASS | `src/Backend/OpenSslBackend.php:76,98` — no shell calls; OpenSSL via native PHP extension |
| #6 V1.3.1 | V1 Encoding<br>V1.3 Sanitization | HTML sanitization for WYSIWYG input | ⚪ N/A | No HTML input accepted; all endpoints receive JSON |
| #7 V1.3.2 | V1 Encoding<br>V1.3 Sanitization | No eval() or dynamic code execution | ✅ PASS | No `eval()`, `preg_replace /e`, or `create_function()` in `src/` |
| #8 V1.5.1 | V1 Encoding<br>V1.5 Safe Deserialization | XML parsers configured securely (XXE) | ⚪ N/A | No XML parsing; only JSON is processed |
| #9 V2.1.1 | V2 Validation<br>V2.1 Documentation | Business logic documentation | ✅ PASS | `docs/DESIGN-SPECIFICATION.md` documents auth, rate limiting, per-client key authorization, algorithm restrictions |
| #10 V2.2.1 | V2 Validation<br>V2.2 Input Validation | Input validation (business rules) | ✅ PASS | `src/Dto/SignRequest.php`, `src/Dto/DecryptRequest.php` — algorithm allowlists, Base64/length constraints |
| #11 V2.2.2 | V2 Validation<br>V2.2 Input Validation | Server-side validation enforced | ✅ PASS | `config/packages/framework.yaml#validation.enabled=true`; DTO constraints enforced in controllers |
| #12 V2.3.1 | V2 Validation<br>V2.3 Business Logic Security | Only process business-viable transactions | ✅ PASS | `src/Controller/SignController.php:35`; strict allowlist prevents invalid operations |
| #13 V3.2.1 | V3 Frontend<br>V3.2 Content Interpretation | Security headers preventing incorrect rendering | ❌ FAIL | `missing:X-Content-Type-Options, CSP, X-Frame-Options in docker/apache-app.conf` |
| #14 V3.2.2 | V3 Frontend<br>V3.2 Content Interpretation | Text content rendered as text | ⚪ N/A | No HTML rendering; all responses are JSON |
| #15 V3.3.1 | V3 Frontend<br>V3.3 Cookie Setup | Cookie Secure attribute | ⚪ N/A | No cookies; sessions disabled in `config/packages/framework.yaml` |
| #16 V3.4.1 | V3 Frontend<br>V3.4 Browser Security Headers | HSTS header present | ⚠️ NEEDS_REVIEW | TLS terminated at upstream reverse proxy; Apache serves HTTP on port 80; HSTS config not in codebase |
| #17 V3.4.2 | V3 Frontend<br>V3.4 Browser Security Headers | CORS uses strict allowlist | ⚪ N/A | Server-to-server API with no browser clients; absence of CORS headers is correct by design |
| #18 V3.5.1 | V3 Frontend<br>V3.5 Browser Origin Separation | CSRF protection (no CORS-PLC) | ⚪ N/A | No browser client; `Authorization: Bearer` header cannot be auto-included cross-site |
| #19 V3.5.2 | V3 Frontend<br>V3.5 Browser Origin Separation | CORS allowlist if relying on CORS-PLC | ⚪ N/A | Application does not rely on CORS protected list of callers |
| #20 V3.5.3 | V3 Frontend<br>V3.5 Browser Origin Separation | Sensitive operations use correct HTTP methods | ✅ PASS | `src/Controller/SignController.php:36` (POST), `src/Controller/DecryptController.php:36` (POST), health uses GET |
| #21 V4.1.1 | V4 API<br>V4.1 Generic Web Service Security | Content-Type response header set | ✅ PASS | `framework:Symfony:JsonResponse` auto-sets `Content-Type: application/json`; charset not appended (RFC 8259 §8.1 mandates UTF-8 for JSON, and IANA omits charset from the `application/json` registration) |
| #22 V4.4.1 | V4 API<br>V4.4 WebSocket | WebSocket over TLS (WSS) | ⚪ N/A | No WebSocket endpoints |
| #23 V5.2.1 | V5 File Handling<br>V5.2 Upload and Content | File upload size/type enforcement | ⚪ N/A | No file upload endpoints |
| #24 V5.2.2 | V5 File Handling<br>V5.2 Upload and Content | File content type enforcement | ⚪ N/A | No file uploads |
| #25 V5.3.1 | V5 File Handling<br>V5.3 File Storage | Uploaded files outside document root | ⚪ N/A | No user-uploaded files; pre-configured keys in `config/keys/` outside DocumentRoot |
| #26 V5.3.2 | V5 File Handling<br>V5.3 File Storage | Path traversal prevention for file operations | ✅ PASS | Key file paths are pre-configured; user-supplied key names look up config entries, not file paths directly |
| #27 V6.1.1 | V6 Authentication<br>V6.1 Documentation | Authentication controls documented | ✅ PASS | `docs/DESIGN-SPECIFICATION.md#Authentication` — Bearer token scheme, `hash_equals()`, rate limiting documented |
| #28 V6.2.1 | V6 Authentication<br>V6.2 Password Security | Passwords ≥ 8 characters | ⚪ N/A | No user passwords; authentication uses operator-configured bearer tokens |
| #29 V6.2.2 | V6 Authentication<br>V6.2 Password Security | Users can change passwords | ⚪ N/A | No user passwords |
| #30 V6.2.3 | V6 Authentication<br>V6.2 Password Security | Password change requires current password | ⚪ N/A | No user passwords |
| #31 V6.2.4 | V6 Authentication<br>V6.2 Password Security | Passwords checked against compromised list | ⚪ N/A | No user passwords |
| #32 V6.2.5 | V6 Authentication<br>V6.2 Password Security | No restrictive password composition rules | ⚪ N/A | No user passwords |
| #33 V6.2.6 | V6 Authentication<br>V6.2 Password Security | Password fields use `type=password` | ⚪ N/A | No HTML forms or UI |
| #34 V6.2.7 | V6 Authentication<br>V6.2 Password Security | Password paste functionality allowed | ⚪ N/A | No HTML forms or UI |
| #35 V6.2.8 | V6 Authentication<br>V6.2 Password Security | Passwords verified verbatim (not truncated) | ⚪ N/A | No user passwords; bearer tokens compared verbatim via `hash_equals()` |
| #36 V6.3.1 | V6 Authentication<br>V6.3 General Authentication Security | Brute force / credential stuffing protection | ✅ PASS | `src/Security/TokenAuthenticator.php:29`; `config/packages/rate_limiter.yaml` — 5 failures/60s per IP, returns 429 with `Retry-After` |
| #37 V6.3.2 | V6 Authentication<br>V6.3 General Authentication Security | Default accounts disabled | ✅ PASS | No default accounts; configuration requires operator-defined clients with explicit tokens |
| #38 V6.4.1 | V6 Authentication<br>V6.4 Factor Lifecycle | System-generated initial passwords are random and changed on first use | ⚪ N/A | No system-generated initial passwords |
| #39 V6.4.2 | V6 Authentication<br>V6.4 Factor Lifecycle | No password hints or KBA | ⚪ N/A | No passwords or knowledge-based authentication |
| #40 V7.2.1 | V7 Session<br>V7.2 Fundamental Session Security | All session management server-side | ⚪ N/A | Stateless application; sessions explicitly disabled in `config/packages/framework.yaml` |
| #41 V7.2.2 | V7 Session<br>V7.2 Fundamental Session Security | Dynamically generated tokens (not static API keys) | ❌ FAIL | `config/private-key-agent.yaml#clients[].token` — static pre-shared secrets with no expiry or rotation |
| #42 V7.2.3 | V7 Session<br>V7.2 Fundamental Session Security | Reference tokens use constant-time comparison and secure session store | ⚪ N/A | No reference token session management |
| #43 V7.2.4 | V7 Session<br>V7.2 Fundamental Session Security | New session token issued on authentication | ⚪ N/A | No sessions; no token issuance on authentication |
| #44 V7.4.1 | V7 Session<br>V7.4 Session Termination | Session terminated on logout | ⚪ N/A | No sessions; no logout mechanism |
| #45 V7.4.2 | V7 Session<br>V7.4 Session Termination | All sessions terminated on password change | ⚪ N/A | No sessions; no password changes |
| #46 V8.1.1 | V8 Authorization<br>V8.1 Documentation | Authorization rules documented | ✅ PASS | `docs/DESIGN-SPECIFICATION.md#per-client-key-authorization` — access rules by key name per client documented |
| #47 V8.2.1 | V8 Authorization<br>V8.2 General Authorization Design | Function-level access controls enforced server-side | ✅ PASS | `src/Controller/SignController.php:40-42`, `src/Controller/DecryptController.php:40-42` — all crypto operations enforce auth; health endpoints are intentionally unauthenticated for liveness probes, documented in `docs/DESIGN-SPECIFICATION.md:269-320` |
| #48 V8.2.2 | V8 Authorization<br>V8.2 General Authorization Design | Data-specific access controls | ✅ PASS | `src/Security/AccessControlService.php:14` — per-client key allowlist enforced before every operation |
| #49 V8.3.1 | V8 Authorization<br>V8.3 Operation Level Authorization | Authorization enforced on every request | ✅ PASS | `src/Controller/SignController.php:36`, `src/Controller/DecryptController.php:36` — authenticate + authorize on every call |
| #50 V9.1.1 | V9 Self-contained Tokens<br>V9.1 Token Source and Integrity | Self-contained tokens validated with crypto signature | ⚪ N/A | No JWTs or self-contained tokens; authentication uses pre-shared opaque bearer tokens |
| #51 V9.1.2 | V9 Self-contained Tokens<br>V9.1 Token Source and Integrity | Algorithm allowlist for self-contained tokens | ⚪ N/A | No self-contained tokens |
| #52 V9.1.3 | V9 Self-contained Tokens<br>V9.1 Token Source and Integrity | Key material for self-contained token validation | ⚪ N/A | No self-contained tokens |
| #53 V9.2.1 | V9 Self-contained Tokens<br>V9.2 Token Content | Token validity time span validated | ⚪ N/A | No self-contained tokens with validity spans |
| #54 V10.4.1 | V10 OAuth/OIDC<br>V10.4 Authorization Server | OAuth redirect URI allowlist | ⚪ N/A | No OAuth 2.0 authorization server or redirect URIs |
| #55 V10.4.2 | V10 OAuth/OIDC<br>V10.4 Authorization Server | Authorization server returns code only | ⚪ N/A | No OAuth |
| #56 V10.4.3 | V10 OAuth/OIDC<br>V10.4 Authorization Server | Authorization code short-lived | ⚪ N/A | No OAuth |
| #57 V10.4.4 | V10 OAuth/OIDC<br>V10.4 Authorization Server | Authorization code single-use | ⚪ N/A | No OAuth |
| #58 V10.4.5 | V10 OAuth/OIDC<br>V10.4 Authorization Server | Refresh token rotation | ⚪ N/A | No OAuth; no refresh tokens |
| #59 V11.3.1 | V11 Cryptography<br>V11.3 Encryption Algorithms | No ECB or PKCS#1 v1.5 padding | ❌ FAIL | `src/Backend/OpenSslBackend.php:30` — `OPENSSL_PKCS1_PADDING` for `rsa-pkcs1-v1_5` decryption |
| #60 V11.3.2 | V11 Cryptography<br>V11.3 Encryption Algorithms | Only approved symmetric ciphers/modes (AES-GCM) | ⚪ N/A | No symmetric encryption; RSA private key operations only |
| #61 V11.4.1 | V11 Cryptography<br>V11.4 Hashing | Only approved hash functions used | ❌ FAIL | `src/Dto/SignRequest.php:19` — `'rsa-pkcs1-v1_5-sha1'` in `ALLOWED_ALGORITHMS`; `src/Crypto/DigestInfoBuilder.php` — SHA-1 OID prefix included; SHA-1 not approved by NIST SP 800-131A Rev 2 for digital signatures |
| #62 V12.1.1 | V12 TLS<br>V12.1 General TLS Guidance | Only TLS 1.2 or 1.3 used | ⚠️ NEEDS_REVIEW | TLS terminated at upstream reverse proxy; Apache serves HTTP on port 80; TLS version config not in codebase |
| #63 V12.2.1 | V12 TLS<br>V12.2 HTTPS for External Services | TLS used for all connections | ⚠️ NEEDS_REVIEW | TLS enforced externally; compose.yaml exposes 443→80; end-to-end TLS depends on deployment environment |
| #64 V12.2.2 | V12 TLS<br>V12.2 HTTPS for External Services | Certificate chain trusted and valid | ⚠️ NEEDS_REVIEW | Certificate management handled by upstream reverse proxy; not assessable from codebase |
| #65 V13.4.1 | V13 Configuration<br>V13.4 Information Leakage | No `.git` metadata exposed | ✅ PASS | `docker/apache-app.conf#DocumentRoot=/var/www/html/public`; `.git` at `/var/www/html/.git` is outside DocumentRoot |
| #66 V14.2.1 | V14 Data Protection<br>V14.2 General Data Protection | Sensitive data not in URLs or query strings | ✅ PASS | `src/Security/TokenAuthenticator.php:22` — token in `Authorization` header; crypto data in request body |
| #67 V14.3.1 | V14 Data Protection<br>V14.3 Client-side Protection | Authenticated data cleared from client storage | ⚪ N/A | No browser client; no DOM; no client-side storage |
| #68 V15.1.1 | V15 Secure Coding<br>V15.1 Documentation | Vulnerability remediation timeframes documented | ❌ FAIL | `missing:vulnerability remediation SLA in README.md and docs/`; no `SECURITY.md` |
| #69 V15.2.1 | V15 Secure Coding<br>V15.2 Dependencies | Components within remediation timeframes | ❌ FAIL | `missing:documented remediation timeframes` — V15.1.1 FAIL means no SLA exists against which to assess compliance; `composer audit` is run but without a policy, adherence cannot be formally demonstrated |
| #70 V15.3.1 | V15 Secure Coding<br>V15.3 Defensive Coding | Only required fields returned in responses | ✅ PASS | `src/Controller/SignController.php:70` — `{signature}`; `src/EventSubscriber/ExceptionSubscriber.php:49` — generic error messages, no stack traces |

---

## Conclusion

The OpenConext Private-Key Agent has a strong security foundation for its narrow purpose. Its stateless design, absence of a database, and server-to-server-only API model eliminate large categories of web application risk. The most significant findings (V11.3.1 and V11.4.1) concern RSA PKCS#1 v1.5 decryption padding and SHA-1 usage — both cryptographic weaknesses present for SAML legacy compatibility that have been exploited in the real world against SAML deployments. V11.3.1 should be prioritized for remediation as it exposes a Bleichenbacher padding oracle attack surface; V11.4.1 follows closely since SHA-1 is fully disallowed by NIST for digital signatures.

The static bearer token scheme (V7.2.2) is a known architectural decision and is acceptable when combined with operational controls such as periodic rotation and tight network access controls. Adding an operational rotation policy and documenting remediation timeframes (V15.1.1) are low-effort, high-compliance-value tasks.

Security headers (V3.2.1) are straightforward to add and should be done in the next maintenance release.

The four NEEDS_REVIEW items all relate to the TLS and HSTS configuration of the upstream reverse proxy, which is outside the codebase. These require verification in the deployment runbook for each environment.

**Recommended remediation priority:**
1. 🟠 **V11.3.1** — Deprecate `rsa-pkcs1-v1_5` decryption; add risk documentation for legacy deployments
2. 🟠 **V11.4.1** — Deprecate `rsa-pkcs1-v1_5-sha1` signing; migrate SAML consumers to SHA-256
3. 🟠 **V7.2.2** — Document and implement a token rotation procedure
4. 🟡 **V3.2.1** — Add security headers to `docker/apache-app.conf`
5. 🟡 **V15.1.1 + V15.2.1** — Create `SECURITY.md` with vulnerability management policy and remediation SLA (resolves both findings)
6. ⚠️ **V3.4.1 / V12.1.1 / V12.2.1 / V12.2.2** — Verify TLS and HSTS configuration in deployment runbook

**Signed:**  
Date: 2026-04-29  
Name: __________________  
Signature:  

---
