# Dawn Technology · OWASP ASVS 5.0 Level 1 · Security Audit Report

**Initial Draft author**: AI Automation (Claude Sonnet 4.6 — dual subagent evaluation)  
**Reviewed & Finalized by**: _____________________  
**Report Date**: 2026-04-19  
**ASVS Version**: 5.0.0  

## Application details

**App Version**: 0.1-dev  
**Git Commit**: c84ed5d  

## Technology Stack

**Language** | PHP 8.5+  
**Framework** | Symfony 7.4 / FrankenPHP (Caddy worker mode)  
**Database** | None  
**Key Libraries** | `symfony/framework-bundle`, `symfony/validator`, `gamringer/php-pkcs11`, `mroest/php-pkcs11` (custom fork for ZTS)  

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

The **OpenConext Private Key Agent** is a purpose-built, machine-to-machine (M2M) REST API that performs RSA cryptographic operations (signing and decryption) using HSM- or file-backed private keys, without exposing the keys to callers. Its narrow, well-defined API surface — two endpoints plus a health check — inherently eliminates large classes of web vulnerabilities.

Of 70 ASVS Level 1 requirements evaluated, **38 are Not Applicable** due to the M2M-API nature of the service (no browser clients, no user accounts, no sessions, no file uploads, no database, no self-contained tokens, no OAuth AS role). Of the 32 applicable items, **24 pass** and **6 fail**.

**Strengths**: Input validation with Symfony allowlists, timing-safe bearer-token comparison, authorization enforcement at the service layer, response data minimisation, and sanitised error messages all represent solid security practice.

**Key risks**:

- RSA decryption still accepts the **PKCS#1 v1.5** padding scheme, which is vulnerable to Bleichenbacher-style padding oracle attacks.
- Authentication relies on **static pre-shared bearer tokens** that never expire or rotate.
- The committed Caddy configuration uses **`tls internal`** (self-signed certificate), which is unsuitable for production.
- **No application-level rate limiting** is implemented; the design specification explicitly delegates this to the operator without specifying expected controls.

**Coverage Statistics**:

- Total Level 1 Items: 70
- Items Verified: 70
- **Result Breakdown**:
  - 🔴 Critical: 0
  - 🟠 High: 3
  - 🟡 Medium: 3
  - 🟢 Low: 0
  - ✅ PASS: 24
  - ⚪ N/A: 38
  - ⚠️ NEEDS_REVIEW: 2
- **Compliance Score**: 80% (24 PASS out of 30 scored items; excludes 38 N/A and 2 NEEDS_REVIEW)
- **Completeness Check**: 70 / 70 (100%)
- **Review Debt**: 2 items require manual verification

---

## Findings

### #1 — V6.1.1 — Authentication Documentation

- **Chapter**: Authentication
- **Section**: Authentication Documentation
- **ASVS ID**: V6.1.1
- **Internal Item #**: 27
- **Requirement**: Verify that application documentation defines how controls such as rate limiting, anti-automation, and adaptive responses are implemented to defend against credential stuffing and brute-force attacks against authentication endpoints.
- **Severity**: 🟡 Medium
- **Location**: `docs/DESIGN-SPECIFICATION.md` (line 1010)
- **Evidence**: `missing:rate_limiting_policy_documentation` — design spec states "No rate limiting (operator responsibility)" but does not define expected controls, thresholds, or implementation guidance
- **Description**: The design specification acknowledges the absence of application-level rate limiting and delegates responsibility to the operator without specifying what controls are expected. This leaves operators without documented expectations and means compliance with this requirement cannot be verified. ASVS requires that documentation define *how* controls are implemented, not merely that they are delegated.
- **Remediation**:
  Add a security-controls section to the design documentation that specifies:
  1. Expected maximum request rate per client token (e.g., 100 req/s)
  2. Expected lockout / throttling behaviour after N failed authentication attempts
  3. Reference implementation for operators (e.g., Caddy `rate_limit` module, WAF rule, Kubernetes NetworkPolicy)

  ```markdown
  ## Rate Limiting and Anti-Automation (Operator Requirements)
  Operators MUST implement the following controls at the infrastructure layer:
  - Max 100 requests/second per client IP
  - Temporary block (≥ 60 s) after 10 consecutive authentication failures
  Recommended: Caddy rate_limit module or upstream WAF / API gateway.
  ```

---

### #3 — V6.3.1 — General Authentication Security

- **Chapter**: Authentication
- **Section**: General Authentication Security
- **ASVS ID**: V6.3.1
- **Internal Item #**: 36
- **Requirement**: Verify that controls to prevent attacks such as credential stuffing and password brute force are implemented according to the application's security documentation.
- **Severity**: 🟡 Medium
- **Location**: `src/Security/TokenAuthenticator.php`
- **Evidence**: `missing:rate_limiting_middleware; missing:attempt_counter` — `TokenAuthenticator::authenticate()` performs `hash_equals()` comparison but has no rate limiting, attempt counting, or lockout logic; no rate-limiting library in `composer.json`
- **Description**: An attacker can make unlimited bearer-token guesses against the `/sign/*` or `/decrypt/*` endpoints without triggering any throttle or lockout. While `hash_equals()` prevents timing-based enumeration, it does not prevent high-volume brute-force attacks against the token space. The design specification explicitly omits this control ("No rate limiting (operator responsibility)"), but no operator-side rate limiting can be verified from the committed configuration.
- **Remediation**:
  Option A — Application layer (preferred): integrate Symfony's built-in rate limiter:

  ```bash
  composer require symfony/rate-limiter
  ```

  ```yaml
  # config/packages/rate_limiter.yaml
  framework:
      rate_limiter:
          token_auth:
              policy: fixed_window
              limit: 10
              interval: '1 minute'
  ```

  Option B — Infrastructure layer: document and enforce Caddy `rate_limit` module or API gateway rules (see V6.1.1 remediation).

---

### #4 — V7.2.2 — Fundamental Session Management Security

- **Chapter**: Session Management
- **Section**: Fundamental Session Management Security
- **ASVS ID**: V7.2.2
- **Internal Item #**: 41
- **Requirement**: Verify that the application uses either self-contained or reference tokens that are dynamically generated for session management.
- **Severity**: 🟠 High
- **Location**: `src/Config/ConfigLoader.php`, `config/private-key-agent.yaml`
- **Evidence**: `src/Config/ClientConfig.php:$token (static string); config/private-key-agent.yaml (tokens statically provisioned in YAML)`
- **Description**: Authentication tokens are static, long-lived strings loaded from YAML configuration. They are never rotated, never expire, and are not generated by the application. A compromised token grants indefinite access with no automatic expiry or rotation mechanism. This is a fundamental design choice that diverges from ASVS session-management requirements.
- **Remediation**:
  For long-term alignment, consider migrating to OAuth 2.0 Client Credentials flow. Callers obtain short-lived access tokens from a trusted authorisation server; the private-key agent validates JWTs. This removes static secrets entirely.

  As a near-term mitigation, document and enforce a token rotation policy:
  1. Minimum token entropy: 256 bits of cryptographic randomness (e.g., `openssl rand -hex 32`)
  2. Maximum token lifetime: 90 days
  3. Immediate revocation procedure on suspected compromise

  ```bash
  # Generate a compliant token
  openssl rand -hex 32
  ```

---

### #5 — V11.3.1 — Encryption Algorithms

- **Chapter**: Cryptography
- **Section**: Encryption Algorithms
- **ASVS ID**: V11.3.1
- **Internal Item #**: 59
- **Requirement**: Verify that insecure block modes (e.g., ECB) and weak padding schemes (e.g., PKCS#1 v1.5) are not used.
- **Severity**: 🟠 High
- **Location**: `src/Dto/DecryptRequest.php:18`, `src/Backend/OpenSslDecryptionBackend.php`
- **Evidence**: `src/Dto/DecryptRequest.php:18 (rsa-pkcs1-v1_5 in ALGORITHMS constant); src/Backend/OpenSslDecryptionBackend.php (OPENSSL_PKCS1_PADDING branch)`
- **Description**: RSA decryption with PKCS#1 v1.5 padding is an explicitly allowed algorithm (`rsa-pkcs1-v1_5`). This scheme is vulnerable to the Bleichenbacher 1998 padding oracle attack and its modern variants (ROBOT, DROWN). An attacker who can submit chosen ciphertext to the decryption endpoint and observe whether decryption succeeds or fails may be able to recover plaintext through an adaptive chosen-ciphertext attack. The `/decrypt` endpoint constitutes a decryption oracle.

  > ⚠️ **This is especially significant** for the private-key agent use-case: the service exists precisely to perform private key operations on behalf of callers, making it a natural decryption oracle.

- **Remediation**:
  Remove `rsa-pkcs1-v1_5` from the allowed decryption algorithms and require OAEP padding only:

  ```php
  // src/Dto/DecryptRequest.php — BEFORE
  const ALGORITHMS = [
      'rsa-pkcs1-v1_5'   => OPENSSL_PKCS1_PADDING,
      'rsa-oaep'         => OPENSSL_PKCS1_OAEP_PADDING,
      'rsa-oaep-sha256'  => OPENSSL_PKCS1_OAEP_PADDING,
  ];

  // src/Dto/DecryptRequest.php — AFTER
  const ALGORITHMS = [
      'rsa-oaep'         => OPENSSL_PKCS1_OAEP_PADDING,
      'rsa-oaep-sha256'  => OPENSSL_PKCS1_OAEP_PADDING,
  ];
  ```

  Update the `#[Assert\Choice]` constraint accordingly. Callers still relying on PKCS#1 v1.5 decryption must migrate to OAEP before this change is deployed.

---

### #6 — V12.2.2 — HTTPS Communication with External Facing Services

- **Chapter**: Secure Communication
- **Section**: HTTPS Communication with External Facing Services
- **ASVS ID**: V12.2.2
- **Internal Item #**: 64
- **Requirement**: Verify that external facing services use publicly trusted TLS certificates.
- **Severity**: 🟠 High
- **Location**: `docker/Caddyfile:2`
- **Evidence**: `docker/Caddyfile:2 (tls internal — Caddy internal CA, not publicly trusted)`
- **Description**: The committed Caddyfile uses `tls internal`, which generates a certificate from Caddy's built-in private CA. This certificate is not trusted by external clients or operating system trust stores. In production this would force clients to disable certificate verification, eliminating TLS's authentication guarantee and opening the channel to MitM attacks. The `tls internal` directive is appropriate only for local development.
- **Remediation**:
  For production deployments, replace `tls internal` with a publicly trusted certificate. Options:

  ```caddy
  # Option A — automatic ACME/Let's Encrypt (requires publicly routable FQDN)
  private-key-agent.example.org {
      tls admin@example.org
      ...
  }

  # Option B — manually provisioned certificate
  {
      tls /etc/ssl/certs/agent.crt /etc/ssl/private/agent.key
      ...
  }
  ```

  Add a `# FOR DEVELOPMENT ONLY` comment to the committed Caddyfile and provide a production Caddyfile template or documented override in the deployment guide.

---

### #7 — V15.1.1 — Secure Coding and Architecture Documentation

- **Chapter**: Secure Coding and Architecture
- **Section**: Secure Coding and Architecture Documentation
- **ASVS ID**: V15.1.1
- **Internal Item #**: 68
- **Requirement**: Verify that application documentation defines risk-based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general.
- **Severity**: 🟡 Medium
- **Location**: Repository root (no `SECURITY.md` present)
- **Evidence**: `missing:SECURITY.md; missing:vulnerability_remediation_policy`
- **Description**: No `SECURITY.md` or equivalent document defines how quickly third-party vulnerabilities must be remediated, nor is there a documented policy for dependency updates. Without documented SLAs, it is impossible to verify that the project remains within acceptable risk thresholds over time.
- **Remediation**:
  Create `SECURITY.md` in the repository root containing at minimum:

  ```markdown
  ## Vulnerability Remediation Policy

  | Severity | Remediation SLA |
  |----------|-----------------|
  | Critical | 72 hours        |
  | High     | 7 days          |
  | Medium   | 30 days         |
  | Low      | 90 days         |

  Automated dependency scanning is run on every PR and weekly on the main branch
  (`composer audit`). Vulnerabilities are tracked as GitHub issues with the
  `security` label.

  ## Reporting a Vulnerability
  Please report security vulnerabilities to [security@example.org].
  ```

---

## Verification Summary

| Item | Chapter / Section | Requirement | Status | Evidence |
|:---|:---|:---|:---|:---|
| #1 V1.2.1 | Encoding and Sanitization<br>Injection Prevention | Output encoding for HTTP response, HTML document, or XML document | ⚪ N/A | Pure JSON API; no HTML/XML output |
| #2 V1.2.2 | Encoding and Sanitization<br>Injection Prevention | URL encoding when dynamically building URLs | ⚪ N/A | No dynamic URL construction with untrusted data |
| #3 V1.2.3 | Encoding and Sanitization<br>Injection Prevention | Output encoding when dynamically building JavaScript / JSON content | ✅ PASS | `framework:symfony:JsonResponse` (json_encode handles all output) |
| #4 V1.2.4 | Encoding and Sanitization<br>Injection Prevention | SQL / NoSQL parameterized queries | ⚪ N/A | No database driver in composer.json |
| #5 V1.2.5 | Encoding and Sanitization<br>Injection Prevention | OS command injection prevention | ✅ PASS | No exec/shell_exec/system/passthru calls found in src/ |
| #6 V1.3.1 | Encoding and Sanitization<br>Sanitization | HTML sanitization for WYSIWYG / untrusted HTML input | ⚪ N/A | No HTML input accepted; pure JSON API |
| #7 V1.3.2 | Encoding and Sanitization<br>Sanitization | No eval() or dynamic code execution | ✅ PASS | No eval(), create_function(), or SpEL usage found in src/ |
| #8 V1.5.1 | Encoding and Sanitization<br>Safe Deserialization | XML parser restrictive config (XXE prevention) | ⚪ N/A | No XML parsing; JSON is the only data format |
| #9 V2.1.1 | Validation and Business Logic<br>Validation and Business Logic Documentation | Input validation documentation for data formats | ✅ PASS | `docs/DESIGN-SPECIFICATION.md` documents API contract; `src/Dto/SignRequest.php`, `src/Dto/DecryptRequest.php` define accepted formats |
| #10 V2.2.1 | Validation and Business Logic<br>Input Validation | Positive / allow-list input validation | ✅ PASS | `src/Dto/SignRequest.php:17-19` (`@Assert\Choice` for algorithms); `src/Dto/DecryptRequest.php:18` (`@Assert\Choice`); `src/Validator/Base64Validator.php` (strict base64 allowlist) |
| #11 V2.2.2 | Validation and Business Logic<br>Input Validation | Input validation at trusted service layer | ✅ PASS | `src/Controller/SignController.php:47-55`; `src/Controller/DecryptController.php:47-55` — `$this->validator->validate()` called server-side before processing |
| #12 V2.3.1 | Validation and Business Logic<br>Business Logic Security | Business logic flows processed in expected sequential order | ⚪ N/A | Single-step operations (sign, decrypt); no multi-step business logic flow |
| #13 V3.2.1 | Web Frontend Security<br>Unintended Content Interpretation | Security controls to prevent incorrect browser rendering context | ✅ PASS | `docker/Caddyfile`: `X-Content-Type-Options: nosniff`; `X-Frame-Options: DENY` |
| #14 V3.2.2 | Web Frontend Security<br>Unintended Content Interpretation | Safe rendering functions for text content | ⚪ N/A | No browser rendering; no HTML responses |
| #15 V3.3.1 | Web Frontend Security<br>Cookie Setup | Cookies have Secure attribute | ⚪ N/A | No cookies; stateless Bearer token authentication |
| #16 V3.4.1 | Web Frontend Security<br>Browser Security Mechanism Headers | Strict-Transport-Security header present | ✅ PASS | `docker/Caddyfile` — `Strict-Transport-Security "max-age=31536000; includeSubDomains"` added (remediated 2026-04-19) |
| #17 V3.4.2 | Web Frontend Security<br>Browser Security Mechanism Headers | CORS Access-Control-Allow-Origin is a fixed value | ✅ PASS | No CORS headers configured; same-origin policy enforced by browser; M2M API |
| #18 V3.5.1 | Web Frontend Security<br>Browser Origin Separation | CSRF protection (anti-CSRF token or equivalent) | ⚪ N/A | No cookies or sessions; Bearer token auth in Authorization header prevents CSRF |
| #19 V3.5.2 | Web Frontend Security<br>Browser Origin Separation | CORS preflight used to prevent disallowed cross-origin requests | ⚪ N/A | No browser clients; no CORS policy required |
| #20 V3.5.3 | Web Frontend Security<br>Browser Origin Separation | Sensitive functionality uses POST / PUT / PATCH / DELETE | ✅ PASS | `src/Controller/SignController.php:#[Route('/sign/{keyName}', methods: ['POST'])]`; `src/Controller/DecryptController.php:#[Route('/decrypt/{keyName}', methods: ['POST'])]` |
| #21 V4.1.1 | API and Web Service<br>Generic Web Service Security | Every HTTP response with body contains matching Content-Type | ✅ PASS | `framework:symfony:JsonResponse` sets `Content-Type: application/json; charset=UTF-8` on all responses |
| #22 V4.4.1 | API and Web Service<br>WebSocket | WebSocket connections use WSS | ⚪ N/A | No WebSocket functionality |
| #23 V5.2.1 | File Handling<br>File Upload and Content | File upload size limits | ⚪ N/A | No file upload functionality |
| #24 V5.2.2 | File Handling<br>File Upload and Content | File upload type validation | ⚪ N/A | No file upload functionality |
| #25 V5.3.1 | File Handling<br>File Storage | Uploaded files in public folder not server-side executed | ⚪ N/A | No file upload functionality |
| #26 V5.3.2 | File Handling<br>File Storage | File paths use internally generated names, not user input | ✅ PASS | `src/Config/BackendGroupConfig.php:$keyPath` loaded from YAML config only; no user-supplied file paths |
| #27 V6.1.1 | Authentication<br>Authentication Documentation | Documentation defines rate limiting and anti-automation controls | ❌ FAIL | `missing:rate_limiting_policy_documentation` — design spec delegates without specifying expected controls |
| #28 V6.2.1 | Authentication<br>Password Security | Passwords minimum 8 characters | ⚪ N/A | No user accounts or passwords |
| #29 V6.2.2 | Authentication<br>Password Security | Users can change their password | ⚪ N/A | No user accounts |
| #30 V6.2.3 | Authentication<br>Password Security | Password change requires current password | ⚪ N/A | No user accounts |
| #31 V6.2.4 | Authentication<br>Password Security | Passwords checked against breached password lists | ⚪ N/A | No user passwords |
| #32 V6.2.5 | Authentication<br>Password Security | Any password composition permitted | ⚪ N/A | No user passwords |
| #33 V6.2.6 | Authentication<br>Password Security | Password input uses type=password | ⚪ N/A | No HTML UI; pure JSON API |
| #34 V6.2.7 | Authentication<br>Password Security | Paste functionality permitted in password fields | ⚪ N/A | No HTML UI |
| #35 V6.2.8 | Authentication<br>Password Security | Password verified exactly as received | ⚪ N/A | No user passwords; bearer tokens use `hash_equals()` |
| #36 V6.3.1 | Authentication<br>General Authentication Security | Controls to prevent credential stuffing / brute force | ❌ FAIL | `missing:rate_limiting_middleware; missing:attempt_counter in src/Security/TokenAuthenticator.php` |
| #37 V6.3.2 | Authentication<br>General Authentication Security | No default user accounts present or enabled | ✅ PASS | No user accounts exist; bearer tokens are operator-provisioned per deployment |
| #38 V6.4.1 | Authentication<br>Authentication Factor Lifecycle and Recovery | System-generated initial passwords securely random | ⚪ N/A | No system-generated initial passwords |
| #39 V6.4.2 | Authentication<br>Authentication Factor Lifecycle and Recovery | No password hints or security questions | ⚪ N/A | No user accounts, no KBA |
| #40 V7.2.1 | Session Management<br>Fundamental Session Management Security | Session token verification at trusted backend service | ✅ PASS | `src/Security/TokenAuthenticator.php:authenticate()` — server-side `hash_equals()` comparison |
| #41 V7.2.2 | Session Management<br>Fundamental Session Management Security | Dynamically generated tokens for session management | ❌ FAIL | `src/Config/ClientConfig.php:$token` static string; tokens loaded from YAML config; never rotated |
| #42 V7.2.3 | Session Management<br>Fundamental Session Management Security | Reference tokens are unique and cryptographically random | ⚠️ NEEDS_REVIEW | Tokens are operator-provisioned; no entropy validation in application code (`src/Security/TokenAuthenticator.php`); quality depends on operator practice |
| #43 V7.2.4 | Session Management<br>Fundamental Session Management Security | New session token generated on authentication | ⚪ N/A | Stateless API; no session establishment on authentication |
| #44 V7.4.1 | Session Management<br>Session Termination | Session tokens invalidated on logout / expiration | ⚪ N/A | Stateless API; no session lifecycle |
| #45 V7.4.2 | Session Management<br>Session Termination | All sessions terminated when account disabled/deleted | ⚪ N/A | No user accounts to disable |
| #46 V8.1.1 | Authorization<br>Authorization Documentation | Authorization documentation defines access rules | ✅ PASS | `docs/DESIGN-SPECIFICATION.md` — client→key mapping model documented; per-client key access and wildcard rules described |
| #47 V8.2.1 | Authorization<br>General Authorization Design | Function-level access restricted to permitted consumers | ✅ PASS | `src/Controller/SignController.php:38-39`; `src/Controller/DecryptController.php:38-39` — authenticate + checkAccess before any operation |
| #48 V8.2.2 | Authorization<br>General Authorization Design | Data-specific access restricted (IDOR / BOLA prevention) | ✅ PASS | `src/Security/AccessControlService.php:checkAccess()` validates per-client key authorisation before every operation |
| #49 V8.3.1 | Authorization<br>Operation Level Authorization | Authorization enforced at trusted service layer | ✅ PASS | `src/Security/AccessControlService.php` (service layer); not reliant on client-supplied claims |
| #50 V9.1.1 | Self-contained Tokens<br>Token source and integrity | Self-contained tokens validated by digital signature/MAC | ⚪ N/A | No self-contained tokens (JWT/PASETO); opaque reference tokens used |
| #51 V9.1.2 | Self-contained Tokens<br>Token source and integrity | Only allowlisted algorithms for self-contained tokens | ⚪ N/A | No self-contained tokens |
| #52 V9.1.3 | Self-contained Tokens<br>Token source and integrity | Key material for token validation from trusted sources | ⚪ N/A | No self-contained tokens |
| #53 V9.2.1 | Self-contained Tokens<br>Token content | Token validity time span respected | ⚪ N/A | No self-contained tokens; opaque reference tokens have no embedded claims |
| #54 V10.4.1 | OAuth and OIDC<br>OAuth Authorization Server | Redirect URI validated against client-specific allowlist | ⚪ N/A | Application is not an OAuth Authorization Server |
| #55 V10.4.2 | OAuth and OIDC<br>OAuth Authorization Server | Authorization code single-use | ⚪ N/A | Not an OAuth AS; no authorization codes issued |
| #56 V10.4.3 | OAuth and OIDC<br>OAuth Authorization Server | Authorization code short-lived | ⚪ N/A | Not an OAuth AS |
| #57 V10.4.4 | OAuth and OIDC<br>OAuth Authorization Server | Client restricted to required grant types | ⚪ N/A | Not an OAuth AS |
| #58 V10.4.5 | OAuth and OIDC<br>OAuth Authorization Server | Refresh token replay attack mitigation | ⚪ N/A | Not an OAuth AS; no refresh tokens |
| #59 V11.3.1 | Cryptography<br>Encryption Algorithms | No insecure block modes or PKCS#1 v1.5 padding | ❌ FAIL | `src/Dto/DecryptRequest.php:18 (rsa-pkcs1-v1_5 in ALGORITHMS)`; `src/Backend/OpenSslDecryptionBackend.php (OPENSSL_PKCS1_PADDING)` |
| #60 V11.3.2 | Cryptography<br>Encryption Algorithms | Only approved ciphers and modes (e.g., AES-GCM) | ⚪ N/A | No symmetric encryption in application code; RSA operations only |
| #61 V11.4.1 | Cryptography<br>Hashing and Hash-based Functions | Only approved hash functions | ✅ PASS | `src/Dto/SignRequest.php:ALGORITHMS` — only SHA-256/384/512 variants (no SHA-1, no MD5) |
| #62 V12.1.1 | Secure Communication<br>General TLS Security Guidance | Only TLS 1.2 and 1.3 enabled | ✅ PASS | `framework:caddy` — TLS 1.2 minimum enforced by default; no TLS 1.0/1.1 override in `docker/Caddyfile` |
| #63 V12.2.1 | Secure Communication<br>HTTPS Communication with External Facing Services | TLS for all client↔service connectivity | ✅ PASS | `docker/Caddyfile` — HTTPS only on port 443; no HTTP listener |
| #64 V12.2.2 | Secure Communication<br>HTTPS Communication with External Facing Services | Publicly trusted TLS certificates for external-facing services | ❌ FAIL | `docker/Caddyfile:2 (tls internal — Caddy internal CA, self-signed)` |
| #65 V13.4.1 | Configuration<br>Unintended Information Leakage | No source control metadata (.git/.svn) in deployment | ✅ PASS | `.git` in `.dockerignore`; webroot is `public/` (Caddyfile: `root * /app/public`) |
| #66 V14.2.1 | Data Protection<br>General Data Protection | Sensitive data in HTTP body/headers, not URLs | ✅ PASS | Bearer token in `Authorization` header; sign/decrypt data in POST JSON body; no sensitive data in query strings or path |
| #67 V14.3.1 | Data Protection<br>Client-side Data Protection | Authenticated data cleared from client storage | ⚪ N/A | Stateless M2M API; no cookies, sessions, or client-side storage |
| #68 V15.1.1 | Secure Coding and Architecture<br>Secure Coding and Architecture Documentation | Risk-based remediation timeframes documented | ❌ FAIL | `missing:SECURITY.md`; `missing:vulnerability_remediation_policy` |
| #69 V15.2.1 | Secure Coding and Architecture<br>Security Architecture and Dependencies | Components within documented remediation timeframes | ⚠️ NEEDS_REVIEW | No timeframes documented (V15.1.1 FAIL); `composer audit` shows no known vulnerabilities at time of audit |
| #70 V15.3.1 | Secure Coding and Architecture<br>Defensive Coding | Only required subset of fields returned | ✅ PASS | `src/Controller/SignController.php` returns `{signature}`; `src/Controller/DecryptController.php` returns `{decrypted_data}`; no extra fields |

---

## Conclusion

The OpenConext Private Key Agent demonstrates a strong security foundation for a cryptographic proxy service: the API surface is minimal, input validation is thorough, authorisation is enforced at the service layer, and sensitive data is properly contained in requests and responses. The stateless, machine-to-machine design eliminates a large class of ASVS requirements (sessions, cookies, user accounts, file uploads, database access, OAuth AS).

Six ASVS L1 requirements fail. The most critical is **V11.3.1**: the service is explicitly a decryption oracle, and allowing PKCS#1 v1.5 decryption exposes it to a well-known class of adaptive chosen-ciphertext attacks (Bleichenbacher). Removing `rsa-pkcs1-v1_5` from the allowed decryption algorithms is the highest-priority remediation.

**V3.4.1 (HSTS) has been remediated** — `Strict-Transport-Security "max-age=31536000; includeSubDomains"` was added to `docker/Caddyfile` on 2026-04-19.

The remaining High-severity findings (**V7.2.2 static tokens**, **V12.2.2 self-signed TLS**) are important for hardening the service in production. The Medium-severity findings (**V6.1.1/V6.3.1 rate limiting** and **V15.1.1 security policy documentation**) represent process and documentation gaps rather than direct exploitation paths.

**Recommended remediation order**:

1. 🟠 **V11.3.1** — Remove `rsa-pkcs1-v1_5` from DecryptRequest allowed algorithms
2. 🟠 **V12.2.2** — Document production TLS configuration; label `tls internal` as dev-only
3. 🟠 **V7.2.2** — Plan migration to OAuth 2.0 Client Credentials or enforce token rotation policy
4. 🟡 **V6.1.1 / V6.3.1** — Document rate limiting requirements; implement or enforce at infrastructure
5. 🟡 **V15.1.1** — Create `SECURITY.md` with remediation SLAs
6. ⚠️ **V7.2.3** — Document and enforce minimum token entropy requirements
7. ⚠️ **V15.2.1** — Re-evaluate once V15.1.1 remediation is in place

**Signed:**  
Date: 2026-04-19  
Name: __________________  
Signature:  

---
