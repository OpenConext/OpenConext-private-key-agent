# OpenConext Private Key Agent — API Reference

## Introduction

The Private Key Agent exposes a REST API that performs RSA cryptographic operations (signing and
decryption) on behalf of authenticated clients, without ever exposing the private keys.

### Base path

All API routes are prefixed with `/v1/`:

```text
http(s)://<host>/v1/<endpoint>
```

### Authentication

All endpoints except the health endpoints require a **static pre-shared Bearer token** as defined in
[RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750). Include the token in every request:

```text
Authorization: Bearer <token>
```

**Health endpoints (`GET /v1/health` and `GET /v1/health/key/{keyName}`) do not require
authentication** and can be called without an `Authorization` header.

### Compatibility policy

Clients and servers **must ignore unknown fields** in request and response bodies. This allows the
API to add new optional fields in future minor versions without breaking existing clients
(forward/backward compatibility).

---

## Endpoints

### GET /v1/health

Returns the overall health status of all registered keys.

| Property           | Value            |
|--------------------|------------------|
| Method             | `GET`            |
| Path               | `/v1/health`     |
| Authentication     | Not required     |

#### Path parameters

None.

#### Request body

None.

#### Responses

##### 200 OK — all keys are healthy

```json
{
  "status": "OK"
}
```

| Field    | Type   | Description       |
|----------|--------|-------------------|
| `status` | string | Always `"OK"`     |

##### 503 Service Unavailable — one or more keys are unhealthy

```json
{
  "status": 503,
  "error": "server_error",
  "message": "One or more keys are unhealthy",
  "unhealthy_keys": ["key-name-a", "key-name-b"]
}
```

| Field            | Type             | Description                                   |
|------------------|------------------|-----------------------------------------------|
| `status`         | integer          | HTTP status code (`503`)                      |
| `error`          | string           | Machine-readable error code                   |
| `message`        | string           | Human-readable description                    |
| `unhealthy_keys` | array of strings | Names of the keys that failed the health check |

##### 405 Method Not Allowed

See [Error responses](#error-responses).

---

### GET /v1/health/key/{keyName}

Returns the health status of a single named key.

| Property           | Value                         |
|--------------------|-------------------------------|
| Method             | `GET`                         |
| Path               | `/v1/health/key/{keyName}`    |
| Authentication     | Not required                  |

#### Path parameters

| Parameter | Pattern                  | Description                |
|-----------|--------------------------|----------------------------|
| `keyName` | `[a-zA-Z0-9_-]{1,64}`   | Logical name of the key    |

#### Request body

None.

#### Responses

##### 200 OK — key is healthy

```json
{
  "status": "OK",
  "key_name": "my-signing-key"
}
```

| Field      | Type   | Description            |
|------------|--------|------------------------|
| `status`   | string | Always `"OK"`          |
| `key_name` | string | Name of the queried key |

##### 404 Not Found — key does not exist

See [Error responses](#error-responses). The `message` field contains the key name.

##### 503 Service Unavailable — key exists but is unhealthy

```json
{
  "status": 503,
  "error": "server_error",
  "message": "Key is unhealthy",
  "key_name": "my-signing-key"
}
```

| Field      | Type    | Description                         |
|------------|---------|-------------------------------------|
| `status`   | integer | HTTP status code (`503`)            |
| `error`    | string  | Machine-readable error code         |
| `message`  | string  | Human-readable description          |
| `key_name` | string  | Name of the key that is unhealthy   |

##### 405 Method Not Allowed

See [Error responses](#error-responses).

---

### POST /v1/sign/{keyName}

Signs a pre-computed hash using the named private key. The client is responsible for hashing the
data; the agent only constructs the DigestInfo structure and applies the RSA private-key operation.

| Property           | Value                       |
|--------------------|-----------------------------|
| Method             | `POST`                      |
| Path               | `/v1/sign/{keyName}`        |
| Authentication     | **Required** (Bearer token) |
| Content-Type       | `application/json`          |

#### Path parameters

| Parameter | Pattern                  | Description                |
|-----------|--------------------------|----------------------------|
| `keyName` | `[a-zA-Z0-9_-]{1,64}`   | Logical name of the key    |

#### Request body

```json
{
  "algorithm": "rsa-pkcs1-v1_5-sha256",
  "hash": "<base64-encoded hash bytes>"
}
```

| Field       | Type   | Required | Description                                                 |
|-------------|--------|----------|-------------------------------------------------------------|
| `algorithm` | string | Yes      | Signing algorithm identifier (see table below)              |
| `hash`      | string | Yes      | Base64-encoded hash bytes; length must match the algorithm  |

**Supported algorithms and required hash lengths:**

| `algorithm`                | Hash function | Required decoded length |
|----------------------------|---------------|-------------------------|
| `rsa-pkcs1-v1_5-sha1`      | SHA-1         | 20 bytes                |
| `rsa-pkcs1-v1_5-sha256`    | SHA-256       | 32 bytes                |
| `rsa-pkcs1-v1_5-sha384`    | SHA-384       | 48 bytes                |
| `rsa-pkcs1-v1_5-sha512`    | SHA-512       | 64 bytes                |

#### Responses

##### 200 OK — signature produced

```json
{
  "signature": "<base64-encoded RSA signature>"
}
```

| Field       | Type   | Description                   |
|-------------|--------|-------------------------------|
| `signature` | string | Base64-encoded RSA signature  |

##### 400 Bad Request

Returned when the request body is invalid: missing or invalid JSON, unknown algorithm, wrong hash
length, or invalid base64 encoding. See [Error responses](#error-responses).

##### 401 Unauthorized

No token provided or the token is invalid. The response includes a `WWW-Authenticate` header:

```
WWW-Authenticate: Bearer realm="private-key-agent", error="invalid_token"
```

See [Error responses](#error-responses).

##### 403 Forbidden

The authenticated client is not allowed to use the requested key.
See [Error responses](#error-responses).

##### 404 Not Found

The key name is not registered in the agent configuration.
See [Error responses](#error-responses).

##### 405 Method Not Allowed

See [Error responses](#error-responses).

##### 500 Internal Server Error

An unexpected error occurred during the signing operation.
See [Error responses](#error-responses).

---

### POST /v1/decrypt/{keyName}

Decrypts RSA-encrypted data (typically a symmetric session key) using the named private key.

| Property           | Value                       |
|--------------------|-----------------------------|
| Method             | `POST`                      |
| Path               | `/v1/decrypt/{keyName}`     |
| Authentication     | **Required** (Bearer token) |
| Content-Type       | `application/json`          |

#### Path parameters

| Parameter | Pattern                  | Description                |
|-----------|--------------------------|----------------------------|
| `keyName` | `[a-zA-Z0-9_-]{1,64}`   | Logical name of the key    |

#### Request body

```json
{
  "algorithm": "rsa-pkcs1-oaep-mgf1-sha256",
  "encrypted_data": "<base64-encoded ciphertext>"
}
```

| Field            | Type   | Required | Description                                                          |
|------------------|--------|----------|----------------------------------------------------------------------|
| `algorithm`      | string | Yes      | Decryption algorithm identifier (see table below)                    |
| `encrypted_data` | string | Yes      | Base64-encoded ciphertext; decoded size must be 128–1024 bytes       |

**Supported algorithms:**

| `algorithm`                     | Description                                      |
|---------------------------------|--------------------------------------------------|
| `rsa-pkcs1-v1_5`                | RSAES-PKCS1-v1.5                                 |
| `rsa-pkcs1-oaep-mgf1-sha1`      | RSAES-OAEP with MGF1 and SHA-1                   |
| `rsa-pkcs1-oaep-mgf1-sha224`    | RSAES-OAEP with MGF1 and SHA-224                 |
| `rsa-pkcs1-oaep-mgf1-sha256`    | RSAES-OAEP with MGF1 and SHA-256 (recommended)   |
| `rsa-pkcs1-oaep-mgf1-sha384`    | RSAES-OAEP with MGF1 and SHA-384                 |
| `rsa-pkcs1-oaep-mgf1-sha512`    | RSAES-OAEP with MGF1 and SHA-512                 |

#### Responses

##### 200 OK — decryption successful

```json
{
  "decrypted_data": "<base64-encoded plaintext>"
}
```

| Field            | Type   | Description                              |
|------------------|--------|------------------------------------------|
| `decrypted_data` | string | Base64-encoded decrypted plaintext bytes |

##### 400 Bad Request

Returned when the request body is invalid: missing or invalid JSON, unknown algorithm, ciphertext
outside the 128–1024 byte range, invalid base64 encoding, or when the decryption operation fails
(e.g., ciphertext encrypted with a different key or corrupted ciphertext).
See [Error responses](#error-responses).

##### 401 Unauthorized

No token provided or the token is invalid. The response includes a `WWW-Authenticate` header:

```
WWW-Authenticate: Bearer realm="private-key-agent", error="invalid_token"
```

See [Error responses](#error-responses).

##### 403 Forbidden

The authenticated client is not allowed to use the requested key.
See [Error responses](#error-responses).

##### 404 Not Found

The key name is not registered in the agent configuration.
See [Error responses](#error-responses).

##### 405 Method Not Allowed

See [Error responses](#error-responses).

##### 500 Internal Server Error

An unexpected internal error occurred. Note: decryption failures due to invalid ciphertext return
400, not 500.
See [Error responses](#error-responses).

---

## Error responses

All error responses use the same JSON structure:

```json
{
  "status": 400,
  "error": "invalid_request",
  "message": "Human-readable description of the problem"
}
```

| Field     | Type    | Description                          |
|-----------|---------|--------------------------------------|
| `status`  | integer | HTTP status code mirrored in the body |
| `error`   | string  | Machine-readable error code           |
| `message` | string  | Human-readable description            |

**Error codes:**

| HTTP status | `error` value    | Meaning                                                                    |
|-------------|------------------|----------------------------------------------------------------------------|
| 400         | `invalid_request`| Request body is missing, malformed, contains invalid field values, or decryption failed |
| 401         | `invalid_token`  | No `Authorization` header, or the Bearer token is invalid or expired       |
| 403         | `access_denied`  | The client is authenticated but not authorised to use the requested key    |
| 404         | `not_found`      | The requested key name is not registered in the agent                      |
| 405         | `method_not_allowed`| The HTTP method is not allowed on this endpoint                            |
| 500         | `server_error`   | Unexpected internal error                                                  |
| 503         | `server_error`   | Key health check failed                                                    |

The two 503 variants (for `/v1/health` and `/v1/health/key/{keyName}`) extend the generic error
body with extra fields; see the individual endpoint sections above.

---

## Response overview

Complete matrix of HTTP status codes returned by each endpoint:

| Endpoint                          | 200 | 400 | 401 | 403 | 404 | 405 | 500 | 503 |
|-----------------------------------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `GET /v1/health`                  |  ✓  |     |     |     |     |  ✓  |     |  ✓  |
| `GET /v1/health/key/{keyName}`    |  ✓  |     |     |     |  ✓  |  ✓  |     |  ✓  |
| `POST /v1/sign/{keyName}`         |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |     |
| `POST /v1/decrypt/{keyName}`      |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |     |
